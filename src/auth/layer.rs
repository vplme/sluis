//! The MCP resource-server tower layer: challenge, validate, enforce scopes.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::response::Response;
use futures_util::future::BoxFuture;
use tower::{Layer, Service};

use super::{AuthError, Challenge, TokenClaims, TokenValidator};
use crate::config::Config;

/// Identity of the validated caller, inserted as a request extension for the
/// inner service (the proxy uses it for `X-Forwarded-User`; embedders can
/// extract it with `Extension<AuthContext>`).
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The token's `sub` claim, if any.
    pub sub: Option<String>,
    /// Scopes granted to the token.
    pub scopes: Vec<String>,
}

struct LayerState {
    validator: Arc<dyn TokenValidator>,
    challenge: Challenge,
    required_scopes: Vec<String>,
    method_scopes: HashMap<String, Vec<String>>,
}

/// Tower layer implementing MCP resource-server authorization for the routes
/// it wraps:
///
/// - no credentials → `401` with a `WWW-Authenticate` challenge pointing at
///   the Protected Resource Metadata;
/// - invalid/expired token → `401` with `error="invalid_token"`;
/// - valid token, missing scopes → `403` with `error="insufficient_scope"`
///   and the required scopes;
/// - valid token → request forwarded with an [`AuthContext`] extension.
///
/// Scope requirements are the global list, overridable per `Mcp-Method`
/// header value. Enforcement never parses the request body; the body is the
/// upstream's business.
///
/// Every decision is made per request from the token alone — nothing is
/// keyed on connections or client-supplied identifiers.
#[derive(Clone)]
pub struct McpAuthLayer {
    state: Arc<LayerState>,
}

impl McpAuthLayer {
    /// Build a layer with explicit parameters (for embedding outside the
    /// proxy binary).
    ///
    /// `prm_url` is the absolute URL of the PRM document to advertise in
    /// challenges; `method_scopes` maps `Mcp-Method` header values to scope
    /// lists that *replace* `required_scopes` for that method.
    pub fn new(
        validator: Arc<dyn TokenValidator>,
        prm_url: impl Into<String>,
        required_scopes: Vec<String>,
        method_scopes: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            state: Arc::new(LayerState {
                validator,
                challenge: Challenge::new("mcp", prm_url),
                required_scopes,
                method_scopes,
            }),
        }
    }

    /// Build a layer from the resolved proxy [`Config`].
    pub fn from_config(config: &Config, validator: Arc<dyn TokenValidator>) -> Self {
        Self::new(
            validator,
            config.prm_url(),
            config.required_scopes.clone(),
            config
                .method_scopes
                .iter()
                .map(|o| (o.method.clone(), o.scopes.clone()))
                .collect(),
        )
    }
}

impl<S> Layer<S> for McpAuthLayer {
    type Service = McpAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        McpAuthService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Service produced by [`McpAuthLayer`].
#[derive(Clone)]
pub struct McpAuthService<S> {
    inner: S,
    state: Arc<LayerState>,
}

impl<S> Service<Request<Body>> for McpAuthService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Take the ready service, leave a clone (standard tower pattern so
        // the future does not borrow self).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let state = self.state.clone();

        Box::pin(async move {
            let token = match bearer_token(&req) {
                Some(t) => t,
                None => {
                    let cid = correlation_id();
                    tracing::info!(correlation_id = %cid, "request without bearer token");
                    return Ok(challenge_response(
                        StatusCode::UNAUTHORIZED,
                        state.challenge.missing_token(&state.required_scopes),
                        "unauthorized",
                    ));
                }
            };

            let claims = match state.validator.validate(&token).await {
                Ok(claims) => claims,
                Err(AuthError::Unavailable { reason }) => {
                    let cid = correlation_id();
                    tracing::error!(correlation_id = %cid, reason = %reason, "token validation unavailable");
                    return Ok(plain_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily unable to validate credentials",
                    ));
                }
                Err(e) => {
                    // Generic message to the client; the specific reason only
                    // goes to the log, tied together by the correlation id.
                    let cid = correlation_id();
                    tracing::info!(correlation_id = %cid, reason = %e, "rejected token");
                    return Ok(challenge_response(
                        StatusCode::UNAUTHORIZED,
                        state.challenge.invalid_token(),
                        "unauthorized",
                    ));
                }
            };

            let required = required_scopes_for(&state, &req);
            if !claims.has_scopes(required) {
                let cid = correlation_id();
                tracing::info!(
                    correlation_id = %cid,
                    required = %required.join(" "),
                    "token lacks required scopes"
                );
                return Ok(challenge_response(
                    StatusCode::FORBIDDEN,
                    state.challenge.insufficient_scope(required),
                    "insufficient_scope",
                ));
            }

            req.extensions_mut().insert(auth_context(&claims));
            inner.call(req).await
        })
    }
}

/// Scopes required for this request: the `Mcp-Method` override when that
/// header is present and mapped, the global list otherwise.
fn required_scopes_for<'a>(state: &'a LayerState, req: &Request<Body>) -> &'a [String] {
    req.headers()
        .get("mcp-method")
        .and_then(|v| v.to_str().ok())
        .and_then(|m| state.method_scopes.get(m))
        .map(Vec::as_slice)
        .unwrap_or(&state.required_scopes)
}

fn auth_context(claims: &TokenClaims) -> AuthContext {
    AuthContext {
        sub: claims.sub.clone(),
        scopes: claims.scopes.clone(),
    }
}

/// Extract the bearer token from `Authorization`, scheme case-insensitive
/// (RFC 9110 §11.1). Returns an owned String so the request can be moved on.
fn bearer_token(req: &Request<Body>) -> Option<String> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

fn challenge_response(status: StatusCode, challenge: String, error_code: &str) -> Response {
    let mut response = plain_error(status, error_code);
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// Small generic JSON error body. Details stay in the logs.
fn plain_error(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "error": message }).to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static response construction cannot fail")
}

/// Cheap process-unique id to correlate a client-facing rejection with its
/// detailed log line. Not a security token.
fn correlation_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    format!("{t:x}-{n:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Extension, Router};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct StaticValidator(Result<TokenClaims, &'static str>);

    #[async_trait::async_trait]
    impl TokenValidator for StaticValidator {
        async fn validate(&self, _token: &str) -> Result<TokenClaims, AuthError> {
            match &self.0 {
                Ok(claims) => Ok(claims.clone()),
                Err(reason) => Err(AuthError::InvalidToken {
                    reason: (*reason).to_owned(),
                }),
            }
        }
    }

    fn app(validator: StaticValidator, method_scopes: HashMap<String, Vec<String>>) -> Router {
        let layer = McpAuthLayer::new(
            Arc::new(validator),
            "https://p/.well-known/oauth-protected-resource",
            vec!["mcp:tools".into()],
            method_scopes,
        );
        Router::new().route(
            "/mcp",
            post(|Extension(ctx): Extension<AuthContext>| async move {
                format!("sub={}", ctx.sub.as_deref().unwrap_or("-"))
            })
            .layer(layer),
        )
    }

    fn post_req(auth: Option<&str>, mcp_method: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri("/mcp");
        if let Some(a) = auth {
            builder = builder.header("authorization", a);
        }
        if let Some(m) = mcp_method {
            builder = builder.header("mcp-method", m);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn ok_claims(scopes: &[&str]) -> TokenClaims {
        TokenClaims {
            sub: Some("alice".into()),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[tokio::test]
    async fn missing_token_gets_401_with_prm_challenge() {
        let app = app(
            StaticValidator(Ok(ok_claims(&["mcp:tools"]))),
            HashMap::new(),
        );
        let res = app.oneshot(post_req(None, None)).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let www = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert_eq!(
            www,
            "Bearer realm=\"mcp\", resource_metadata=\"https://p/.well-known/oauth-protected-resource\", scope=\"mcp:tools\""
        );
    }

    #[tokio::test]
    async fn invalid_token_gets_401_invalid_token() {
        let app = app(StaticValidator(Err("bad signature")), HashMap::new());
        let res = app
            .oneshot(post_req(Some("Bearer nope"), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let www = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(www.contains("error=\"invalid_token\""));
        // The detailed reason must not leak to the client.
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("bad signature"));
    }

    #[tokio::test]
    async fn insufficient_scope_gets_403_with_required_scope() {
        let app = app(StaticValidator(Ok(ok_claims(&["other"]))), HashMap::new());
        let res = app.oneshot(post_req(Some("Bearer t"), None)).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let www = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(www.contains("error=\"insufficient_scope\""));
        assert!(www.contains("scope=\"mcp:tools\""));
    }

    #[tokio::test]
    async fn method_scope_override_applies_only_to_that_method() {
        let overrides = HashMap::from([("tools/call".to_owned(), vec!["mcp:admin".to_owned()])]);

        // Token with only the base scope: fine for tools/list...
        let app1 = app(
            StaticValidator(Ok(ok_claims(&["mcp:tools"]))),
            overrides.clone(),
        );
        let res = app1
            .oneshot(post_req(Some("Bearer t"), Some("tools/list")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // ...but rejected for tools/call, which demands the override scope.
        let app2 = app(StaticValidator(Ok(ok_claims(&["mcp:tools"]))), overrides);
        let res = app2
            .oneshot(post_req(Some("Bearer t"), Some("tools/call")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let www = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(www.contains("scope=\"mcp:admin\""));
    }

    #[tokio::test]
    async fn valid_token_reaches_inner_service_with_auth_context() {
        let app = app(
            StaticValidator(Ok(ok_claims(&["mcp:tools"]))),
            HashMap::new(),
        );
        let res = app
            .oneshot(post_req(Some("bearer t"), None)) // lowercase scheme is fine
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"sub=alice");
    }
}
