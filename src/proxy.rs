//! The authenticated reverse proxy to the unsecured upstream MCP server.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use axum::response::Response;
use url::Url;

use crate::auth::AuthContext;
use crate::config::{Config, TransportCompat};

/// Inbound identity headers are always stripped so a client can never spoof
/// them; they are re-injected from the validated token when enabled.
const X_FORWARDED_USER: HeaderName = HeaderName::from_static("x-forwarded-user");
const X_FORWARDED_SCOPES: HeaderName = HeaderName::from_static("x-forwarded-scopes");

/// Hop-by-hop headers (RFC 9110 §7.6.1) — meaningful only for a single
/// connection, never forwarded in either direction.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Shared state for the proxy handler.
pub struct ProxyState {
    http: reqwest::Client,
    upstream_url: Url,
    compat: TransportCompat,
    identity_headers_enabled: bool,
}

impl ProxyState {
    /// `http` should be built with the configured connect/idle timeouts and
    /// **no** total-duration timeout (that would kill long-lived
    /// `subscriptions/listen` streams).
    pub fn new(config: &Config, http: reqwest::Client) -> Self {
        Self {
            http,
            upstream_url: config.upstream_mcp_url.clone(),
            compat: config.transport_compat,
            identity_headers_enabled: config.identity_headers_enabled,
        }
    }
}

/// Axum handler: validate transport shape, then forward the request and
/// stream the response back untouched.
///
/// Runs strictly *after* [`crate::auth::McpAuthLayer`]; the [`AuthContext`]
/// extension is present on every request that reaches this point.
pub async fn proxy_handler(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response {
    if state.compat == TransportCompat::Strict
        && let Err(response) = validate_strict_headers(req.method(), req.headers())
    {
        return *response;
    }

    let mcp_method = header_str(req.headers(), "mcp-method").map(str::to_owned);
    let mcp_name = header_str(req.headers(), "mcp-name").map(str::to_owned);

    let auth = req
        .extensions()
        .get::<AuthContext>()
        .cloned()
        .unwrap_or(AuthContext {
            sub: None,
            scopes: Vec::new(),
        });

    let (parts, body) = req.into_parts();
    let headers = build_upstream_headers(&parts.headers, &auth, &state);

    let mut upstream_req = state
        .http
        .request(parts.method.clone(), state.upstream_url.clone())
        .headers(headers);
    // GET/DELETE (compat mode only) carry no body.
    if parts.method == Method::POST {
        upstream_req = upstream_req.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }

    let upstream_res = match upstream_req.send().await {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(error = %e, "upstream request failed");
            return error_response(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
    };

    let status = upstream_res.status();
    // Free audit trail: who did what, never bodies, never tokens.
    tracing::info!(
        http_method = %parts.method,
        mcp_method = mcp_method.as_deref().unwrap_or("-"),
        mcp_name = mcp_name.as_deref().unwrap_or("-"),
        sub = auth.sub.as_deref().unwrap_or("-"),
        status = status.as_u16(),
        "proxied request"
    );

    let mut builder = Response::builder().status(status);
    if let Some(headers) = builder.headers_mut() {
        copy_response_headers(upstream_res.headers(), headers);
    }
    builder
        .body(Body::from_stream(upstream_res.bytes_stream()))
        .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "invalid upstream response"))
}

/// 2026-07-28 transport shape: POST-only is enforced by routing; here we
/// enforce the mandatory metadata headers. Per the spec, an intermediary
/// rejects on missing/malformed headers with 400; the JSON-RPC
/// `HeaderMismatch` body (code -32020) is included as a courtesy.
///
/// `Mcp-Name` is required exactly when `Mcp-Method` is one of `tools/call`,
/// `resources/read`, `prompts/get` — decidable from headers alone, without
/// parsing the body (the upstream re-validates header/body consistency).
fn validate_strict_headers(method: &Method, headers: &HeaderMap) -> Result<(), Box<Response>> {
    debug_assert_eq!(method, Method::POST, "non-POST is rejected by routing");
    if header_str(headers, "mcp-protocol-version").is_none() {
        return Err(Box::new(header_mismatch_response(
            "required header MCP-Protocol-Version is missing",
        )));
    }
    let Some(mcp_method) = header_str(headers, "mcp-method") else {
        return Err(Box::new(header_mismatch_response(
            "required header Mcp-Method is missing",
        )));
    };
    let name_required = matches!(mcp_method, "tools/call" | "resources/read" | "prompts/get");
    if name_required && header_str(headers, "mcp-name").is_none() {
        return Err(Box::new(header_mismatch_response(&format!(
            "required header Mcp-Name is missing for {mcp_method}"
        ))));
    }
    Ok(())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Filter client headers for forwarding and inject trusted identity headers.
fn build_upstream_headers(
    client_headers: &HeaderMap,
    auth: &AuthContext,
    state: &ProxyState,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in client_headers {
        if !forwardable(name, state.compat) {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    if state.identity_headers_enabled {
        if let Some(sub) = &auth.sub
            && let Ok(v) = HeaderValue::from_str(sub)
        {
            headers.insert(X_FORWARDED_USER, v);
        }
        if let Ok(v) = HeaderValue::from_str(&auth.scopes.join(" ")) {
            headers.insert(X_FORWARDED_SCOPES, v);
        }
    }
    headers
}

/// Which client headers may reach the upstream.
fn forwardable(name: &HeaderName, compat: TransportCompat) -> bool {
    let n = name.as_str();
    // The upstream is unsecured and must never see client tokens
    // (token-passthrough anti-pattern).
    if n == "authorization" {
        return false;
    }
    // Anti-spoofing: identity headers only ever originate here.
    if n == "x-forwarded-user" || n == "x-forwarded-scopes" {
        return false;
    }
    if HOP_BY_HOP.contains(&n) {
        return false;
    }
    // Set by the HTTP client from the upstream URL.
    if n == "host" || n == "content-length" {
        return false;
    }
    // 2026-07-28 removed sessions: ignore (do not forward) session ids in
    // strict mode. Compat mode passes them through transparently — they are
    // never used for authorization decisions either way.
    if n == "mcp-session-id" && compat == TransportCompat::Strict {
        return false;
    }
    true
}

/// Copy upstream response headers, dropping hop-by-hop ones. Everything
/// else — including `Mcp-Session-Id` in compat mode, `X-Accel-Buffering`,
/// SSE content types — passes through untouched.
fn copy_response_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for (name, value) in from {
        let n = name.as_str();
        if HOP_BY_HOP.contains(&n) || n == "content-length" {
            continue;
        }
        to.append(name.clone(), value.clone());
    }
}

fn header_mismatch_response(message: &str) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": { "code": -32020, "message": format!("Header mismatch: {message}") },
    });
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("static response construction cannot fail")
}

fn error_response(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "error": message }).to_string(),
        ))
        .expect("static response construction cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(compat: TransportCompat, identity: bool) -> ProxyState {
        ProxyState {
            http: reqwest::Client::new(),
            upstream_url: "http://127.0.0.1:9/mcp".parse().unwrap(),
            compat,
            identity_headers_enabled: identity,
        }
    }

    fn client_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer secret".parse().unwrap());
        h.insert("x-forwarded-user", "mallory".parse().unwrap());
        h.insert("x-forwarded-scopes", "admin".parse().unwrap());
        h.insert("mcp-method", "tools/call".parse().unwrap());
        h.insert("mcp-name", "get_weather".parse().unwrap());
        h.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        h.insert("mcp-session-id", "abc123".parse().unwrap());
        h.insert(
            "accept",
            "application/json, text/event-stream".parse().unwrap(),
        );
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert("connection", "keep-alive".parse().unwrap());
        h.insert("host", "mcp.example.com".parse().unwrap());
        h
    }

    fn auth() -> AuthContext {
        AuthContext {
            sub: Some("alice".into()),
            scopes: vec!["mcp:tools".into()],
        }
    }

    #[test]
    fn authorization_never_reaches_upstream() {
        let headers = build_upstream_headers(
            &client_headers(),
            &auth(),
            &state(TransportCompat::Strict, true),
        );
        assert!(headers.get("authorization").is_none());
    }

    #[test]
    fn inbound_identity_headers_are_replaced_not_forwarded() {
        let headers = build_upstream_headers(
            &client_headers(),
            &auth(),
            &state(TransportCompat::Strict, true),
        );
        assert_eq!(headers.get("x-forwarded-user").unwrap(), "alice");
        assert_eq!(headers.get("x-forwarded-scopes").unwrap(), "mcp:tools");
    }

    #[test]
    fn identity_headers_stripped_when_disabled() {
        let headers = build_upstream_headers(
            &client_headers(),
            &auth(),
            &state(TransportCompat::Strict, false),
        );
        assert!(headers.get("x-forwarded-user").is_none());
        assert!(headers.get("x-forwarded-scopes").is_none());
    }

    #[test]
    fn mcp_headers_are_preserved() {
        let headers = build_upstream_headers(
            &client_headers(),
            &auth(),
            &state(TransportCompat::Strict, false),
        );
        assert_eq!(headers.get("mcp-method").unwrap(), "tools/call");
        assert_eq!(headers.get("mcp-name").unwrap(), "get_weather");
        assert_eq!(headers.get("mcp-protocol-version").unwrap(), "2026-07-28");
        assert_eq!(
            headers.get("accept").unwrap(),
            "application/json, text/event-stream"
        );
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn hop_by_hop_and_host_are_dropped() {
        let headers = build_upstream_headers(
            &client_headers(),
            &auth(),
            &state(TransportCompat::Strict, false),
        );
        assert!(headers.get("connection").is_none());
        assert!(headers.get("host").is_none());
    }

    #[test]
    fn session_id_dropped_in_strict_passed_in_compat() {
        let strict = build_upstream_headers(
            &client_headers(),
            &auth(),
            &state(TransportCompat::Strict, false),
        );
        assert!(strict.get("mcp-session-id").is_none());
        let compat = build_upstream_headers(
            &client_headers(),
            &auth(),
            &state(TransportCompat::Compat2025, false),
        );
        assert_eq!(compat.get("mcp-session-id").unwrap(), "abc123");
    }

    #[test]
    fn strict_header_validation_matrix() {
        let ok = |headers: &HeaderMap| validate_strict_headers(&Method::POST, headers).is_ok();

        let mut h = HeaderMap::new();
        h.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        h.insert("mcp-method", "tools/list".parse().unwrap());
        assert!(ok(&h), "tools/list needs no Mcp-Name");

        h.insert("mcp-method", "tools/call".parse().unwrap());
        assert!(!ok(&h), "tools/call without Mcp-Name is rejected");
        h.insert("mcp-name", "get_weather".parse().unwrap());
        assert!(ok(&h));

        let mut h = HeaderMap::new();
        h.insert("mcp-method", "tools/list".parse().unwrap());
        assert!(!ok(&h), "missing MCP-Protocol-Version is rejected");

        let mut h = HeaderMap::new();
        h.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        assert!(!ok(&h), "missing Mcp-Method is rejected");
    }
}
