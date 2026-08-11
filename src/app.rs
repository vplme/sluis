//! Router assembly and server lifecycle for the proxy binary (and tests).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use crate::auth::{
    DiscoveryError, IntrospectionValidator, JwksValidator, McpAuthLayer, TokenValidator,
};
use crate::config::{Config, TokenValidationMode, TransportCompat};
use crate::metadata::ProtectedResourceMetadata;
use crate::proxy::{ProxyState, proxy_handler};

/// Build the shared HTTP client used for upstream proxying and for talking
/// to the authorization server: connect timeout and optional idle (read)
/// timeout, but deliberately **no** total-duration timeout — long-lived
/// streamed responses must be able to outlive any fixed deadline.
pub fn build_http_client(config: &Config) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(config.upstream_connect_timeout_secs));
    if let Some(idle) = config.upstream_idle_timeout_secs {
        builder = builder.read_timeout(Duration::from_secs(idle));
    }
    builder.build()
}

/// Construct the configured token validator. Performs AS metadata discovery
/// (and, in JWKS mode, the initial key fetch) — a hard failure by design so
/// startup fails fast on IdP misconfiguration.
pub async fn build_validator(
    config: &Config,
    http: reqwest::Client,
) -> Result<Arc<dyn TokenValidator>, DiscoveryError> {
    match config.token_validation {
        TokenValidationMode::Jwks => Ok(Arc::new(
            JwksValidator::discover(
                http,
                &config.oidc_issuer_url,
                config.resource_url(),
                config.clock_skew_secs,
                Duration::from_secs(config.jwks_cache_ttl),
            )
            .await?,
        )),
        TokenValidationMode::Introspection => Ok(Arc::new(
            IntrospectionValidator::discover(
                http,
                &config.oidc_issuer_url,
                config.resource_url(),
                // validate() guarantees presence in introspection mode.
                config.introspection_client_id.clone().unwrap_or_default(),
                config
                    .introspection_client_secret
                    .clone()
                    .unwrap_or_default(),
                config.clock_skew_secs,
            )
            .await?,
        )),
    }
}

/// Assemble the complete application router:
///
/// - `GET /healthz` — liveness, no auth, no IdP dependency;
/// - `GET /.well-known/oauth-protected-resource` (and the RFC 9728 §3
///   path-suffixed variant for the MCP path) — PRM, no auth, permissive CORS
///   for browser-based MCP clients;
/// - the MCP endpoint — auth layer + reverse proxy. POST-only in strict
///   mode (GET/DELETE get `405` from routing); compat mode also forwards
///   GET and DELETE, with GET subject to the same token checks as POST.
pub fn build_router(config: &Config, validator: Arc<dyn TokenValidator>) -> Router {
    let prm = ProtectedResourceMetadata::from_config(config);
    let prm_router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get({
                let prm = prm.clone();
                move || async move { Json(prm) }
            }),
        )
        .route(
            // RFC 9728 §3: metadata for a resource with a path component
            // lives at /.well-known/oauth-protected-resource/<path>.
            &format!("/.well-known/oauth-protected-resource{}", config.mcp_path),
            get(move || async move { Json(prm) }),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET]),
        );

    let http = build_http_client(config).expect("HTTP client construction cannot fail");
    let proxy_state = Arc::new(ProxyState::new(config, http));
    let mcp_endpoint = match config.transport_compat {
        TransportCompat::Strict => post(proxy_handler),
        TransportCompat::Compat2025 => post(proxy_handler).get(proxy_handler).delete(proxy_handler),
    };

    let allowed_origins = config.allowed_origins.clone().map(Arc::new);
    let mcp_router = Router::new()
        .route(&config.mcp_path, mcp_endpoint.with_state(proxy_state))
        .layer(McpAuthLayer::from_config(config, validator))
        // Outside auth: reject disallowed Origins before any token work.
        .layer(axum::middleware::from_fn(
            move |req: Request<Body>, next: Next| {
                let allowed = allowed_origins.clone();
                async move {
                    if let Some(allowed) = allowed
                        && let Some(origin) = req.headers().get(header::ORIGIN)
                    {
                        let ok = origin
                            .to_str()
                            .is_ok_and(|o| allowed.iter().any(|a| a == o));
                        if !ok {
                            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
                        }
                    }
                    next.run(req).await
                }
            },
        ))
        .layer(RequestBodyLimitLayer::new(config.max_body_bytes));

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(prm_router)
        .merge(mcp_router)
}

/// Serve `router` on `config.bind_addr` until SIGTERM/SIGINT, then stop
/// accepting connections and drain in-flight requests for up to
/// `shutdown_grace_secs` before aborting what remains.
pub async fn serve(config: &Config, router: Router) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "listening");

    let grace = Duration::from_secs(config.shutdown_grace_secs);
    let server = axum::serve(listener, router).with_graceful_shutdown(shutdown_signal());

    tokio::select! {
        result = server => result,
        // graceful_shutdown resolves the future only once connections have
        // drained; cap the drain time and abort stragglers.
        () = async {
            shutdown_signal().await;
            tokio::time::sleep(grace).await;
        } => {
            tracing::warn!(grace_secs = grace.as_secs(), "drain deadline reached, aborting remaining connections");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
