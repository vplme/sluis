//! Embedding `McpAuthLayer` in a plain axum app that serves an MCP endpoint
//! directly (no reverse proxy involved).
//!
//! Run with:
//! ```sh
//! cargo run --example embedded
//! ```
//! then observe the challenge:
//! ```sh
//! curl -i -XPOST http://127.0.0.1:3000/mcp
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use sluis::auth::{AuthContext, JwksValidator, McpAuthLayer};
use sluis::metadata::ProtectedResourceMetadata;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Point this at a real authorization server to run the example.
    let issuer: url::Url = std::env::var("ISSUER")
        .unwrap_or_else(|_| "https://idp.example.com/realms/lab".into())
        .parse()?;
    let resource = "http://127.0.0.1:3000/mcp".to_owned();
    let prm_url = "http://127.0.0.1:3000/.well-known/oauth-protected-resource".to_owned();

    // Discovery is a startup hard-fail by design.
    let validator = Arc::new(
        JwksValidator::discover(
            reqwest::Client::new(),
            &issuer,
            resource.clone(),
            30,
            Duration::from_secs(300),
        )
        .await?,
    );

    let auth = McpAuthLayer::new(
        validator,
        prm_url,
        vec!["mcp:tools".into()],
        Default::default(),
    );

    let prm = ProtectedResourceMetadata {
        resource,
        authorization_servers: vec![issuer.as_str().trim_end_matches('/').to_owned()],
        scopes_supported: vec!["mcp:tools".into()],
        bearer_methods_supported: vec!["header".into()],
    };

    let app = Router::new()
        .route(
            "/mcp",
            // Your in-process MCP handler; `AuthContext` carries the caller.
            post(|Extension(ctx): Extension<AuthContext>| async move {
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "served_for": ctx.sub }
                }))
            })
            .layer(auth),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(move || async move { Json(prm) }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
