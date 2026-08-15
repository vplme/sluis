//! End-to-end test against a real Keycloak in a container.
//!
//! Where `tests/integration.rs` controls every claim with a wiremock AS,
//! this suite proves the other half: a stock IdP, configured the way the
//! README prescribes (custom `mcp:tools` client scope, audience mapper
//! injecting the canonical resource URL, manually pre-registered
//! confidential clients), yields tokens that sluis accepts — and that the
//! IdP-side misconfigurations we warn about are actually rejected.
//!
//! Requires Docker; ignored by default. Run with:
//!
//! ```sh
//! cargo test --test keycloak -- --ignored
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use http_body_util::BodyExt;
use serde_json::json;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use tokio::sync::Mutex;
use tower::ServiceExt;

const KEYCLOAK_IMAGE: &str = "quay.io/keycloak/keycloak";
const KEYCLOAK_TAG: &str = "26.3";
const REALM: &str = "sluis";
/// Must match `proxy_public_url` + `mcp_path` below and the audience
/// mapper in the realm import.
const RESOURCE: &str = "https://mcp.example.com/mcp";

/// Realm import: the exact IdP-side setup the README requires.
///
/// - client scope `mcp:tools`, included in the token `scope` claim;
/// - client scope `sluis-resource` carrying an audience mapper that puts
///   the canonical resource URL into `aud` (Keycloak's substitute for
///   RFC 8707 resource indicators);
/// - `canal-client`: a pre-registered confidential client wired to both —
///   the `claude mcp add --client-id … --client-secret` counterpart;
/// - `other-api-client`: can request `mcp:tools` but lacks the audience
///   mapper — its tokens are valid at the IdP yet must die at sluis;
/// - `sluis-introspector`: the credentials sluis itself uses in
///   introspection mode.
fn realm_import() -> String {
    json!({
        "realm": REALM,
        "enabled": true,
        "accessTokenLifespan": 300,
        "clientScopes": [
            {
                "name": "mcp:tools",
                "protocol": "openid-connect",
                "attributes": { "include.in.token.scope": "true" }
            },
            {
                "name": "sluis-resource",
                "protocol": "openid-connect",
                "attributes": { "include.in.token.scope": "false" },
                "protocolMappers": [{
                    "name": "sluis audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": false,
                    "config": {
                        "included.custom.audience": RESOURCE,
                        "access.token.claim": "true",
                        "id.token.claim": "false"
                    }
                }]
            }
        ],
        "clients": [
            {
                "clientId": "canal-client",
                "secret": "canal-secret",
                "enabled": true,
                "protocol": "openid-connect",
                "publicClient": false,
                "serviceAccountsEnabled": true,
                "standardFlowEnabled": false,
                "directAccessGrantsEnabled": false,
                "defaultClientScopes": ["sluis-resource"],
                "optionalClientScopes": ["mcp:tools"]
            },
            {
                "clientId": "other-api-client",
                "secret": "other-secret",
                "enabled": true,
                "protocol": "openid-connect",
                "publicClient": false,
                "serviceAccountsEnabled": true,
                "standardFlowEnabled": false,
                "directAccessGrantsEnabled": false,
                "defaultClientScopes": [],
                "optionalClientScopes": ["mcp:tools"]
            },
            {
                "clientId": "sluis-introspector",
                "secret": "introspector-secret",
                "enabled": true,
                "protocol": "openid-connect",
                "publicClient": false,
                "serviceAccountsEnabled": true,
                "standardFlowEnabled": false,
                "directAccessGrantsEnabled": false,
                "defaultClientScopes": [],
                "optionalClientScopes": []
            }
        ]
    })
    .to_string()
}

/// Start Keycloak with the realm imported and wait until its OIDC
/// discovery document answers.
async fn start_keycloak() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new(KEYCLOAK_IMAGE, KEYCLOAK_TAG)
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Listening on:"))
        .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
        .with_copy_to(
            "/opt/keycloak/data/import/sluis-realm.json",
            realm_import().into_bytes(),
        )
        .with_cmd(["start-dev", "--import-realm"])
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await
        .expect("keycloak container starts (is Docker running?)");

    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(8080)
        .await
        .expect("mapped port");
    let issuer = format!("http://{host}:{port}/realms/{REALM}");

    // The log line fires before the realm is necessarily queryable; poll
    // discovery until it answers.
    let http = reqwest::Client::new();
    let discovery = format!("{issuer}/.well-known/openid-configuration");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        match http.get(&discovery).send().await {
            Ok(res) if res.status().is_success() => break,
            _ if tokio::time::Instant::now() > deadline => {
                panic!("keycloak discovery never became ready at {discovery}")
            }
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    (container, issuer)
}

/// Client-credentials token from Keycloak — the headless stand-in for the
/// browser authorization-code flow a real MCP client would run.
async fn obtain_token(issuer: &str, client_id: &str, secret: &str, scope: Option<&str>) -> String {
    let mut form = vec![("grant_type", "client_credentials")];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    let res = reqwest::Client::new()
        .post(format!("{issuer}/protocol/openid-connect/token"))
        .basic_auth(client_id, Some(secret))
        .form(&form)
        .send()
        .await
        .expect("token endpoint reachable");
    assert!(
        res.status().is_success(),
        "token request for {client_id} failed: {}",
        res.status()
    );
    let body: serde_json::Value = res.json().await.expect("token response is JSON");
    body["access_token"]
        .as_str()
        .expect("response carries access_token")
        .to_owned()
}

async fn revoke_token(issuer: &str, client_id: &str, secret: &str, token: &str) {
    let res = reqwest::Client::new()
        .post(format!("{issuer}/protocol/openid-connect/revoke"))
        .basic_auth(client_id, Some(secret))
        .form(&[("token", token)])
        .send()
        .await
        .expect("revocation endpoint reachable");
    assert!(
        res.status().is_success(),
        "revocation failed: {}",
        res.status()
    );
}

// ---------- minimal upstream that records what it sees ----------

type Seen = Arc<Mutex<Vec<HeaderMap>>>;

async fn spawn_upstream() -> (SocketAddr, Seen) {
    let seen: Seen = Arc::default();

    async fn handler(State(seen): State<Seen>, req: Request<Body>) -> Response {
        seen.lock().await.push(req.headers().clone());
        (
            [(header::CONTENT_TYPE, "application/json")],
            json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } }).to_string(),
        )
            .into_response()
    }

    let app = axum::Router::new()
        .route("/mcp", post(handler))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, seen)
}

async fn build_app(
    issuer: &str,
    upstream: SocketAddr,
    overrides: serde_json::Value,
) -> axum::Router {
    let mut cfg = json!({
        "proxyPublicUrl": "https://mcp.example.com",
        "upstreamMcpUrl": format!("http://{upstream}/mcp"),
        "oidcIssuerUrl": issuer,
        "enableIdentityHeaders": true,
    });
    cfg.as_object_mut()
        .unwrap()
        .extend(overrides.as_object().cloned().unwrap_or_default());
    let config: sluis::Config = serde_json::from_value(cfg).unwrap();
    config.validate().unwrap();
    let http = sluis::app::build_http_client(&config).unwrap();
    let validator = sluis::app::build_validator(&config, http).await.unwrap();
    sluis::app::build_router(&config, validator)
}

fn mcp_post(token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json");
    if let Some(token) = token {
        b = b.header("authorization", format!("Bearer {token}"));
    }
    b.body(Body::from(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string(),
    ))
    .unwrap()
}

async fn status_and_www(app: &axum::Router, token: &str) -> (StatusCode, String) {
    let res = app.clone().oneshot(mcp_post(Some(token))).await.unwrap();
    let status = res.status();
    let www = res
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .unwrap_or_default();
    (status, www)
}

// ---------- the test ----------

#[tokio::test]
#[ignore = "requires Docker (Keycloak testcontainer); run with: cargo test --test keycloak -- --ignored"]
async fn keycloak_end_to_end_jwks_and_introspection() {
    let (_keycloak, issuer) = start_keycloak().await;
    let (upstream, seen) = spawn_upstream().await;

    // -------- JWKS mode (default) --------
    let app = build_app(&issuer, upstream, json!({})).await;

    // No token → 401 challenge pointing at the PRM.
    let res = app.clone().oneshot(mcp_post(None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Pre-registered client, correct scope → real Keycloak token → proxied.
    let token = obtain_token(&issuer, "canal-client", "canal-secret", Some("mcp:tools")).await;
    let res = app.clone().oneshot(mcp_post(Some(&token))).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "keycloak-minted token must pass"
    );
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["result"]["ok"], json!(true));

    // Header hygiene: token stripped, identity injected from the real
    // service-account subject.
    {
        let requests = seen.lock().await;
        let headers = requests.last().expect("upstream saw the request");
        assert!(headers.get("authorization").is_none());
        let sub = headers.get("x-forwarded-user").expect("identity header");
        assert!(!sub.is_empty());
        let scopes = headers.get("x-forwarded-scopes").unwrap().to_str().unwrap();
        assert!(
            scopes.split(' ').any(|s| s == "mcp:tools"),
            "forwarded scopes carry mcp:tools, got: {scopes}"
        );
    }

    // Same client, scope not requested → valid at the IdP, 403 here.
    let unscoped = obtain_token(&issuer, "canal-client", "canal-secret", None).await;
    let (status, www) = status_and_www(&app, &unscoped).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(www.contains("insufficient_scope"), "got: {www}");

    // Client without the audience mapper → token lacks the resource `aud`
    // → 401, even though the signature, issuer, and scope are all good.
    // This is the token-replay defense working against a real IdP token.
    let foreign = obtain_token(
        &issuer,
        "other-api-client",
        "other-secret",
        Some("mcp:tools"),
    )
    .await;
    let (status, www) = status_and_www(&app, &foreign).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(www.contains("invalid_token"), "got: {www}");

    // Garbage is garbage.
    let (status, _) = status_and_www(&app, "not-a-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // -------- introspection mode --------
    let app = build_app(
        &issuer,
        upstream,
        json!({
            "tokenValidation": "introspection",
            "introspectionClientId": "sluis-introspector",
            "introspectionClientSecret": "introspector-secret",
        }),
    )
    .await;

    // The same well-formed token passes via RFC 7662.
    let token = obtain_token(&issuer, "canal-client", "canal-secret", Some("mcp:tools")).await;
    let res = app.clone().oneshot(mcp_post(Some(&token))).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "introspected token must pass");

    // The audience check is enforced on introspection responses too.
    let foreign = obtain_token(
        &issuer,
        "other-api-client",
        "other-secret",
        Some("mcp:tools"),
    )
    .await;
    let (status, _) = status_and_www(&app, &foreign).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Revocation — the reason introspection mode exists. A revoked token
    // dies immediately (it was never cached: revoked before first use).
    let doomed = obtain_token(&issuer, "canal-client", "canal-secret", Some("mcp:tools")).await;
    revoke_token(&issuer, "canal-client", "canal-secret", &doomed).await;
    let (status, www) = status_and_www(&app, &doomed).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revoked token must be rejected"
    );
    assert!(www.contains("invalid_token"), "got: {www}");
}
