//! End-to-end tests: mock authorization server (wiremock: discovery + JWKS +
//! introspection) and a real mock upstream MCP server (axum on an ephemeral
//! port), with the full router driven in between.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::json;
use tokio::sync::Mutex;
use tower::ServiceExt;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_KEY_PEM: &str = include_str!("keys/test_key.pem");
const WRONG_KEY_PEM: &str = include_str!("keys/wrong_key.pem");
const KID: &str = "integration-test-key";
const PUBLIC_URL: &str = "https://mcp.example.com";
const RESOURCE: &str = "https://mcp.example.com/mcp";

// ---------- mock authorization server ----------

fn jwk_for(pem: &str, kid: &str) -> serde_json::Value {
    let key = RsaPrivateKey::from_pkcs8_pem(pem).expect("test key parses");
    let public = key.to_public_key();
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    })
}

/// Wiremock AS serving OIDC discovery and a JWKS for `TEST_KEY_PEM`.
async fn mock_as() -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "introspection_endpoint": format!("{issuer}/introspect"),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "keys": [jwk_for(TEST_KEY_PEM, KID)] })),
        )
        .mount(&server)
        .await;
    server
}

// ---------- token minting ----------

struct TokenSpec {
    issuer: String,
    aud: serde_json::Value,
    scope: &'static str,
    exp_offset_secs: i64,
    signing_pem: &'static str,
    kid: &'static str,
}

impl TokenSpec {
    fn valid(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            aud: json!(RESOURCE),
            scope: "mcp:tools",
            exp_offset_secs: 300,
            signing_pem: TEST_KEY_PEM,
            kid: KID,
        }
    }
}

fn mint(spec: &TokenSpec) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = json!({
        "iss": spec.issuer,
        "aud": spec.aud,
        "sub": "alice",
        "scope": spec.scope,
        "iat": now,
        "exp": now + spec.exp_offset_secs,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(spec.kid.to_owned());
    let key = EncodingKey::from_rsa_pem(spec.signing_pem.as_bytes()).expect("test key");
    encode(&header, &claims, &key).expect("token signs")
}

// ---------- mock upstream MCP server ----------

#[derive(Clone, Default)]
struct UpstreamSeen {
    requests: Arc<Mutex<Vec<(String, HeaderMap)>>>,
}

/// Real HTTP upstream. POST answers a JSON-RPC result; `Mcp-Method:
/// subscriptions/listen` (or any GET) answers a slow three-chunk SSE stream
/// so streaming behavior is observable. Echoes `Mcp-Session-Id`.
async fn spawn_upstream() -> (SocketAddr, UpstreamSeen) {
    let seen = UpstreamSeen::default();

    async fn handler(State(seen): State<UpstreamSeen>, req: Request<Body>) -> Response {
        let headers = req.headers().clone();
        let http_method = req.method().to_string();
        seen.requests
            .lock()
            .await
            .push((http_method.clone(), headers.clone()));

        let session = headers.get("mcp-session-id").cloned();
        let streaming = http_method == "GET"
            || headers
                .get("mcp-method")
                .is_some_and(|v| v == "subscriptions/listen");

        let mut response = if streaming {
            let stream = futures_util::stream::unfold(0u8, |i| async move {
                if i >= 3 {
                    return None;
                }
                if i > 0 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                let chunk = format!("data: {{\"chunk\":{i}}}\n\n");
                Some((Ok::<_, std::convert::Infallible>(Bytes::from(chunk)), i + 1))
            });
            Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header("x-accel-buffering", "no")
                .body(Body::from_stream(stream))
                .unwrap()
        } else {
            (
                [(header::CONTENT_TYPE, "application/json")],
                json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } }).to_string(),
            )
                .into_response()
        };
        if let Some(session) = session {
            response.headers_mut().insert("mcp-session-id", session);
        }
        response
    }

    let app = Router::new()
        .route("/mcp", any(handler))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, seen)
}

// ---------- app under test ----------

async fn build_app(as_uri: &str, upstream: SocketAddr, overrides: serde_json::Value) -> Router {
    let mut cfg = json!({
        "proxy_public_url": PUBLIC_URL,
        "upstream_mcp_url": format!("http://{upstream}/mcp"),
        "oidc_issuer_url": as_uri,
        "identity_headers_enabled": true,
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

fn mcp_post(token: Option<&str>, mcp_method: &str, mcp_name: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", mcp_method)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json");
    if let Some(name) = mcp_name {
        b = b.header("mcp-name", name);
    }
    if let Some(token) = token {
        b = b.header("authorization", format!("Bearer {token}"));
    }
    b.body(Body::from(
        json!({ "jsonrpc": "2.0", "id": 1, "method": mcp_method }).to_string(),
    ))
    .unwrap()
}

async fn body_string(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------- the full flow ----------

#[tokio::test]
async fn full_flow_challenge_prm_authenticated_post_passthrough() {
    let as_server = mock_as().await;
    let (upstream, seen) = spawn_upstream().await;
    let app = build_app(&as_server.uri(), upstream, json!({})).await;

    // 1. Unauthenticated request → 401 with a PRM pointer.
    let res = app
        .clone()
        .oneshot(mcp_post(None, "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let www = res.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .to_owned();
    let prm_url = www
        .split("resource_metadata=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("challenge carries resource_metadata");
    assert_eq!(
        prm_url,
        format!("{PUBLIC_URL}/.well-known/oauth-protected-resource")
    );

    // 2. PRM fetch (same path the client would derive from the challenge).
    let res = app
        .clone()
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .header("origin", "https://webclient.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // Browser-based MCP clients fetch PRM cross-origin.
    assert_eq!(
        res.headers()["access-control-allow-origin"]
            .to_str()
            .unwrap(),
        "*"
    );
    let prm: serde_json::Value = serde_json::from_str(&body_string(res).await).unwrap();
    assert_eq!(prm["resource"], RESOURCE);
    assert_eq!(prm["authorization_servers"], json!([as_server.uri()]));
    assert_eq!(prm["bearer_methods_supported"], json!(["header"]));

    // Path-suffixed PRM variant (RFC 9728 §3) is served too.
    let res = app
        .clone()
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 3. Authenticated POST → upstream response passes through.
    let token = mint(&TokenSpec::valid(&as_server.uri()));
    let res = app
        .clone()
        .oneshot(mcp_post(Some(&token), "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(res).await).unwrap();
    assert_eq!(body["result"]["ok"], json!(true));

    // 4. Header hygiene at the upstream: token stripped, identity injected.
    let requests = seen.requests.lock().await;
    let (_, headers) = requests.last().expect("upstream saw the request");
    assert!(
        headers.get("authorization").is_none(),
        "token must never reach upstream"
    );
    assert_eq!(headers.get("x-forwarded-user").unwrap(), "alice");
    assert_eq!(headers.get("x-forwarded-scopes").unwrap(), "mcp:tools");
    assert_eq!(headers.get("mcp-method").unwrap(), "tools/list");
    assert_eq!(headers.get("mcp-protocol-version").unwrap(), "2026-07-28");
}

// ---------- negative token matrix (claims fully controlled here) ----------

async fn assert_rejected(app: &Router, token: &str, expected_status: StatusCode) {
    let res = app
        .clone()
        .oneshot(mcp_post(Some(token), "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), expected_status);
    let www = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
    match expected_status {
        StatusCode::UNAUTHORIZED => assert!(www.contains("error=\"invalid_token\""), "got: {www}"),
        StatusCode::FORBIDDEN => {
            assert!(www.contains("error=\"insufficient_scope\""), "got: {www}")
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn negative_cases_bad_sig_expired_wrong_iss_wrong_aud_missing_scope() {
    let as_server = mock_as().await;
    let (upstream, seen) = spawn_upstream().await;
    let app = build_app(&as_server.uri(), upstream, json!({})).await;
    let issuer = as_server.uri();

    let bad_signature = TokenSpec {
        signing_pem: WRONG_KEY_PEM,
        ..TokenSpec::valid(&issuer)
    };
    assert_rejected(&app, &mint(&bad_signature), StatusCode::UNAUTHORIZED).await;

    let expired = TokenSpec {
        exp_offset_secs: -120, // beyond the 30 s default clock skew
        ..TokenSpec::valid(&issuer)
    };
    assert_rejected(&app, &mint(&expired), StatusCode::UNAUTHORIZED).await;

    let wrong_issuer = TokenSpec {
        issuer: "https://evil-idp.example.com".into(),
        ..TokenSpec::valid(&issuer)
    };
    assert_rejected(&app, &mint(&wrong_issuer), StatusCode::UNAUTHORIZED).await;

    // Tokens minted for a *different resource* at the same IdP must not be
    // replayable here — and catch-all audiences are not accepted either.
    for aud in [
        json!("https://other-service.example.com"),
        json!(["https://other-service.example.com", "api"]),
        json!(PUBLIC_URL), // base URL is not the canonical resource URL
    ] {
        let wrong_aud = TokenSpec {
            aud,
            ..TokenSpec::valid(&issuer)
        };
        assert_rejected(&app, &mint(&wrong_aud), StatusCode::UNAUTHORIZED).await;
    }

    // Audience as an array containing the resource is fine.
    let aud_array = TokenSpec {
        aud: json!(["something-else", RESOURCE]),
        ..TokenSpec::valid(&issuer)
    };
    let res = app
        .clone()
        .oneshot(mcp_post(Some(&mint(&aud_array)), "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let missing_scope = TokenSpec {
        scope: "profile email",
        ..TokenSpec::valid(&issuer)
    };
    assert_rejected(&app, &mint(&missing_scope), StatusCode::FORBIDDEN).await;

    let unknown_kid = TokenSpec {
        kid: "no-such-key",
        ..TokenSpec::valid(&issuer)
    };
    assert_rejected(&app, &mint(&unknown_kid), StatusCode::UNAUTHORIZED).await;

    // None of the rejected requests may have reached the upstream.
    assert_eq!(
        seen.requests.lock().await.len(),
        1,
        "only the aud-array success reaches upstream"
    );
}

// ---------- transport shape: strict mode ----------

#[tokio::test]
async fn strict_mode_rejects_get_and_delete_with_405() {
    let as_server = mock_as().await;
    let (upstream, _) = spawn_upstream().await;
    let app = build_app(&as_server.uri(), upstream, json!({})).await;
    let token = mint(&TokenSpec::valid(&as_server.uri()));

    for m in ["GET", "DELETE"] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(m)
                    .uri("/mcp")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED, "{m} must 405");
    }
}

#[tokio::test]
async fn strict_mode_enforces_mandatory_metadata_headers() {
    let as_server = mock_as().await;
    let (upstream, seen) = spawn_upstream().await;
    let app = build_app(&as_server.uri(), upstream, json!({})).await;
    let token = mint(&TokenSpec::valid(&as_server.uri()));

    // Missing Mcp-Method → 400 with JSON-RPC HeaderMismatch (-32020).
    let req = Request::post("/mcp")
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-protocol-version", "2026-07-28")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_str(&body_string(res).await).unwrap();
    assert_eq!(body["error"]["code"], json!(-32020));

    // tools/call without Mcp-Name → 400; with it → forwarded.
    let res = app
        .clone()
        .oneshot(mcp_post(Some(&token), "tools/call", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = app
        .clone()
        .oneshot(mcp_post(Some(&token), "tools/call", Some("get_weather")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Missing MCP-Protocol-Version → 400.
    let req = Request::post("/mcp")
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-method", "tools/list")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    assert_eq!(seen.requests.lock().await.len(), 1);
}

// ---------- per-method scope overrides ----------

#[tokio::test]
async fn method_scope_override_enforced_from_header_only() {
    let as_server = mock_as().await;
    let (upstream, _) = spawn_upstream().await;
    let app = build_app(
        &as_server.uri(),
        upstream,
        json!({ "method_scopes": { "tools/call": ["mcp:tools", "mcp:tools:write"] } }),
    )
    .await;
    let token = mint(&TokenSpec::valid(&as_server.uri())); // scope: mcp:tools only

    let res = app
        .clone()
        .oneshot(mcp_post(Some(&token), "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(mcp_post(Some(&token), "tools/call", Some("get_weather")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let www = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        www.contains("scope=\"mcp:tools mcp:tools:write\""),
        "got: {www}"
    );
}

// ---------- compat mode ----------

#[tokio::test]
async fn compat_mode_forwards_get_stream_and_session_ids() {
    let as_server = mock_as().await;
    let (upstream, seen) = spawn_upstream().await;
    let app = build_app(
        &as_server.uri(),
        upstream,
        json!({ "transport_compat": "2025" }),
    )
    .await;
    let token = mint(&TokenSpec::valid(&as_server.uri()));

    // GET without a token is challenged exactly like POST.
    let res = app
        .clone()
        .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Authenticated GET listening stream passes through, session id intact,
    // and no 2026 metadata headers are required.
    let res = app
        .clone()
        .oneshot(
            Request::get("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("accept", "text/event-stream")
                .header("mcp-session-id", "sess-42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    assert_eq!(res.headers()["mcp-session-id"], "sess-42");
    let body = body_string(res).await;
    assert_eq!(body.matches("data:").count(), 3);

    // The upstream saw the session id but never the token.
    {
        let requests = seen.requests.lock().await;
        let (m, headers) = requests.last().unwrap();
        assert_eq!(m, "GET");
        assert_eq!(headers.get("mcp-session-id").unwrap(), "sess-42");
        assert!(headers.get("authorization").is_none());
    }

    // POST without Mcp-Method/MCP-Protocol-Version is forwarded in compat.
    let res = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ---------- long-lived stream passthrough ----------

#[tokio::test]
async fn long_lived_stream_is_forwarded_incrementally() {
    let as_server = mock_as().await;
    let (upstream, _) = spawn_upstream().await;
    let app = build_app(&as_server.uri(), upstream, json!({})).await;
    let token = mint(&TokenSpec::valid(&as_server.uri()));

    let res = app
        .clone()
        .oneshot(mcp_post(Some(&token), "subscriptions/listen", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/event-stream");

    let mut stream = res.into_body().into_data_stream();

    // The first chunk must arrive well before the upstream finishes the
    // stream (~600 ms in) — proof of no whole-response buffering.
    let first = tokio::time::timeout(Duration::from_millis(200), stream.next())
        .await
        .expect("first chunk streams immediately")
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("\"chunk\":0"));

    let mut rest = Vec::new();
    while let Some(chunk) = stream.next().await {
        rest.extend_from_slice(&chunk.unwrap());
    }
    let rest = String::from_utf8_lossy(&rest);
    assert!(rest.contains("\"chunk\":1") && rest.contains("\"chunk\":2"));
}

// ---------- introspection mode ----------

#[tokio::test]
async fn introspection_validates_caches_and_maps_outages_to_503() {
    let as_server = mock_as().await;
    let (upstream, _) = spawn_upstream().await;

    // One mock per token value, all mounted up front.
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .and(body_string_contains("opaque-token-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "sub": "alice",
            "scope": "mcp:tools",
            "aud": RESOURCE,
            "iss": as_server.uri(),
        })))
        .expect(1) // the second request must be served from cache
        .mount(&as_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .and(body_string_contains("opaque-token-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "active": false })))
        .mount(&as_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .and(body_string_contains("opaque-token-3"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&as_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .and(body_string_contains("opaque-token-4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "scope": "mcp:tools",
            "aud": "https://other.example.com",
        })))
        .mount(&as_server)
        .await;

    let app = build_app(
        &as_server.uri(),
        upstream,
        json!({
            "token_validation": "introspection",
            "introspection_client_id": "sluis",
            "introspection_client_secret": "s3cret",
        }),
    )
    .await;

    for _ in 0..2 {
        let res = app
            .clone()
            .oneshot(mcp_post(Some("opaque-token-1"), "tools/list", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
    as_server.verify().await;

    // Inactive token → 401.
    let res = app
        .clone()
        .oneshot(mcp_post(Some("opaque-token-2"), "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Introspection endpoint down → 503, not 401: the token might be fine.
    let res = app
        .clone()
        .oneshot(mcp_post(Some("opaque-token-3"), "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Wrong audience in the introspection response → 401.
    let res = app
        .clone()
        .oneshot(mcp_post(Some("opaque-token-4"), "tools/list", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ---------- request body limit ----------

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let as_server = mock_as().await;
    let (upstream, _) = spawn_upstream().await;
    let app = build_app(
        &as_server.uri(),
        upstream,
        json!({ "max_body_bytes": 1024 }),
    )
    .await;
    let token = mint(&TokenSpec::valid(&as_server.uri()));

    // Real clients send Content-Length for sized bodies; the limit layer
    // rejects on it before any byte is forwarded upstream.
    let mut req = mcp_post(Some(&token), "tools/list", None);
    req.headers_mut()
        .insert(header::CONTENT_LENGTH, "4096".parse().unwrap());
    *req.body_mut() = Body::from(vec![b'x'; 4096]);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
