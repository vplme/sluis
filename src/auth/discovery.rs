//! Authorization server metadata discovery (RFC 8414 / OIDC Discovery).

use serde::Deserialize;
use url::Url;

/// The subset of authorization server metadata the proxy needs.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Issuer identifier; must match the configured issuer exactly.
    pub issuer: String,
    /// Where to fetch signing keys (JWKS mode).
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// RFC 7662 endpoint (introspection mode).
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
}

/// Failure to discover or validate authorization server metadata.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("failed to fetch {url}: {reason}")]
    Fetch { url: String, reason: String },
    #[error(
        "no authorization server metadata at {issuer} \
         (tried /.well-known/openid-configuration and /.well-known/oauth-authorization-server)"
    )]
    NotFound { issuer: String },
    #[error("metadata issuer mismatch: configured {configured:?}, document says {advertised:?}")]
    IssuerMismatch {
        configured: String,
        advertised: String,
    },
    #[error("authorization server metadata is missing {field}")]
    MissingField { field: &'static str },
}

impl AuthorizationServerMetadata {
    /// Discover metadata for `issuer`: try OIDC discovery
    /// (`/.well-known/openid-configuration`) first, then fall back to RFC 8414
    /// (`/.well-known/oauth-authorization-server`). Both are resolved relative
    /// to the issuer path, which is what IdPs with path-scoped issuers (e.g.
    /// Keycloak realms) serve in practice.
    ///
    /// The document's `issuer` must equal the configured issuer (modulo a
    /// trailing slash), per RFC 8414 §3.3 — otherwise tokens from a different
    /// realm at the same host could be accepted.
    pub async fn discover(http: &reqwest::Client, issuer: &Url) -> Result<Self, DiscoveryError> {
        let base = issuer.as_str().trim_end_matches('/');
        let candidates = [
            format!("{base}/.well-known/openid-configuration"),
            format!("{base}/.well-known/oauth-authorization-server"),
        ];

        let mut last_fetch_error = None;
        for url in &candidates {
            match fetch_metadata(http, url).await {
                Ok(Some(meta)) => {
                    if meta.issuer.trim_end_matches('/') != base {
                        return Err(DiscoveryError::IssuerMismatch {
                            configured: base.to_owned(),
                            advertised: meta.issuer,
                        });
                    }
                    return Ok(meta);
                }
                Ok(None) => {} // 404: try the next well-known location
                Err(e) => last_fetch_error = Some(e),
            }
        }
        Err(last_fetch_error.unwrap_or(DiscoveryError::NotFound {
            issuer: base.to_owned(),
        }))
    }
}

/// Ok(None) means a clean 404 (try the next candidate); Err means the fetch
/// itself failed in a way worth reporting.
async fn fetch_metadata(
    http: &reqwest::Client,
    url: &str,
) -> Result<Option<AuthorizationServerMetadata>, DiscoveryError> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|e| DiscoveryError::Fetch {
            url: url.to_owned(),
            reason: e.to_string(),
        })?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(DiscoveryError::Fetch {
            url: url.to_owned(),
            reason: format!("HTTP {}", response.status()),
        });
    }
    response
        .json::<AuthorizationServerMetadata>()
        .await
        .map(Some)
        .map_err(|e| DiscoveryError::Fetch {
            url: url.to_owned(),
            reason: format!("invalid metadata document: {e}"),
        })
}
