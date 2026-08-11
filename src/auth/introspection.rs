//! RFC 7662 token introspection for opaque tokens.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

use super::discovery::{AuthorizationServerMetadata, DiscoveryError};
use super::{AuthError, TokenClaims, TokenValidator, audience_matches, scopes_from_claims};

/// Positive results are cached briefly to keep per-request latency sane;
/// never longer than this, and never past the token's `exp`.
const POSITIVE_TTL: Duration = Duration::from_secs(30);
/// Negative results are cached only long enough to blunt brute-force
/// hammering — a token revoked-then-unrevoked must not stay dead for long.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);
/// Expired entries are swept once the cache grows past this many entries.
const SWEEP_THRESHOLD: usize = 10_000;

/// Validates opaque tokens by POSTing them to the authorization server's
/// RFC 7662 introspection endpoint, authenticated with the configured
/// client credentials.
///
/// Trade-off vs [`super::JwksValidator`]: every cache miss costs a network
/// round-trip to the IdP (and the IdP being down makes requests fail with
/// 503), but revocation takes effect within the cache TTL instead of at
/// token expiry.
pub struct IntrospectionValidator {
    http: reqwest::Client,
    endpoint: String,
    client_id: String,
    client_secret: String,
    issuer: String,
    resource: String,
    clock_skew_secs: u64,
    /// Keyed by SHA-256 of the token so raw tokens never sit in memory as
    /// map keys.
    cache: RwLock<HashMap<[u8; 32], CacheEntry>>,
}

#[derive(Clone)]
struct CacheEntry {
    result: Result<TokenClaims, String>,
    expires_at: Instant,
}

impl IntrospectionValidator {
    /// Discover the AS metadata for `issuer` and return a ready validator.
    /// Fails hard if the metadata lacks an `introspection_endpoint`.
    pub async fn discover(
        http: reqwest::Client,
        issuer: &Url,
        resource: String,
        client_id: String,
        client_secret: String,
        clock_skew_secs: u64,
    ) -> Result<Self, DiscoveryError> {
        let metadata = AuthorizationServerMetadata::discover(&http, issuer).await?;
        let endpoint = metadata
            .introspection_endpoint
            .ok_or(DiscoveryError::MissingField {
                field: "introspection_endpoint",
            })?;
        tracing::info!(issuer = %metadata.issuer, endpoint = %endpoint, "introspection validator ready");
        Ok(Self {
            http,
            endpoint,
            client_id,
            client_secret,
            issuer: metadata.issuer,
            resource,
            clock_skew_secs,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Returns the claims plus the token's `exp` (to bound the cache TTL).
    async fn introspect(&self, token: &str) -> Result<(TokenClaims, Option<u64>), AuthError> {
        let response = self
            .http
            .post(&self.endpoint)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token)])
            // Hard deadline: a hung IdP must fail the request as 503, not
            // hang it (the shared client has no total timeout).
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AuthError::Unavailable {
                reason: format!("introspection request failed: {e}"),
            })?;
        if !response.status().is_success() {
            return Err(AuthError::Unavailable {
                reason: format!("introspection endpoint returned HTTP {}", response.status()),
            });
        }
        let body: serde_json::Value =
            response.json().await.map_err(|e| AuthError::Unavailable {
                reason: format!("undecodable introspection response: {e}"),
            })?;

        if body.get("active").and_then(|v| v.as_bool()) != Some(true) {
            return Err(AuthError::InvalidToken {
                reason: "token is not active".into(),
            });
        }
        // Audience validation is not optional, introspection or not.
        if !audience_matches(body.get("aud"), &self.resource) {
            return Err(AuthError::InvalidToken {
                reason: format!("audience does not contain {}", self.resource),
            });
        }
        // `iss` is optional in RFC 7662 responses; when present it must be
        // the configured issuer.
        if let Some(iss) = body.get("iss").and_then(|v| v.as_str())
            && iss != self.issuer
        {
            return Err(AuthError::InvalidToken {
                reason: format!("issuer mismatch: {iss:?}"),
            });
        }
        let now = unix_now();
        let exp = body.get("exp").and_then(|v| v.as_u64());
        if let Some(exp) = exp
            && exp + self.clock_skew_secs < now
        {
            return Err(AuthError::InvalidToken {
                reason: "token is expired".into(),
            });
        }
        if let Some(nbf) = body.get("nbf").and_then(|v| v.as_u64())
            && nbf > now + self.clock_skew_secs
        {
            return Err(AuthError::InvalidToken {
                reason: "token is not yet valid".into(),
            });
        }

        Ok((
            TokenClaims {
                sub: body.get("sub").and_then(|v| v.as_str()).map(str::to_owned),
                scopes: scopes_from_claims(&body),
            },
            exp,
        ))
    }

    /// TTL for caching a positive result: at most [`POSITIVE_TTL`], never
    /// past `exp`.
    fn positive_ttl(exp: Option<u64>) -> Duration {
        let until_exp = exp
            .map(|e| Duration::from_secs(e.saturating_sub(unix_now())))
            .unwrap_or(POSITIVE_TTL);
        POSITIVE_TTL.min(until_exp)
    }
}

#[async_trait::async_trait]
impl TokenValidator for IntrospectionValidator {
    async fn validate(&self, token: &str) -> Result<TokenClaims, AuthError> {
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();

        if let Some(entry) = self.cache.read().await.get(&key)
            && entry.expires_at > Instant::now()
        {
            return match &entry.result {
                Ok(claims) => Ok(claims.clone()),
                Err(reason) => Err(AuthError::InvalidToken {
                    reason: reason.clone(),
                }),
            };
        }

        // Introspect outside the lock; concurrent misses for the same token
        // just introspect twice, which is harmless.
        let outcome = match self.introspect(token).await {
            Ok((claims, exp)) => Ok((claims, Self::positive_ttl(exp))),
            Err(e) => Err(e),
        };

        let (result, ttl) = match &outcome {
            Ok((claims, ttl)) => (Ok(claims.clone()), *ttl),
            Err(AuthError::InvalidToken { reason }) => (Err(reason.clone()), NEGATIVE_TTL),
            // Infrastructure failures are never cached.
            Err(_) => return outcome.map(|(claims, _)| claims),
        };

        let mut cache = self.cache.write().await;
        if cache.len() >= SWEEP_THRESHOLD {
            let now = Instant::now();
            cache.retain(|_, e| e.expires_at > now);
        }
        cache.insert(
            key,
            CacheEntry {
                result,
                expires_at: Instant::now() + ttl,
            },
        );
        drop(cache);
        outcome.map(|(claims, _)| claims)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
}
