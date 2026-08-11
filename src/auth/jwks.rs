//! Local JWT validation against the authorization server's JWKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use tokio::sync::{Mutex, RwLock};
use url::Url;

use super::discovery::{AuthorizationServerMetadata, DiscoveryError};
use super::{AuthError, TokenClaims, TokenValidator, scopes_from_claims};

/// Minimum interval between JWKS re-fetches triggered by unknown `kid`s or
/// TTL expiry. Prevents a flood of bogus tokens from hammering the IdP.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Validates JWT access tokens locally: signature via the AS's JWKS, plus
/// `exp`/`nbf` (with clock skew), exact `iss`, and audience containment of
/// the canonical resource URL.
///
/// Operational behavior:
/// - keys are cached; a refresh is attempted when the TTL lapses or an
///   unknown `kid` shows up (rate-limited to one attempt per 10 s);
/// - refresh failures never invalidate the cache — stale keys keep serving
///   and a warning is logged. The IdP being down does not take the proxy down.
pub struct JwksValidator {
    http: reqwest::Client,
    /// Expected `iss` claim value, taken from the discovered metadata.
    issuer: String,
    /// Canonical resource URL that must appear in `aud`.
    resource: String,
    jwks_uri: String,
    clock_skew_secs: u64,
    cache_ttl: Duration,
    keys: RwLock<KeyCache>,
    refresh_gate: Mutex<Option<Instant>>,
}

struct KeyCache {
    /// Keyed by `kid`; keys without a `kid` are stored under `None` and used
    /// only when the token header also has no `kid`.
    by_kid: HashMap<Option<String>, CachedKey>,
    fetched_at: Instant,
}

#[derive(Clone)]
struct CachedKey {
    key: Arc<DecodingKey>,
    algorithms: Vec<Algorithm>,
}

impl JwksValidator {
    /// Discover the AS metadata for `issuer`, fetch the JWKS once (hard
    /// failure — this runs at startup), and return a ready validator.
    pub async fn discover(
        http: reqwest::Client,
        issuer: &Url,
        resource: String,
        clock_skew_secs: u64,
        cache_ttl: Duration,
    ) -> Result<Self, DiscoveryError> {
        let metadata = AuthorizationServerMetadata::discover(&http, issuer).await?;
        let jwks_uri = metadata
            .jwks_uri
            .ok_or(DiscoveryError::MissingField { field: "jwks_uri" })?;
        let by_kid = fetch_jwks(&http, &jwks_uri).await?;
        if by_kid.is_empty() {
            return Err(DiscoveryError::MissingField {
                field: "jwks keys (document contained no usable signing keys)",
            });
        }
        tracing::info!(
            issuer = %metadata.issuer,
            jwks_uri = %jwks_uri,
            keys = by_kid.len(),
            "JWKS validator ready"
        );
        Ok(Self {
            http,
            issuer: metadata.issuer,
            resource,
            jwks_uri,
            clock_skew_secs,
            cache_ttl,
            keys: RwLock::new(KeyCache {
                by_kid,
                fetched_at: Instant::now(),
            }),
            refresh_gate: Mutex::new(None),
        })
    }

    /// Look up the decoding key for `kid`, refreshing the JWKS if the cache
    /// is past its TTL or the `kid` is unknown (both rate-limited). A failed
    /// refresh serves stale keys rather than erroring.
    async fn key_for(&self, kid: Option<&str>) -> Option<CachedKey> {
        let (hit, expired) = {
            let cache = self.keys.read().await;
            (
                cache.by_kid.get(&kid.map(str::to_owned)).cloned(),
                cache.fetched_at.elapsed() > self.cache_ttl,
            )
        };
        if hit.is_some() && !expired {
            return hit;
        }
        self.try_refresh().await;
        let cache = self.keys.read().await;
        cache.by_kid.get(&kid.map(str::to_owned)).cloned()
    }

    /// Refresh the JWKS, at most once per [`MIN_REFRESH_INTERVAL`]. Never
    /// clears the existing cache on failure.
    async fn try_refresh(&self) {
        let mut gate = self.refresh_gate.lock().await;
        if let Some(last) = *gate
            && last.elapsed() < MIN_REFRESH_INTERVAL
        {
            return;
        }
        *gate = Some(Instant::now());
        match fetch_jwks(&self.http, &self.jwks_uri).await {
            Ok(by_kid) if !by_kid.is_empty() => {
                let mut cache = self.keys.write().await;
                cache.by_kid = by_kid;
                cache.fetched_at = Instant::now();
                tracing::debug!(keys = cache.by_kid.len(), "JWKS refreshed");
            }
            Ok(_) => {
                tracing::warn!("JWKS refresh returned no usable keys; serving stale cache");
            }
            Err(e) => {
                tracing::warn!(error = %e, "JWKS refresh failed; serving stale cache");
            }
        }
    }
}

#[async_trait::async_trait]
impl TokenValidator for JwksValidator {
    async fn validate(&self, token: &str) -> Result<TokenClaims, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken {
            reason: format!("undecodable JWT header: {e}"),
        })?;

        let cached =
            self.key_for(header.kid.as_deref())
                .await
                .ok_or_else(|| AuthError::InvalidToken {
                    reason: format!("no JWKS key for kid {:?}", header.kid),
                })?;

        if !cached.algorithms.contains(&header.alg) {
            return Err(AuthError::InvalidToken {
                reason: format!("token alg {:?} not permitted for this key", header.alg),
            });
        }

        let mut validation = Validation::new(header.alg);
        validation.leeway = self.clock_skew_secs;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.issuer]);
        // Audience containment of the canonical resource URL (RFC 8707).
        // `aud` and `iss` are required claims: a token without them is
        // rejected, never waved through.
        validation.set_audience(&[&self.resource]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);

        let data = decode::<serde_json::Value>(token, &cached.key, &validation).map_err(|e| {
            AuthError::InvalidToken {
                reason: format!("JWT validation failed: {e}"),
            }
        })?;

        Ok(TokenClaims {
            sub: data
                .claims
                .get("sub")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            scopes: scopes_from_claims(&data.claims),
        })
    }
}

/// Fetch and index a JWKS document. Keys that jsonwebtoken cannot represent
/// (unsupported kty/crv) are skipped with a warning rather than failing the
/// whole set.
async fn fetch_jwks(
    http: &reqwest::Client,
    jwks_uri: &str,
) -> Result<HashMap<Option<String>, CachedKey>, DiscoveryError> {
    let jwks: JwkSet = http
        .get(jwks_uri)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| DiscoveryError::Fetch {
            url: jwks_uri.to_owned(),
            reason: e.to_string(),
        })?
        .json()
        .await
        .map_err(|e| DiscoveryError::Fetch {
            url: jwks_uri.to_owned(),
            reason: format!("invalid JWKS document: {e}"),
        })?;

    let mut by_kid = HashMap::new();
    for jwk in &jwks.keys {
        let algorithms = match allowed_algorithms(&jwk.algorithm) {
            Some(algs) => match jwk
                .common
                .key_algorithm
                .and_then(|a| a.to_string().parse::<Algorithm>().ok())
            {
                // If the JWK pins an alg, honor it; otherwise allow the
                // asymmetric algorithms of its key family.
                Some(pinned) if algs.contains(&pinned) => vec![pinned],
                _ => algs,
            },
            None => {
                tracing::warn!(kid = ?jwk.common.key_id, "skipping unsupported JWK");
                continue;
            }
        };
        match DecodingKey::from_jwk(jwk) {
            Ok(key) => {
                by_kid.insert(
                    jwk.common.key_id.clone(),
                    CachedKey {
                        key: Arc::new(key),
                        algorithms,
                    },
                );
            }
            Err(e) => {
                tracing::warn!(kid = ?jwk.common.key_id, error = %e, "skipping unusable JWK");
            }
        }
    }
    Ok(by_kid)
}

/// Asymmetric signature algorithms acceptable for a JWK. Symmetric (oct)
/// keys are rejected outright: a shared-secret JWKS makes no sense for a
/// resource server and would let anyone mint tokens.
fn allowed_algorithms(params: &AlgorithmParameters) -> Option<Vec<Algorithm>> {
    match params {
        AlgorithmParameters::RSA(_) => Some(vec![
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ]),
        AlgorithmParameters::EllipticCurve(_) => Some(vec![Algorithm::ES256, Algorithm::ES384]),
        AlgorithmParameters::OctetKeyPair(_) => Some(vec![Algorithm::EdDSA]),
        // Symmetric keys and any future kty the library grows.
        _ => None,
    }
}
