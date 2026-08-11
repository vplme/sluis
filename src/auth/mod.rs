//! Token validation and the MCP resource-server tower layer.
//!
//! The centerpiece is [`McpAuthLayer`]: a tower layer that turns any inner
//! service into an MCP-spec-compliant protected resource — `401` +
//! `WWW-Authenticate` challenges, bearer-token validation, and scope
//! enforcement. The reverse proxy in this crate is just one consumer; the
//! layer can equally protect an MCP endpoint served in-process.

mod discovery;
mod introspection;
mod jwks;
mod layer;

pub use discovery::{AuthorizationServerMetadata, DiscoveryError};
pub use introspection::IntrospectionValidator;
pub use jwks::JwksValidator;
pub use layer::{AuthContext, McpAuthLayer, McpAuthService};

use std::collections::BTreeSet;

/// Claims extracted from a validated access token.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    /// The `sub` claim, if present.
    pub sub: Option<String>,
    /// Granted scopes (from the `scope` string or `scp` array claim).
    pub scopes: Vec<String>,
}

impl TokenClaims {
    /// Whether every scope in `required` was granted.
    pub fn has_scopes(&self, required: &[String]) -> bool {
        let granted: BTreeSet<&str> = self.scopes.iter().map(String::as_str).collect();
        required.iter().all(|s| granted.contains(s.as_str()))
    }
}

/// Why a request was denied (or could not be authorized).
///
/// Client-facing messages stay generic; the detailed `reason` strings are
/// only ever logged.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No bearer token in the `Authorization` header.
    #[error("missing bearer token")]
    MissingToken,
    /// The token failed validation (signature, expiry, issuer, audience, …).
    #[error("invalid token: {reason}")]
    InvalidToken { reason: String },
    /// The token is valid but lacks required scopes.
    #[error("insufficient scope, required: {}", required.join(" "))]
    InsufficientScope { required: Vec<String> },
    /// Validation infrastructure failed (e.g. introspection endpoint down).
    /// Maps to `503`, not a token error — the client's token may be fine.
    #[error("validation unavailable: {reason}")]
    Unavailable { reason: String },
}

/// Validates a bearer token and returns its claims.
///
/// Implementations: [`JwksValidator`] (local JWT validation) and
/// [`IntrospectionValidator`] (RFC 7662).
#[async_trait::async_trait]
pub trait TokenValidator: Send + Sync {
    /// Validate `token`. `Err(AuthError::InvalidToken)` for bad tokens,
    /// `Err(AuthError::Unavailable)` for infrastructure failures.
    async fn validate(&self, token: &str) -> Result<TokenClaims, AuthError>;
}

/// Builds the `WWW-Authenticate` challenge values this resource emits.
#[derive(Debug, Clone)]
pub struct Challenge {
    realm: String,
    prm_url: String,
}

impl Challenge {
    /// `prm_url` is the absolute URL of the Protected Resource Metadata
    /// document, derived from the configured public URL.
    pub fn new(realm: impl Into<String>, prm_url: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            prm_url: prm_url.into(),
        }
    }

    /// Challenge for a request with no credentials (401).
    pub fn missing_token(&self, scopes: &[String]) -> String {
        format!(
            "Bearer realm=\"{}\", resource_metadata=\"{}\", scope=\"{}\"",
            self.realm,
            self.prm_url,
            scopes.join(" ")
        )
    }

    /// Challenge for an invalid or expired token (401).
    pub fn invalid_token(&self) -> String {
        format!(
            "Bearer realm=\"{}\", error=\"invalid_token\", resource_metadata=\"{}\"",
            self.realm, self.prm_url
        )
    }

    /// Challenge for a valid token lacking scopes (403), per RFC 6750 §3.1.
    pub fn insufficient_scope(&self, required: &[String]) -> String {
        format!(
            "Bearer realm=\"{}\", error=\"insufficient_scope\", scope=\"{}\", resource_metadata=\"{}\"",
            self.realm,
            required.join(" "),
            self.prm_url
        )
    }
}

/// Parse a `scope` value (space-delimited string) into a scope list.
pub(crate) fn parse_scope_string(scope: &str) -> Vec<String> {
    scope.split_whitespace().map(str::to_owned).collect()
}

/// Extract scopes from token claims: RFC 9068/OAuth `scope` string, with a
/// fallback to the nonstandard-but-common `scp` array (e.g. Entra ID).
pub(crate) fn scopes_from_claims(claims: &serde_json::Value) -> Vec<String> {
    if let Some(scope) = claims.get("scope").and_then(|v| v.as_str()) {
        return parse_scope_string(scope);
    }
    if let Some(scp) = claims.get("scp") {
        match scp {
            serde_json::Value::String(s) => return parse_scope_string(s),
            serde_json::Value::Array(items) => {
                return items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect();
            }
            _ => {}
        }
    }
    Vec::new()
}

/// Check that the token's `aud` claim contains exactly the canonical
/// resource URL. String and array forms are accepted; anything else fails.
pub(crate) fn audience_matches(aud: Option<&serde_json::Value>, resource: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(s)) => s == resource,
        Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(resource)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn challenge_missing_token_format() {
        let c = Challenge::new(
            "mcp",
            "https://mcp.example.com/.well-known/oauth-protected-resource",
        );
        assert_eq!(
            c.missing_token(&["mcp:tools".into()]),
            "Bearer realm=\"mcp\", resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:tools\""
        );
    }

    #[test]
    fn challenge_invalid_token_format() {
        let c = Challenge::new("mcp", "https://p/.well-known/oauth-protected-resource");
        let v = c.invalid_token();
        assert!(v.starts_with("Bearer realm=\"mcp\", error=\"invalid_token\""));
        assert!(v.contains("resource_metadata=\"https://p/.well-known/oauth-protected-resource\""));
    }

    #[test]
    fn challenge_insufficient_scope_lists_required_scopes() {
        let c = Challenge::new("mcp", "https://p/.well-known/oauth-protected-resource");
        let v = c.insufficient_scope(&["a".into(), "b".into()]);
        assert!(v.contains("error=\"insufficient_scope\""));
        assert!(v.contains("scope=\"a b\""));
    }

    #[test]
    fn scopes_from_scope_string_and_scp_array() {
        assert_eq!(scopes_from_claims(&json!({"scope": "a b"})), vec!["a", "b"]);
        assert_eq!(
            scopes_from_claims(&json!({"scp": ["x", "y"]})),
            vec!["x", "y"]
        );
        assert_eq!(scopes_from_claims(&json!({"scp": "x y"})), vec!["x", "y"]);
        assert!(scopes_from_claims(&json!({})).is_empty());
    }

    #[test]
    fn audience_requires_exact_resource_match() {
        let resource = "https://mcp.example.com/mcp";
        assert!(audience_matches(Some(&json!(resource)), resource));
        assert!(audience_matches(
            Some(&json!(["other", resource])),
            resource
        ));
        assert!(!audience_matches(
            Some(&json!("https://mcp.example.com")),
            resource
        ));
        assert!(!audience_matches(Some(&json!("api")), resource));
        assert!(!audience_matches(None, resource));
    }

    #[test]
    fn has_scopes_is_subset_check() {
        let claims = TokenClaims {
            sub: None,
            scopes: vec!["a".into(), "b".into()],
        };
        assert!(claims.has_scopes(&["a".into()]));
        assert!(claims.has_scopes(&[]));
        assert!(!claims.has_scopes(&["c".into()]));
    }
}
