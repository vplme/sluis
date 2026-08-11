//! Typed runtime configuration for the proxy.
//!
//! The library deals only in this plain struct; how it gets populated (YAML
//! file, environment variables) is the binary's concern. Deserialize it once
//! at startup, call [`Config::validate`], and pass it around by reference.

use std::collections::HashMap;
use std::net::SocketAddr;

use serde::Deserialize;
use url::Url;

/// How bearer tokens are validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenValidationMode {
    /// Validate JWTs locally against the authorization server's JWKS (default).
    Jwks,
    /// Validate opaque tokens via RFC 7662 token introspection.
    Introspection,
}

/// Which Streamable HTTP dialect the upstream speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportCompat {
    /// 2026-07-28 transport: stateless, POST-only, mandatory `Mcp-Method`
    /// header (default).
    Strict,
    /// 2025-era dialect: sessions via `Mcp-Session-Id`, GET listening
    /// streams, DELETE for session teardown, no 2026 metadata headers.
    /// Authorization semantics are identical; only transport shape relaxes.
    Compat2025,
}

// Hand-rolled so the "2025" spelling also works where the source has already
// turned it into a number: unquoted YAML, and env vars under the `config`
// crate's try_parsing.
impl<'de> Deserialize<'de> for TransportCompat {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = TransportCompat;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(r#""strict" or "2025""#)
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match v {
                    "strict" => Ok(TransportCompat::Strict),
                    "2025" => Ok(TransportCompat::Compat2025),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Str(v), &self)),
                }
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                match v {
                    2025 => Ok(TransportCompat::Compat2025),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Unsigned(v), &self)),
                }
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                u64::try_from(v)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(v), &self))
                    .and_then(|v| self.visit_u64(v))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// Runtime configuration. See the README for the full reference.
///
/// All fields can come from a YAML file or from `SLUIS_`-prefixed environment
/// variables (env wins). [`Config::validate`] must be called before use.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// External base URL of this proxy. Every URL the proxy hands out
    /// (metadata, challenges) derives from this — never from `Host` headers.
    pub proxy_public_url: Url,

    /// Base URL of the unsecured upstream MCP server.
    pub upstream_mcp_url: Url,

    /// Issuer URL of the external OAuth 2.1 / OIDC authorization server.
    pub oidc_issuer_url: Url,

    /// Path at which the MCP endpoint is served (and appended to
    /// `proxy_public_url` to form the canonical resource URL).
    #[serde(default = "default_mcp_path")]
    pub mcp_path: String,

    /// Scopes advertised in Protected Resource Metadata.
    #[serde(default = "default_scopes")]
    pub scopes_supported: Vec<String>,

    /// Scopes a token must carry for any MCP request.
    #[serde(default = "default_scopes")]
    pub required_scopes: Vec<String>,

    /// Per-method scope overrides keyed on the `Mcp-Method` request header
    /// (e.g. stricter scopes for `tools/call`). An override *replaces* the
    /// global `required_scopes` for that method. YAML-only in practice —
    /// maps do not fit flat env vars.
    #[serde(default)]
    pub method_scopes: HashMap<String, Vec<String>>,

    /// Token validation mode.
    #[serde(default = "default_token_validation")]
    pub token_validation: TokenValidationMode,

    /// Transport compatibility mode.
    #[serde(default = "default_transport_compat")]
    pub transport_compat: TransportCompat,

    /// RFC 7662 client credentials (introspection mode only).
    #[serde(default)]
    pub introspection_client_id: Option<String>,
    #[serde(default)]
    pub introspection_client_secret: Option<String>,

    /// How long fetched JWKS keys stay fresh before a background refresh.
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl: u64,

    /// Leeway applied to `exp`/`nbf` checks, in seconds.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,

    /// Inject `X-Forwarded-User` / `X-Forwarded-Scopes` towards the upstream.
    #[serde(default)]
    pub identity_headers_enabled: bool,

    /// Socket the proxy listens on.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// TCP connect timeout towards the upstream, in seconds.
    #[serde(default = "default_connect_timeout")]
    pub upstream_connect_timeout_secs: u64,

    /// Optional idle (between-reads) timeout on upstream responses, in
    /// seconds. Disabled by default: a timeout here would kill long-lived
    /// `subscriptions/listen` streams during quiet periods.
    #[serde(default)]
    pub upstream_idle_timeout_secs: Option<u64>,

    /// Grace period for draining in-flight requests on SIGTERM, in seconds.
    #[serde(default = "default_shutdown_grace")]
    pub shutdown_grace_secs: u64,

    /// Maximum accepted request body size, in bytes.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Origin allowlist for the MCP endpoint. When set, requests carrying an
    /// `Origin` header not in this list are rejected with 403 (DNS-rebinding
    /// defence per the Streamable HTTP spec). When unset, `Origin` is not
    /// checked — appropriate when an ingress in front already enforces this.
    #[serde(default)]
    pub allowed_origins: Option<Vec<String>>,
}

fn default_mcp_path() -> String {
    "/mcp".to_owned()
}
fn default_scopes() -> Vec<String> {
    vec!["mcp:tools".to_owned()]
}
fn default_token_validation() -> TokenValidationMode {
    TokenValidationMode::Jwks
}
fn default_transport_compat() -> TransportCompat {
    TransportCompat::Strict
}
fn default_jwks_cache_ttl() -> u64 {
    300
}
fn default_clock_skew() -> u64 {
    30
}
fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("valid literal")
}
fn default_connect_timeout() -> u64 {
    5
}
fn default_shutdown_grace() -> u64 {
    20
}
fn default_max_body_bytes() -> usize {
    2 * 1024 * 1024
}

/// Configuration errors with the offending key spelled out.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{key}: {reason}")]
    Invalid { key: &'static str, reason: String },
}

impl ConfigError {
    fn invalid(key: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            key,
            reason: reason.into(),
        }
    }
}

impl Config {
    /// Canonical resource URL of this MCP server (RFC 8707 / RFC 9728):
    /// `proxy_public_url` + `mcp_path`, no trailing slash.
    pub fn resource_url(&self) -> String {
        let base = self.proxy_public_url.as_str().trim_end_matches('/');
        format!("{}{}", base, self.mcp_path)
    }

    /// URL of the root Protected Resource Metadata document.
    pub fn prm_url(&self) -> String {
        let base = self.proxy_public_url.as_str().trim_end_matches('/');
        format!("{base}/.well-known/oauth-protected-resource")
    }

    /// Scopes required for a given `Mcp-Method` header value: the per-method
    /// override if present, the global list otherwise.
    pub fn required_scopes_for(&self, mcp_method: Option<&str>) -> &[String] {
        mcp_method
            .and_then(|m| self.method_scopes.get(m))
            .map(Vec::as_slice)
            .unwrap_or(&self.required_scopes)
    }

    /// Cross-field validation with explicit, actionable error messages.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (key, url) in [
            ("proxy_public_url", &self.proxy_public_url),
            ("upstream_mcp_url", &self.upstream_mcp_url),
            ("oidc_issuer_url", &self.oidc_issuer_url),
        ] {
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ConfigError::invalid(
                    key,
                    format!("must be an http(s) URL, got scheme {:?}", url.scheme()),
                ));
            }
            if url.fragment().is_some() {
                return Err(ConfigError::invalid(key, "must not contain a fragment"));
            }
        }
        if !self.mcp_path.starts_with('/') || self.mcp_path.len() < 2 {
            return Err(ConfigError::invalid(
                "mcp_path",
                format!(
                    "must be a non-root path starting with '/', got {:?}",
                    self.mcp_path
                ),
            ));
        }
        if self.mcp_path.ends_with('/') {
            return Err(ConfigError::invalid(
                "mcp_path",
                "must not end with '/' (the canonical resource URL has no trailing slash)",
            ));
        }
        if self.required_scopes.is_empty() {
            return Err(ConfigError::invalid(
                "required_scopes",
                "must not be empty; the proxy always enforces at least one scope",
            ));
        }
        if self.token_validation == TokenValidationMode::Introspection {
            if self
                .introspection_client_id
                .as_deref()
                .unwrap_or("")
                .is_empty()
            {
                return Err(ConfigError::invalid(
                    "introspection_client_id",
                    "required when token_validation = introspection",
                ));
            }
            if self
                .introspection_client_secret
                .as_deref()
                .unwrap_or("")
                .is_empty()
            {
                return Err(ConfigError::invalid(
                    "introspection_client_secret",
                    "required when token_validation = introspection",
                ));
            }
        }
        for (method, scopes) in &self.method_scopes {
            if scopes.is_empty() {
                return Err(ConfigError::invalid(
                    "method_scopes",
                    format!("override for {method:?} must not be an empty scope list"),
                ));
            }
        }
        if self.shutdown_grace_secs == 0 {
            return Err(ConfigError::invalid(
                "shutdown_grace_secs",
                "must be at least 1 second",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_config() -> Config {
        serde_json::from_value(serde_json::json!({
            "proxy_public_url": "https://mcp.example.com",
            "upstream_mcp_url": "http://127.0.0.1:9000/mcp",
            "oidc_issuer_url": "https://idp.example.com/realms/lab",
        }))
        .expect("valid test config")
    }

    #[test]
    fn defaults_are_applied() {
        let cfg = test_config();
        assert_eq!(cfg.mcp_path, "/mcp");
        assert_eq!(cfg.required_scopes, vec!["mcp:tools"]);
        assert_eq!(cfg.token_validation, TokenValidationMode::Jwks);
        assert_eq!(cfg.transport_compat, TransportCompat::Strict);
        assert_eq!(cfg.max_body_bytes, 2 * 1024 * 1024);
        cfg.validate().expect("default config is valid");
    }

    #[test]
    fn transport_compat_accepts_string_and_number() {
        for value in [serde_json::json!("2025"), serde_json::json!(2025)] {
            let compat: TransportCompat =
                serde_json::from_value(value).expect("2025 spelling accepted");
            assert_eq!(compat, TransportCompat::Compat2025);
        }
        let compat: TransportCompat = serde_json::from_value(serde_json::json!("strict")).unwrap();
        assert_eq!(compat, TransportCompat::Strict);
        assert!(serde_json::from_value::<TransportCompat>(serde_json::json!("2026")).is_err());
        assert!(serde_json::from_value::<TransportCompat>(serde_json::json!(2026)).is_err());
    }

    #[test]
    fn resource_url_has_no_double_slash() {
        let mut cfg = test_config();
        cfg.proxy_public_url = "https://mcp.example.com/".parse().unwrap();
        assert_eq!(cfg.resource_url(), "https://mcp.example.com/mcp");
        assert_eq!(
            cfg.prm_url(),
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn introspection_requires_credentials() {
        let mut cfg = test_config();
        cfg.token_validation = TokenValidationMode::Introspection;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("introspection_client_id"));
    }

    #[test]
    fn method_scope_override_wins() {
        let mut cfg = test_config();
        cfg.method_scopes
            .insert("tools/call".into(), vec!["mcp:tools:write".into()]);
        assert_eq!(
            cfg.required_scopes_for(Some("tools/call")),
            &["mcp:tools:write".to_owned()]
        );
        assert_eq!(
            cfg.required_scopes_for(Some("tools/list")),
            &["mcp:tools".to_owned()]
        );
        assert_eq!(cfg.required_scopes_for(None), &["mcp:tools".to_owned()]);
    }
}
