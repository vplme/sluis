//! RFC 9728 Protected Resource Metadata.

use serde::Serialize;

use crate::config::Config;

/// The Protected Resource Metadata document served at
/// `/.well-known/oauth-protected-resource` (and its RFC 9728 §3
/// path-suffixed variant).
#[derive(Debug, Clone, Serialize)]
pub struct ProtectedResourceMetadata {
    /// Canonical resource URL of the MCP server.
    pub resource: String,
    /// Issuer URL(s) of the authorization server(s) protecting this resource.
    pub authorization_servers: Vec<String>,
    /// Scopes this resource understands.
    pub scopes_supported: Vec<String>,
    /// Bearer tokens are accepted in the `Authorization` header only.
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    /// Build the PRM document from the resolved configuration.
    pub fn from_config(config: &Config) -> Self {
        Self {
            resource: config.resource_url(),
            // RFC 8414 §2: the issuer identifier must have no trailing slash.
            authorization_servers: vec![
                config
                    .oidc_issuer_url
                    .as_str()
                    .trim_end_matches('/')
                    .to_owned(),
            ],
            scopes_supported: config.scopes_supported.clone(),
            bearer_methods_supported: vec!["header".to_owned()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        serde_json::from_value(serde_json::json!({
            "proxy_public_url": "https://mcp.example.com",
            "upstream_mcp_url": "http://127.0.0.1:9000/mcp",
            "oidc_issuer_url": "https://idp.example.com/realms/lab/",
        }))
        .unwrap()
    }

    #[test]
    fn builds_expected_document() {
        let prm = ProtectedResourceMetadata::from_config(&config());
        assert_eq!(prm.resource, "https://mcp.example.com/mcp");
        assert_eq!(
            prm.authorization_servers,
            vec!["https://idp.example.com/realms/lab"]
        );
        assert_eq!(prm.bearer_methods_supported, vec!["header"]);
        let json = serde_json::to_value(&prm).unwrap();
        assert_eq!(json["scopes_supported"], serde_json::json!(["mcp:tools"]));
    }
}
