//! Thin CLI wrapper: clap parsing, config loading, tracing init, startup.
//! All behavior lives in the `sluis` library.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};

use sluis::app;
use sluis::config::TokenValidationMode;

#[derive(Parser)]
#[command(
    name = "sluis",
    version,
    about = "OAuth 2.1 resource-server proxy for MCP"
)]
struct Cli {
    /// Path to the YAML config file (env: SLUIS_CONFIG; flag wins).
    #[arg(long, global = true, env = "SLUIS_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy (default).
    Serve,
    /// Load + validate config, run AS discovery and JWKS fetch, print the
    /// resolved config with secrets redacted; non-zero exit on any failure.
    Check,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sluis=info".into()),
        )
        .init();

    let config = load_config(cli.config.as_deref())?;

    let runtime = tokio::runtime::Runtime::new().context("failed to start tokio runtime")?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => runtime.block_on(serve(config)),
        Command::Check => runtime.block_on(check(config)),
    }
}

/// Layering: defaults (serde) < YAML file < `SLUIS_*` environment.
fn load_config(path: Option<&std::path::Path>) -> anyhow::Result<sluis::Config> {
    let mut builder = config::Config::builder();
    if let Some(path) = path {
        builder = builder.add_source(config::File::from(path).format(config::FileFormat::Yaml));
    }
    // SLUIS_CONFIG selects the file itself and must not be treated as a
    // settings key, so feed the env source a pre-filtered variable map.
    let env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("SLUIS_") && k != "SLUIS_CONFIG")
        .collect();
    builder = builder.add_source(
        config::Environment::with_prefix("SLUIS")
            .source(Some(env))
            // Env vars stay SCREAMING_SNAKE (SLUIS_PROXY_PUBLIC_URL); this
            // maps them onto the camelCase config keys (proxyPublicUrl).
            .convert_case(config::Case::Camel)
            .try_parsing(true)
            .list_separator(",")
            .with_list_parse_key("scopesSupported")
            .with_list_parse_key("requiredScopes")
            .with_list_parse_key("allowedOrigins"),
    );

    let config: sluis::Config = builder
        .build()
        .context("failed to read configuration")?
        .try_deserialize()
        .context("configuration does not match the expected schema")?;
    config.validate().context("invalid configuration")?;
    Ok(config)
}

async fn serve(config: sluis::Config) -> anyhow::Result<()> {
    let http = app::build_http_client(&config).context("failed to build HTTP client")?;
    let validator: Arc<dyn sluis::auth::TokenValidator> = app::build_validator(&config, http)
        .await
        .context("authorization server discovery failed")?;
    let router = app::build_router(&config, validator);
    app::serve(&config, router).await.context("server error")
}

/// `sluis check`: everything `serve` does up to binding the socket, plus a
/// redacted dump of the resolved config. Intended for CI and as a K8s
/// initContainer / startup probe helper.
async fn check(config: sluis::Config) -> anyhow::Result<()> {
    let http = app::build_http_client(&config).context("failed to build HTTP client")?;
    app::build_validator(&config, http)
        .await
        .context("authorization server discovery / key fetch failed")?;
    println!("configuration OK\n");
    print_redacted(&config);
    Ok(())
}

fn print_redacted(config: &sluis::Config) {
    let row = |key: &str, value: &dyn std::fmt::Display| println!("{key:<31}{value}");
    row("proxyPublicUrl:", &config.proxy_public_url);
    row("upstreamMcpUrl:", &config.upstream_mcp_url);
    row("oidcIssuerUrl:", &config.oidc_issuer_url);
    row("resource (canonical):", &config.resource_url());
    row("mcpPath:", &config.mcp_path);
    row("bindAddress:", &config.bind_address);
    row(
        "tokenValidation:",
        &format!("{:?}", config.token_validation),
    );
    row(
        "transportCompat:",
        &format!("{:?}", config.transport_compat),
    );
    row("scopesSupported:", &config.scopes_supported.join(", "));
    row("requiredScopes:", &config.required_scopes.join(", "));
    if !config.method_scopes.is_empty() {
        let mut overrides: Vec<_> = config.method_scopes.iter().collect();
        overrides.sort_by_key(|o| o.method.as_str());
        for o in overrides {
            row(
                &format!("methodScopes[{}]:", o.method),
                &o.scopes.join(", "),
            );
        }
    }
    if config.token_validation == TokenValidationMode::Introspection {
        row(
            "introspectionClientId:",
            &config.introspection_client_id.as_deref().unwrap_or(""),
        );
        row("introspectionClientSecret:", &"<redacted>");
    }
    row(
        "jwksCacheTtlSeconds:",
        &format!("{}s", config.jwks_cache_ttl_seconds),
    );
    row(
        "clockSkewSeconds:",
        &format!("{}s", config.clock_skew_seconds),
    );
    row("enableIdentityHeaders:", &config.enable_identity_headers);
    row(
        "upstreamConnectTimeoutSeconds:",
        &format!("{}s", config.upstream_connect_timeout_seconds),
    );
    match config.upstream_idle_timeout_seconds {
        Some(s) => row("upstreamIdleTimeoutSeconds:", &format!("{s}s")),
        None => row("upstreamIdleTimeoutSeconds:", &"disabled"),
    }
    row(
        "shutdownGracePeriodSeconds:",
        &format!("{}s", config.shutdown_grace_period_seconds),
    );
    row("maxBodyBytes:", &config.max_body_bytes);
    match &config.allowed_origins {
        Some(origins) => row("allowedOrigins:", &origins.join(", ")),
        None => row("allowedOrigins:", &"(origin not checked)"),
    }
}
