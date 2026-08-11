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
#[command(name = "sluis", version, about = "OAuth 2.1 resource-server proxy for MCP")]
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
        builder = builder.add_source(
            config::File::from(path).format(config::FileFormat::Yaml),
        );
    }
    // SLUIS_CONFIG selects the file itself and must not be treated as a
    // settings key, so feed the env source a pre-filtered variable map.
    let env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("SLUIS_") && k != "SLUIS_CONFIG")
        .collect();
    builder = builder.add_source(
        config::Environment::with_prefix("SLUIS")
            .source(Some(env))
            .try_parsing(true)
            .list_separator(",")
            .with_list_parse_key("scopes_supported")
            .with_list_parse_key("required_scopes")
            .with_list_parse_key("allowed_origins"),
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
    println!("proxy_public_url:             {}", config.proxy_public_url);
    println!("upstream_mcp_url:             {}", config.upstream_mcp_url);
    println!("oidc_issuer_url:              {}", config.oidc_issuer_url);
    println!("resource (canonical):         {}", config.resource_url());
    println!("mcp_path:                     {}", config.mcp_path);
    println!("bind_addr:                    {}", config.bind_addr);
    println!("token_validation:             {:?}", config.token_validation);
    println!("transport_compat:             {:?}", config.transport_compat);
    println!("scopes_supported:             {}", config.scopes_supported.join(", "));
    println!("required_scopes:              {}", config.required_scopes.join(", "));
    if !config.method_scopes.is_empty() {
        let mut methods: Vec<_> = config.method_scopes.iter().collect();
        methods.sort_by_key(|(m, _)| m.as_str());
        for (method, scopes) in methods {
            println!("method_scopes[{method}]:      {}", scopes.join(", "));
        }
    }
    if config.token_validation == TokenValidationMode::Introspection {
        println!(
            "introspection_client_id:      {}",
            config.introspection_client_id.as_deref().unwrap_or("")
        );
        println!("introspection_client_secret:  <redacted>");
    }
    println!("jwks_cache_ttl:               {}s", config.jwks_cache_ttl);
    println!("clock_skew_secs:              {}s", config.clock_skew_secs);
    println!("identity_headers_enabled:     {}", config.identity_headers_enabled);
    println!(
        "upstream_connect_timeout:     {}s",
        config.upstream_connect_timeout_secs
    );
    match config.upstream_idle_timeout_secs {
        Some(s) => println!("upstream_idle_timeout:        {s}s"),
        None => println!("upstream_idle_timeout:        disabled"),
    }
    println!("shutdown_grace_secs:          {}s", config.shutdown_grace_secs);
    println!("max_body_bytes:               {}", config.max_body_bytes);
    match &config.allowed_origins {
        Some(origins) => println!("allowed_origins:              {}", origins.join(", ")),
        None => println!("allowed_origins:              (origin not checked)"),
    }
}
