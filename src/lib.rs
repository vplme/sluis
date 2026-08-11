//! # sluis
//!
//! OAuth 2.1 resource-server proxy for MCP servers — one controlled gate
//! that traffic must pass through.
//!
//! `sluis` puts the MCP authorization layer (spec revision 2026-07-28) in
//! front of an unsecured MCP server speaking Streamable HTTP. It is a *pure*
//! resource server: it challenges with `401` + `WWW-Authenticate`, validates
//! bearer tokens issued by a configured external authorization server, and
//! forwards valid requests upstream. It never mints tokens, never handles
//! login, and never forwards client tokens upstream.
//!
//! ## Library use
//!
//! The reusable core is [`auth::McpAuthLayer`], a tower layer that turns any
//! axum/tower service into an MCP-compliant protected resource. See
//! `examples/embedded.rs` for protecting a plain axum route:
//!
//! ```no_run
//! use std::sync::Arc;
//! use sluis::auth::{McpAuthLayer, TokenValidator};
//!
//! fn protect(routes: axum::Router, validator: Arc<dyn TokenValidator>) -> axum::Router {
//!     let layer = McpAuthLayer::new(
//!         validator,
//!         "https://mcp.example.com/.well-known/oauth-protected-resource",
//!         vec!["mcp:tools".into()],
//!         Default::default(),
//!     );
//!     routes.layer(layer)
//! }
//! ```
//!
//! The binary in this crate is a thin consumer of the same public API:
//! [`config::Config`], [`app::build_validator`], [`app::build_router`],
//! [`app::serve`].

#![forbid(unsafe_code)]

pub mod app;
pub mod auth;
pub mod config;
pub mod metadata;
pub mod proxy;

pub use config::Config;
