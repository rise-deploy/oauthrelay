//! Embeddable OAuth/OIDC multiplexing engine.
//!
//! A host can provide resources from any dynamic store and mount two-segment
//! routes without depending on a standalone config provider:
//!
//! ```no_run
//! use oauthrelay_core::{router, KeyStrategy, RelayConfig, ProviderSnapshot, XChaChaSealer};
//! use std::sync::Arc;
//! let resources = ProviderSnapshot::default(); // Populate from the host database.
//! let config = RelayConfig {
//!     public_url: "https://rise.example.com/oidc".parse().unwrap(),
//!     sealer: Arc::new(XChaChaSealer::new(&[7; 32], None).unwrap()),
//!     replay_cache: None,
//!     http: reqwest::Client::new(),
//!     client_assertion_http: Default::default(),
//!     allow_localhost_loopback: false,
//! };
//! let app = router(Arc::new(resources), config, KeyStrategy::TwoSegment);
//! let _host = axum::Router::new().nest("/", app);
//! ```

mod config;
mod jwks;
mod model;
mod resolver;
mod router;
mod seal;

pub use config::*;
pub use jwks::*;
pub use model::*;
pub use resolver::*;
pub use router::*;
pub use seal::*;
