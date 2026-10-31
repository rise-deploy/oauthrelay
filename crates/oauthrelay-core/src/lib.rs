//! Embeddable OAuth/OIDC multiplexing engine.
//!
//! A host can provide resources from any dynamic store and mount two-segment
//! routes without depending on a standalone config provider. The URLs below `public_url` come
//! from a [`PathLayout`]; [`DefaultLayout`] serves `/relay/{key}/…` and `/upstream/{key}/callback`,
//! and a host that wants its own paths implements the trait:
//!
//! ```no_run
//! use oauthrelay_core::{router, DefaultLayout, KeyStrategy, RelayConfig, ProviderSnapshot, XChaChaSealer};
//! use std::sync::Arc;
//! let resources = ProviderSnapshot::default(); // Populate from the host database.
//! let config = RelayConfig {
//!     public_url: "https://rise.example.com/oidc".parse().unwrap(),
//!     sealer: Arc::new(XChaChaSealer::new(&[7; 32], None).unwrap()),
//!     store: None,
//!     http: reqwest::Client::new(),
//!     client_assertion_http: Default::default(),
//!     allow_localhost_loopback: false,
//! };
//! let layout = Arc::new(DefaultLayout::new(KeyStrategy::TwoSegment));
//! let app = router(Arc::new(resources), config, layout);
//! let _host = axum::Router::new().nest("/", app);
//! ```

mod config;
mod id_token_policy;
mod jwks;
mod layout;
mod model;
mod refresh_handle;
mod resolver;
mod rotation;
mod router;
mod seal;
mod store;

pub use config::*;
pub use id_token_policy::*;
pub use jwks::*;
pub use layout::*;
pub use model::*;
pub use resolver::*;
pub use router::*;
pub use seal::*;
pub use store::*;
