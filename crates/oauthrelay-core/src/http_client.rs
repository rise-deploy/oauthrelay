//! The HTTP client builder the service and the embedder defaults share.

use std::sync::Arc;

/// A [`reqwest::ClientBuilder`] that trusts the bundled Mozilla root certificates
/// (`webpki-roots`, including its name constraints) instead of the host's certificate store.
///
/// The client therefore works the same on every platform, including container images without a
/// system CA bundle, where a client built from the platform verifier fails. HTTP/1.1 only. Add
/// timeouts, proxies, or other settings to the returned builder as needed; do not replace its TLS
/// configuration.
pub fn default_client_builder() -> reqwest::ClientBuilder {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the aws-lc-rs provider supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    reqwest::Client::builder().tls_backend_preconfigured(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_builder_yields_a_working_client() {
        // A preconfigured backend that reqwest does not recognize fails here, which is how a
        // rustls version drift between this crate and reqwest shows up.
        default_client_builder().build().unwrap();
        crate::ClientAssertionHttpClient::default();
    }
}
