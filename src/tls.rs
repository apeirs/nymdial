//! TLS for streams through the tunnel: rustls with the Mozilla root store (webpki-roots), ring as the crypto
//! provider, set explicitly so it never depends on a process-wide default.

use std::sync::Arc;

use tokio_rustls::TlsConnector;

/// A connector that verifies certificates against the webpki roots and offers `alpn` (may be empty).
pub fn connector(alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(cfg))
}
