//! Shared rustls client configuration for the encrypted transports.

use std::sync::{Arc, OnceLock};

use rustls::{ClientConfig, RootCertStore};

/// Install the process-wide ring crypto provider exactly once.
fn ensure_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// A rustls client config for DoT (no special ALPN required).
pub fn dot_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        ensure_provider();
        let cfg = ClientConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

/// A rustls client config for DoQ: TLS 1.3 only with the `doq` ALPN token.
pub fn doq_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        ensure_provider();
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"doq".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}
