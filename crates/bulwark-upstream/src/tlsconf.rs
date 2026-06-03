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
    #[cfg(feature = "test-trust-roots")]
    for cert in test_roots::extra_roots() {
        // Additive only: this never replaces or weakens the webpki defaults, it
        // just lets a private CA (e.g. a local mock upstream in benchmarks) be
        // trusted in addition to them. Compiled out unless the feature is on.
        let _ = roots.add(cert);
    }
    roots
}

/// Additional, caller-supplied trust anchors. Feature-gated so this entire
/// mechanism is absent from the shipped binary; it exists so a benchmark or test
/// can point the real DoT/DoQ/DoH client code at a local mock that presents a
/// self-signed cert, without disabling certificate verification.
#[cfg(feature = "test-trust-roots")]
pub mod test_roots {
    use std::sync::{Mutex, OnceLock};

    use rustls_pki_types::CertificateDer;

    fn store() -> &'static Mutex<Vec<CertificateDer<'static>>> {
        static EXTRA: OnceLock<Mutex<Vec<CertificateDer<'static>>>> = OnceLock::new();
        EXTRA.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// Register an extra trust anchor (a DER-encoded CA certificate).
    ///
    /// Must be called *before* the first use of any encrypted transport, because
    /// the rustls client configs are built once and cached. The reqwest-based DoH
    /// client reads these lazily per client, so it picks them up as long as the
    /// root is registered before the first DoH query.
    pub fn add_trust_root(der: CertificateDer<'static>) {
        store().lock().unwrap().push(der);
    }

    /// Snapshot of the registered extra roots.
    pub fn extra_roots() -> Vec<CertificateDer<'static>> {
        store().lock().unwrap().clone()
    }
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
