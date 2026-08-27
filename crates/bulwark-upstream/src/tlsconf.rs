//! Rustls client configuration.

use std::sync::{Arc, OnceLock};

use rustls::{ClientConfig, RootCertStore};

/// Installs the process-wide ring crypto provider.
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
        let _ = roots.add(cert);
    }
    roots
}

/// Extra trust anchors for tests and benchmarks.
#[cfg(feature = "test-trust-roots")]
pub mod test_roots {
    use std::sync::{Mutex, OnceLock};

    use rustls_pki_types::CertificateDer;

    fn store() -> &'static Mutex<Vec<CertificateDer<'static>>> {
        static EXTRA: OnceLock<Mutex<Vec<CertificateDer<'static>>>> = OnceLock::new();
        EXTRA.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// Registers a DER CA before encrypted transports are initialized.
    pub fn add_trust_root(der: CertificateDer<'static>) {
        store().lock().unwrap().push(der);
    }

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
