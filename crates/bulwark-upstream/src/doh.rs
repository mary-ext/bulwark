//! DNS-over-HTTPS (RFC 8484), POST `application/dns-message`.
//!
//! Uses `reqwest` with connection pooling. The upstream host is resolved via the
//! bootstrap resolver and pinned on the client so we never go through the system
//! resolver (which could loop back into Bulwark).
//!
//! HTTP version selection:
//! * `https://` negotiates HTTP/1.1 + HTTP/2 over ALPN, and auto-upgrades to
//!   HTTP/3 once the server advertises it via an `Alt-Svc: h3=...` header. The
//!   advertisement is cached (honouring its `ma=` max-age) so subsequent queries
//!   go straight over HTTP/3. reqwest has no built-in Alt-Svc cache, so we keep a
//!   small one here.
//! * `h3://` pins the transport to HTTP/3 from the first packet, skipping
//!   discovery (`UpstreamSpec::force_http3`).
//!
//! To avoid relying on per-request version negotiation, HTTP/3 uses a separate
//! reqwest client built with `http3_prior_knowledge()`; the h1/h2 client is used
//! for everything else.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use parking_lot::Mutex;
use tokio::sync::OnceCell;

use crate::bootstrap::SharedBootstrap;
use crate::error::{Result, UpstreamError};
use crate::spec::UpstreamSpec;
use crate::transport::{decode, encode, matches_query, Transport};

const DNS_MESSAGE: &str = "application/dns-message";

/// Default Alt-Svc lifetime when the advertisement omits `ma=` (RFC 7838 §3.1).
const DEFAULT_ALT_SVC_MA: Duration = Duration::from_secs(86_400);

/// What an `Alt-Svc` response header tells us about HTTP/3 availability.
#[derive(Debug, PartialEq, Eq)]
enum AltSvcH3 {
    /// An `h3` (or `h3-NN`) alternative is offered, valid for this duration.
    Found(Duration),
    /// `Alt-Svc: clear` — drop any cached alternative.
    Clear,
    /// No HTTP/3 information; leave the cache untouched.
    Absent,
}

/// HTTP/3 strategy for a DoH upstream.
///
/// Modeled as an enum so the Alt-Svc discovery cache (`h3_until`) only exists
/// when it can actually be used — a forced-HTTP/3 transport never negotiates, so
/// it carries no discovery state at all.
enum H3Mode {
    /// Pinned to HTTP/3 (`force_http3`): no Alt-Svc discovery, no fallback.
    Forced,
    /// Negotiated: when an advertised HTTP/3 alternative stops being trusted.
    /// `None` means we have no current advertisement and should use h1/h2.
    Auto { until: Mutex<Option<Instant>> },
}

pub struct DohTransport {
    spec: UpstreamSpec,
    bootstrap: SharedBootstrap,
    url: String,
    /// Bootstrap-resolved addresses for the upstream host, pinned on the clients.
    ips: OnceCell<Vec<IpAddr>>,
    /// HTTP/1.1 + HTTP/2 client (also the discovery path for Alt-Svc).
    client_h12: OnceCell<reqwest::Client>,
    /// HTTP/3-only client (`http3_prior_knowledge`), built lazily on first use.
    client_h3: OnceCell<reqwest::Client>,
    h3: H3Mode,
    desc: String,
}

impl DohTransport {
    pub fn new(spec: UpstreamSpec, bootstrap: SharedBootstrap) -> Self {
        let url = format!("https://{}:{}{}", spec.server_name(), spec.port, spec.path);
        let h3 = if spec.force_http3 {
            H3Mode::Forced
        } else {
            H3Mode::Auto {
                until: Mutex::new(None),
            }
        };
        Self {
            desc: url.clone(),
            url,
            spec,
            bootstrap,
            ips: OnceCell::new(),
            client_h12: OnceCell::new(),
            client_h3: OnceCell::new(),
            h3,
        }
    }

    /// Bootstrap-resolve the upstream host once.
    async fn ips(&self) -> Result<&Vec<IpAddr>> {
        self.ips
            .get_or_try_init(|| async {
                let host = self.spec.host.to_string();
                self.bootstrap.resolve(&host).await
            })
            .await
    }

    fn build_client(&self, ips: &[IpAddr], force_h3: bool) -> Result<reqwest::Client> {
        let host = self.spec.host.to_string();
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent("bulwark");
        if force_h3 {
            builder = builder.http3_prior_knowledge();
        } else {
            // Negotiate h1/h2 via ALPN (don't force "prior knowledge", which is
            // for cleartext h2c and breaks over TLS).
            builder = builder.http2_keep_alive_interval(Duration::from_secs(30));
        }
        // Pin the resolved addresses for the host:port in a single call.
        // `resolve()` in a loop would not accumulate: reqwest keys the override
        // by host and *overwrites* on each call, so only the last IP would
        // survive. Given bootstrap's A-then-AAAA order that last IP is the IPv6
        // address, pinning the client to IPv6 only — which stalls on hosts
        // without working IPv6 egress (e.g. an IPv4-only container) even though
        // DoT/DoQ to the same upstream succeed over IPv4. `resolve_to_addrs`
        // keeps the whole set so the connector can fall back across families.
        let addrs: Vec<SocketAddr> = ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.spec.port))
            .collect();
        builder = builder.resolve_to_addrs(&host, &addrs);
        // Additive test/benchmark trust anchors (feature-gated, absent from the
        // shipped binary). Lets the DoH client trust a local mock's private CA.
        #[cfg(feature = "test-trust-roots")]
        for der in crate::tlsconf::test_roots::extra_roots() {
            if let Ok(cert) = reqwest::Certificate::from_der(&der) {
                builder = builder.add_root_certificate(cert);
            }
        }
        builder
            .build()
            .map_err(|e| UpstreamError::Http(e.to_string()))
    }

    async fn h12(&self) -> Result<&reqwest::Client> {
        let ips = self.ips().await?;
        self.client_h12
            .get_or_try_init(|| async { self.build_client(ips, false) })
            .await
    }

    async fn h3(&self) -> Result<&reqwest::Client> {
        let ips = self.ips().await?;
        self.client_h3
            .get_or_try_init(|| async { self.build_client(ips, true) })
            .await
    }

    /// Whether a previously advertised HTTP/3 alternative is still within its
    /// max-age. Always false in forced mode (it never negotiates).
    fn h3_fresh(&self) -> bool {
        match &self.h3 {
            H3Mode::Auto { until } => matches!(*until.lock(), Some(t) if t > Instant::now()),
            H3Mode::Forced => false,
        }
    }

    /// Record (or clear) an HTTP/3 alternative learned from a response. No-op in
    /// forced mode, which has no discovery state.
    fn learn_alt_svc(&self, decision: AltSvcH3) {
        let H3Mode::Auto { until } = &self.h3 else {
            return;
        };
        match decision {
            AltSvcH3::Found(ma) => *until.lock() = Some(Instant::now() + ma),
            AltSvcH3::Clear => *until.lock() = None,
            AltSvcH3::Absent => {}
        }
    }

    async fn query_inner(&self, query: &Message) -> Result<Message> {
        // RFC 8484 recommends id 0 for cacheability; restore the caller's id.
        let original_id = query.metadata.id;
        let mut q = query.clone();
        q.metadata.id = 0;
        let body = encode(&q)?;

        // Pinned to HTTP/3: no discovery, no fallback.
        if matches!(self.h3, H3Mode::Forced) {
            return self
                .exchange(self.h3().await?, &body, &q, original_id, false, true)
                .await;
        }

        // Auto-upgrade: prefer HTTP/3 while a fresh advertisement stands, but fall
        // back to h1/h2 (and forget the advertisement) if the h3 attempt fails.
        if self.h3_fresh() {
            match self
                .exchange(self.h3().await?, &body, &q, original_id, false, true)
                .await
            {
                Ok(msg) => return Ok(msg),
                Err(e) => {
                    self.learn_alt_svc(AltSvcH3::Clear);
                    tracing::debug!(upstream = %self.desc, error = %e, "DoH HTTP/3 failed, falling back to h1/h2");
                }
            }
        }

        // h1/h2 path: also the discovery path for future HTTP/3 upgrades.
        self.exchange(self.h12().await?, &body, &q, original_id, true, false)
            .await
    }

    /// Send one DoH request over `client`, optionally learning HTTP/3 availability
    /// from the response's `Alt-Svc` header.
    ///
    /// `http3` must be set when `client` is the HTTP/3 client: reqwest's
    /// `http3_prior_knowledge()` still routes a request over TCP (h1/h2) unless
    /// the request explicitly opts into `Version::HTTP_3`, so without this an
    /// `h3://` upstream would silently never use QUIC.
    async fn exchange(
        &self,
        client: &reqwest::Client,
        body: &[u8],
        expect: &Message,
        original_id: u16,
        learn_alt_svc: bool,
        http3: bool,
    ) -> Result<Message> {
        let mut req = client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, DNS_MESSAGE)
            .header(reqwest::header::ACCEPT, DNS_MESSAGE)
            .body(body.to_vec());
        if http3 {
            req = req.version(reqwest::Version::HTTP_3);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| UpstreamError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(UpstreamError::Http(format!("status {}", resp.status())));
        }

        if learn_alt_svc {
            if let Some(value) = resp
                .headers()
                .get(reqwest::header::ALT_SVC)
                .and_then(|v| v.to_str().ok())
            {
                self.learn_alt_svc(parse_alt_svc_h3(value));
            }
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| UpstreamError::Http(e.to_string()))?;
        let mut msg = decode(&bytes)?;
        // `expect` and the response both carry id 0 (RFC 8484), so verify the
        // response answers our question before trusting it — otherwise a buggy
        // or hostile server could get its answer cached under our key.
        if !matches_query(expect, &msg) {
            return Err(UpstreamError::Http(
                "DoH response does not match query".into(),
            ));
        }
        msg.metadata.id = original_id;
        Ok(msg)
    }
}

/// Parse an `Alt-Svc` header value for an HTTP/3 alternative.
///
/// Examples: `h3=":443"; ma=2592000,h3-29=":443"; ma=2592000` advertises HTTP/3;
/// `clear` retracts all alternatives.
fn parse_alt_svc_h3(value: &str) -> AltSvcH3 {
    let value = value.trim();
    if value.eq_ignore_ascii_case("clear") {
        return AltSvcH3::Clear;
    }
    // Each comma-separated entry is `protocol-id=authority; param=value; ...`.
    for entry in value.split(',') {
        let mut params = entry.split(';').map(str::trim);
        let Some(proto) = params.next() else { continue };
        let id = proto.split('=').next().unwrap_or("").trim();
        // `h3` plus draft variants such as `h3-29`.
        if id == "h3" || id.starts_with("h3-") {
            let ma = params
                .find_map(|p| p.strip_prefix("ma="))
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_ALT_SVC_MA);
            return AltSvcH3::Found(ma);
        }
    }
    AltSvcH3::Absent
}

impl Transport for DohTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        self.query_inner(query).boxed()
    }

    fn describe(&self) -> &str {
        &self.desc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_svc_advertises_h3() {
        assert_eq!(
            parse_alt_svc_h3("h3=\":443\"; ma=2592000"),
            AltSvcH3::Found(Duration::from_secs(2_592_000))
        );
    }

    #[test]
    fn alt_svc_h3_among_others() {
        // h2 listed first, h3 second; we still find the h3 alternative.
        assert_eq!(
            parse_alt_svc_h3("h2=\":443\"; ma=3600, h3-29=\":443\"; ma=600"),
            AltSvcH3::Found(Duration::from_secs(600))
        );
    }

    #[test]
    fn alt_svc_h3_default_ma() {
        assert_eq!(
            parse_alt_svc_h3("h3=\":443\""),
            AltSvcH3::Found(DEFAULT_ALT_SVC_MA)
        );
    }

    #[test]
    fn alt_svc_clear() {
        assert_eq!(parse_alt_svc_h3("clear"), AltSvcH3::Clear);
    }

    #[test]
    fn alt_svc_no_h3() {
        assert_eq!(parse_alt_svc_h3("h2=\":443\"; ma=3600"), AltSvcH3::Absent);
    }
}
