//! DNS-over-HTTPS (RFC 8484), POST `application/dns-message`.
//!
//! Uses `reqwest` (HTTP/2 keep-alive connection pooling). The upstream host is
//! resolved via the bootstrap resolver and pinned on the client so we never go
//! through the system resolver (which could loop back into Bulwark).

use std::net::SocketAddr;

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use tokio::sync::OnceCell;

use crate::bootstrap::SharedBootstrap;
use crate::error::{Result, UpstreamError};
use crate::spec::UpstreamSpec;
use crate::transport::{decode, encode, Transport};

const DNS_MESSAGE: &str = "application/dns-message";

pub struct DohTransport {
    spec: UpstreamSpec,
    bootstrap: SharedBootstrap,
    url: String,
    client: OnceCell<reqwest::Client>,
    desc: String,
}

impl DohTransport {
    pub fn new(spec: UpstreamSpec, bootstrap: SharedBootstrap) -> Self {
        let url = format!("https://{}:{}{}", spec.server_name(), spec.port, spec.path);
        Self {
            desc: url.clone(),
            url,
            spec,
            bootstrap,
            client: OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<&reqwest::Client> {
        self.client
            .get_or_try_init(|| async {
                let host = self.spec.host.to_string();
                let ips = self.bootstrap.resolve(&host).await?;
                // Negotiate HTTP/2 via ALPN (don't force "prior knowledge",
                // which is for cleartext h2c and breaks over TLS).
                let mut builder = reqwest::Client::builder()
                    .https_only(true)
                    .http2_keep_alive_interval(std::time::Duration::from_secs(30))
                    .pool_idle_timeout(std::time::Duration::from_secs(90))
                    .user_agent("bulwark");
                // Pin the resolved addresses for the host:port.
                for ip in ips {
                    builder = builder.resolve(&host, SocketAddr::new(ip, self.spec.port));
                }
                builder
                    .build()
                    .map_err(|e| UpstreamError::Http(e.to_string()))
            })
            .await
    }

    async fn query_inner(&self, query: &Message) -> Result<Message> {
        // RFC 8484 recommends id 0 for cacheability; restore the caller's id.
        let original_id = query.metadata.id;
        let mut q = query.clone();
        q.metadata.id = 0;
        let body = encode(&q)?;

        let client = self.client().await?;
        let resp = client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, DNS_MESSAGE)
            .header(reqwest::header::ACCEPT, DNS_MESSAGE)
            .body(body)
            .send()
            .await
            .map_err(|e| UpstreamError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(UpstreamError::Http(format!("status {}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| UpstreamError::Http(e.to_string()))?;
        let mut msg = decode(&bytes)?;
        msg.metadata.id = original_id;
        Ok(msg)
    }
}

impl Transport for DohTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        self.query_inner(query).boxed()
    }

    fn describe(&self) -> &str {
        &self.desc
    }
}
