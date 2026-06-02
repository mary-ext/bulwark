//! DNS-over-TLS (RFC 7858).
//!
//! Maintains a single persistent TLS connection that is reused across queries.
//! Queries are serialised over the connection (one outstanding at a time),
//! which keeps the implementation simple and correct; the cache and
//! single-flight layers keep the actual DoT query rate low.

use std::net::SocketAddr;

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::bootstrap::SharedBootstrap;
use crate::error::{Result, UpstreamError};
use crate::plain::{read_tcp_message, write_tcp_message};
use crate::spec::UpstreamSpec;
use crate::tlsconf::dot_config;
use crate::transport::{matches_query, Transport};

pub struct DotTransport {
    spec: UpstreamSpec,
    bootstrap: SharedBootstrap,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    conn: Mutex<Option<TlsStream<TcpStream>>>,
    desc: String,
}

impl DotTransport {
    pub fn new(spec: UpstreamSpec, bootstrap: SharedBootstrap) -> Result<Self> {
        let server_name = ServerName::try_from(spec.server_name())
            .map_err(|e| UpstreamError::Tls(format!("invalid server name: {e}")))?;
        Ok(Self {
            desc: format!("tls://{}", spec.server_name()),
            connector: TlsConnector::from(dot_config()),
            server_name,
            spec,
            bootstrap,
            conn: Mutex::new(None),
        })
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let ips = self.bootstrap.resolve(&self.spec.host.to_string()).await?;
        let mut last = UpstreamError::Bootstrap(self.spec.host.to_string());
        for ip in ips {
            let addr = SocketAddr::new(ip, self.spec.port);
            match TcpStream::connect(addr).await {
                Ok(tcp) => {
                    tcp.set_nodelay(true).ok();
                    match self.connector.connect(self.server_name.clone(), tcp).await {
                        Ok(tls) => return Ok(tls),
                        Err(e) => last = UpstreamError::Tls(e.to_string()),
                    }
                }
                Err(e) => last = UpstreamError::Io(e.to_string()),
            }
        }
        Err(last)
    }

    async fn query_locked(
        &self,
        conn: &mut Option<TlsStream<TcpStream>>,
        query: &Message,
    ) -> Result<Message> {
        // (Re)establish if needed.
        if conn.is_none() {
            *conn = Some(self.connect().await?);
        }
        let stream = conn.as_mut().unwrap();
        write_tcp_message(stream, query).await?;
        loop {
            let resp = read_tcp_message(stream).await?;
            if matches_query(query, &resp) {
                return Ok(resp);
            }
        }
    }
}

impl Transport for DotTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        async move {
            let mut guard = self.conn.lock().await;
            match self.query_locked(&mut guard, query).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    // Drop the (possibly broken) connection and retry once fresh.
                    *guard = None;
                    tracing::debug!(upstream = %self.desc, error = %e, "DoT retry on fresh connection");
                    self.query_locked(&mut guard, query).await
                }
            }
        }
        .boxed()
    }

    fn describe(&self) -> &str {
        &self.desc
    }
}
