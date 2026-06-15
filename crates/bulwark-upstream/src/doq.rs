//! DNS-over-QUIC (RFC 9250).
//!
//! Each query is sent on its own bidirectional QUIC stream (streams are cheap),
//! so queries are naturally concurrent over one connection. Per RFC 9250 the
//! DNS message id MUST be 0 on the wire; we restore the caller's id on the
//! response.

use std::net::SocketAddr;
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use tokio::sync::{Mutex, OnceCell};

use crate::bootstrap::SharedBootstrap;
use crate::error::{Result, UpstreamError};
use crate::spec::UpstreamSpec;
use crate::tlsconf::doq_config;
use crate::transport::{decode, encode, matches_query, Transport, UPSTREAM_IDLE_TIMEOUT};

pub struct DoqTransport {
    spec: UpstreamSpec,
    bootstrap: SharedBootstrap,
    endpoint: OnceCell<Endpoint>,
    conn: Mutex<Option<Connection>>,
    desc: String,
}

fn quic(e: impl std::fmt::Display) -> UpstreamError {
    UpstreamError::Quic(e.to_string())
}

impl DoqTransport {
    pub fn new(spec: UpstreamSpec, bootstrap: SharedBootstrap) -> Self {
        Self {
            desc: format!("quic://{}", spec.server_name()),
            spec,
            bootstrap,
            endpoint: OnceCell::new(),
            conn: Mutex::new(None),
        }
    }

    async fn endpoint(&self) -> Result<&Endpoint> {
        self.endpoint
            .get_or_try_init(|| async {
                let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(quic)?;
                let crypto = QuicClientConfig::try_from((*doq_config()).clone())
                    .map_err(|e| UpstreamError::Tls(e.to_string()))?;
                let mut client_config = ClientConfig::new(Arc::new(crypto));
                // Close the connection after the shared idle window so a quiet box
                // doesn't keep the QUIC session resident. We leave keep_alive_interval
                // at its default (None), so we never ping the connection alive — an
                // idle connection genuinely idles out and closes, after which
                // `connection()` re-dials on the next query. The handshake that costs
                // is exactly what persistence is worth paying for on a burst after
                // idle; holding it open around the clock is not.
                let mut transport = TransportConfig::default();
                transport.max_idle_timeout(Some(
                    IdleTimeout::try_from(UPSTREAM_IDLE_TIMEOUT)
                        .expect("idle timeout fits in a QUIC varint"),
                ));
                client_config.transport_config(Arc::new(transport));
                endpoint.set_default_client_config(client_config);
                Ok(endpoint)
            })
            .await
    }

    /// Get a live connection, dialing if necessary.
    async fn connection(&self) -> Result<Connection> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            // close_reason is Some once the connection is gone.
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        let endpoint = self.endpoint().await?;
        let ips = self.bootstrap.resolve(&self.spec.host.to_string()).await?;
        let server_name = self.spec.server_name();
        let mut last = UpstreamError::Bootstrap(self.spec.host.to_string());
        for ip in ips {
            let addr = SocketAddr::new(ip, self.spec.port);
            match endpoint.connect(addr, &server_name) {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => {
                        *guard = Some(conn.clone());
                        return Ok(conn);
                    }
                    Err(e) => last = quic(e),
                },
                Err(e) => last = quic(e),
            }
        }
        Err(last)
    }

    async fn query_inner(&self, query: &Message) -> Result<Message> {
        // RFC 9250 carries id 0 on the wire; restore the caller's id on the
        // response. Patch the id directly into the encoded header rather than
        // cloning the whole `Message` to zero it.
        let original_id = query.metadata.id;
        let mut body = encode(query)?;
        if body.len() > u16::MAX as usize {
            return Err(UpstreamError::Proto("message too large".into()));
        }
        body[..2].copy_from_slice(&[0, 0]);

        let conn = self.connection().await?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(quic)?;

        let len = (body.len() as u16).to_be_bytes();
        send.write_all(&len).await.map_err(quic)?;
        send.write_all(&body).await.map_err(quic)?;
        send.finish().map_err(quic)?;

        let data = recv.read_to_end(64 * 1024).await.map_err(quic)?;
        if data.len() < 2 {
            return Err(UpstreamError::Proto("short DoQ response".into()));
        }
        let mut msg = decode(&data[2..])?;
        // The response carries id 0 on the wire (RFC 9250); restore the caller's
        // id, then verify the response actually answers our question
        // (name/type/class) before trusting it — a hostile or buggy upstream must
        // not get its answer cached under our key.
        msg.metadata.id = original_id;
        if !matches_query(query, &msg) {
            return Err(UpstreamError::Proto(
                "DoQ response does not match query".into(),
            ));
        }
        Ok(msg)
    }
}

impl Transport for DoqTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        async move {
            match self.query_inner(query).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    // Drop a dead connection so the next attempt redials.
                    *self.conn.lock().await = None;
                    tracing::debug!(upstream = %self.desc, error = %e, "DoQ query failed");
                    Err(e)
                }
            }
        }
        .boxed()
    }

    fn describe(&self) -> &str {
        &self.desc
    }
}
