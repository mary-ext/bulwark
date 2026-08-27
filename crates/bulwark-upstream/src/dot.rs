//! Pipelined DNS-over-TLS (RFC 7858).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use parking_lot::Mutex as SyncMutex;
use rustls_pki_types::ServerName;
use tokio::io::{split, AsyncRead, AsyncWrite, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::bootstrap::SharedBootstrap;
use crate::error::{Result, UpstreamError};
use crate::plain::{read_tcp_message, write_tcp_bytes};
use crate::spec::UpstreamSpec;
use crate::tlsconf::dot_config;
use crate::transport::{
    encode, matches_query, Pending, PendingGuard, PendingState, Transport, UPSTREAM_IDLE_TIMEOUT,
};

/// One pipelined TLS connection.
struct Conn<S> {
    /// Serialized framed writes.
    write: Mutex<WriteHalf<S>>,
    pending: Pending,
    next_id: AtomicU16,
    reader: JoinHandle<()>,
}

impl<S> Drop for Conn<S> {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl<S> Conn<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn new(stream: S, idle_timeout: Duration) -> Arc<Self> {
        let (read, write) = split(stream);
        let pending: Pending = Arc::new(SyncMutex::new(PendingState::default()));
        let reader = tokio::spawn(reader_loop(read, pending.clone(), idle_timeout));
        Arc::new(Conn {
            write: Mutex::new(write),
            pending,
            next_id: AtomicU16::new(0),
            reader,
        })
    }

    fn is_dead(&self) -> bool {
        self.pending.lock().dead
    }

    /// Exchanges a query using a connection-local demultiplexing id.
    async fn exchange(&self, query: &Message) -> Result<Message> {
        let original_id = query.metadata.id;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut buf = encode(query)?;
        buf[..2].copy_from_slice(&id.to_be_bytes());

        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.pending.lock();
            if p.dead {
                return Err(UpstreamError::Io("DoT connection closed".into()));
            }
            p.map.insert(id, tx);
        }
        let _guard = PendingGuard {
            pending: self.pending.clone(),
            id,
        };

        {
            let mut w = self.write.lock().await;
            write_tcp_bytes(&mut *w, &buf).await?;
        }

        let mut resp = rx
            .await
            .map_err(|_| UpstreamError::Io("DoT connection closed".into()))?;
        resp.metadata.id = original_id;
        if !matches_query(query, &resp) {
            return Err(UpstreamError::Proto(
                "DoT response does not match query".into(),
            ));
        }
        Ok(resp)
    }
}

/// Demultiplexes responses and tears down on read error or idle timeout.
async fn reader_loop<R: AsyncRead + Unpin>(mut read: R, pending: Pending, idle_timeout: Duration) {
    while let Ok(Ok(msg)) = tokio::time::timeout(idle_timeout, read_tcp_message(&mut read)).await {
        let waiter = pending.lock().map.remove(&msg.metadata.id);
        if let Some(tx) = waiter {
            let _ = tx.send(msg);
        }
    }
    let mut p = pending.lock();
    p.dead = true;
    p.map.clear();
}

pub struct DotTransport {
    spec: UpstreamSpec,
    bootstrap: SharedBootstrap,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    conn: Mutex<Option<Arc<Conn<TlsStream<TcpStream>>>>>,
    idle_timeout: Duration,
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
            idle_timeout: UPSTREAM_IDLE_TIMEOUT,
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

    /// Returns the shared live connection.
    async fn connection(&self) -> Result<Arc<Conn<TlsStream<TcpStream>>>> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            if !c.is_dead() {
                return Ok(c.clone());
            }
        }
        let conn = Conn::new(self.connect().await?, self.idle_timeout);
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Drops the shared connection if it matches the failed one.
    async fn invalidate(&self, dead: &Arc<Conn<TlsStream<TcpStream>>>) {
        let mut guard = self.conn.lock().await;
        if matches!(guard.as_ref(), Some(c) if Arc::ptr_eq(c, dead)) {
            *guard = None;
        }
    }
}

impl Transport for DotTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        async move {
            let conn = self.connection().await?;
            match conn.exchange(query).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    self.invalidate(&conn).await;
                    tracing::debug!(upstream = %self.desc, error = %e, "DoT retry on fresh connection");
                    let fresh = self.connection().await?;
                    fresh.exchange(query).await
                }
            }
        }
        .boxed()
    }

    fn describe(&self) -> &str {
        &self.desc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plain::write_tcp_message;
    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::io::DuplexStream;

    use crate::transport::{decode, encode};

    fn query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        let mut q = Query::query(Name::from_str(name).unwrap(), RecordType::A);
        q.set_query_class(DNSClass::IN);
        msg.queries.push(q);
        msg
    }

    fn answer_for(q: &Message) -> Message {
        let mut resp = q.clone();
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        resp
    }
    async fn serve(mut server: DuplexStream, hold: usize, reorder: bool) {
        let mut pending = Vec::new();
        while pending.len() < hold {
            match read_tcp_message(&mut server).await {
                Ok(q) => pending.push(answer_for(&q)),
                Err(_) => return,
            }
        }
        if reorder {
            pending.reverse();
        }
        for resp in pending {
            write_tcp_message(&mut server, &resp).await.unwrap();
        }
    }

    #[tokio::test]
    async fn pipelines_concurrent_queries_out_of_order() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve(server, 2, true));
        let conn = Conn::new(client, UPSTREAM_IDLE_TIMEOUT);

        let qa = query(0x1111, "a.test.");
        let qb = query(0x2222, "b.test.");
        let (ra, rb) = tokio::join!(conn.exchange(&qa), conn.exchange(&qb));

        let ra = ra.unwrap();
        let rb = rb.unwrap();
        assert_eq!(ra.metadata.id, 0x1111);
        assert_eq!(ra.queries[0].name().to_ascii(), "a.test.");
        assert_eq!(rb.metadata.id, 0x2222);
        assert_eq!(rb.queries[0].name().to_ascii(), "b.test.");
    }

    #[tokio::test]
    async fn second_query_not_blocked_by_first() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve(server, 2, true));
        let conn = Conn::new(client, UPSTREAM_IDLE_TIMEOUT);
        let qa = query(1, "first.test.");
        let qb = query(2, "second.test.");
        let res = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(conn.exchange(&qa), conn.exchange(&qb))
        })
        .await
        .expect("pipelined queries must not deadlock");
        assert!(res.0.is_ok() && res.1.is_ok());
    }

    #[tokio::test]
    async fn connection_close_wakes_waiters() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut server = server;
            let _ = read_tcp_message(&mut server).await;
            drop(server); // close without responding
        });
        let conn = Conn::new(client, UPSTREAM_IDLE_TIMEOUT);

        let err = tokio::time::timeout(Duration::from_secs(2), conn.exchange(&query(7, "x.test.")))
            .await
            .expect("must not hang on a dropped connection");
        assert!(
            err.is_err(),
            "a closed connection must wake the waiter with an error"
        );
        assert!(conn.is_dead(), "the connection should be marked dead");
    }

    #[tokio::test]
    async fn idle_connection_closes() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let _keepalive = server; // hold the far end open; just never write to it.
        let conn = Conn::new(client, Duration::from_millis(150));

        assert!(!conn.is_dead(), "a fresh connection is live");
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(
            conn.is_dead(),
            "an idle connection must self-close after the idle window"
        );
    }

    #[tokio::test]
    async fn rejects_mismatched_response() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut server = server;
            let q = read_tcp_message(&mut server).await.unwrap();
            let mut resp = answer_for(&query(0, "evil.test."));
            resp.metadata.id = q.metadata.id;
            write_tcp_message(&mut server, &resp).await.unwrap();
        });
        let conn = Conn::new(client, UPSTREAM_IDLE_TIMEOUT);

        let r = conn.exchange(&query(5, "good.test.")).await;
        assert!(matches!(r, Err(UpstreamError::Proto(_))));
    }
    #[test]
    fn answer_round_trips() {
        let q = query(0x4242, "rt.test.");
        let resp = answer_for(&q);
        let wire = encode(&resp).unwrap();
        assert_eq!(decode(&wire).unwrap().metadata.id, 0x4242);
    }
}
