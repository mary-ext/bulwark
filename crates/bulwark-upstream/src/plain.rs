//! Plain DNS transports: UDP (with TCP fallback on truncation) and TCP.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;

use crate::error::{Result, UpstreamError};
use crate::transport::{
    decode, encode, matches_query, Pending, PendingGuard, PendingState, Transport, MAX_UDP_PAYLOAD,
    UPSTREAM_IDLE_TIMEOUT,
};

fn io(e: std::io::Error) -> UpstreamError {
    UpstreamError::Io(e.to_string())
}

/// Read a 2-byte length-prefixed DNS message from a stream (TCP / DoT framing).
pub(crate) async fn read_tcp_message<R>(stream: &mut R) -> Result<Message>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(io)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(io)?;
    decode(&buf)
}

/// Write a 2-byte length-prefixed DNS message to a stream.
pub(crate) async fn write_tcp_message<W>(stream: &mut W, msg: &Message) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let bytes = encode(msg)?;
    write_tcp_bytes(stream, &bytes).await
}

/// Writes encoded DNS bytes with a TCP length prefix.
pub(crate) async fn write_tcp_bytes<W>(stream: &mut W, bytes: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if bytes.len() > u16::MAX as usize {
        return Err(UpstreamError::Proto("message too large for TCP".into()));
    }
    let len = (bytes.len() as u16).to_be_bytes();
    stream.write_all(&len).await.map_err(io)?;
    stream.write_all(bytes).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    Ok(())
}

/// Multiplexed connected UDP socket.
struct UdpConn {
    sock: Arc<UdpSocket>,
    pending: Pending,
    next_id: AtomicU16,
    reader: JoinHandle<()>,
}

impl Drop for UdpConn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl UdpConn {
    fn new(sock: UdpSocket, idle_timeout: Duration) -> Arc<Self> {
        let sock = Arc::new(sock);
        let pending: Pending = Arc::new(SyncMutex::new(PendingState::default()));
        let reader = tokio::spawn(udp_reader_loop(sock.clone(), pending.clone(), idle_timeout));
        Arc::new(UdpConn {
            sock,
            pending,
            next_id: AtomicU16::new(0),
            reader,
        })
    }

    fn is_dead(&self) -> bool {
        self.pending.lock().dead
    }

    /// Exchanges a query using a socket-local demultiplexing id.
    async fn exchange(&self, query: &Message) -> Result<Message> {
        let original_id = query.metadata.id;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut buf = encode(query)?;
        buf[..2].copy_from_slice(&id.to_be_bytes());

        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.pending.lock();
            if p.dead {
                return Err(UpstreamError::Io("UDP socket closed".into()));
            }
            p.map.insert(id, tx);
        }
        let _guard = PendingGuard {
            pending: self.pending.clone(),
            id,
        };

        self.sock.send(&buf).await.map_err(io)?;

        let mut resp = rx
            .await
            .map_err(|_| UpstreamError::Io("UDP socket closed".into()))?;
        resp.metadata.id = original_id;
        if !matches_query(query, &resp) {
            return Err(UpstreamError::Proto(
                "UDP response does not match query".into(),
            ));
        }
        Ok(resp)
    }
}

/// Demultiplexes UDP responses and closes an idle socket without waiters.
async fn udp_reader_loop(sock: Arc<UdpSocket>, pending: Pending, idle_timeout: Duration) {
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD as usize];
    loop {
        match tokio::time::timeout(idle_timeout, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Ok(msg) = decode(&buf[..n]) {
                    let waiter = pending.lock().map.remove(&msg.metadata.id);
                    if let Some(tx) = waiter {
                        let _ = tx.send(msg);
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_elapsed) => {
                let mut p = pending.lock();
                if p.map.is_empty() {
                    p.dead = true;
                    break;
                }
            }
        }
    }
    let mut p = pending.lock();
    p.dead = true;
    p.map.clear();
}

/// Plain DNS over UDP. Falls back to TCP automatically if the UDP response is
/// truncated.
pub struct UdpTransport {
    addr: SocketAddr,
    conn: Mutex<Option<Arc<UdpConn>>>,
    idle_timeout: Duration,
    desc: String,
}

impl UdpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            desc: format!("udp://{addr}"),
            addr,
            conn: Mutex::new(None),
            idle_timeout: UPSTREAM_IDLE_TIMEOUT,
        }
    }

    /// Construct with a custom idle-close window (tests use a short one to drive
    /// the close/redial cycle without waiting [`UPSTREAM_IDLE_TIMEOUT`]).
    #[cfg(test)]
    pub(crate) fn with_idle_timeout(addr: SocketAddr, idle_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            ..Self::new(addr)
        }
    }

    /// Whether the cached connection currently exists and has been marked dead
    /// (e.g. by an idle close). Used by tests to observe the lifecycle.
    #[cfg(test)]
    pub(crate) async fn cached_conn_is_dead(&self) -> bool {
        matches!(self.conn.lock().await.as_ref(), Some(c) if c.is_dead())
    }

    /// Connects an ephemeral socket to the upstream.
    async fn dial(&self) -> Result<UdpSocket> {
        let bind: SocketAddr = if self.addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await.map_err(io)?;
        sock.connect(self.addr).await.map_err(io)?;
        Ok(sock)
    }

    /// Returns the shared live socket.
    async fn connection(&self) -> Result<Arc<UdpConn>> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            if !c.is_dead() {
                return Ok(c.clone());
            }
        }
        let conn = UdpConn::new(self.dial().await?, self.idle_timeout);
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Drops the shared socket if it matches the failed one.
    async fn invalidate(&self, dead: &Arc<UdpConn>) {
        let mut guard = self.conn.lock().await;
        if matches!(guard.as_ref(), Some(c) if Arc::ptr_eq(c, dead)) {
            *guard = None;
        }
    }
}

impl Transport for UdpTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        async move {
            let conn = self.connection().await?;
            let msg = match conn.exchange(query).await {
                Ok(m) => m,
                Err(e) => {
                    self.invalidate(&conn).await;
                    tracing::debug!(upstream = %self.desc, error = %e, "UDP retry on fresh socket");
                    let fresh = self.connection().await?;
                    fresh.exchange(query).await?
                }
            };
            if msg.metadata.truncation {
                let tcp = TcpTransport::new(self.addr);
                return tcp.query_once(query).await;
            }
            Ok(msg)
        }
        .boxed()
    }

    fn describe(&self) -> &str {
        &self.desc
    }
}

/// Plain DNS over TCP.
pub struct TcpTransport {
    addr: SocketAddr,
    desc: String,
}

impl TcpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            desc: format!("tcp://{addr}"),
            addr,
        }
    }

    async fn query_once(&self, query: &Message) -> Result<Message> {
        let mut stream = TcpStream::connect(self.addr).await.map_err(io)?;
        stream.set_nodelay(true).ok();
        write_tcp_message(&mut stream, query).await?;
        loop {
            let msg = read_tcp_message(&mut stream).await?;
            if matches_query(query, &msg) {
                return Ok(msg);
            }
        }
    }
}

impl Transport for TcpTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        self.query_once(query).boxed()
    }

    fn describe(&self) -> &str {
        &self.desc
    }
}
