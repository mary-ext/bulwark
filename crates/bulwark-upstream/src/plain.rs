//! Plain DNS transports: UDP (with TCP fallback on truncation) and TCP.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;

use crate::error::{Result, UpstreamError};
use crate::transport::{decode, encode, matches_query, Pending, PendingGuard, PendingState, Transport};

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
    if bytes.len() > u16::MAX as usize {
        return Err(UpstreamError::Proto("message too large for TCP".into()));
    }
    let len = (bytes.len() as u16).to_be_bytes();
    stream.write_all(&len).await.map_err(io)?;
    stream.write_all(&bytes).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    Ok(())
}

/// One persistent connected UDP socket, multiplexed: many queries can be in
/// flight at once, each tagged with a distinct socket-local id, and a background
/// reader demultiplexes datagrams back to the waiting callers by that id. This
/// avoids binding a fresh socket and allocating a 64 KiB receive buffer for every
/// single query (the old behaviour), which was syscall- and allocation-heavy on
/// the cache-miss path for plain-UDP upstreams.
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
    fn new(sock: UdpSocket) -> Arc<Self> {
        let sock = Arc::new(sock);
        let pending: Pending = Arc::new(SyncMutex::new(PendingState::default()));
        let reader = tokio::spawn(udp_reader_loop(sock.clone(), pending.clone()));
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

    /// Send one query and await its matching response, demuxed by a socket-local
    /// id (the caller's id is restored on the way out), validating the response
    /// against the sent question to reject off-path spoofs.
    async fn exchange(&self, query: &Message) -> Result<Message> {
        let original_id = query.metadata.id;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut sent = query.clone();
        sent.metadata.id = id;
        let buf = encode(&sent)?;

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
        if !matches_query(&sent, &resp) {
            return Err(UpstreamError::Proto(
                "UDP response does not match query".into(),
            ));
        }
        resp.metadata.id = original_id;
        Ok(resp)
    }
}

/// Drain datagrams off the connected socket and hand each to its waiter, keyed by
/// the response id. On a socket error the connection is dead: mark it and drop
/// every pending sender so all in-flight queries wake with an error and fail over
/// promptly. Undecodable or unsolicited datagrams are ignored.
async fn udp_reader_loop(sock: Arc<UdpSocket>, pending: Pending) {
    let mut buf = vec![0u8; 65535];
    while let Ok(n) = sock.recv(&mut buf).await {
        if let Ok(msg) = decode(&buf[..n]) {
            let waiter = pending.lock().map.remove(&msg.metadata.id);
            if let Some(tx) = waiter {
                let _ = tx.send(msg);
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
    desc: String,
}

impl UdpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            desc: format!("udp://{addr}"),
            addr,
            conn: Mutex::new(None),
        }
    }

    /// Bind an ephemeral socket connected to the upstream. A connected UDP socket
    /// only receives datagrams from that peer, so the kernel drops off-path spoofs
    /// before they reach us.
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

    /// The live connected socket, dialing (and replacing a dead one) under the
    /// lock so concurrent callers share a single socket rather than each binding
    /// their own.
    async fn connection(&self) -> Result<Arc<UdpConn>> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            if !c.is_dead() {
                return Ok(c.clone());
            }
        }
        let conn = UdpConn::new(self.dial().await?);
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Drop the shared socket if it's still the one that just failed, so the next
    /// `connection()` dials fresh.
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
                    // The reused socket may have errored (e.g. ICMP port
                    // unreachable surfacing as a recv error): discard it and retry
                    // once on a fresh socket.
                    self.invalidate(&conn).await;
                    tracing::debug!(upstream = %self.desc, error = %e, "UDP retry on fresh socket");
                    let fresh = self.connection().await?;
                    fresh.exchange(query).await?
                }
            };
            if msg.metadata.truncation {
                // Retry over TCP to get the full answer.
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
