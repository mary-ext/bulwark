//! UDP + TCP DNS listeners that drive the [`crate::Engine`] pipeline.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::{Engine, Ingress};

/// Idle timeout for a TCP DNS connection (between queries, waiting for a length
/// prefix).
const TCP_IDLE: Duration = Duration::from_secs(30);

/// Active read/write timeout once a TCP query is in progress: a peer that sends
/// the length prefix then stalls (slow-loris) can't pin the connection forever.
const TCP_IO: Duration = Duration::from_secs(10);

/// Max concurrent in-flight UDP queries per listener. When saturated the recv
/// loop awaits a free slot, so a flood sheds at the kernel UDP buffer instead of
/// spawning unbounded tasks.
const MAX_UDP_INFLIGHT: usize = 1024;

/// Max concurrent TCP connections per listener.
const MAX_TCP_CONNS: usize = 512;

/// Encode a response for UDP, truncating (setting TC) if it exceeds `max`.
fn encode_udp(resp: &Message, max: usize) -> Vec<u8> {
    match resp.to_vec() {
        Ok(bytes) if bytes.len() <= max => bytes,
        Ok(_) => {
            // Build a truncated header-only response.
            let mut tc = Message::new(
                resp.metadata.id,
                hickory_proto::op::MessageType::Response,
                resp.metadata.op_code,
            );
            tc.metadata.truncation = true;
            tc.metadata.recursion_available = resp.metadata.recursion_available;
            tc.metadata.recursion_desired = resp.metadata.recursion_desired;
            tc.metadata.response_code = resp.metadata.response_code;
            for q in &resp.queries {
                tc.queries.push(q.clone());
            }
            tc.to_vec().unwrap_or_default()
        }
        Err(_) => Vec::new(),
    }
}

/// Bind UDP + TCP on every address and spawn their serve loops.
pub async fn spawn(engine: Arc<Engine>, binds: &[SocketAddr]) -> io::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    for &addr in binds {
        let udp = UdpSocket::bind(addr).await?;
        let tcp = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "DNS listening (UDP + TCP)");
        handles.push(spawn_udp(engine.clone(), udp));
        handles.push(spawn_tcp(engine.clone(), tcp));
    }
    Ok(handles)
}

fn spawn_udp(engine: Arc<Engine>, socket: UdpSocket) -> JoinHandle<()> {
    let socket = Arc::new(socket);
    let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_UDP_INFLIGHT));
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "UDP recv error");
                    continue;
                }
            };
            let Some(ingress) = Ingress::parse(&buf[..n]) else {
                continue;
            };
            // Bound concurrent in-flight queries. When saturated this awaits a
            // free slot, so the loop stops draining the socket and the kernel
            // sheds the excess — rather than spawning unbounded tasks.
            let Ok(permit) = inflight.clone().acquire_owned().await else {
                return; // semaphore closed: listener is shutting down.
            };
            let engine = engine.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let max = ingress.udp_max_payload();
                let resp = engine.handle(ingress, peer.ip()).await;
                // Fast path: a wire-byte cache hit is already encoded and almost
                // always fits the UDP limit — send it as-is. Otherwise (a
                // `Message`, or oversized wire needing truncation) fall back to
                // `encode_udp`, which decodes the wire only in that rare case.
                let bytes = match resp {
                    crate::EngineResponse::Wire(b) if b.len() <= max => b,
                    other => encode_udp(&other.into_message(), max),
                };
                if !bytes.is_empty() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            });
        }
    })
}

fn spawn_tcp(engine: Arc<Engine>, listener: TcpListener) -> JoinHandle<()> {
    let conns = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNS));
    tokio::spawn(async move {
        loop {
            // Bound concurrent connections: await a slot before accepting, so a
            // connection flood can't spawn unbounded tasks/sockets.
            let Ok(permit) = conns.clone().acquire_owned().await else {
                return; // semaphore closed: listener is shutting down.
            };
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = serve_tcp_conn(engine, stream, peer).await {
                            tracing::trace!(error = %e, "TCP connection closed");
                        }
                    });
                }
                Err(e) => {
                    drop(permit);
                    tracing::warn!(error = %e, "TCP accept error");
                }
            }
        }
    })
}

async fn serve_tcp_conn(
    engine: Arc<Engine>,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    loop {
        // Read the 2-byte length prefix (with an idle timeout).
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()), // EOF, error, or idle: close.
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; len];
        // Bound the body read: a peer that sends the prefix then stalls (or sends
        // the body a byte at a time) must not pin the task indefinitely.
        match tokio::time::timeout(TCP_IO, stream.read_exact(&mut msg_buf)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()), // body error or stall: close.
        }

        // Move the exactly-sized body buffer into the parser: the fast path keeps
        // it without a second copy, and it isn't reused after this.
        let Some(ingress) = Ingress::parse_owned(msg_buf) else {
            return Ok(());
        };
        let resp = engine.handle(ingress, peer.ip()).await;
        let bytes = match resp.into_wire() {
            Some(b) => b,
            None => return Ok(()),
        };
        if bytes.len() > u16::MAX as usize {
            return Ok(());
        }
        // Bound the response write too: a peer that stops reading can't wedge the
        // task on a full send buffer.
        let write = async {
            stream
                .write_all(&(bytes.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(&bytes).await?;
            stream.flush().await
        };
        match tokio::time::timeout(TCP_IO, write).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()), // write stalled: close.
        }
    }
}
