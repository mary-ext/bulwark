//! UDP + TCP DNS listeners that drive the [`crate::Engine`] pipeline.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::Engine;

/// Idle timeout for a TCP DNS connection.
const TCP_IDLE: Duration = Duration::from_secs(30);

fn decode(bytes: &[u8]) -> Option<Message> {
    Message::from_vec(bytes).ok()
}

/// The maximum UDP payload the client will accept (EDNS, clamped to 512..4096).
fn udp_max_payload(query: &Message) -> usize {
    let advertised = query.edns.as_ref().map(|e| e.max_payload()).unwrap_or(512);
    (advertised as usize).clamp(512, 4096)
}

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
            let Some(query) = decode(&buf[..n]) else {
                continue;
            };
            let engine = engine.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                let max = udp_max_payload(&query);
                let resp = engine.handle(query, peer.ip()).await;
                let bytes = encode_udp(&resp, max);
                if !bytes.is_empty() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            });
        }
    })
}

fn spawn_tcp(engine: Arc<Engine>, listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_tcp_conn(engine, stream, peer).await {
                            tracing::trace!(error = %e, "TCP connection closed");
                        }
                    });
                }
                Err(e) => {
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
        stream.read_exact(&mut msg_buf).await?;

        let Some(query) = decode(&msg_buf) else {
            return Ok(());
        };
        let resp = engine.handle(query, peer.ip()).await;
        let bytes = match resp.to_vec() {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };
        if bytes.len() > u16::MAX as usize {
            return Ok(());
        }
        stream
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
    }
}
