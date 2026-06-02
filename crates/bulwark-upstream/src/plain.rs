//! Plain DNS transports: UDP (with TCP fallback on truncation) and TCP.

use std::net::SocketAddr;

use futures::future::BoxFuture;
use futures::FutureExt;
use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::error::{Result, UpstreamError};
use crate::transport::{decode, encode, matches_query, Transport};

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

/// Plain DNS over UDP. Falls back to TCP automatically if the UDP response is
/// truncated.
pub struct UdpTransport {
    addr: SocketAddr,
    desc: String,
}

impl UdpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            desc: format!("udp://{addr}"),
            addr,
        }
    }

    async fn query_once(&self, query: &Message) -> Result<Message> {
        let bind: SocketAddr = if self.addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await.map_err(io)?;
        sock.connect(self.addr).await.map_err(io)?;
        let buf = encode(query)?;
        sock.send(&buf).await.map_err(io)?;

        let mut resp = vec![0u8; 65535];
        loop {
            let n = sock.recv(&mut resp).await.map_err(io)?;
            let msg = decode(&resp[..n])?;
            // Ignore stray/spoofed datagrams that don't match the question.
            if matches_query(query, &msg) {
                return Ok(msg);
            }
        }
    }
}

impl Transport for UdpTransport {
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>> {
        async move {
            let msg = self.query_once(query).await?;
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
