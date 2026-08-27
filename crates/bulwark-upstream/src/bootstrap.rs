//! Plain-DNS bootstrap resolution for encrypted upstreams.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use parking_lot::Mutex;
use rand::Rng;

use crate::error::{Result, UpstreamError};
use crate::plain::UdpTransport;
use crate::transport::Transport;

const CACHE_TTL: Duration = Duration::from_secs(300);

struct Entry {
    ips: Vec<IpAddr>,
    at: Instant,
}

/// Resolves hostnames through bootstrap servers with a short cache.
pub struct Bootstrap {
    servers: Vec<SocketAddr>,
    cache: Mutex<HashMap<String, Entry>>,
}

impl Bootstrap {
    /// Create with the given bootstrap servers (e.g. `1.1.1.1:53`). Falls back
    /// to Cloudflare + Google if the list is empty.
    pub fn new(mut servers: Vec<SocketAddr>) -> Self {
        if servers.is_empty() {
            servers = vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()];
        }
        Self {
            servers,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `host` to one or more IP addresses. IP literals are returned
    /// as-is.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if let Some(ips) = self.cached(host) {
            return Ok(ips);
        }

        let mut ips = Vec::new();
        for rtype in [RecordType::A, RecordType::AAAA] {
            if let Ok(found) = self.lookup(host, rtype).await {
                ips.extend(found);
            }
        }
        if ips.is_empty() {
            return Err(UpstreamError::Bootstrap(host.to_string()));
        }
        self.cache.lock().insert(
            host.to_string(),
            Entry {
                ips: ips.clone(),
                at: Instant::now(),
            },
        );
        Ok(ips)
    }

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock();
        let e = cache.get(host)?;
        if e.at.elapsed() < CACHE_TTL {
            Some(e.ips.clone())
        } else {
            None
        }
    }

    async fn lookup(&self, host: &str, rtype: RecordType) -> Result<Vec<IpAddr>> {
        // Echoed response questions are fully qualified.
        let mut name = Name::from_str(host).map_err(|e| UpstreamError::Proto(e.to_string()))?;
        name.set_fqdn(true);
        let mut msg = Message::new(rand::rng().random(), MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let mut q = Query::query(name, rtype);
        q.set_query_class(DNSClass::IN);
        msg.queries.push(q);

        let mut last_err = UpstreamError::Bootstrap(host.to_string());
        for server in &self.servers {
            let udp = UdpTransport::new(*server);
            match tokio::time::timeout(Duration::from_secs(5), udp.query(&msg)).await {
                Ok(Ok(resp)) => {
                    let ips = extract_ips(&resp);
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
                Ok(Err(e)) => last_err = e,
                Err(_) => last_err = UpstreamError::Timeout,
            }
        }
        Err(last_err)
    }
}

fn extract_ips(msg: &Message) -> Vec<IpAddr> {
    msg.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

/// Shared bootstrap handle.
pub type SharedBootstrap = Arc<Bootstrap>;
