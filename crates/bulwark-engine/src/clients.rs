//! Client identification & naming.
//!
//! Maps a source IP to a configured client (name + tags + per-client filtering
//! toggle), matching by exact IP or CIDR range.

use std::net::IpAddr;

use bulwark_config::ClientConfig;
use ipnet::IpNet;

struct ClientEntry {
    name: String,
    nets: Vec<IpNet>,
    tags: Vec<String>,
    filtering_enabled: bool,
}

/// A resolved client for a request.
#[derive(Debug, Clone)]
pub struct ResolvedClient {
    pub ip: IpAddr,
    /// Friendly name, if the IP matched a configured client.
    pub name: Option<String>,
    pub tags: Vec<String>,
    pub filtering_enabled: bool,
}

impl ResolvedClient {
    /// Display label: the configured name, else the IP string.
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.ip.to_string())
    }
}

/// Matches source IPs to configured clients.
#[derive(Default)]
pub struct ClientMatcher {
    entries: Vec<ClientEntry>,
}

impl ClientMatcher {
    /// Build from configured clients. Invalid id strings are skipped.
    pub fn build(clients: &[ClientConfig]) -> Self {
        let mut entries = Vec::new();
        for c in clients {
            let mut nets = Vec::new();
            for id in &c.ids {
                if let Ok(net) = id.parse::<IpNet>() {
                    nets.push(net);
                } else if let Ok(ip) = id.parse::<IpAddr>() {
                    // Single IP -> host route.
                    let net = match ip {
                        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
                    };
                    nets.push(net);
                }
            }
            entries.push(ClientEntry {
                name: c.name.clone(),
                nets,
                tags: c.tags.clone(),
                filtering_enabled: c.filtering_enabled,
            });
        }
        Self { entries }
    }

    /// Identify the client behind `ip`. Unknown IPs resolve to an unnamed client
    /// with filtering enabled.
    pub fn identify(&self, ip: IpAddr) -> ResolvedClient {
        for e in &self.entries {
            if e.nets.iter().any(|n| n.contains(&ip)) {
                return ResolvedClient {
                    ip,
                    name: Some(e.name.clone()),
                    tags: e.tags.clone(),
                    filtering_enabled: e.filtering_enabled,
                };
            }
        }
        ResolvedClient {
            ip,
            name: None,
            tags: Vec::new(),
            filtering_enabled: true,
        }
    }

    /// The configured name for `ip`, if it matches a client. Borrows from the
    /// matcher (no allocation). Used to resolve display names at read time so a
    /// rename or removal in the client config applies retroactively.
    pub fn name_for(&self, ip: IpAddr) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.nets.iter().any(|n| n.contains(&ip)))
            .map(|e| e.name.as_str())
    }

    /// Resolve a stored client-IP string to its current configured name, if any.
    /// Convenience over [`name_for`](Self::name_for) for data (stats, query log)
    /// that holds the client IP as a string.
    pub fn name_for_str(&self, ip: &str) -> Option<&str> {
        ip.parse::<IpAddr>().ok().and_then(|ip| self.name_for(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, ids: &[&str], tags: &[&str]) -> ClientConfig {
        ClientConfig {
            name: name.into(),
            ids: ids.iter().map(|s| s.to_string()).collect(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            filtering_enabled: true,
        }
    }

    #[test]
    fn matches_exact_ip_and_cidr() {
        let m = ClientMatcher::build(&[
            cfg("laptop", &["192.168.1.10"], &["trusted"]),
            cfg("guests", &["10.0.0.0/8"], &["device_guest"]),
        ]);
        assert_eq!(
            m.identify("192.168.1.10".parse().unwrap()).name.as_deref(),
            Some("laptop")
        );
        assert_eq!(
            m.identify("10.5.6.7".parse().unwrap()).name.as_deref(),
            Some("guests")
        );
        assert_eq!(m.identify("8.8.8.8".parse().unwrap()).name, None);
    }

    #[test]
    fn unknown_client_defaults_to_filtering_on() {
        let m = ClientMatcher::default();
        let c = m.identify("1.2.3.4".parse().unwrap());
        assert!(c.filtering_enabled);
        assert_eq!(c.label(), "1.2.3.4");
    }
}
