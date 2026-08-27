//! Client identification by IP or CIDR.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use bulwark_config::ClientConfig;
use ipnet::IpNet;

struct ClientEntry {
    name: Arc<str>,
    nets: Vec<IpNet>,
    tags: Arc<[String]>,
    filtering_enabled: bool,
}

/// Client settings resolved for a request.
#[derive(Debug, Clone)]
pub struct ResolvedClient {
    pub ip: IpAddr,
    /// Friendly name, if the IP matched a configured client.
    pub name: Option<Arc<str>>,
    pub tags: Arc<[String]>,
    pub filtering_enabled: bool,
}

impl ResolvedClient {
    /// Returns the configured name or IP address.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) => name.to_string(),
            None => self.ip.to_string(),
        }
    }
}

/// Matches source IPs to client configuration.
#[derive(Default)]
pub struct ClientMatcher {
    /// Exact `/32` and `/128` matches.
    hosts: HashMap<IpAddr, usize>,
    entries: Vec<ClientEntry>,
    empty_tags: Arc<[String]>,
}

impl ClientMatcher {
    /// Build from configured clients. Invalid id strings are skipped.
    pub fn build(clients: &[ClientConfig]) -> Self {
        let mut entries = Vec::new();
        let mut hosts: HashMap<IpAddr, usize> = HashMap::new();
        for c in clients {
            let idx = entries.len();
            let mut nets = Vec::new();
            for id in &c.ids {
                if let Ok(ip) = id.parse::<IpAddr>() {
                    hosts.entry(ip).or_insert(idx);
                } else if let Ok(net) = id.parse::<IpNet>() {
                    nets.push(net);
                }
            }
            entries.push(ClientEntry {
                name: Arc::from(c.name.as_str()),
                nets,
                tags: Arc::from(c.tags.as_slice()),
                filtering_enabled: c.filtering_enabled,
            });
        }
        Self {
            hosts,
            entries,
            empty_tags: Arc::from(Vec::new()),
        }
    }

    /// Finds the longest-prefix CIDR match; config order breaks ties.
    fn best_match(&self, ip: IpAddr) -> Option<&ClientEntry> {
        if let Some(&idx) = self.hosts.get(&ip) {
            return Some(&self.entries[idx]);
        }
        let mut best: Option<(u8, &ClientEntry)> = None;
        for e in &self.entries {
            if let Some(plen) = e
                .nets
                .iter()
                .filter(|n| n.contains(&ip))
                .map(|n| n.prefix_len())
                .max()
            {
                if best.is_none_or(|(b, _)| plen > b) {
                    best = Some((plen, e));
                }
            }
        }
        best.map(|(_, e)| e)
    }

    /// Identify the client behind `ip`. Unknown IPs resolve to an unnamed client
    /// with filtering enabled.
    pub fn identify(&self, ip: IpAddr) -> ResolvedClient {
        match self.best_match(ip) {
            Some(e) => ResolvedClient {
                ip,
                name: Some(e.name.clone()),
                tags: e.tags.clone(),
                filtering_enabled: e.filtering_enabled,
            },
            None => ResolvedClient {
                ip,
                name: None,
                tags: self.empty_tags.clone(),
                filtering_enabled: true,
            },
        }
    }

    /// Returns the configured name for an IP.
    pub fn name_for(&self, ip: IpAddr) -> Option<&str> {
        self.best_match(ip).map(|e| e.name.as_ref())
    }

    /// Returns the configured name for a stored IP string.
    pub fn name_for_str(&self, ip: &str) -> Option<&str> {
        ip.parse::<IpAddr>().ok().and_then(|ip| self.name_for(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, ids: &[&str], tags: &[&str]) -> ClientConfig {
        ClientConfig {
            id: name.into(),
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
    fn longest_prefix_wins_over_config_order() {
        let m = ClientMatcher::build(&[
            ClientConfig {
                filtering_enabled: false,
                ..cfg("lan", &["10.0.0.0/8"], &["broad"])
            },
            cfg("server", &["10.1.2.3"], &["specific"]),
        ]);
        let c = m.identify("10.1.2.3".parse().unwrap());
        assert_eq!(c.name.as_deref(), Some("server"));
        assert!(c.filtering_enabled, "specific entry's policy applies");
        assert_eq!(
            m.identify("10.9.9.9".parse().unwrap()).name.as_deref(),
            Some("lan")
        );
    }

    #[test]
    fn unknown_client_defaults_to_filtering_on() {
        let m = ClientMatcher::default();
        let c = m.identify("1.2.3.4".parse().unwrap());
        assert!(c.filtering_enabled);
        assert_eq!(c.label(), "1.2.3.4");
    }
}
