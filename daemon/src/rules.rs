use anyhow::{anyhow, Context, Result};
use goodbyedpi_proto::{Event, MAX_PAYLOAD_SIZE};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    Exact(String),
    Suffix(String),
}

impl HostPattern {
    pub fn parse(raw: &str) -> Option<Self> {
        let value = normalize_host(raw)?;
        if let Some(suffix) = value.strip_prefix("*.") {
            if suffix.is_empty() {
                return None;
            }
            return Some(Self::Suffix(suffix.to_string()));
        }
        Some(Self::Exact(value))
    }

    pub fn matches(&self, host: &str) -> bool {
        let Some(host) = normalize_host(host) else {
            return false;
        };
        match self {
            Self::Exact(value) => host == *value || host.ends_with(&format!(".{value}")),
            Self::Suffix(suffix) => host.ends_with(&format!(".{suffix}")) || host == *suffix,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(anyhow!("Empty ipset entry"));
        }

        let (ip_part, prefix_part) = match raw.split_once('/') {
            Some((ip, prefix)) => (ip.trim(), Some(prefix.trim())),
            None => (raw, None),
        };

        let ip: IpAddr = ip_part
            .parse()
            .with_context(|| format!("Invalid IP '{}' in ipset", ip_part))?;

        match ip {
            IpAddr::V4(v4) => {
                let prefix = prefix_part
                    .map(|v| v.parse::<u8>())
                    .transpose()
                    .with_context(|| format!("Invalid IPv4 prefix in '{}'", raw))?
                    .unwrap_or(32);
                if prefix > 32 {
                    return Err(anyhow!("IPv4 prefix out of range in '{}'", raw));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Ok(Self::V4 {
                    network: u32::from(v4) & mask,
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                let prefix = prefix_part
                    .map(|v| v.parse::<u8>())
                    .transpose()
                    .with_context(|| format!("Invalid IPv6 prefix in '{}'", raw))?
                    .unwrap_or(128);
                if prefix > 128 {
                    return Err(anyhow!("IPv6 prefix out of range in '{}'", raw));
                }
                let raw = u128::from_be_bytes(v6.octets());
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Ok(Self::V6 {
                    network: raw & mask,
                    prefix,
                })
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, prefix }, IpAddr::V4(addr)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - *prefix)
                };
                (u32::from(addr) & mask) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(addr)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - *prefix)
                };
                (u128::from_be_bytes(addr.octets()) & mask) == *network
            }
            _ => false,
        }
    }
}

fn normalize_host(raw: &str) -> Option<String> {
    let lowered = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if lowered.is_empty() {
        None
    } else {
        Some(lowered)
    }
}

fn parse_list_source(raw: &str) -> Result<Vec<String>> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }

    if Path::new(value).exists() {
        let content = std::fs::read_to_string(value)
            .with_context(|| format!("Failed to read list file '{}'", value))?;
        let mut out = Vec::new();
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if !line.is_empty() {
                out.push(line.to_string());
            }
        }
        return Ok(out);
    }

    Ok(value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(std::string::ToString::to_string)
        .collect())
}

pub fn parse_hostlist(raw: &str) -> Result<Vec<HostPattern>> {
    parse_list_source(raw)?
        .into_iter()
        .map(|entry| {
            HostPattern::parse(&entry).ok_or_else(|| anyhow!("Invalid hostlist entry '{}'", entry))
        })
        .collect()
}

pub fn parse_ipset(raw: &str) -> Result<Vec<IpNetwork>> {
    parse_list_source(raw)?
        .into_iter()
        .map(|entry| IpNetwork::parse(&entry))
        .collect()
}

pub fn extract_target_host(event: &Event) -> Option<String> {
    extract_sni(event).or_else(|| extract_http_host(event))
}

pub fn target_lists_allow_event(
    event: &Event,
    hostlist: &[HostPattern],
    hostlist_exclude: &[HostPattern],
    ipset: &[IpNetwork],
    ipset_exclude: &[IpNetwork],
) -> bool {
    let dst_ip = if event.is_ipv6 != 0 {
        IpAddr::V6(event.dst_ip_v6())
    } else {
        IpAddr::V4(event.dst_ip_v4())
    };

    let host = extract_target_host(event);

    if let Some(ref host) = host {
        if hostlist_exclude.iter().any(|rule| rule.matches(host)) {
            return false;
        }
    }
    if ipset_exclude.iter().any(|rule| rule.contains(dst_ip)) {
        return false;
    }

    let has_include_filters = !hostlist.is_empty() || !ipset.is_empty();
    if !has_include_filters {
        return true;
    }

    let host_match = host
        .as_deref()
        .map(|h| hostlist.iter().any(|rule| rule.matches(h)))
        .unwrap_or(false);
    let ip_match = ipset.iter().any(|rule| rule.contains(dst_ip));

    host_match || ip_match
}

fn extract_sni(event: &Event) -> Option<String> {
    if event.sni_offset == 0 || event.sni_length == 0 {
        return None;
    }

    let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
    let start = event.sni_offset as usize;
    let end = start + event.sni_length as usize;
    if start >= payload_len || end > payload_len {
        return None;
    }

    let raw = std::str::from_utf8(&event.payload[start..end]).ok()?;
    normalize_host(raw)
}

fn extract_http_host(event: &Event) -> Option<String> {
    let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
    if payload_len == 0 {
        return None;
    }

    let payload = std::str::from_utf8(&event.payload[..payload_len]).ok()?;
    for line in payload.lines() {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        let mut parts = line.splitn(2, ':');
        let header = parts.next()?.trim();
        if !header.eq_ignore_ascii_case("host") {
            continue;
        }
        let value = parts.next()?.trim();
        let host_only = value.split(':').next().unwrap_or(value);
        return normalize_host(host_only);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use goodbyedpi_proto::Event;

    #[test]
    fn test_host_pattern_exact_and_subdomain() {
        let p = HostPattern::parse("example.com").unwrap();
        assert!(p.matches("example.com"));
        assert!(p.matches("www.example.com"));
        assert!(!p.matches("example.org"));
    }

    #[test]
    fn test_host_pattern_wildcard() {
        let p = HostPattern::parse("*.googlevideo.com").unwrap();
        assert!(p.matches("rr1---sn.googlevideo.com"));
        assert!(p.matches("googlevideo.com"));
        assert!(!p.matches("youtube.com"));
    }

    #[test]
    fn test_ip_network_contains() {
        let net = IpNetwork::parse("192.168.10.0/24").unwrap();
        assert!(net.contains("192.168.10.42".parse().unwrap()));
        assert!(!net.contains("192.168.11.1".parse().unwrap()));

        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:dead::1".parse().unwrap()));
    }

    #[test]
    fn test_extract_host_from_sni() {
        let mut event = Event::default();
        let sni = b"example.com";
        let offset = 20usize;
        event.payload[offset..offset + sni.len()].copy_from_slice(sni);
        event.payload_len = 128;
        event.sni_offset = offset as u16;
        event.sni_length = sni.len() as u16;

        assert_eq!(extract_target_host(&event).as_deref(), Some("example.com"));
    }

    #[test]
    fn test_extract_host_from_http_host_header() {
        let mut event = Event::default();
        let req = b"GET / HTTP/1.1\r\nHost: YouTube.com:443\r\nUser-Agent: x\r\n\r\n";
        event.payload[..req.len()].copy_from_slice(req);
        event.payload_len = req.len() as u16;
        assert_eq!(extract_target_host(&event).as_deref(), Some("youtube.com"));
    }

    #[test]
    fn test_target_lists_semantics() {
        let mut event = Event::default();
        event.dst_ip[0] = u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4)).to_be();
        event.payload_len = 40;
        let host = b"blocked.example";
        event.sni_offset = 5;
        event.sni_length = host.len() as u16;
        event.payload[5..5 + host.len()].copy_from_slice(host);

        let include_hosts = parse_hostlist("other.example").unwrap();
        let exclude_hosts = parse_hostlist("blocked.example").unwrap();
        let include_ips = parse_ipset("1.2.3.0/24").unwrap();
        let exclude_ips = parse_ipset("1.2.3.4").unwrap();

        assert!(!target_lists_allow_event(
            &event,
            &include_hosts,
            &[],
            &[],
            &[]
        ));
        assert!(!target_lists_allow_event(
            &event,
            &[],
            &exclude_hosts,
            &[],
            &[]
        ));
        assert!(!target_lists_allow_event(
            &event,
            &[],
            &[],
            &include_ips,
            &exclude_ips
        ));
        assert!(target_lists_allow_event(
            &event,
            &[],
            &[],
            &include_ips,
            &[]
        ));
    }
}
