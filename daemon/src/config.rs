use anyhow::{anyhow, Context, Result};
use goodbyedpi_proto::Event;
use goodbyedpi_proto::{
    Config as ProtoConfig, PortRange, Rule as RuleConfig, RuleAction, RuleProtocol,
};
use std::fmt;

use crate::rules::{parse_hostlist, parse_ipset, target_lists_allow_event, HostPattern, IpNetwork};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct FakeProfiles {
    pub quic: Option<Vec<u8>>,
    pub discord: Option<Vec<u8>>,
    pub stun: Option<Vec<u8>>,
}

impl fmt::Debug for FakeProfiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeProfiles")
            .field("quic_len", &self.quic.as_ref().map(Vec::len))
            .field("discord_len", &self.discord.as_ref().map(Vec::len))
            .field("stun_len", &self.stun.as_ref().map(Vec::len))
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
struct RuleDraft {
    proto: Option<RuleProtocol>,
    ports: Vec<PortRange>,
    action: Option<RuleAction>,
    repeats: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpiConfig {
    pub split_pos: Option<usize>,
    pub oob_positions: Vec<usize>,
    pub fake_offset: Option<isize>,
    pub tlsrec_pos: Option<i32>,
    pub auto_rst: bool,
    pub auto_redirect: bool,
    pub auto_ssl: bool,
    pub ip_fragment: bool,  /* Enable IP fragmentation for QUIC/UDP */
    pub frag_size: u16,     /* Fragment size (0 = default 8 bytes) */
    pub use_disorder: bool, /* Enable packet disorder technique */
    pub bpf_printk: bool,   /* Enable bpf_printk debug logs */
    pub filter_tcp: Vec<PortRange>,
    pub filter_udp: Vec<PortRange>,
    pub hostlist: Vec<HostPattern>,
    pub hostlist_exclude: Vec<HostPattern>,
    pub ipset: Vec<IpNetwork>,
    pub ipset_exclude: Vec<IpNetwork>,
    pub fake_profiles: FakeProfiles,
    pub rules: Vec<RuleConfig>,
}

impl DpiConfig {
    pub fn parse(s: &str) -> Result<Self> {
        let mut config = DpiConfig {
            split_pos: None,
            oob_positions: Vec::new(),
            fake_offset: None,
            tlsrec_pos: None,
            auto_rst: false,
            auto_redirect: false,
            auto_ssl: false,
            ip_fragment: false,
            frag_size: 0,
            use_disorder: false,
            bpf_printk: false,
            filter_tcp: Vec::new(),
            filter_udp: Vec::new(),
            hostlist: Vec::new(),
            hostlist_exclude: Vec::new(),
            ipset: Vec::new(),
            ipset_exclude: Vec::new(),
            fake_profiles: FakeProfiles::default(),
            rules: Vec::new(),
        };

        let mut tokens = s.split_whitespace().peekable();
        let mut current_rule: Option<RuleDraft> = None;

        while let Some(token) = tokens.next() {
            if token.is_empty() {
                continue;
            }

            if token == "--new" {
                if let Some(draft) = current_rule.take() {
                    config.rules.push(finalize_rule(draft)?);
                }
                current_rule = Some(RuleDraft::default());
                continue;
            }

            if let Some(consumed) = parse_global_filter_token(token, &mut tokens, &mut config)? {
                if consumed {
                    continue;
                }
            }

            if let Some(ref mut draft) = current_rule {
                if parse_rule_token(token, &mut tokens, draft)? {
                    continue;
                }
            }

            parse_legacy_token(token, &mut config)?;
        }

        if let Some(draft) = current_rule.take() {
            config.rules.push(finalize_rule(draft)?);
        }

        Ok(config)
    }

    pub fn to_proto(&self) -> ProtoConfig {
        ProtoConfig {
            split_pos: self.split_pos.map(|p| p as i32).unwrap_or(-1),
            oob_pos: self.oob_positions.first().map(|p| *p as i32).unwrap_or(-1),
            fake_offset: self.fake_offset.unwrap_or(0) as i32,
            tlsrec_pos: self.tlsrec_pos.unwrap_or(-1),
            auto_rst: self.auto_rst,
            auto_redirect: self.auto_redirect,
            auto_ssl: self.auto_ssl,
            ip_fragment: self.ip_fragment as u8,
            frag_size: self.frag_size,
            disorder: self.use_disorder,
            bpf_printk: self.bpf_printk,
        }
    }

    /// Convert config to bytes for BPF map
    ///
    /// # Safety
    /// This uses unsafe code to reinterpret the struct as bytes.
    /// The struct is repr(C) and should match the eBPF struct layout.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let proto = self.to_proto();
        let size = std::mem::size_of::<ProtoConfig>();

        if size == 0 {
            return Err(anyhow!(
                "Invalid ProtoConfig size (0 bytes). This is likely a bug in the protocol definitions."
            ));
        }

        let bytes = unsafe { std::slice::from_raw_parts(&proto as *const _ as *const u8, size) };
        Ok(bytes.to_vec())
    }

    /// Returns true when destination TCP port passes global filter.
    /// Empty filter means allow all.
    pub fn tcp_port_allowed(&self, port: u16) -> bool {
        port_allowed(&self.filter_tcp, port)
    }

    /// Returns true when destination UDP port passes global filter.
    /// Empty filter means allow all.
    pub fn udp_port_allowed(&self, port: u16) -> bool {
        port_allowed(&self.filter_udp, port)
    }

    /// Returns true when host/ip list targeting allows this event.
    /// If all include-lists are empty, event is allowed by default.
    pub fn target_allowed(&self, event: &Event) -> bool {
        target_lists_allow_event(
            event,
            &self.hostlist,
            &self.hostlist_exclude,
            &self.ipset,
            &self.ipset_exclude,
        )
    }
}

fn port_allowed(ranges: &[PortRange], port: u16) -> bool {
    if ranges.is_empty() {
        return true;
    }
    ranges.iter().any(|range| range.contains(port))
}

fn parse_global_filter_token<'a, I>(
    token: &str,
    tokens: &mut std::iter::Peekable<I>,
    config: &mut DpiConfig,
) -> Result<Option<bool>>
where
    I: Iterator<Item = &'a str>,
{
    if let Some(value) = parse_long_option_value("--filter-tcp", token, tokens) {
        let value = value?;
        config.filter_tcp = parse_ports(&value)?;
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--filter-udp", token, tokens) {
        let value = value?;
        config.filter_udp = parse_ports(&value)?;
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--hostlist", token, tokens) {
        let value = value?;
        config.hostlist = parse_hostlist(&value)?;
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--hostlist-exclude", token, tokens) {
        let value = value?;
        config.hostlist_exclude = parse_hostlist(&value)?;
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--ipset", token, tokens) {
        let value = value?;
        config.ipset = parse_ipset(&value)?;
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--ipset-exclude", token, tokens) {
        let value = value?;
        config.ipset_exclude = parse_ipset(&value)?;
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--fake-quic", token, tokens) {
        let value = value?;
        config.fake_profiles.quic = Some(load_fake_payload(&value)?);
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--fake-discord", token, tokens) {
        let value = value?;
        config.fake_profiles.discord = Some(load_fake_payload(&value)?);
        return Ok(Some(true));
    }
    if let Some(value) = parse_long_option_value("--fake-stun", token, tokens) {
        let value = value?;
        config.fake_profiles.stun = Some(load_fake_payload(&value)?);
        return Ok(Some(true));
    }
    Ok(None)
}

fn load_fake_payload(path: &str) -> Result<Vec<u8>> {
    const MAX_FAKE_PROFILE_SIZE: usize = 64 * 1024;

    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read fake payload file '{}'", path))?;
    if bytes.is_empty() {
        return Err(anyhow!("Fake payload file '{}' is empty", path));
    }
    if bytes.len() > MAX_FAKE_PROFILE_SIZE {
        return Err(anyhow!(
            "Fake payload file '{}' is too large: {} bytes (max {})",
            path,
            bytes.len(),
            MAX_FAKE_PROFILE_SIZE
        ));
    }
    Ok(bytes)
}

fn parse_legacy_token(token: &str, config: &mut DpiConfig) -> Result<()> {
    // Handle short form without dash (e.g., "s1", "o1")
    let (prefix, rest) = if token.starts_with('-') {
        if token.len() < 2 {
            return Err(anyhow!("Invalid option '{}'", token));
        }
        (&token[..2], &token[2..])
    } else {
        if token.is_empty() {
            return Ok(());
        }
        (&token[..1], &token[1..])
    };

    match prefix {
        "s" | "-s" => {
            let pos: usize = rest.parse().with_context(|| {
                format!(
                    "Invalid split position in token '{}'. \
                     Expected a positive number (e.g., 's1' or '-s10'), got '{}'.",
                    token, rest
                )
            })?;
            config.split_pos = Some(pos);
        }
        "o" | "-o" => {
            let pos: usize = rest.parse().with_context(|| {
                format!(
                    "Invalid OOB (Out-of-Band) position in token '{}'. \
                     Expected a positive number (e.g., 'o1' or '-o5'), got '{}'.",
                    token, rest
                )
            })?;
            config.oob_positions.push(pos);
        }
        "f" | "-f" => {
            let offset: isize = rest.parse().with_context(|| {
                format!(
                    "Invalid fake offset in token '{}'. \
                     Expected a number (e.g., 'f-1' or '-f10'), got '{}'.",
                    token, rest
                )
            })?;
            config.fake_offset = Some(offset);
        }
        "r" | "-r" => {
            // TLS record split:
            //   rN+s  -> offset from SNI start (legacy syntax)
            //   rN    -> signed offset (negative means from SNI end)
            if rest.contains("+s") {
                let num: i32 = rest.split("+s").next().unwrap().parse().with_context(|| {
                    format!(
                        "Invalid TLS record position in token '{}'. \
                         Expected format 'N+s' where N is a signed number (e.g., 'r1+s' or 'r-2+s'), got '{}'.",
                        token, rest
                    )
                })?;
                config.tlsrec_pos = Some(num);
            } else {
                let pos: i32 = rest.parse().with_context(|| {
                    format!(
                        "Invalid TLS record position in token '{}'. \
                         Expected a signed number or 'N+s' format (e.g., 'r1', 'r-2', or 'r1+s'), got '{}'.",
                        token, rest
                    )
                })?;
                config.tlsrec_pos = Some(pos);
            }
        }
        "-A" => match rest {
            "r" | "rst" => config.auto_rst = true,
            "t" | "redirect" => config.auto_redirect = true,
            "s" | "ssl" => config.auto_ssl = true,
            _ => {
                return Err(anyhow!(
                    "Unknown auto flag '{}' in token '{}'. \
                     Valid flags are: 'r' (rst), 't' (redirect), 's' (ssl). \
                     Example: -Ar -At -As",
                    rest,
                    token
                ))
            }
        },
        "g" | "-g" => {
            /* IP Fragmentation for QUIC/UDP - format: g or g8 for 8-byte fragments */
            if rest.is_empty() {
                config.ip_fragment = true;
                config.frag_size = 8; /* Default 8 bytes */
            } else {
                let size: u16 = rest.parse().with_context(|| {
                    format!(
                        "Invalid fragment size in token '{}'. \
                         Expected a positive number (e.g., 'g8' or '-g16'), got '{}'.",
                        token, rest
                    )
                })?;
                config.ip_fragment = true;
                /* Minimum 8 bytes, maximum 1500 to avoid issues */
                config.frag_size = size.clamp(8, 1500);
            }
        }
        "d" | "-d" => {
            /* Packet disorder - enable sending packets out of order */
            config.use_disorder = true;
        }
        _ => {
            return Err(anyhow!(
                "Unknown option '{}' in token '{}'. \
                 Valid options: s (split), o (oob), f (fake), r (tlsrec), g (fragment), d (disorder), -A (auto), --new/--proto/--ports/--action/--repeats, --filter-tcp/--filter-udp, --hostlist/--hostlist-exclude, --ipset/--ipset-exclude, --fake-quic/--fake-discord/--fake-stun. \
                 Example: 's1 -o1 -Ar -f-1 -r1+s -g8 -d --filter-tcp=443 --hostlist=googlevideo.com --fake-quic=/path/fake.bin --new --proto=tcp --ports=443 --action=split --repeats=2'",
                prefix, token
            ))
        }
    }

    Ok(())
}

fn parse_rule_token<'a, I>(
    token: &str,
    tokens: &mut std::iter::Peekable<I>,
    rule: &mut RuleDraft,
) -> Result<bool>
where
    I: Iterator<Item = &'a str>,
{
    if let Some(value) = parse_long_option_value("--proto", token, tokens) {
        let value = value?;
        rule.proto = Some(
            RuleProtocol::from_cli(&value)
                .ok_or_else(|| anyhow!("Invalid --proto '{}'. Expected 'tcp' or 'udp'", value))?,
        );
        return Ok(true);
    }

    if let Some(value) = parse_long_option_value("--ports", token, tokens) {
        let value = value?;
        rule.ports = parse_ports(&value)?;
        return Ok(true);
    }

    if let Some(value) = parse_long_option_value("--action", token, tokens) {
        let value = value?;
        rule.action = Some(RuleAction::from_cli(&value).ok_or_else(|| {
            anyhow!(
                "Invalid --action '{}'. Expected one of: split,oob,fake,tlsrec,disorder,frag",
                value
            )
        })?);
        return Ok(true);
    }

    if let Some(value) = parse_long_option_value("--repeats", token, tokens) {
        let value = value?;
        let repeats: u8 = value.parse().with_context(|| {
            format!("Invalid --repeats '{}'. Expected integer in 1..=255", value)
        })?;
        if repeats == 0 {
            return Err(anyhow!("Invalid --repeats '{}'. Value must be >= 1", value));
        }
        rule.repeats = Some(repeats);
        return Ok(true);
    }

    Ok(false)
}

fn finalize_rule(draft: RuleDraft) -> Result<RuleConfig> {
    let action = draft
        .action
        .ok_or_else(|| anyhow!("Rule after --new must include --action"))?;
    let proto = draft.proto.unwrap_or_else(|| action.default_protocol());
    let repeats = draft.repeats.unwrap_or(1);

    Ok(RuleConfig {
        proto,
        ports: draft.ports,
        action,
        repeats,
    })
}

fn parse_ports(raw: &str) -> Result<Vec<PortRange>> {
    let mut ranges = Vec::new();

    for chunk in raw.split(',') {
        let part = chunk.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u16 = start_s
                .parse()
                .with_context(|| format!("Invalid port range start '{}'", start_s))?;
            let end: u16 = end_s
                .parse()
                .with_context(|| format!("Invalid port range end '{}'", end_s))?;
            if start > end {
                return Err(anyhow!(
                    "Invalid port range '{}': start must be <= end",
                    part
                ));
            }
            ranges.push(PortRange::new(start, end));
        } else {
            let port: u16 = part
                .parse()
                .with_context(|| format!("Invalid port '{}'", part))?;
            ranges.push(PortRange::new(port, port));
        }
    }

    Ok(ranges)
}

fn parse_long_option_value<'a, I>(
    option: &str,
    token: &str,
    tokens: &mut std::iter::Peekable<I>,
) -> Option<Result<String>>
where
    I: Iterator<Item = &'a str>,
{
    if token == option {
        return Some(
            tokens
                .next()
                .map(std::string::ToString::to_string)
                .ok_or_else(|| anyhow!("Option '{}' requires a value", option)),
        );
    }

    let prefix = format!("{option}=");
    if let Some(value) = token.strip_prefix(&prefix) {
        return Some(Ok(value.to_string()));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full() {
        let cfg = DpiConfig::parse("s1 -o1 -Ar -f-1 -r1+s -At -As").unwrap();
        assert_eq!(cfg.split_pos, Some(1));
        assert_eq!(cfg.oob_positions, vec![1]);
        assert_eq!(cfg.fake_offset, Some(-1));
        assert_eq!(cfg.tlsrec_pos, Some(1));
        assert!(cfg.auto_rst);
        assert!(cfg.auto_redirect);
        assert!(cfg.auto_ssl);
    }

    #[test]
    fn test_parse_multiple_oob() {
        let cfg = DpiConfig::parse("s1 -o1 -o5 -o10").unwrap();
        assert_eq!(cfg.oob_positions, vec![1, 5, 10]);
    }

    #[test]
    fn test_parse_simple() {
        let cfg = DpiConfig::parse("s2 -o5").unwrap();
        assert_eq!(cfg.split_pos, Some(2));
        assert_eq!(cfg.oob_positions, vec![5]);
        assert!(!cfg.auto_rst);
    }

    #[test]
    fn test_parse_empty() {
        let cfg = DpiConfig::parse("").unwrap();
        assert_eq!(cfg.split_pos, None);
        assert!(cfg.oob_positions.is_empty());
        assert_eq!(cfg.fake_offset, None);
        assert_eq!(cfg.tlsrec_pos, None);
        assert!(!cfg.auto_rst);
        assert!(!cfg.auto_redirect);
        assert!(!cfg.auto_ssl);
        assert!(!cfg.bpf_printk);
    }

    #[test]
    fn test_parse_whitespace_only() {
        let cfg = DpiConfig::parse("   \n\t  ").unwrap();
        assert_eq!(cfg.split_pos, None);
        assert!(cfg.oob_positions.is_empty());
    }

    #[test]
    fn test_parse_split_only() {
        let cfg = DpiConfig::parse("s100").unwrap();
        assert_eq!(cfg.split_pos, Some(100));
        assert!(cfg.oob_positions.is_empty());
        assert!(!cfg.auto_rst);
    }

    #[test]
    fn test_parse_short_form_dash() {
        let cfg = DpiConfig::parse("-s50 -o25").unwrap();
        assert_eq!(cfg.split_pos, Some(50));
        assert_eq!(cfg.oob_positions, vec![25]);
    }

    #[test]
    fn test_parse_tlsrec_without_s() {
        let cfg = DpiConfig::parse("r10").unwrap();
        assert_eq!(cfg.tlsrec_pos, Some(10));
    }

    #[test]
    fn test_parse_tlsrec_with_s() {
        let cfg = DpiConfig::parse("r5+s").unwrap();
        assert_eq!(cfg.tlsrec_pos, Some(5));
    }

    #[test]
    fn test_parse_negative_tlsrec_without_s() {
        let cfg = DpiConfig::parse("r-2").unwrap();
        assert_eq!(cfg.tlsrec_pos, Some(-2));
    }

    #[test]
    fn test_parse_negative_tlsrec_with_s() {
        let cfg = DpiConfig::parse("r-3+s").unwrap();
        assert_eq!(cfg.tlsrec_pos, Some(-3));
    }

    #[test]
    fn test_parse_negative_fake_offset() {
        let cfg = DpiConfig::parse("f-10").unwrap();
        assert_eq!(cfg.fake_offset, Some(-10));
    }

    #[test]
    fn test_parse_positive_fake_offset() {
        let cfg = DpiConfig::parse("f5").unwrap();
        assert_eq!(cfg.fake_offset, Some(5));
    }

    #[test]
    fn test_parse_auto_flags_variants() {
        // Long form variants
        let cfg = DpiConfig::parse("-Arst -Aredirect -Assl").unwrap();
        assert!(cfg.auto_rst);
        assert!(cfg.auto_redirect);
        assert!(cfg.auto_ssl);

        // Short form
        let cfg = DpiConfig::parse("-Ar -At -As").unwrap();
        assert!(cfg.auto_rst);
        assert!(cfg.auto_redirect);
        assert!(cfg.auto_ssl);
    }

    #[test]
    fn test_parse_invalid_split_position() {
        let result = DpiConfig::parse("sabc");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid split position"));
    }

    #[test]
    fn test_parse_invalid_oob_position() {
        let result = DpiConfig::parse("o-5");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_fake_offset() {
        let result = DpiConfig::parse("fxyz");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid fake offset"));
    }

    #[test]
    fn test_parse_unknown_option() {
        let result = DpiConfig::parse("-x10");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown option"));
    }

    #[test]
    fn test_parse_unknown_auto_flag() {
        let result = DpiConfig::parse("-Az");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown auto flag"));
    }

    #[test]
    fn test_parse_invalid_tlsrec() {
        let result = DpiConfig::parse("r+s");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_proto() {
        let cfg = DpiConfig::parse("s10 -o5 -f-1 -r20+s -Ar").unwrap();
        let proto = cfg.to_proto();
        assert_eq!(proto.split_pos, 10);
        assert_eq!(proto.oob_pos, 5);
        assert_eq!(proto.fake_offset, -1);
        assert_eq!(proto.tlsrec_pos, 20);
        assert!(proto.auto_rst);
        assert!(!proto.auto_redirect);
        assert!(!proto.auto_ssl);
    }

    #[test]
    fn test_to_proto_defaults() {
        let cfg = DpiConfig::parse("").unwrap();
        let proto = cfg.to_proto();
        assert_eq!(proto.split_pos, -1);
        assert_eq!(proto.oob_pos, -1);
        assert_eq!(proto.fake_offset, 0);
        assert_eq!(proto.tlsrec_pos, -1);
        assert!(!proto.auto_rst);
        assert!(!proto.auto_redirect);
        assert!(!proto.auto_ssl);
        assert!(!proto.bpf_printk);
    }

    #[test]
    fn test_to_bytes() {
        let cfg = DpiConfig::parse("s10 -o5").unwrap();
        let bytes = cfg.to_bytes().unwrap();
        // Should match the size of the C struct
        assert_eq!(bytes.len(), std::mem::size_of::<ProtoConfig>());
    }

    #[test]
    fn test_clone_config() {
        let cfg = DpiConfig::parse("s1 -o2 -Ar").unwrap();
        let cloned = cfg.clone();
        assert_eq!(cloned.split_pos, cfg.split_pos);
        assert_eq!(cloned.oob_positions, cfg.oob_positions);
        assert_eq!(cloned.fake_offset, cfg.fake_offset);
        assert_eq!(cloned.tlsrec_pos, cfg.tlsrec_pos);
        assert_eq!(cloned.auto_rst, cfg.auto_rst);
        assert_eq!(cloned.auto_redirect, cfg.auto_redirect);
        assert_eq!(cloned.auto_ssl, cfg.auto_ssl);
        assert_eq!(cloned.bpf_printk, cfg.bpf_printk);
        assert_eq!(cloned.filter_tcp, cfg.filter_tcp);
        assert_eq!(cloned.filter_udp, cfg.filter_udp);
        assert_eq!(cloned.hostlist, cfg.hostlist);
        assert_eq!(cloned.hostlist_exclude, cfg.hostlist_exclude);
        assert_eq!(cloned.ipset, cfg.ipset);
        assert_eq!(cloned.ipset_exclude, cfg.ipset_exclude);
        assert_eq!(cloned.fake_profiles, cfg.fake_profiles);
        assert_eq!(cloned.rules, cfg.rules);
    }

    #[test]
    fn test_parse_ip_fragment_default() {
        let cfg = DpiConfig::parse("g").unwrap();
        assert!(cfg.ip_fragment);
        assert_eq!(cfg.frag_size, 8); // Default 8 bytes
    }

    #[test]
    fn test_parse_ip_fragment_minimum() {
        // Values less than 8 should be clamped to 8
        let cfg = DpiConfig::parse("g1").unwrap();
        assert!(cfg.ip_fragment);
        assert_eq!(cfg.frag_size, 8); // Clamped to minimum 8 bytes
    }

    #[test]
    fn test_parse_ip_fragment_custom_size() {
        let cfg = DpiConfig::parse("g16").unwrap();
        assert!(cfg.ip_fragment);
        assert_eq!(cfg.frag_size, 16);
    }

    #[test]
    fn test_parse_ip_fragment_short_form() {
        let cfg = DpiConfig::parse("-g32").unwrap();
        assert!(cfg.ip_fragment);
        assert_eq!(cfg.frag_size, 32);
    }

    #[test]
    fn test_to_proto_with_fragment() {
        let cfg = DpiConfig::parse("s10 -g8 -Ar").unwrap();
        let proto = cfg.to_proto();
        assert_eq!(proto.split_pos, 10);
        assert_eq!(proto.ip_fragment, 1);
        assert_eq!(proto.frag_size, 8);
        assert!(proto.auto_rst);
    }

    #[test]
    fn test_parse_disorder_short_form() {
        let cfg = DpiConfig::parse("d").unwrap();
        assert!(cfg.use_disorder);
    }

    #[test]
    fn test_parse_disorder_long_form() {
        let cfg = DpiConfig::parse("-d").unwrap();
        assert!(cfg.use_disorder);
    }

    #[test]
    fn test_parse_disorder_with_other_options() {
        let cfg = DpiConfig::parse("s1 -o1 -d -Ar").unwrap();
        assert_eq!(cfg.split_pos, Some(1));
        assert_eq!(cfg.oob_positions, vec![1]);
        assert!(cfg.use_disorder);
        assert!(cfg.auto_rst);
    }

    #[test]
    fn test_disorder_default_disabled() {
        let cfg = DpiConfig::parse("s1 -o1").unwrap();
        assert!(!cfg.use_disorder);
    }

    #[test]
    fn test_clone_config_with_disorder() {
        let cfg = DpiConfig::parse("s1 -d -Ar").unwrap();
        let cloned = cfg.clone();
        assert_eq!(cloned.use_disorder, cfg.use_disorder);
        assert!(cloned.use_disorder);
    }

    #[test]
    fn test_to_proto_with_disorder() {
        let cfg = DpiConfig::parse("s1 -o1 -d -Ar").unwrap();
        let proto = cfg.to_proto();
        assert_eq!(proto.split_pos, 1);
        assert_eq!(proto.oob_pos, 1);
        assert!(proto.disorder);
        assert!(proto.auto_rst);
    }

    #[test]
    fn test_to_proto_disorder_disabled() {
        let cfg = DpiConfig::parse("s1 -o1 -Ar").unwrap();
        let proto = cfg.to_proto();
        assert!(!proto.disorder);
    }

    #[test]
    fn test_parse_rule_engine_single_rule() {
        let cfg = DpiConfig::parse(
            "--new --proto=tcp --ports=443,2053,1024-2048 --action=split --repeats=3",
        )
        .unwrap();
        assert_eq!(cfg.rules.len(), 1);
        let rule = &cfg.rules[0];
        assert_eq!(rule.proto, RuleProtocol::Tcp);
        assert_eq!(rule.action, RuleAction::Split);
        assert_eq!(rule.repeats, 3);
        assert_eq!(
            rule.ports,
            vec![
                PortRange::new(443, 443),
                PortRange::new(2053, 2053),
                PortRange::new(1024, 2048)
            ]
        );
    }

    #[test]
    fn test_parse_rule_engine_multiple_rules() {
        let cfg = DpiConfig::parse(
            "s1 -o1 --new --action=split --ports=443 --repeats=2 --new --proto=udp --action=frag --ports=443",
        )
        .unwrap();
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.split_pos, Some(1));
        assert_eq!(cfg.oob_positions, vec![1]);
        assert_eq!(cfg.rules[0].proto, RuleProtocol::Tcp);
        assert_eq!(cfg.rules[0].repeats, 2);
        assert_eq!(cfg.rules[1].proto, RuleProtocol::Udp);
        assert_eq!(cfg.rules[1].action, RuleAction::Frag);
    }

    #[test]
    fn test_parse_rule_engine_default_protocol_for_frag() {
        let cfg = DpiConfig::parse("--new --action=frag").unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].proto, RuleProtocol::Udp);
    }

    #[test]
    fn test_parse_rule_engine_requires_action() {
        let err = DpiConfig::parse("--new --proto=tcp").unwrap_err();
        assert!(err.to_string().contains("must include --action"));
    }

    #[test]
    fn test_parse_rule_engine_invalid_repeats() {
        let err = DpiConfig::parse("--new --action=split --repeats=0").unwrap_err();
        assert!(err.to_string().contains("Value must be >= 1"));
    }

    #[test]
    fn test_parse_filter_tcp_udp() {
        let cfg = DpiConfig::parse("--filter-tcp=443,2053,1024-65535 --filter-udp 443,50000-50010")
            .unwrap();
        assert_eq!(
            cfg.filter_tcp,
            vec![
                PortRange::new(443, 443),
                PortRange::new(2053, 2053),
                PortRange::new(1024, 65535)
            ]
        );
        assert_eq!(
            cfg.filter_udp,
            vec![PortRange::new(443, 443), PortRange::new(50000, 50010)]
        );
    }

    #[test]
    fn test_filter_port_allowed_semantics() {
        let cfg = DpiConfig::parse("--filter-tcp=443,8443-8444 --filter-udp=53").unwrap();

        assert!(cfg.tcp_port_allowed(443));
        assert!(cfg.tcp_port_allowed(8443));
        assert!(!cfg.tcp_port_allowed(80));

        assert!(cfg.udp_port_allowed(53));
        assert!(!cfg.udp_port_allowed(443));
    }

    #[test]
    fn test_parse_hostlist_and_ipset() {
        let cfg = DpiConfig::parse(
            "--hostlist=googlevideo.com,*.youtube.com --hostlist-exclude=blocked.youtube.com \
             --ipset=1.1.1.1,10.0.0.0/8 --ipset-exclude=10.10.10.10,2001:db8::/32",
        )
        .unwrap();
        assert_eq!(cfg.hostlist.len(), 2);
        assert_eq!(cfg.hostlist_exclude.len(), 1);
        assert_eq!(cfg.ipset.len(), 2);
        assert_eq!(cfg.ipset_exclude.len(), 2);
    }

    #[test]
    fn test_target_allow_semantics_from_lists() {
        let cfg = DpiConfig::parse("--hostlist=example.com --ipset=10.0.0.0/8").unwrap();

        let mut event = Event::default();
        event.payload_len = 100;
        event.sni_offset = 10;
        event.sni_length = 11;
        event.payload[10..21].copy_from_slice(b"example.com");
        event.dst_ip[0] = u32::from(std::net::Ipv4Addr::new(192, 0, 2, 10)).to_be();

        assert!(cfg.target_allowed(&event));

        let mut cfg_ex = cfg.clone();
        cfg_ex.hostlist_exclude = parse_hostlist("example.com").unwrap();
        assert!(!cfg_ex.target_allowed(&event));
    }

    #[test]
    fn test_parse_fake_profiles_from_files() {
        let tmp = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let quic_path = tmp.join(format!("gdb-fake-quic-{pid}-{nanos}.bin"));
        let discord_path = tmp.join(format!("gdb-fake-discord-{pid}-{nanos}.bin"));
        let stun_path = tmp.join(format!("gdb-fake-stun-{pid}-{nanos}.bin"));

        std::fs::write(&quic_path, [0xc3, 0xff, 0x00, 0x01]).unwrap();
        std::fs::write(&discord_path, b"discord-fake").unwrap();
        std::fs::write(&stun_path, [0x00, 0x01, 0x00, 0x20]).unwrap();

        let cfg = DpiConfig::parse(&format!(
            "--fake-quic={} --fake-discord={} --fake-stun={}",
            quic_path.display(),
            discord_path.display(),
            stun_path.display()
        ))
        .unwrap();

        assert_eq!(
            cfg.fake_profiles.quic.as_deref(),
            Some(&[0xc3, 0xff, 0x00, 0x01][..])
        );
        assert_eq!(
            cfg.fake_profiles.discord.as_deref(),
            Some(&b"discord-fake"[..])
        );
        assert_eq!(
            cfg.fake_profiles.stun.as_deref(),
            Some(&[0x00, 0x01, 0x00, 0x20][..])
        );

        let _ = std::fs::remove_file(quic_path);
        let _ = std::fs::remove_file(discord_path);
        let _ = std::fs::remove_file(stun_path);
    }
}
