use anyhow::{anyhow, Context, Result};
use goodbyedpi_proto::Config as ProtoConfig;

#[derive(Debug, Clone)]
pub struct DpiConfig {
    pub split_pos: Option<usize>,
    pub oob_positions: Vec<usize>,
    pub fake_offset: Option<isize>,
    pub tlsrec_pos: Option<usize>,
    pub auto_rst: bool,
    pub auto_redirect: bool,
    pub auto_ssl: bool,
    pub ip_fragment: bool,     /* Enable IP fragmentation for QUIC/UDP */
    pub frag_size: u16,        /* Fragment size (0 = default 8 bytes) */
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
        };

        let tokens = s.split_whitespace();

        for token in tokens {
            if token.is_empty() {
                continue;
            }

            // Handle short form without dash (e.g., "s1", "o1")
            let (prefix, rest) = if token.starts_with('-') {
                (&token[..2], &token[2..])
            } else {
                (&token[..1], &token[1..])
            };

            match prefix {
                "s" | "-s" => {
                    let pos: usize = rest.parse()
                        .with_context(|| format!(
                            "Invalid split position in token '{}'. \
                             Expected a positive number (e.g., 's1' or '-s10'), got '{}'.",
                            token, rest
                        ))?;
                    config.split_pos = Some(pos);
                }
                "o" | "-o" => {
                    let pos: usize = rest.parse()
                        .with_context(|| format!(
                            "Invalid OOB (Out-of-Band) position in token '{}'. \
                             Expected a positive number (e.g., 'o1' or '-o5'), got '{}'.",
                            token, rest
                        ))?;
                    config.oob_positions.push(pos);
                }
                "f" | "-f" => {
                    let offset: isize = rest.parse()
                        .with_context(|| format!(
                            "Invalid fake offset in token '{}'. \
                             Expected a number (e.g., 'f-1' or '-f10'), got '{}'.",
                            token, rest
                        ))?;
                    config.fake_offset = Some(offset);
                }
                "r" | "-r" => {
                    // TLS record split: format like "1+s" or just "1"
                    if rest.contains("+s") {
                        let num: usize = rest.split("+s").next().unwrap().parse()
                            .with_context(|| format!(
                                "Invalid TLS record position in token '{}'. \
                                 Expected format 'N+s' where N is a number (e.g., 'r1+s'), got '{}'.",
                                token, rest
                            ))?;
                        config.tlsrec_pos = Some(num);
                    } else {
                        let pos: usize = rest.parse()
                            .with_context(|| format!(
                                "Invalid TLS record position in token '{}'. \
                                 Expected a positive number or 'N+s' format (e.g., 'r1' or 'r1+s'), got '{}'.",
                                token, rest
                            ))?;
                        config.tlsrec_pos = Some(pos);
                    }
                }
                "-A" => {
                    match rest {
                        "r" | "rst" => config.auto_rst = true,
                        "t" | "redirect" => config.auto_redirect = true,
                        "s" | "ssl" => config.auto_ssl = true,
                        _ => return Err(anyhow!(
                            "Unknown auto flag '{}' in token '{}'. \
                             Valid flags are: 'r' (rst), 't' (redirect), 's' (ssl). \
                             Example: -Ar -At -As",
                            rest, token
                        )),
                    }
                }
                "g" | "-g" => {
                    /* IP Fragmentation for QUIC/UDP - format: g or g8 for 8-byte fragments */
                    if rest.is_empty() {
                        config.ip_fragment = true;
                        config.frag_size = 8; /* Default 8 bytes */
                    } else {
                        let size: u16 = rest.parse()
                            .with_context(|| format!(
                                "Invalid fragment size in token '{}'. \
                                 Expected a positive number (e.g., 'g8' or '-g16'), got '{}'.",
                                token, rest
                            ))?;
                        config.ip_fragment = true;
                        /* Minimum 8 bytes, maximum 1500 to avoid issues */
                        config.frag_size = size.clamp(8, 1500);
                    }
                }
                _ => return Err(anyhow!(
                    "Unknown option '{}' in token '{}'. \
                     Valid options: s (split), o (oob), f (fake), r (tlsrec), g (fragment), -A (auto). \
                     Example: 's1 -o1 -Ar -f-1 -r1+s -g8'",
                    prefix, token
                )),
            }
        }

        Ok(config)
    }

    pub fn to_proto(&self) -> ProtoConfig {
        ProtoConfig {
            split_pos: self.split_pos.map(|p| p as i32).unwrap_or(-1),
            oob_pos: self.oob_positions.first().map(|p| *p as i32).unwrap_or(-1),
            fake_offset: self.fake_offset.unwrap_or(0) as i32,
            tlsrec_pos: self.tlsrec_pos.map(|p| p as i32).unwrap_or(-1),
            auto_rst: self.auto_rst,
            auto_redirect: self.auto_redirect,
            auto_ssl: self.auto_ssl,
            ip_fragment: self.ip_fragment as u8,
            frag_size: self.frag_size,
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
        
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &proto as *const _ as *const u8,
                size
            )
        };
        Ok(bytes.to_vec())
    }
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
        assert!(result.unwrap_err().to_string().contains("Invalid split position"));
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
        assert!(result.unwrap_err().to_string().contains("Invalid fake offset"));
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
        assert!(result.unwrap_err().to_string().contains("Unknown auto flag"));
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
}
