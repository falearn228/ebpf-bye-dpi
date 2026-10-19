//! Человекочитаемое описание и статические проверки (lint) разобранного профиля.
//!
//! Парсер в `config.rs` ловит синтаксические ошибки; здесь — семантика:
//! профиль корректен, но заведомо ничего не делает или делает не то, что ожидает пользователь.

use crate::config::DpiConfig;
use goodbyedpi_proto::PortRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lint {
    pub severity: Severity,
    pub message: String,
}

impl Lint {
    fn warn(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    fn info(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            message: message.into(),
        }
    }
}

/// Минимальный размер QUIC Initial (RFC 9000 §14.1): фрагмент такого размера
/// или больше означает, что пакет уйдёт целиком.
const QUIC_INITIAL_MIN: u16 = 1200;

fn format_ports(ports: &[PortRange]) -> String {
    if ports.is_empty() {
        return "any".to_string();
    }
    ports
        .iter()
        .map(|r| {
            if r.start == r.end {
                r.start.to_string()
            } else {
                format!("{}-{}", r.start, r.end)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn on_off(v: bool) -> String {
    if v { "on" } else { "off" }.to_string()
}

/// Ключ-значение для вывода `validate`/`--dry-run`/TUI.
pub fn summarize(cfg: &DpiConfig) -> Vec<(&'static str, String)> {
    let mut out = vec![
        (
            "split",
            cfg.split_pos
                .map_or("off".to_string(), |p| format!("at byte {}", p)),
        ),
        (
            "oob",
            if cfg.oob_positions.is_empty() {
                "off".to_string()
            } else {
                format!("{:?}", cfg.oob_positions)
            },
        ),
        (
            "fake",
            cfg.fake_offset
                .map_or("off".to_string(), |o| format!("offset {}", o)),
        ),
        (
            "tlsrec",
            cfg.tlsrec_pos
                .map_or("off".to_string(), |p| format!("SNI {:+}", p)),
        ),
        ("disorder", on_off(cfg.use_disorder)),
        (
            "quic frag",
            if cfg.ip_fragment {
                format!("{} bytes", cfg.frag_size)
            } else {
                "off".to_string()
            },
        ),
        (
            "auto",
            format!(
                "rst={} redirect={} ssl={}",
                on_off(cfg.auto_rst),
                on_off(cfg.auto_redirect),
                on_off(cfg.auto_ssl)
            ),
        ),
        ("tcp ports", format_ports(&cfg.filter_tcp)),
        ("udp ports", format_ports(&cfg.filter_udp)),
    ];

    if !cfg.hostlist.is_empty() || !cfg.hostlist_exclude.is_empty() {
        out.push((
            "hostlist",
            format!(
                "{} include / {} exclude",
                cfg.hostlist.len(),
                cfg.hostlist_exclude.len()
            ),
        ));
    }
    if !cfg.ipset.is_empty() || !cfg.ipset_exclude.is_empty() {
        out.push((
            "ipset",
            format!(
                "{} include / {} exclude",
                cfg.ipset.len(),
                cfg.ipset_exclude.len()
            ),
        ));
    }
    if !cfg.dpi_desync_actions.is_empty() {
        out.push(("dpi-desync", format!("{:?}", cfg.dpi_desync_actions)));
    }
    if !cfg.rules.is_empty() {
        out.push(("rules", cfg.rules.len().to_string()));
    }
    if !cfg.sections.is_empty() {
        out.push(("sections", cfg.sections.len().to_string()));
    }
    out
}

fn has_any_technique(cfg: &DpiConfig) -> bool {
    cfg.split_pos.is_some_and(|p| p > 0)
        || !cfg.oob_positions.is_empty()
        || cfg.fake_offset.is_some()
        || cfg.tlsrec_pos.is_some()
        || cfg.use_disorder
        || cfg.ip_fragment
        || cfg.auto_rst
        || cfg.auto_redirect
        || cfg.auto_ssl
        || !cfg.dpi_desync_actions.is_empty()
        || !cfg.rules.is_empty()
        || cfg.sections.iter().any(|s| !s.actions.is_empty())
}

pub fn lint(cfg: &DpiConfig) -> Vec<Lint> {
    let mut lints = Vec::new();

    if !has_any_technique(cfg) {
        lints.push(Lint::warn(
            "profile enables no bypass technique: traffic will only be counted. \
             Example: \"s1 -o1 -Ar\"",
        ));
    }

    if cfg.split_pos == Some(0) {
        lints.push(Lint::warn(
            "split position 0 disables split (s0); use s1 or larger",
        ));
    }

    if cfg.oob_positions.len() > 1 {
        lints.push(Lint::info(format!(
            "{} OOB positions given, only the first ({}) is used",
            cfg.oob_positions.len(),
            cfg.oob_positions[0]
        )));
    }

    if cfg.ip_fragment {
        if !cfg.frag_size.is_multiple_of(8) {
            lints.push(Lint::info(format!(
                "fragment size {} is not a multiple of 8, it will be rounded down to {}",
                cfg.frag_size,
                (cfg.frag_size / 8 * 8).max(8)
            )));
        }
        if cfg.frag_size >= QUIC_INITIAL_MIN {
            lints.push(Lint::warn(format!(
                "fragment size {} >= {} (minimum QUIC Initial size): \
                 QUIC packets will be sent unfragmented",
                cfg.frag_size, QUIC_INITIAL_MIN
            )));
        }
        if !cfg.filter_udp.is_empty() && !cfg.filter_udp.iter().any(|r| r.contains(443)) {
            lints.push(Lint::warn(
                "QUIC fragmentation is on, but UDP filter excludes port 443",
            ));
        }
    }

    if !cfg.filter_tcp.is_empty()
        && !cfg
            .filter_tcp
            .iter()
            .any(|r| r.contains(443) || r.contains(80))
        && (cfg.split_pos.is_some() || cfg.tlsrec_pos.is_some())
    {
        lints.push(Lint::info(
            "TCP filter excludes both 80 and 443: HTTP/TLS techniques may never trigger",
        ));
    }

    lints
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lints_for(cfg: &str) -> Vec<Lint> {
        lint(&DpiConfig::parse(cfg).unwrap())
    }

    #[test]
    fn empty_profile_warns() {
        let lints = lints_for("");
        assert!(lints
            .iter()
            .any(|l| l.severity == Severity::Warning && l.message.contains("no bypass")));
    }

    #[test]
    fn common_profile_is_clean() {
        assert!(lints_for("s1 -o1 -Ar").is_empty());
    }

    #[test]
    fn big_fragment_warns() {
        let lints = lints_for("-g1400");
        assert!(lints.iter().any(|l| l.message.contains("unfragmented")));
    }

    #[test]
    fn odd_fragment_is_rounded() {
        let lints = lints_for("-g12");
        assert!(lints
            .iter()
            .any(|l| l.message.contains("rounded down to 8")));
    }

    #[test]
    fn summary_lists_split() {
        let cfg = DpiConfig::parse("s2 -d").unwrap();
        let summary = summarize(&cfg);
        assert!(summary.contains(&("split", "at byte 2".to_string())));
        assert!(summary.contains(&("disorder", "on".to_string())));
    }
}
