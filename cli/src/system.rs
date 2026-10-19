//! Чтение состояния системы: ядро, capabilities, интерфейсы, TC.
//! Только чтение — ничего не меняет, поэтому безопасно для `doctor`/`status`/`tui`.

use std::path::Path;
use std::process::Command;

pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_BPF: u32 = 39;

pub fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn is_root() -> bool {
    // SAFETY: geteuid не имеет побочных эффектов
    unsafe { libc::geteuid() == 0 }
}

/// Версия ядра (major, minor) и полная строка release.
pub fn kernel_version() -> Option<((u32, u32), String)> {
    let release = read_trimmed("/proc/sys/kernel/osrelease")?;
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some(((major, minor), release))
}

/// Эффективные capabilities текущего процесса (битовая маска CapEff).
pub fn effective_caps() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("CapEff:"))?;
    u64::from_str_radix(line.trim_start_matches("CapEff:").trim(), 16).ok()
}

pub fn has_cap(caps: u64, cap: u32) -> bool {
    caps & (1u64 << cap) != 0
}

/// Ищет конфиг ядра в стандартных местах.
pub fn kernel_config(release: &str) -> Option<(String, String)> {
    if Path::new("/proc/config.gz").exists() {
        if let Ok(out) = Command::new("zcat").arg("/proc/config.gz").output() {
            if out.status.success() {
                return Some((
                    "/proc/config.gz".to_string(),
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                ));
            }
        }
    }
    for path in [
        format!("/boot/config-{}", release),
        format!("/lib/modules/{}/config", release),
        format!("/usr/lib/modules/{}/config", release),
    ] {
        if let Ok(text) = std::fs::read_to_string(&path) {
            return Some((path, text));
        }
    }
    None
}

/// Значение опции `CONFIG_X` из текста конфига: Some("y"|"m"|...) или None.
pub fn kconfig_value<'a>(config: &'a str, option: &str) -> Option<&'a str> {
    config.lines().find_map(|line| {
        line.strip_prefix(option)
            .and_then(|rest| rest.strip_prefix('='))
            .map(str::trim)
    })
}

pub fn command_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(cmd).is_file()))
        .unwrap_or(false)
}

pub fn run_command(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn list_interfaces() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|dir| {
            dir.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Интерфейс по умолчанию: тот, через который идёт default route.
pub fn default_route_interface() -> Option<String> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    routes.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        (cols.len() > 2 && cols[1] == "00000000").then(|| cols[0].to_string())
    })
}

/// Интерфейс для запуска без `-i`: default route, иначе первый поднятый
/// физический (есть `device` в sysfs, значит не veth/docker/bridge).
pub fn guess_interface() -> Option<String> {
    default_route_interface().or_else(|| {
        list_interfaces().into_iter().find(|name| {
            let base = Path::new("/sys/class/net").join(name);
            base.join("device").exists()
                && read_trimmed(base.join("operstate")).as_deref() == Some("up")
        })
    })
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub exists: bool,
    pub operstate: String,
    /// ARPHRD_*: 1 = Ethernet/Wi-Fi, 772 = loopback, 65534 = L3 (tun/wireguard), 512 = PPP
    pub link_type: Option<u32>,
}

pub fn interface_info(name: &str) -> InterfaceInfo {
    let base = Path::new("/sys/class/net").join(name);
    InterfaceInfo {
        exists: base.exists(),
        operstate: read_trimmed(base.join("operstate")).unwrap_or_else(|| "unknown".into()),
        link_type: read_trimmed(base.join("type")).and_then(|t| t.parse().ok()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcFilter {
    pub direction: &'static str,
    pub pref: Option<u32>,
    pub handle: Option<String>,
    pub name: String,
    /// Наш фильтр (dpi_egress/dpi_ingress)
    pub ours: bool,
}

/// Разбирает вывод `tc filter show dev X <dir>`: оставляет только bpf-фильтры с handle.
pub fn parse_tc_filters(direction: &'static str, output: &str) -> Vec<TcFilter> {
    output
        .lines()
        .filter(|l| l.contains(" bpf ") && l.contains(" handle "))
        .map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let after = |key: &str| {
                tokens
                    .iter()
                    .position(|t| *t == key)
                    .and_then(|i| tokens.get(i + 1))
                    .map(|s| s.to_string())
            };
            let pref = after("pref").and_then(|p| p.parse().ok());
            let handle = after("handle");
            // Имя: "name X" в новых iproute2, иначе токен сразу после значения handle
            let name = after("name")
                .or_else(|| {
                    tokens
                        .iter()
                        .position(|t| *t == "handle")
                        .and_then(|i| tokens.get(i + 2))
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "?".into());
            let ours = line.contains("dpi_egress") || line.contains("dpi_ingress");
            TcFilter {
                direction,
                pref,
                handle,
                name,
                ours,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TcState {
    /// `tc` недоступен или упал
    pub available: bool,
    pub filters: Vec<TcFilter>,
    pub has_clsact: bool,
    /// Классический `ingress` qdisc занимает ffff: и мешает созданию clsact
    pub has_ingress_qdisc: bool,
}

impl TcState {
    pub fn ours_attached(&self, direction: &str) -> bool {
        self.filters
            .iter()
            .any(|f| f.ours && f.direction == direction)
    }
}

pub fn tc_state(iface: &str) -> TcState {
    let Some(qdisc) = run_command("tc", &["qdisc", "show", "dev", iface]) else {
        return TcState::default();
    };
    let mut state = TcState {
        available: true,
        has_clsact: qdisc.contains("qdisc clsact"),
        has_ingress_qdisc: qdisc.contains("qdisc ingress"),
        ..TcState::default()
    };
    for direction in ["egress", "ingress"] {
        if let Some(out) = run_command("tc", &["filter", "show", "dev", iface, direction]) {
            state.filters.extend(parse_tc_filters(direction, &out));
        }
    }
    state
}

/// Прочие процессы обхода DPI, которые могут модифицировать тот же трафик.
pub fn conflicting_processes() -> Vec<(u32, String)> {
    const KNOWN: &[&str] = &["nfqws", "tpws", "ciadpi", "byedpi", "dpitunnel", "spoofdpi"];
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.filter_map(|e| e.ok())
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let comm = read_trimmed(e.path().join("comm"))?;
            KNOWN
                .iter()
                .any(|k| comm.starts_with(k))
                .then_some((pid, comm))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libbpf_tc_filter() {
        let out = "filter protocol all pref 1 bpf chain 0 \n\
                   filter protocol all pref 1 bpf chain 0 handle 0x1 dpi_egress direct-action not_in_hw id 412 tag 5b8f jited \n";
        let filters = parse_tc_filters("egress", out);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].pref, Some(1));
        assert_eq!(filters[0].handle.as_deref(), Some("0x1"));
        assert_eq!(filters[0].name, "dpi_egress");
        assert!(filters[0].ours);
    }

    #[test]
    fn parses_foreign_filter_with_name_field() {
        let out = "filter protocol all pref 49152 bpf chain 0 handle 0x1 name cil_from_netdev direct-action not_in_hw id 7\n";
        let filters = parse_tc_filters("ingress", out);
        assert_eq!(filters[0].name, "cil_from_netdev");
        assert!(!filters[0].ours);
    }

    #[test]
    fn kconfig_lookup() {
        let cfg =
            "CONFIG_BPF=y\nCONFIG_BPF_SYSCALL=y\n# CONFIG_FOO is not set\nCONFIG_NET_CLS_BPF=m\n";
        assert_eq!(kconfig_value(cfg, "CONFIG_BPF"), Some("y"));
        assert_eq!(kconfig_value(cfg, "CONFIG_NET_CLS_BPF"), Some("m"));
        assert_eq!(kconfig_value(cfg, "CONFIG_FOO"), None);
    }
}
