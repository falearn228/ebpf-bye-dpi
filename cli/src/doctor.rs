//! `goodbyedpi doctor`: объясняет, почему демон не стартует или не работает.
//!
//! Каждая проверка возвращает статус, что именно увидели и как исправить.
//! Проверки только читают систему; единственное «активное» действие —
//! пробная загрузка eBPF-объекта в verifier без attach (только под root).

use goodbyedpi_daemon::bpf::{self, ObjectReport, REQUIRED_MAPS, REQUIRED_PROGRAMS};
use goodbyedpi_daemon::control::RunDir;
use goodbyedpi_daemon::profile::Severity;
use serde::Serialize;

use crate::profile::{self, ProfileSource};
use crate::system::{self, CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Skip,
    Warn,
    Fail,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Skip => "SKIP",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub group: &'static str,
    pub title: String,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub interfaces: Vec<String>,
    pub profile: Option<ProfileSource>,
    pub run_dir: RunDir,
    /// Пробная загрузка в verifier (нужен root)
    pub load_bpf: bool,
    pub metrics_bind: String,
}

struct Report {
    checks: Vec<Check>,
    group: &'static str,
}

impl Report {
    fn push(&mut self, status: Status, title: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            group: self.group,
            title: title.into(),
            status,
            detail: detail.into(),
            hint: None,
        });
    }

    fn push_hint(
        &mut self,
        status: Status,
        title: impl Into<String>,
        detail: impl Into<String>,
        hint: impl Into<String>,
    ) {
        self.checks.push(Check {
            group: self.group,
            title: title.into(),
            status,
            detail: detail.into(),
            hint: Some(hint.into()),
        });
    }
}

pub fn run(opts: &DoctorOptions) -> Vec<Check> {
    let mut r = Report {
        checks: Vec::new(),
        group: "kernel",
    };
    let kernel = system::kernel_version();
    check_kernel(&mut r, kernel.as_ref());

    r.group = "privileges";
    let privileged = check_privileges(&mut r);

    r.group = "tools";
    check_tools(&mut r);

    r.group = "daemon";
    let daemon_pid = check_daemon(&mut r, opts);

    r.group = "interfaces";
    // Хуки ожидаем только на интерфейсах, которыми управляет живой демон
    let managed: Vec<String> = daemon_pid
        .and_then(|_| opts.run_dir.read_state().ok().flatten())
        .map(|st| st.interfaces)
        .unwrap_or_default();
    for iface in &opts.interfaces {
        check_interface(&mut r, iface, managed.contains(iface));
    }

    r.group = "ebpf";
    check_bpf_object(&mut r, opts.load_bpf && privileged && is_root_like());
    check_live_bpf(&mut r, daemon_pid.is_some());

    r.group = "profile";
    check_profile(&mut r, opts.profile.as_ref());

    r.checks
}

fn is_root_like() -> bool {
    bpf::has_bpf_privileges()
}

fn check_kernel(r: &mut Report, kernel: Option<&((u32, u32), String)>) {
    match kernel {
        Some(((major, minor), release)) if (*major, *minor) >= (5, 8) => {
            r.push(
                Status::Pass,
                "kernel version",
                format!("{} (>= 5.8)", release),
            );
        }
        Some((_, release)) => r.push_hint(
            Status::Fail,
            "kernel version",
            format!(
                "{} is older than 5.8: no BPF ring buffer and no CAP_BPF",
                release
            ),
            "upgrade to a 5.8+ kernel (5.15 LTS or newer recommended)",
        ),
        None => r.push(
            Status::Warn,
            "kernel version",
            "cannot read /proc/sys/kernel/osrelease",
        ),
    }

    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        r.push(
            Status::Pass,
            "kernel BTF",
            "/sys/kernel/btf/vmlinux present",
        );
    } else {
        r.push_hint(
            Status::Fail,
            "kernel BTF",
            "/sys/kernel/btf/vmlinux missing: CO-RE relocations in the eBPF program cannot be resolved",
            "use a kernel built with CONFIG_DEBUG_INFO_BTF=y (default on Arch, Debian 11+, Fedora, Ubuntu 20.10+)",
        );
    }

    let release = kernel.map(|(_, rel)| rel.as_str()).unwrap_or("");
    match system::kernel_config(release) {
        Some((path, config)) => {
            const REQUIRED: &[(&str, &str)] = &[
                ("CONFIG_BPF_SYSCALL", "bpf() syscall"),
                ("CONFIG_NET_CLS_BPF", "TC bpf classifier"),
                ("CONFIG_NET_SCH_INGRESS", "clsact qdisc"),
                ("CONFIG_NET_CLS_ACT", "TC actions (direct-action)"),
                ("CONFIG_DEBUG_INFO_BTF", "kernel BTF"),
            ];
            let missing: Vec<String> = REQUIRED
                .iter()
                .filter(|(opt, _)| {
                    !matches!(system::kconfig_value(&config, opt), Some("y") | Some("m"))
                })
                .map(|(opt, what)| format!("{} ({})", opt, what))
                .collect();
            if missing.is_empty() {
                r.push(
                    Status::Pass,
                    "kernel config",
                    format!("all TC/BPF options enabled ({})", path),
                );
            } else {
                r.push_hint(
                    Status::Fail,
                    "kernel config",
                    format!("missing in {}: {}", path, missing.join(", ")),
                    "rebuild the kernel with these options or use a distribution kernel",
                );
            }
            if system::kconfig_value(&config, "CONFIG_BPF_JIT") != Some("y") {
                r.push(
                    Status::Warn,
                    "BPF JIT",
                    "CONFIG_BPF_JIT is off: programs run in the interpreter (slow)",
                );
            }
        }
        None => r.push(
            Status::Skip,
            "kernel config",
            "no /proc/config.gz or /boot/config-*: option check skipped",
        ),
    }

    if let Some(lockdown) = system::read_trimmed("/sys/kernel/security/lockdown") {
        if lockdown.contains("[confidentiality]") {
            r.push_hint(
                Status::Warn,
                "kernel lockdown",
                "lockdown=confidentiality blocks some BPF helpers and trace_pipe",
                "boot with lockdown=integrity or none (Secure Boot setups may force it)",
            );
        } else {
            // Формат файла: "[none] integrity confidentiality" — активный режим в скобках
            let active = lockdown
                .split_whitespace()
                .find(|m| m.starts_with('['))
                .map(|m| m.trim_matches(|c| c == '[' || c == ']').to_string())
                .unwrap_or(lockdown);
            r.push(Status::Pass, "kernel lockdown", active);
        }
    }

    // До 5.11 карты учитываются в RLIMIT_MEMLOCK, а не в memcg
    if let Some(((major, minor), _)) = kernel {
        if (*major, *minor) < (5, 11) {
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: валидный указатель на rlimit
            let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
            if rc == 0 && lim.rlim_cur != libc::RLIM_INFINITY && lim.rlim_cur < 64 << 20 {
                r.push_hint(
                    Status::Warn,
                    "memlock limit",
                    format!(
                        "RLIMIT_MEMLOCK is {} KiB; kernels < 5.11 charge BPF maps to it and fail with EPERM",
                        lim.rlim_cur / 1024
                    ),
                    "run `ulimit -l unlimited` or set LimitMEMLOCK=infinity in the unit",
                );
            }
        }
    }
}

fn check_privileges(r: &mut Report) -> bool {
    let Some(caps) = system::effective_caps() else {
        r.push(
            Status::Warn,
            "capabilities",
            "cannot read /proc/self/status",
        );
        return false;
    };
    let bpf_ok = system::has_cap(caps, CAP_BPF) || system::has_cap(caps, CAP_SYS_ADMIN);
    let mut missing = Vec::new();
    if !bpf_ok {
        missing.push("CAP_BPF (or CAP_SYS_ADMIN)");
    }
    if !system::has_cap(caps, CAP_NET_ADMIN) {
        missing.push("CAP_NET_ADMIN");
    }
    if !system::has_cap(caps, CAP_NET_RAW) {
        missing.push("CAP_NET_RAW");
    }

    if missing.is_empty() {
        r.push(
            Status::Pass,
            "capabilities",
            "CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW available",
        );
    } else {
        r.push_hint(
            Status::Warn,
            "capabilities",
            format!(
                "doctor itself lacks {}; kernel load checks are skipped",
                missing.join(", ")
            ),
            "the daemon needs these too: run `sudo goodbyedpi doctor` for a full diagnosis",
        );
    }

    if let Some(v) = system::read_trimmed("/proc/sys/kernel/unprivileged_bpf_disabled") {
        r.push(
            Status::Pass,
            "unprivileged bpf",
            format!(
                "kernel.unprivileged_bpf_disabled={} (daemon runs privileged, fine)",
                v
            ),
        );
    }

    // Raw socket нужен для инъекций; проверяем реальным socket(), а не только капой
    if system::has_cap(caps, CAP_NET_RAW) {
        // SAFETY: создаём и сразу закрываем сокет
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            r.push(
                Status::Pass,
                "raw socket",
                "AF_INET/SOCK_RAW opened (packet injection works)",
            );
        } else {
            r.push_hint(
                Status::Fail,
                "raw socket",
                format!(
                    "socket(SOCK_RAW) failed: {}",
                    std::io::Error::last_os_error()
                ),
                "check seccomp/LSM policy (AppArmor/SELinux) for the daemon",
            );
        }
    }
    missing.is_empty()
}

fn check_tools(r: &mut Report) {
    if system::command_exists("tc") {
        r.push(Status::Pass, "tc", "iproute2 tc found");
    } else {
        r.push_hint(
            Status::Warn,
            "tc",
            "tc not in PATH: daemon cannot clean up the clsact qdisc on exit, doctor cannot inspect hooks",
            "install iproute2",
        );
    }
    if system::command_exists("bpftool") {
        r.push(Status::Pass, "bpftool", "found (optional, for debugging)");
    } else {
        r.push(Status::Skip, "bpftool", "not installed (optional)");
    }

    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    if mounts
        .lines()
        .any(|l| l.split_whitespace().nth(2) == Some("bpf"))
    {
        r.push(Status::Pass, "bpffs", "bpf filesystem mounted");
    } else {
        r.push_hint(
            Status::Warn,
            "bpffs",
            "/sys/fs/bpf is not mounted (not required for loading, needed by bpftool pinning)",
            "mount -t bpf bpf /sys/fs/bpf",
        );
    }

    let others = system::conflicting_processes();
    if others.is_empty() {
        r.push(
            Status::Pass,
            "other DPI tools",
            "no zapret/byedpi-like processes found",
        );
    } else {
        let list: Vec<String> = others
            .iter()
            .map(|(p, c)| format!("{} (pid {})", c, p))
            .collect();
        r.push_hint(
            Status::Warn,
            "other DPI tools",
            format!("running: {}", list.join(", ")),
            "two bypass tools on the same traffic double-modify packets; stop one of them",
        );
    }
}

fn check_daemon(r: &mut Report, opts: &DoctorOptions) -> Option<u32> {
    let pid = opts.run_dir.running_pid();
    match (pid, opts.run_dir.read_pid()) {
        (Some(pid), _) => {
            let state = opts.run_dir.read_state().ok().flatten();
            let detail = match &state {
                Some(st) => format!("pid {} on {}", pid, st.interfaces.join(", ")),
                None => format!("pid {} (no state.json yet)", pid),
            };
            r.push(Status::Pass, "daemon process", detail);
            if let Some(st) = state.filter(|s| s.reload.generation > 0 && !s.reload.ok) {
                r.push_hint(
                    Status::Warn,
                    "last reload",
                    format!(
                        "reload #{} rejected: {}",
                        st.reload.generation, st.reload.message
                    ),
                    "daemon keeps the previous profile; fix it and `goodbyedpi reload`",
                );
            }
        }
        (None, Some(stale)) => r.push_hint(
            Status::Warn,
            "daemon process",
            format!("stale pid file ({}) — previous daemon crashed", stale),
            format!(
                "check TC hooks below; remove {} if nothing is attached",
                opts.run_dir.pid_path().display()
            ),
        ),
        (None, None) => {
            r.push(Status::Skip, "daemon process", "not running");
            // Метрики только логируют ошибку, но лучше знать заранее
            if std::net::TcpListener::bind(&opts.metrics_bind).is_err() {
                r.push_hint(
                    Status::Warn,
                    "metrics port",
                    format!("{} is busy", opts.metrics_bind),
                    "pass --metrics-bind <addr> or --no-metrics to the daemon",
                );
            }
        }
    }
    pid
}

fn check_interface(r: &mut Report, iface: &str, daemon_running: bool) {
    let info = system::interface_info(iface);
    let title = format!("{}: link", iface);
    if !info.exists {
        let available = system::list_interfaces().join(", ");
        let default = system::default_route_interface()
            .map(|d| format!(" (default route via {})", d))
            .unwrap_or_default();
        r.push_hint(
            Status::Fail,
            title,
            format!("interface does not exist; available: {}", available),
            format!("pass the right one with -i{}", default),
        );
        return;
    }

    match info.link_type {
        Some(1) => {}
        Some(772) => r.push(
            Status::Warn,
            format!("{}: type", iface),
            "loopback: no internet traffic goes here",
        ),
        Some(t) => r.push_hint(
            Status::Fail,
            format!("{}: type", iface),
            format!(
                "link type {} has no Ethernet header (tun/wireguard/ppp); the eBPF program parses ETH_HLEN=14 and will misparse every packet",
                t
            ),
            "attach to the underlying Ethernet/Wi-Fi interface instead",
        ),
        None => {}
    }

    if info.operstate == "up" || info.operstate == "unknown" {
        r.push(Status::Pass, title, format!("operstate {}", info.operstate));
    } else {
        r.push(
            Status::Warn,
            title,
            format!(
                "operstate {}: hooks attach, but no traffic flows",
                info.operstate
            ),
        );
    }

    let tc = system::tc_state(iface);
    if !tc.available {
        r.push(
            Status::Skip,
            format!("{}: tc hooks", iface),
            "tc unavailable",
        );
        return;
    }

    let tc_title = format!("{}: tc hooks", iface);
    if tc.has_ingress_qdisc {
        r.push_hint(
            Status::Fail,
            tc_title.clone(),
            "classic `ingress` qdisc holds handle ffff:, so clsact cannot be created",
            format!(
                "sudo tc qdisc del dev {} ingress   # removes its filters too, check who owns it",
                iface
            ),
        );
    }

    let ours: Vec<_> = tc.filters.iter().filter(|f| f.ours).collect();
    let foreign: Vec<_> = tc.filters.iter().filter(|f| !f.ours).collect();

    for f in &foreign {
        // libbpf TcHook по умолчанию ставит handle 1 prio 1
        let collides = f.pref == Some(1) && f.handle.as_deref() == Some("0x1");
        let detail = format!(
            "foreign bpf filter '{}' on {} (pref {:?}, handle {})",
            f.name,
            f.direction,
            f.pref,
            f.handle.as_deref().unwrap_or("?")
        );
        if collides {
            r.push_hint(
                Status::Fail,
                tc_title.clone(),
                format!("{}: same slot as ours, attach fails with EEXIST", detail),
                "the other program (cilium? another goodbyedpi build?) must be detached first",
            );
        } else {
            r.push_hint(
                Status::Warn,
                tc_title.clone(),
                detail,
                "another TC program sees the same packets; if it returns TC_ACT_SHOT/REDIRECT ours may never run",
            );
        }
    }

    match (daemon_running, ours.is_empty()) {
        (true, false) => {
            let dirs: Vec<&str> = ours.iter().map(|f| f.direction).collect();
            let status = if dirs.contains(&"egress") && dirs.contains(&"ingress") {
                Status::Pass
            } else {
                Status::Fail
            };
            r.push(
                status,
                tc_title,
                format!("our programs attached: {}", dirs.join(" + ")),
            );
        }
        (true, true) => r.push_hint(
            Status::Fail,
            tc_title,
            "daemon is running but dpi_egress/dpi_ingress are not attached here",
            "the interface may have been recreated (VPN/Wi-Fi reconnect): restart the daemon",
        ),
        (false, false) => {
            let cmds: Vec<String> = ours
                .iter()
                .map(|f| {
                    format!(
                        "sudo tc filter del dev {} {} pref {} handle {} bpf",
                        iface,
                        f.direction,
                        f.pref.unwrap_or(1),
                        f.handle.as_deref().unwrap_or("0x1")
                    )
                })
                .collect();
            r.push_hint(
                Status::Warn,
                tc_title,
                "stale dpi_egress/dpi_ingress filters left by a crashed daemon (traffic still hits them, no userspace listens)",
                cmds.join("\n"),
            );
        }
        (false, true) if foreign.is_empty() && !tc.has_ingress_qdisc => {
            r.push(Status::Pass, tc_title, "no conflicting TC filters");
        }
        (false, true) => {}
    }

    if system::command_exists("bpftool") {
        if let Some(out) = system::run_command("bpftool", &["net", "show", "dev", iface]) {
            let tcx: Vec<&str> = out.lines().filter(|l| l.contains("tcx/")).collect();
            if !tcx.is_empty() {
                r.push_hint(
                    Status::Warn,
                    format!("{}: tcx", iface),
                    format!("tcx programs run before classic TC: {}", tcx.join("; ")),
                    "if they drop/redirect traffic, our hooks never see it",
                );
            }
            if out.lines().any(|l| l.contains("xdp")) && out.contains("prog_id") {
                let xdp: Vec<&str> = out
                    .lines()
                    .filter(|l| l.contains("xdp") && l.contains("prog_id"))
                    .collect();
                if !xdp.is_empty() {
                    r.push(
                        Status::Warn,
                        format!("{}: xdp", iface),
                        format!(
                            "XDP program attached (sees ingress first): {}",
                            xdp.join("; ")
                        ),
                    );
                }
            }
        }
    }
}

fn check_bpf_object(r: &mut Report, load: bool) {
    let report = match bpf::inspect_object(load) {
        Ok(report) => report,
        Err(e) => {
            r.push_hint(
                Status::Fail,
                "embedded object",
                format!("{:#}", e),
                "rebuild with clang, libbpf-dev and make installed",
            );
            return;
        }
    };

    r.push(
        Status::Pass,
        "embedded object",
        format!("{} bytes, ELF opened", report.object_size),
    );

    if report.missing_programs.is_empty() {
        r.push(Status::Pass, "programs", REQUIRED_PROGRAMS.join(", "));
    } else {
        r.push_hint(
            Status::Fail,
            "programs",
            format!("missing in object: {}", report.missing_programs.join(", ")),
            "eBPF source and daemon are out of sync: rebuild both",
        );
    }

    let bad: Vec<String> = report
        .maps
        .iter()
        .filter(|m| !m.ok())
        .map(|m| {
            if !m.found {
                format!("{} missing", m.name)
            } else {
                format!(
                    "{} value_size {} != Rust struct {}",
                    m.name,
                    m.value_size.unwrap_or(0),
                    m.expected_value_size.unwrap_or(0)
                )
            }
        })
        .collect();
    if bad.is_empty() {
        r.push(
            Status::Pass,
            "map ABI",
            "all maps present, value sizes match proto structs",
        );
    } else {
        r.push_hint(
            Status::Fail,
            "map ABI",
            bad.join("; "),
            "C structs in goodbyedpi.bpf.c and proto/src/lib.rs diverged: fix layout and rebuild",
        );
    }

    check_verifier(r, &report);
}

fn check_verifier(r: &mut Report, report: &ObjectReport) {
    if !report.load_attempted {
        r.push(
            Status::Skip,
            "verifier",
            "trial load skipped (needs root; use `sudo goodbyedpi doctor`)",
        );
        return;
    }
    let Some(err) = &report.load_error else {
        r.push(
            Status::Pass,
            "verifier",
            "programs accepted by the kernel verifier (loaded and unloaded, nothing attached)",
        );
        return;
    };

    let log = &report.libbpf_log;
    let (detail, hint) = explain_load_failure(err, log);
    let tail: Vec<&str> = verifier_excerpt(log);
    let mut full = format!("{}\nerror: {}", detail, err);
    if !tail.is_empty() {
        full.push_str("\nverifier log (tail):\n");
        full.push_str(&tail.join("\n"));
    }
    r.push_hint(Status::Fail, "verifier", full, hint);
}

/// Последние строки лога verifier'а: от него самого, без шума libbpf.
fn verifier_excerpt(log: &[String]) -> Vec<&str> {
    let start = log
        .iter()
        .rposition(|l| l.contains("BEGIN PROG LOAD LOG"))
        .map(|i| i + 1)
        .unwrap_or(0);
    let end = log[start..]
        .iter()
        .position(|l| l.contains("END PROG LOAD LOG"))
        .map(|i| start + i)
        .unwrap_or(log.len());
    let body = &log[start..end];
    body[body.len().saturating_sub(25)..]
        .iter()
        .map(String::as_str)
        .collect()
}

/// Переводит типичные отказы загрузки в человеческое объяснение и совет.
pub fn explain_load_failure(err: &str, log: &[String]) -> (String, String) {
    let all = format!("{}\n{}", err, log.join("\n")).to_lowercase();
    let has = |needle: &str| all.contains(needle);

    if has("operation not permitted") || has("permission denied") {
        return (
            "kernel refused bpf(): not enough privileges".into(),
            "run as root or grant CAP_BPF+CAP_NET_ADMIN; on kernels < 5.11 also raise RLIMIT_MEMLOCK; \
             lockdown/LSM can block bpf() too"
                .into(),
        );
    }
    if has("failed to find valid kernel btf") || has("btf is required") || has("no btf") {
        return (
            "kernel BTF unavailable, CO-RE cannot relocate field offsets".into(),
            "use a kernel with CONFIG_DEBUG_INFO_BTF=y".into(),
        );
    }
    if has("relo") && (has("failed") || has("cannot")) {
        return (
            "CO-RE relocation failed: a kernel struct field used by the program does not exist on this kernel".into(),
            "report the kernel version and this log in an issue".into(),
        );
    }
    if has("unknown func") || has("invalid func") {
        let helper = log
            .iter()
            .find(|l| l.contains("unknown func") || l.contains("invalid func"))
            .cloned()
            .unwrap_or_default();
        return (
            format!(
                "program calls a BPF helper this kernel does not have: {}",
                helper.trim()
            ),
            "upgrade the kernel (helpers are tied to kernel versions)".into(),
        );
    }
    if has("bpf program is too large") || has("processed 1000001 insns") || has("too complex") {
        return (
            "verifier complexity limit exceeded".into(),
            "newer kernels allow more states; otherwise this is a bug: report it with the log"
                .into(),
        );
    }
    if has("back-edge") || has("infinite loop") || has("loop is not bounded") {
        return (
            "verifier could not prove a loop is bounded".into(),
            "kernels < 5.3 reject all loops; on newer kernels report the log as a bug".into(),
        );
    }
    if has("invalid access to packet") || has("invalid mem access") || has("out of bounds") {
        return (
            "verifier rejected a memory access: missing or weak bounds check against data_end".into(),
            "this is a program bug for this kernel/compiler combo: report with kernel and clang versions".into(),
        );
    }
    if has("license") && has("gpl") {
        return (
            "GPL-only helper used without a GPL license section".into(),
            "rebuild the object; license section must say GPL".into(),
        );
    }
    (
        "kernel verifier rejected the program".into(),
        "see the verifier log tail; report it with `uname -r` and `clang --version`".into(),
    )
}

/// Сравнивает загруженные в ядро программы/карты с ожидаемыми (через bpf_*_get_next_id).
fn check_live_bpf(r: &mut Report, daemon_running: bool) {
    if !is_root_like() {
        r.push(
            Status::Skip,
            "live programs/maps",
            "enumerating kernel BPF objects needs root",
        );
        return;
    }

    let progs: Vec<String> = libbpf_rs::query::ProgInfoIter::default()
        .map(|p| p.name.to_string_lossy().into_owned())
        .filter(|n| REQUIRED_PROGRAMS.contains(&n.as_str()))
        .collect();
    let maps: Vec<String> = libbpf_rs::query::MapInfoIter::default()
        .map(|m| m.name.to_string_lossy().into_owned())
        .collect();

    if !daemon_running {
        if progs.is_empty() {
            r.push(
                Status::Pass,
                "live programs/maps",
                "nothing loaded (daemon stopped)",
            );
        } else {
            r.push_hint(
                Status::Warn,
                "live programs/maps",
                format!(
                    "{} goodbyedpi programs still loaded without a daemon",
                    progs.len()
                ),
                "they are held by stale TC filters, see interface checks",
            );
        }
        return;
    }

    let missing_maps: Vec<&str> = REQUIRED_MAPS
        .iter()
        .copied()
        .filter(|name| !maps.iter().any(|m| m == name))
        .collect();
    if progs.is_empty() {
        r.push_hint(
            Status::Fail,
            "live programs",
            "daemon is alive but no dpi_egress/dpi_ingress program is loaded",
            "daemon is stuck or lost its BPF thread: restart it and check its log",
        );
    } else {
        r.push(
            Status::Pass,
            "live programs",
            format!("{} loaded", progs.len()),
        );
    }
    if missing_maps.is_empty() {
        r.push(Status::Pass, "live maps", REQUIRED_MAPS.join(", "));
    } else {
        r.push_hint(
            Status::Fail,
            "live maps",
            format!("missing BPF maps: {}", missing_maps.join(", ")),
            "config/stats/events cannot flow without them: restart the daemon; if it persists, rebuild",
        );
    }
}

fn check_profile(r: &mut Report, source: Option<&ProfileSource>) {
    let Some(source) = source.filter(|s| !s.is_empty()) else {
        r.push(
            Status::Skip,
            "profile",
            "no profile given (-c / --config-file)",
        );
        return;
    };
    let v = profile::validate(source);
    if let Some(err) = &v.error {
        let at = v
            .location
            .as_ref()
            .map(|l| {
                format!(
                    "\n  at {}:{}:{}: {}",
                    l.origin,
                    l.line,
                    l.column,
                    l.text.trim()
                )
            })
            .unwrap_or_default();
        r.push_hint(
            Status::Fail,
            "profile",
            format!("{}{}", err, at),
            "fix the profile; `goodbyedpi validate` shows the same error",
        );
        return;
    }
    r.push(Status::Pass, "profile", "parsed");
    for lint in v.lints {
        let status = match lint.severity {
            Severity::Warning => Status::Warn,
            Severity::Info => Status::Pass,
        };
        r.push(status, "profile lint", lint.message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explains_eperm() {
        let (d, _) = explain_load_failure("Operation not permitted (os error 1)", &[]);
        assert!(d.contains("privileges"));
    }

    #[test]
    fn explains_packet_bounds() {
        let log = vec![
            "-- BEGIN PROG LOAD LOG --".to_string(),
            "R3 invalid access to packet, off=14 size=1".to_string(),
            "-- END PROG LOAD LOG --".to_string(),
        ];
        let (d, _) = explain_load_failure("Invalid argument (os error 22)", &log);
        assert!(d.contains("bounds"));
        assert_eq!(
            verifier_excerpt(&log),
            vec!["R3 invalid access to packet, off=14 size=1"]
        );
    }

    #[test]
    fn explains_unknown_helper() {
        let log = vec!["unknown func bpf_loop#181".to_string()];
        let (d, _) = explain_load_failure("Invalid argument", &log);
        assert!(d.contains("bpf_loop"));
    }
}
