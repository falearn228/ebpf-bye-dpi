use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

const BPF_PIN_DIR: &str = "/sys/fs/bpf/goodbyedpi";
const BPF_FS_PATH: &str = "/sys/fs/bpf";

/// Ensure BPF filesystem is mounted
fn ensure_bpf_fs_mounted() -> Result<()> {
    // Check if already mounted
    let check = Command::new("mount")
        .args(["-t", "bpf"])  // TODO: тут нужен & ?
        .output()
        .context("Failed to check BPF filesystem mount status. Ensure 'mount' command is available.")?;
    
    if check.status.success() && !String::from_utf8_lossy(&check.stdout).is_empty() {
        debug!("BPF filesystem already mounted");
        return Ok(());
    }

    // Try to mount
    info!("Mounting BPF filesystem...");
    let output = Command::new("mount")
        .args(&["-t", "bpf", "none", BPF_FS_PATH]) // TODO: тут нужен & ?
        .output()
        .context("Failed to execute mount command for BPF filesystem")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to mount BPF filesystem at {}: {}. \
             Make sure you run with sufficient privileges (CAP_SYS_ADMIN) and the kernel supports BPF.",
            BPF_FS_PATH, stderr
        ));
    }

    info!("BPF filesystem mounted successfully at {}", BPF_FS_PATH);
    Ok(())
}

/// Setup TC qdisc for BPF attachment
pub fn setup_qdisc(interface: &str) -> Result<()> {
    // Try to clean up any existing clsact qdisc first (ignore errors)
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"]) // TODO: тут нужен & ?
        .output();

    let output = Command::new("tc")
        .args(["qdisc", "add", "dev", interface, "clsact"]) // TODO: тут нужен & ?
        .output()
        .with_context(|| format!(
            "Failed to execute 'tc qdisc add' for interface '{}'. \
             Ensure 'tc' (iproute2) is installed and you have CAP_NET_ADMIN capability.",
            interface
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(anyhow!(
                "Failed to add clsact qdisc to interface '{}': {}. \
                 The interface may not exist or you may lack sufficient privileges.",
                interface, stderr
            ));
        }
    }

    info!("TC clsact qdisc configured on {}", interface);
    Ok(())
}

/// Remove TC qdisc
pub fn cleanup_qdisc(interface: &str) -> Result<()> {
    let output = Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"]) // TODO: тут нужен & ?
        .output()
        .with_context(|| format!(
            "Failed to execute 'tc qdisc del' for interface '{}'. \
             Ensure 'tc' (iproute2) is installed.",
            interface
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Only warn if it's not "No such file or directory" (qdisc didn't exist)
        if !stderr.contains("No such file") && !stderr.contains("Invalid argument") {
            warn!("tc qdisc del warning for '{}': {}", interface, stderr);
        }
    }

    info!("TC clsact qdisc removed from {}", interface);
    Ok(())
}

/// Create BPF pin directory
fn ensure_pin_dir() -> Result<()> {
    // First ensure BPF fs is mounted
    ensure_bpf_fs_mounted()
        .context("Failed to ensure BPF filesystem is mounted before creating pin directory")?;
    
    if !Path::new(BPF_PIN_DIR).exists() {
        fs::create_dir_all(BPF_PIN_DIR)
            .with_context(|| format!(
                "Failed to create BPF pin directory '{}'. \
                 Ensure the BPF filesystem is mounted and you have write permissions.",
                BPF_PIN_DIR
            ))?;
    }
    Ok(())
}

/// Clean up pinned BPF objects
fn cleanup_pins() {
    let _ = fs::remove_dir_all(BPF_PIN_DIR);
}

/// Find bpftool binary
fn find_bpftool() -> Result<String> {
    // Try common locations first
    for path in &["/usr/local/sbin/bpftool", "/usr/sbin/bpftool", "/sbin/bpftool"] {
        if Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    
    // Try to find in PATH
    let output = Command::new("which")
        .arg("bpftool")
        .output();
    
    match output {
        Ok(out) if out.status.success() => {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
        _ => {}
    }
    
    Err(anyhow!(
        "bpftool not found. Please install bpftool (usually in linux-tools-common package) \
         or ensure it's in your PATH. Common locations checked: /usr/local/sbin/bpftool, \
         /usr/sbin/bpftool, /sbin/bpftool"
    ))
}

/// Load BPF programs using bpftool loadall
fn load_bpf_programs(bpf_obj: &str) -> Result<(String, String)> {
    ensure_pin_dir()
        .context("Failed to set up BPF pin directory before loading programs")?;
    
    let bpftool = find_bpftool()
        .context("Cannot load BPF programs without bpftool")?;
    let prog_pin = format!("{}/progs", BPF_PIN_DIR);
    
    // Verify the BPF object file exists
    if !Path::new(bpf_obj).exists() {
        return Err(anyhow!(
            "BPF object file not found: '{}'. \
             Please build the eBPF code first by running 'cargo build' or 'make -C ebpf/src'.",
            bpf_obj
        ));
    }
    
    info!("Loading BPF programs from: {}", bpf_obj);
    
    // Load all programs with map pinning
    let output = Command::new(&bpftool)
        .args([
            "prog", "loadall",
            bpf_obj,
            &prog_pin,
            "type", "tc",
            "pinmaps", BPF_PIN_DIR
        ])
        .output()
        .with_context(|| format!(
            "Failed to execute bpftool to load BPF programs from '{}'",
            bpf_obj
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "bpftool prog loadall failed: {}. \
             Common causes: incompatible BPF bytecode, missing kernel BTF support, \
             or insufficient privileges (need CAP_BPF or root).",
            stderr
        ));
    }

    // Get the pinned program names (based on section names in BPF code)
    let egress_pin = format!("{}/dpi_egress", prog_pin);
    let ingress_pin = format!("{}/dpi_ingress", prog_pin);
    
    // Verify the programs were actually pinned
    if !Path::new(&egress_pin).exists() {
        return Err(anyhow!(
            "Egress program was not pinned at '{}'. BPF load may have partially failed.",
            egress_pin
        ));
    }
    
    info!("BPF programs loaded successfully: egress={}, ingress={}", egress_pin, ingress_pin);
    Ok((egress_pin, ingress_pin))
}

/// Attach pinned BPF program to TC
fn attach_pinned_prog(interface: &str, direction: &str, pinned_path: &str) -> Result<()> {
    if !Path::new(pinned_path).exists() {
        return Err(anyhow!(
            "Pinned BPF program not found at '{}'. \
             Ensure the BPF programs were loaded successfully before attaching.",
            pinned_path
        ));
    }

    info!("Attaching {} filter from {}", direction, pinned_path);
    
    let output = Command::new("tc")
        .args([
            "filter", "add", "dev", interface,
            direction, "prio", "1",
            "bpf", "pinned", pinned_path,
            "direct-action"
        ])
        .output()
        .with_context(|| format!(
            "Failed to execute 'tc filter add' for {} on interface '{}'",
            direction, interface
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to attach BPF {} filter to interface '{}': {}. \
             Ensure the clsact qdisc is configured and you have CAP_NET_ADMIN capability.",
            direction, interface, stderr
        ));
    }

    info!("BPF {} filter attached to {}", direction, interface);
    Ok(())
}

/// Attach BPF program to TC egress with config
pub fn attach_egress(interface: &str, bpf_obj: &str, config_bytes: &[u8]) -> Result<()> {
    info!("Setting up BPF on {} (config {} bytes)", interface, config_bytes.len());

    // Clean up any old pins
    cleanup_pins();
    
    // Load BPF programs (both egress and ingress)
    let (egress_pin, _) = load_bpf_programs(bpf_obj)?;
    
    // Attach egress
    attach_pinned_prog(interface, "egress", &egress_pin)?;
    
    // Wait and load config
    thread::sleep(Duration::from_millis(100));
    load_config_to_map(config_bytes)?;

    info!("BPF egress ready on {}", interface);
    Ok(())
}

/// Attach BPF program to TC ingress
pub fn attach_ingress(interface: &str, _bpf_obj: &str) -> Result<()> {
    let ingress_pin = format!("{}/progs/dpi_ingress", BPF_PIN_DIR);
    attach_pinned_prog(interface, "ingress", &ingress_pin)
}

fn load_config_to_map(config_bytes: &[u8]) -> Result<()> {
    let config_map_pin = format!("{}/config_map", BPF_PIN_DIR);
    
    if !Path::new(&config_map_pin).exists() {
        return Err(anyhow!(
            "config_map not pinned at '{}'. \
             Ensure the BPF programs were loaded with 'pinmaps' option and the map is declared in the eBPF code.",
            config_map_pin
        ));
    }

    let hex_values: Vec<String> = config_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let hex_str = hex_values.join(" ");

    info!("Loading config into pinned map");
    
    let cmd = format!(
        "bpftool map update pinned {} key hex 00 00 00 00 value hex {}",
        config_map_pin, hex_str
    );

    let output = Command::new("sh")
        .args(["-c", &cmd])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to update config_map at '{}': {}. \
             The map may be inaccessible or the config data may be invalid ({} bytes).",
            config_map_pin, stderr, config_bytes.len()
        ));
    }

    info!("✓ Config loaded ({} bytes)", config_bytes.len());

    // Verify
    thread::sleep(Duration::from_millis(50));
    if let Ok(verify) = Command::new("sh")
        .args(["-c", &format!("bpftool map lookup pinned {} key hex 00 00 00 00", config_map_pin)])
        .output() 
    {
        debug!("Map content: {}", String::from_utf8_lossy(&verify.stdout));
    }

    Ok(())
}

/// Remove TC filters
pub fn remove_filters(interface: &str) -> Result<()> {
    let _ = Command::new("tc")
        .args(["filter", "del", "dev", interface, "egress"])
        .output();

    let _ = Command::new("tc")
        .args(["filter", "del", "dev", interface, "ingress"])
        .output();

    Ok(())
}

/// Full cleanup
pub fn full_cleanup(interface: &str) -> Result<()> {
    remove_filters(interface)?;
    cleanup_qdisc(interface)?;
    cleanup_pins();
    Ok(())
}


// TODO: function `show_config` is never used
/// Show TC configuration
pub fn show_config(interface: &str) -> Result<String> {
    let output = Command::new("tc")
        .args(["filter", "show", "dev", interface])
        .output()
        .with_context(|| format!(
            "Failed to execute 'tc filter show' for interface '{}'",
            interface
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to show TC filters for interface '{}': {}. \
             Ensure the interface exists and you have sufficient privileges.",
            interface, stderr
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
