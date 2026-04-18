//! TC (Traffic Control) cleanup utilities
//!
//! This module provides cleanup functions for TC qdiscs and filters.
//! BPF loading is now handled by libbpf-rs directly in bpf.rs.

use anyhow::{Context, Result};
use log::{info, warn};
use std::process::Command;

/// Remove TC filters from interface
fn remove_filters(interface: &str) -> Result<()> {
    let _ = Command::new("tc")
        .args(["filter", "del", "dev", interface, "egress"])
        .output();

    let _ = Command::new("tc")
        .args(["filter", "del", "dev", interface, "ingress"])
        .output();

    Ok(())
}

/// Remove TC qdisc
fn cleanup_qdisc(interface: &str) -> Result<()> {
    let output = Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"])
        .output()
        .with_context(|| {
            format!(
                "Failed to execute 'tc qdisc del' for interface '{}'",
                interface
            )
        })?;

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

/// Full cleanup - removes filters, qdisc, and pinned maps
pub fn full_cleanup(interface: &str) -> Result<()> {
    remove_filters(interface)?;
    cleanup_qdisc(interface)?;
    Ok(())
}
