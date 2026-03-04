use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "requires root and network namespace tooling; run with GBD_RUN_NETNS_TESTS=1 cargo test -p goodbyedpi-daemon --test netns_integration -- --ignored --nocapture"]
fn netns_quic_fragmentation_flow() {
    if std::env::var("GBD_RUN_NETNS_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set GBD_RUN_NETNS_TESTS=1 to execute runtime netns test");
        return;
    }

    let euid = unsafe { libc::geteuid() };
    assert_eq!(euid, 0, "must be run as root");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("daemon crate should be inside workspace root");
    let script = repo_root.join("scripts/test-netns-integration.sh");

    assert!(
        script.exists(),
        "integration script not found: {}",
        script.display()
    );

    let status = Command::new("bash")
        .arg(&script)
        .status()
        .expect("failed to execute netns integration script");

    assert!(status.success(), "netns integration script failed");
}
