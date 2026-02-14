use std::path::{Path, PathBuf};
use std::process::Command;

fn project_root() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("crate directory has two parents")
}

fn run_script(path: &Path, args: &[&str]) -> anyhow::Result<(bool, String)> {
    let output = Command::new(path).args(args).output()?;
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), combined))
}

#[test]
fn live_network_scripts_support_dry_run() -> anyhow::Result<()> {
    let root = project_root();
    let preflight = root.join("scripts/live-network/preflight.sh");
    let harness = root.join("scripts/run-live-network-harness.sh");

    assert!(preflight.exists(), "missing {}", preflight.display());
    assert!(harness.exists(), "missing {}", harness.display());

    let (ok, out) = run_script(&preflight, &["--dry-run"])?;
    assert!(ok, "preflight dry-run failed:\n{}", out);

    let (ok, out) = run_script(&harness, &["--dry-run"])?;
    assert!(ok, "harness dry-run failed:\n{}", out);

    Ok(())
}

#[test]
fn live_harness_fails_before_writing_state_when_preflight_fails() -> anyhow::Result<()> {
    let root = project_root();
    let harness = root.join("scripts/run-live-network-harness.sh");

    let tmp = tempfile::Builder::new()
        .prefix("xmr-wow-live-harness-preflight-")
        .tempdir()?;
    let run_dir = tmp.path().join("run-dir-not-created");

    assert!(
        !run_dir.exists(),
        "test invariant: run dir should not exist yet"
    );

    let output = Command::new(&harness)
        .arg("--run-dir")
        .arg(&run_dir)
        .env("XMR_WOW_BIN", "/usr/bin/true")
        .env("XMR_WOW_LIVE_CONFIRM", "1")
        .env("XMR_DAEMON_URL", "http://127.0.0.1:1")
        .env("WOW_DAEMON_URL", "http://127.0.0.1:1")
        .env("SHARECHAIN_NODE_URL", "http://127.0.0.1:1")
        .env("ALICE_PASSWORD", "test")
        .env("BOB_PASSWORD", "test")
        .env("ALICE_XMR_REFUND_ADDRESS", "test")
        .env("BOB_WOW_REFUND_ADDRESS", "test")
        .env("ALICE_WOW_DESTINATION_ADDRESS", "test")
        .env("BOB_XMR_DESTINATION_ADDRESS", "test")
        .env("ALICE_XMR_MNEMONIC", "test test test test test test test test test test test test test test test test test test test test test test test test test")
        .env("BOB_WOW_MNEMONIC", "test test test test test test test test test test test test test test test test test test test test test test test test test")
        .output()?;

    assert!(
        !output.status.success(),
        "expected harness to fail when preflight cannot reach daemons"
    );

    assert!(
        !run_dir.exists(),
        "harness created run dir before preflight passed"
    );

    Ok(())
}

#[test]
fn live_network_harness_opt_in_e2e() -> anyhow::Result<()> {
    if std::env::var("RUN_LIVE_NETWORK_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping live-network harness e2e (set RUN_LIVE_NETWORK_TESTS=1 to enable)");
        return Ok(());
    }

    let root = project_root();
    let harness = root.join("scripts/run-live-network-harness.sh");

    let output = Command::new(&harness)
        .env("XMR_WOW_LIVE_CONFIRM", "1")
        .output()?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        anyhow::bail!(
            "live harness failed (requires live daemons and funded wallets). Output:\n{}",
            combined
        );
    }

    Ok(())
}
