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
fn regression_matrix_supports_dry_run() -> anyhow::Result<()> {
    let root = project_root();
    let script = root.join("scripts/run-e2e-regression-matrix.sh");

    assert!(script.exists(), "missing {}", script.display());

    let temp = tempfile::Builder::new()
        .prefix("xmr-wow-regression-matrix-dry-run-")
        .tempdir()?;
    let artifact_root = temp.path().join("artifacts");
    let work_root = temp.path().join("work");
    let artifact_root_str = artifact_root.to_string_lossy().into_owned();
    let work_root_str = work_root.to_string_lossy().into_owned();

    let (ok, out) = run_script(
        &script,
        &[
            "--dry-run",
            "--artifact-root",
            artifact_root_str.as_str(),
            "--work-root",
            work_root_str.as_str(),
        ],
    )?;
    assert!(ok, "matrix dry-run failed:\n{}", out);
    assert!(
        out.contains("shadow-oob")
            && out.contains("shadow-sharechain")
            && out.contains("live-dry-run"),
        "matrix dry-run output missing expected lanes:\n{}",
        out
    );
    assert!(
        !artifact_root.exists(),
        "matrix dry-run should not create artifact directories"
    );

    Ok(())
}
