/// Regression: view private key must only be printed under --verbose.
use std::fs;
use std::path::PathBuf;

/// Return the path to `crates/xmr-wow-client/src/main.rs` relative to the
/// workspace root, which we locate via the CARGO_MANIFEST_DIR env var that
/// Cargo sets when running integration tests.
fn main_rs_path() -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by cargo test");
    PathBuf::from(manifest_dir).join("src/main.rs")
}

#[test]
fn view_privkey_string_exists_in_source() {
    // guard: string must exist so the gating test below isn't vacuously true
    let source = fs::read_to_string(main_rs_path()).expect("cannot read main.rs");
    assert!(
        source.contains("View privkey"),
        "Expected 'View privkey' to still appear in main.rs (as a gated print). \
         If you intentionally removed it, update this test to reflect that \
         scan-test no longer prints key material at all."
    );
}

#[test]
fn view_privkey_only_printed_under_verbose_gate() {
    let source = fs::read_to_string(main_rs_path()).expect("cannot read main.rs");
    let lines: Vec<&str> = source.lines().collect();

    let leak_candidates: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains("View privkey"))
        .map(|(i, _)| i + 1) // 1-indexed for error messages
        .collect();

    assert!(
        !leak_candidates.is_empty(),
        "No 'View privkey' lines found: view_privkey_string_exists_in_source should have caught this"
    );

    for lineno in &leak_candidates {
        let idx = lineno - 1; // back to 0-indexed

        // look for `if verbose` guard in the 5 lines above
        let window_start = idx.saturating_sub(5);
        let window = &lines[window_start..=idx];

        let guarded = window.iter().any(|l| {
            l.contains("if verbose") || l.contains("if args.verbose") || l.contains("verbose {")
        });

        assert!(
            guarded,
            "Line {} of main.rs prints 'View privkey' without a visible verbose gate \
             in the 5 preceding lines. \
             Gate the print behind `if verbose {{ ... }}` and re-run the test.",
            lineno
        );
    }
}
