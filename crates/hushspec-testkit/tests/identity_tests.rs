use std::process::Command;

#[test]
fn reference_runner_rejects_identity_overrides() {
    for flag in [
        "--implementation",
        "--implementation-version",
        "--implementation-language",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        let output = Command::new(env!("CARGO_BIN_EXE_hushspec-testkit"))
            .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
            .args([
                "--report",
                report.to_str().unwrap(),
                flag,
                "not-the-reference",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{flag}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
        assert!(!report.exists());
    }
}
