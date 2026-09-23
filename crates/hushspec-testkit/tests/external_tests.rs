#![cfg(target_os = "linux")]

use hushspec_testkit::{
    external::{json, model::ExecutionRecord},
    manifest::{Manifest, ManifestEntry, digest_bytes},
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Mutex, OnceLock},
};

// Every real controller retains its running image. Serialize these black-box
// runs to keep memory/disk bounded on small CI runners without changing limits.
static RUN_LOCK: Mutex<()> = Mutex::new(());
fn controller_image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("controller");
        std::fs::copy(env!("CARGO_BIN_EXE_hushspec-testkit"), &binary).unwrap();
        let result = Command::new("strip")
            .arg("--strip-debug")
            .arg(&binary)
            .output()
            .expect("binutils strip is required for the Linux fault-test image");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        std::fs::read(binary).unwrap()
    })
}
fn engine_image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("engine");
        let result = Command::new("go")
            .env("CGO_ENABLED", "0")
            .args(["build", "-trimpath", "-o"])
            .arg(&binary)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/external_engine.go"))
            .output()
            .expect("Go is required; an unavailable engine is not a skip");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        std::fs::read(binary).unwrap()
    })
}

struct Fixture {
    dir: tempfile::TempDir,
    controller: PathBuf,
    fixtures: PathBuf,
    engine: PathBuf,
    profile: PathBuf,
    out: PathBuf,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fixtures = dir.path().join("fixtures");
        std::fs::create_dir(&fixtures).unwrap();
        let controller = dir.path().join("controller");
        std::fs::write(&controller, controller_image()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o500)).unwrap();
        let engine = dir.path().join("original-engine");
        std::fs::write(&engine, engine_image()).unwrap();
        let profile = dir.path().join("profile.json");
        let out = dir.path().join("packet");
        let value = json!({"protocol":"0.1.0","implementation":{"name":"fault-fixture","version":"test","language":"Go"},
            "executable":{"path":"original-engine","sha256":digest_bytes(engine_image())},"args":[mode],"error_codes":"registry"});
        std::fs::write(&profile, serde_json::to_vec(&value).unwrap()).unwrap();
        let fixture = Self {
            dir,
            controller,
            fixtures,
            engine,
            profile,
            out,
        };
        fixture.corpus(&[
            ("one.yaml", "valid", 1, "hushspec: '1.0.0'\n"),
            ("two.yaml", "valid", 1, "hushspec: '1.0.0'\n"),
        ]);
        fixture
    }
    fn corpus(&self, files: &[(&str, &str, u8, &str)]) {
        let mut entries = Vec::new();
        for (name, category, level, bytes) in files {
            std::fs::write(self.fixtures.join(name), bytes).unwrap();
            entries.push(ManifestEntry {
                path: format!("fixtures/{name}"),
                sha256: digest_bytes(bytes.as_bytes()),
                category: (*category).into(),
                module: "core".into(),
                level: *level,
            });
        }
        let manifest = Manifest {
            manifest_version: "0.1".into(),
            fixtures_version: "1.0.0".into(),
            generated_at: "2026-09-23T00:00:00Z".into(),
            files: entries,
        };
        std::fs::write(
            self.fixtures.join("MANIFEST.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }
    fn append_arg(&self, arg: &Path) {
        let mut profile: Value =
            serde_json::from_slice(&std::fs::read(&self.profile).unwrap()).unwrap();
        profile["args"].as_array_mut().unwrap().push(json!(arg));
        std::fs::write(&self.profile, serde_json::to_vec(&profile).unwrap()).unwrap();
    }
    fn run(&self, level: u8, extra: &[&str]) -> Output {
        let _guard = RUN_LOCK.lock().unwrap();
        Command::new(&self.controller)
            .arg("external")
            .arg("--engine")
            .arg(&self.profile)
            .arg("--fixtures")
            .arg(&self.fixtures)
            .arg("--out")
            .arg(&self.out)
            .arg("--level")
            .arg(level.to_string())
            .args(extra)
            .output()
            .unwrap()
    }
    fn record(&self) -> ExecutionRecord {
        json::decode(
            &std::fs::read(self.out.join("execution.json")).unwrap(),
            "conformance-execution",
        )
        .unwrap()
    }
    fn report(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.out.join("report.json")).unwrap()).unwrap()
    }
}

#[test]
fn external_cli_publishes_digest_bound_packet_and_controller_owned_identity() {
    let f = Fixture::new("honest");
    let result = f.run(0, &[]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let record = f.record();
    let report = f.report();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&f.out).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(report["highest_level"], 0);
    assert_eq!(report["implementation"]["name"], "fault-fixture");
    assert_eq!(record.cases.len(), record.planned.len());
    for artifact in [
        &record.report,
        &record.profile,
        &record.manifest,
        &record.engine,
        &record.controller,
    ] {
        let bytes = std::fs::read(f.out.join(&artifact.path)).unwrap();
        assert_eq!(artifact.sha256, digest_bytes(&bytes));
        assert_eq!(artifact.bytes, bytes.len());
    }
    for case in &record.cases {
        for artifact in [&case.request, &case.input, &case.stdout, &case.stderr] {
            assert_eq!(
                artifact.sha256,
                digest_bytes(&std::fs::read(f.out.join(&artifact.path)).unwrap())
            );
        }
    }
}

#[test]
fn external_cli_bad_protocol_or_process_never_qualifies_and_retains_remaining_slots() {
    for mode in [
        "stale",
        "wrong_case",
        "wrong_operation",
        "wrong_digest",
        "missing",
        "duplicate",
        "multiple",
        "malformed",
        "exit",
        "signal",
        "hang",
        "stdout",
        "stderr",
        "error",
    ] {
        let f = Fixture::new(mode);
        let result = f.run(
            0,
            &[
                "--timeout-ms",
                "100",
                "--stdout-bytes",
                "1024",
                "--stderr-bytes",
                "512",
            ],
        );
        assert_eq!(
            result.status.code(),
            Some(1),
            "{mode}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let record = f.record();
        assert_eq!(record.cases.len(), 1, "{mode}");
        assert_eq!(record.planned.len(), 2, "{mode}");
        assert_ne!(f.report()["highest_level"], 0, "{mode}");
        assert!(
            f.report()["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["level"] == 0 && r["status"] == "not_attempted")
        );
    }
}

#[test]
fn external_cli_unsupported_and_lying_observations_remain_unqualified() {
    let f = Fixture::new("unsupported");
    let result = f.run(0, &[]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(f.record().cases.len(), 2);
    let f = Fixture::new("lying");
    f.corpus(&[("one.yaml","valid",1,"hushspec: '1.0.0'\n"),("two.yaml","valid",1,"hushspec: '1.0.0'\n"),
        ("decision.yaml","evaluation",3,"hushspec_test: '0.1.0'\ndescription: unknown action\npolicy: {hushspec: '1.0.0'}\ncases: [{description: deny, action: {type: unknown}, expect: {decision: deny}}]\n")]);
    let result = f.run(3, &[]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = f.report();
    assert!(
        report["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["path"] == "fixtures/decision.yaml#0/evaluate" && r["status"] == "fail")
    );
}

#[test]
fn external_cli_executes_and_retains_captured_bytes_after_original_path_mutation() {
    for mode in ["replace_original", "replace_fixture"] {
        let f = Fixture::new(mode);
        let path = if mode == "replace_original" {
            f.engine.clone()
        } else {
            f.fixtures.join("two.yaml")
        };
        f.append_arg(&path);
        let result = f.run(0, &[]);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{mode}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(path).unwrap(), b"changed after capture");
        assert_eq!(f.record().engine.sha256, digest_bytes(engine_image()));
        if mode == "replace_fixture" {
            assert_eq!(
                std::fs::read(f.out.join("inputs/fixtures/two.yaml")).unwrap(),
                b"hushspec: '1.0.0'\n"
            );
        }
    }
}

#[test]
fn external_cli_refuses_substitution_existing_output_and_input_output_collision() {
    let f = Fixture::new("honest");
    std::fs::write(&f.engine, b"replaced before capture").unwrap();
    let result = f.run(0, &[]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!f.out.exists());
    let f = Fixture::new("honest");
    std::fs::create_dir(&f.out).unwrap();
    std::fs::write(f.out.join("sentinel"), b"keep").unwrap();
    assert_eq!(f.run(0, &[]).status.code(), Some(2));
    assert_eq!(std::fs::read(f.out.join("sentinel")).unwrap(), b"keep");
    assert!(!f.out.join("execution.json").exists());
    let mut f = Fixture::new("honest");
    f.out = f.fixtures.join("packet");
    assert_eq!(f.run(0, &[]).status.code(), Some(2));
    assert!(!f.out.exists());
    let mut f = Fixture::new("honest");
    f.out = f.dir.path().join("missing-parent/packet");
    assert_eq!(f.run(0, &[]).status.code(), Some(2));
    assert!(!f.out.exists());
}
