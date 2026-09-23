use hushspec_testkit::external::{json, model::EngineProfile, snapshot};
use hushspec_testkit::manifest::{Manifest, ManifestEntry, digest_bytes};
use serde_json::json;
use std::path::Path;

fn profile() -> serde_json::Value {
    json!({"protocol":"0.1.0","implementation":{"name":"test","version":"1","language":"Go"},
        "executable":{"path":"engine","sha256":"a".repeat(64)},"args":[],"error_codes":"registry"})
}

#[test]
fn external_json_rejects_ambiguity_and_excessive_depth() {
    for bytes in [
        br#"{"a":1,"\u0061":2}"#.as_slice(),
        b"{} {}",
        b"[NaN]",
        b"\xff",
    ] {
        assert!(json::parse_json(bytes).is_err());
    }
    assert!(json::parse_json(format!("{}0{}", "[".repeat(65), "]".repeat(65)).as_bytes()).is_err());
    assert!(json::parse_json(format!("{}0{}", "[".repeat(64), "]".repeat(64)).as_bytes()).is_ok());
}

#[test]
fn external_profile_is_closed_and_rejects_null_or_invalid_identity() {
    assert!(
        json::decode::<EngineProfile>(&serde_json::to_vec(&profile()).unwrap(), "engine-profile")
            .is_ok()
    );
    for (key, value) in [
        ("extra", json!(true)),
        ("materials", json!(null)),
        ("protocol", json!("9")),
        ("args", json!(null)),
        ("error_codes", json!("sometimes")),
    ] {
        let mut p = profile();
        p[key] = value;
        assert!(
            json::decode::<EngineProfile>(&serde_json::to_vec(&p).unwrap(), "engine-profile")
                .is_err(),
            "{key}"
        );
    }
    for digest in ["xyz", &"A".repeat(64)] {
        let mut p = profile();
        p["executable"]["sha256"] = json!(digest);
        assert!(
            json::decode::<EngineProfile>(&serde_json::to_vec(&p).unwrap(), "engine-profile")
                .is_err()
        );
    }
}

fn corpus(root: &Path) {
    std::fs::create_dir(root.join("core")).unwrap();
    std::fs::write(root.join("core/input.yaml"), b"hushspec: '1.0.0'\n").unwrap();
    let manifest = Manifest {
        manifest_version: "0.1".into(),
        fixtures_version: "1".into(),
        generated_at: "now".into(),
        files: vec![ManifestEntry {
            path: "fixtures/core/input.yaml".into(),
            sha256: digest_bytes(b"hushspec: '1.0.0'\n"),
            category: "valid".into(),
            module: "core".into(),
            level: 1,
        }],
    };
    std::fs::write(
        root.join("MANIFEST.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}

fn mutate_manifest(root: &Path, f: impl FnOnce(&mut Manifest)) {
    let path = root.join("MANIFEST.json");
    let mut manifest: Manifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    f(&mut manifest);
    std::fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

#[test]
fn external_captured_bytes_survive_path_replacement_and_enforce_caps() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    let captured = snapshot::snapshot_corpus(dir.path()).unwrap();
    let path = dir.path().join("core/input.yaml");
    std::fs::write(&path, b"replacement").unwrap();
    assert_eq!(
        captured.files["fixtures/core/input.yaml"].bytes,
        b"hushspec: '1.0.0'\n"
    );
    assert!(snapshot::snapshot_corpus(dir.path()).is_err());
    assert!(snapshot::snapshot_file(&path, "test", 5).is_err());
    assert!(snapshot::snapshot_file(dir.path(), "test", 5).is_err());
}

#[test]
fn external_corpus_rejects_missing_unlisted_duplicate_and_escaping_entries() {
    for kind in [
        "missing",
        "unlisted",
        "duplicate",
        "escape",
        "category",
        "digest",
    ] {
        let dir = tempfile::tempdir().unwrap();
        corpus(dir.path());
        match kind {
            "missing" => std::fs::remove_file(dir.path().join("core/input.yaml")).unwrap(),
            "unlisted" => std::fs::write(dir.path().join("extra"), b"extra").unwrap(),
            _ => mutate_manifest(dir.path(), |m| match kind {
                "duplicate" => m.files.push(m.files[0].clone()),
                "escape" => m.files[0].path = "fixtures/../secret".into(),
                "category" => m.files[0].category = "future-unknown".into(),
                "digest" => m.files[0].sha256 = "bad".into(),
                _ => unreachable!(),
            }),
        }
        assert!(snapshot::snapshot_corpus(dir.path()).is_err(), "{kind}");
    }
}

#[cfg(unix)]
#[test]
fn external_corpus_rejects_symlinks_and_physical_aliases() {
    use std::os::unix::fs::symlink;
    for symlinked in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        corpus(dir.path());
        let source = dir.path().join("core/input.yaml");
        let alias = dir.path().join("core/alias.yaml");
        if symlinked {
            symlink(&source, &alias).unwrap();
        } else {
            std::fs::hard_link(&source, &alias).unwrap();
        }
        mutate_manifest(dir.path(), |m| {
            let mut e = m.files[0].clone();
            e.path = "fixtures/core/alias.yaml".into();
            m.files.push(e);
        });
        assert!(snapshot::snapshot_corpus(dir.path()).is_err());
    }
}

#[test]
fn external_image_check_rejects_scripts_and_dynamic_elf() {
    assert!(snapshot::validate_engine_image(b"#!/bin/sh\nexit 0").is_err());
    #[cfg(target_os = "linux")]
    assert!(snapshot::validate_engine_image(&std::fs::read("/bin/sh").unwrap()).is_err());
}

#[test]
fn external_corpus_file_aggregate_and_entry_limits_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    for limits in [
        snapshot::CorpusLimits {
            file_bytes: 1,
            total_bytes: 1024,
            entries: 10,
        },
        snapshot::CorpusLimits {
            file_bytes: 1024,
            total_bytes: 1,
            entries: 10,
        },
        snapshot::CorpusLimits {
            file_bytes: 1024,
            total_bytes: 1024,
            entries: 0,
        },
    ] {
        assert!(snapshot::snapshot_corpus_with_limits(dir.path(), limits).is_err());
    }
}

#[test]
fn external_response_rejects_null_missing_unknown_and_duplicate_result() {
    use hushspec_testkit::external::model::Response;
    let good = json!({"protocol":"0.1.0","run_id":"run","case_id":"case","operation":"parse",
        "input_sha256":"a".repeat(64),"result":{"status":"ok","value":{"hushspec":"1.0.0"}}});
    assert!(
        json::decode::<Response>(&serde_json::to_vec(&good).unwrap(), "engine-response").is_ok()
    );
    for result in [
        json!(null),
        json!({"status":"ok"}),
        json!({"status":"ok","value":{},"passed":true}),
        json!({"status":"rejected","phase":"parse","diagnostic":"x","code":null}),
    ] {
        let mut bad = good.clone();
        bad["result"] = result;
        assert!(
            json::decode::<Response>(&serde_json::to_vec(&bad).unwrap(), "engine-response")
                .is_err()
        );
    }
    let bytes = serde_json::to_string(&good).unwrap().replace(
        "\"run_id\":\"run\"",
        "\"run_id\":\"run\",\"run_id\":\"other\"",
    );
    assert!(json::decode::<Response>(bytes.as_bytes(), "engine-response").is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn external_controller_snapshot_identifies_running_inode() {
    if let Ok(path) = std::env::var("HUSH_TEST_REPLACED_LAUNCH") {
        let expected = std::env::var("HUSH_TEST_RUNNING_DIGEST").unwrap();
        let replacement = format!("{path}.replacement");
        std::fs::write(&replacement, b"new pathname bytes").unwrap();
        std::fs::rename(replacement, &path).unwrap();
        let running = snapshot::snapshot_controller().unwrap();
        assert_eq!(running.sha256, expected);
        assert_ne!(running.sha256, digest_bytes(&std::fs::read(path).unwrap()));
        return;
    }
    let running = snapshot::snapshot_controller().unwrap();
    assert_eq!(
        running.sha256,
        digest_bytes(&std::fs::read("/proc/self/exe").unwrap())
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("launch");
    std::fs::copy("/proc/self/exe", &path).unwrap();
    let output = std::process::Command::new(&path)
        .args([
            "--exact",
            "external_controller_snapshot_identifies_running_inode",
            "--nocapture",
        ])
        .env("HUSH_TEST_REPLACED_LAUNCH", &path)
        .env("HUSH_TEST_RUNNING_DIGEST", running.sha256)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
