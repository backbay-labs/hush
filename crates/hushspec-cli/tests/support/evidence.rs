use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub profile: serde_json::Value,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

impl Fixture {
    pub fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = tempfile::tempdir().unwrap();
        let signed: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("fixtures/receipts/signed/valid/allow-egress.signed.json"))
                .unwrap(),
        )
        .unwrap();
        let bytes = format!("{signed}\n").into_bytes();
        std::fs::write(dir.path().join("evidence.jsonl"), &bytes).unwrap();
        let mut profile: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("fixtures/assurance/profile-shape.json")).unwrap(),
        )
        .unwrap();
        profile["streams"][0]["files"][0]["sha256"] = digest(&bytes).into();
        let fixture = Self { dir, root, profile };
        fixture.save_profile();
        fixture
    }

    pub fn save_profile(&self) {
        std::fs::write(
            self.dir.path().join("profile.json"),
            self.profile.to_string(),
        )
        .unwrap();
    }

    pub fn command(&self) -> assert_cmd::Command {
        self.command_with(&[
            "--format",
            "json",
            "--out",
            "report.json",
            "--verification-out",
            "verification.json",
        ])
    }

    pub fn command_with(&self, output: &[&str]) -> assert_cmd::Command {
        let mut command = assert_cmd::Command::cargo_bin("h2h").unwrap();
        command
            .current_dir(self.dir.path())
            .args([
                "report",
                "evidence.jsonl",
                "--evidence-profile",
                "profile.json",
                "--now",
                "2026-09-15T12:00:00Z",
                "--keyring",
            ])
            .arg(self.root.join("fixtures/signing/keys/keyring.json"))
            .args(output);
        command
    }

    pub fn json(&self, name: &str) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.dir.path().join(name)).unwrap()).unwrap()
    }
}
