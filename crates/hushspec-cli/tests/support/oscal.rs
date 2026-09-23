use crate::evidence::{Fixture, digest};
use hushspec::receipt::{AuditConfig, AuditContext, EnforcementMode, evaluate_audited};
use hushspec::signing::{SignOptions, parse_private_key_pem, sign_receipt};
use serde_json::json;

impl Fixture {
    pub fn monitor() -> Self {
        let mut fixture = Self::new();
        let text = "hushspec: '1.0.0'\nname: synthetic-pilot\nrules:\n  tool_access:\n    require_confirmation: [risky_tool]\n    default: block\nmetadata:\n  controls:\n    - framework: pilot\n      control_id: tool-access\n      rule_paths: [rules.tool_access]\n";
        std::fs::write(fixture.dir.path().join("policy.yaml"), text).unwrap();
        let spec = hushspec::HushSpec::parse(text).unwrap();
        let resolution = hushspec::resolve_with_options(
            &spec,
            Some("policy.yaml"),
            &|_, _| panic!("resolved example must not load another policy"),
            &Default::default(),
        )
        .unwrap();
        let action =
            serde_json::from_value(json!({"type":"tool_call","target":"risky_tool"})).unwrap();
        let clock = "2026-09-15T12:00:00Z".parse().unwrap();
        let receipt = evaluate_audited(
            &resolution,
            &action,
            &AuditConfig {
                record_duration: false,
                ..Default::default()
            },
            &AuditContext {
                clock: Some(clock),
                receipt_id: Some("01994b7e-2c1a-7c3e-8f4a-0123456789ab".into()),
                enforcement_mode: EnforcementMode::Monitor,
                ..Default::default()
            },
        );
        assert_eq!(receipt.decision, hushspec::Decision::Warn);
        let key = parse_private_key_pem(
            &std::fs::read_to_string(
                fixture
                    .root
                    .join("fixtures/signing/keys/test-signing.key.pem"),
            )
            .unwrap(),
        )
        .unwrap();
        let signed = sign_receipt(
            &receipt,
            &key,
            &SignOptions {
                signed_at: Some(clock),
                ..Default::default()
            },
        )
        .unwrap();
        let bytes = format!("{}\n", serde_json::to_string(&signed).unwrap()).into_bytes();
        std::fs::write(fixture.dir.path().join("evidence.jsonl"), &bytes).unwrap();
        fixture.profile["streams"][0]["files"][0]["sha256"] = digest(&bytes).into();
        fixture.profile["streams"][0]["allowed_policy_hashes"][0] =
            receipt.policy.content_hash.clone().into();
        fixture.profile["policies"][0]["content_hash"] = receipt.policy.content_hash.into();
        fixture.profile["policies"][0]["artifact"] =
            json!({"path":"policy.yaml","sha256":digest(text.as_bytes())});
        fixture.save_profile();
        std::fs::create_dir(fixture.dir.path().join("context")).unwrap();
        for name in ["context.json", "ap.json", "ssp.json", "catalog.json"] {
            std::fs::copy(
                fixture.root.join("fixtures/assurance/oscal").join(name),
                fixture.dir.path().join("context").join(name),
            )
            .unwrap();
        }
        fixture
    }

    pub fn command_oscal(&self) -> assert_cmd::Command {
        self.command_with(&[
            "--format",
            "oscal",
            "--experimental-oscal",
            "--assessment-context",
            "context/context.json",
            "--native-report-out",
            "report.json",
            "--out",
            "assessment-results.json",
            "--verification-out",
            "verification.json",
        ])
    }
}
