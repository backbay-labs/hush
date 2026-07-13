use serde::{Deserialize, Serialize};

pub const BUNDLE_FORMAT_VERSION: &str = "0.1.0";

/// A portable set of differential test cases: policies with actions to
/// evaluate. Serialized as JSON so every SDK replays identical cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseBundle {
    pub hushspec_diff: String,
    pub seed: u64,
    pub generated_by: String,
    pub groups: Vec<CaseGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseGroup {
    pub id: String,
    pub policy: serde_json::Value,
    pub actions: Vec<CaseAction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAction {
    pub id: String,
    pub action: serde_json::Value,
}

impl CaseBundle {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Fail-closed: rejects unknown fields and unsupported format versions.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let bundle: CaseBundle = serde_json::from_str(json).map_err(|error| error.to_string())?;
        if bundle.hushspec_diff != BUNDLE_FORMAT_VERSION {
            return Err(format!(
                "unsupported hushspec_diff version: {} (expected {BUNDLE_FORMAT_VERSION})",
                bundle.hushspec_diff
            ));
        }
        Ok(bundle)
    }

    pub fn case_count(&self) -> usize {
        self.groups.iter().map(|group| group.actions.len()).sum()
    }

    /// One-group, one-action bundle keyed "g0001/a0001".
    pub fn single_case(policy: serde_json::Value, action: serde_json::Value) -> Self {
        CaseBundle {
            hushspec_diff: BUNDLE_FORMAT_VERSION.to_string(),
            seed: 0,
            generated_by: "single-case".to_string(),
            groups: vec![CaseGroup {
                id: "g0001".to_string(),
                policy,
                actions: vec![CaseAction {
                    id: "a0001".to_string(),
                    action,
                }],
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CaseBundle {
        CaseBundle {
            hushspec_diff: BUNDLE_FORMAT_VERSION.to_string(),
            seed: 7,
            generated_by: "test".to_string(),
            groups: vec![CaseGroup {
                id: "g0001".to_string(),
                policy: serde_json::json!({"hushspec": "0.1.0"}),
                actions: vec![CaseAction {
                    id: "a0001".to_string(),
                    action: serde_json::json!({"type": "tool_call", "target": "read_file"}),
                }],
            }],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let bundle = sample();
        let json = bundle.to_json().expect("serializes");
        assert_eq!(CaseBundle::from_json(&json).expect("parses"), bundle);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bundle = sample();
        bundle.hushspec_diff = "9.9.9".to_string();
        let json = bundle.to_json().expect("serializes");
        let error = CaseBundle::from_json(&json).expect_err("must reject");
        assert!(error.contains("unsupported hushspec_diff version"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let json =
            r#"{"hushspec_diff":"0.1.0","seed":1,"generated_by":"t","groups":[],"extra":true}"#;
        assert!(CaseBundle::from_json(json).is_err());
    }

    #[test]
    fn counts_cases_and_builds_single_case_bundles() {
        assert_eq!(sample().case_count(), 1);
        let single = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.1.0"}),
            serde_json::json!({"type": "egress", "target": "api.example.com"}),
        );
        assert_eq!(single.case_count(), 1);
        assert_eq!(single.groups[0].id, "g0001");
        assert_eq!(single.groups[0].actions[0].id, "a0001");
    }

    #[test]
    fn parses_sample_testdata() {
        let bundle = CaseBundle::from_json(include_str!("../testdata/sample-bundle.json"))
            .expect("sample bundle parses");
        assert_eq!(bundle.case_count(), 4);
        assert_eq!(bundle.groups.len(), 2);
    }
}
