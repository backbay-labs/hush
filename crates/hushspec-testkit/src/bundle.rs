use hushspec::receipt::Actor;
use serde::{Deserialize, Serialize};

pub const BUNDLE_FORMAT_VERSION: &str = "0.1.0";

/// The fixed evaluation time of every audited differential case, as
/// `fixtures/receipts/expected/README.md` spells it.
pub const AUDIT_CLOCK: &str = "2026-09-15T12:00:00.000Z";
/// `AUDIT_CLOCK` in milliseconds since the Unix epoch. The receipt id of a
/// case is `deterministic_uuid_v7(AUDIT_CLOCK_MILLIS, case index)`.
pub const AUDIT_CLOCK_MILLIS: u64 = 1_789_473_600_000;

/// [`AUDIT_CLOCK_MILLIS`] as an instant (2026-09-15T12:00:00Z).
///
/// Every vector that needs a clock reads it from here, so a receipt recorded
/// by one part of the testkit and verified by another cannot disagree about
/// what "now" was.
#[must_use]
pub fn audit_clock() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(AUDIT_CLOCK_MILLIS as i64)
        .expect("AUDIT_CLOCK_MILLIS is a representable instant")
}

/// A portable set of differential test cases: policies with actions to
/// evaluate. Serialized as JSON so every SDK replays identical cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseBundle {
    pub hushspec_diff: String,
    pub seed: u64,
    pub generated_by: String,
    /// The audited-evaluation inputs every SDK replays (added after 0.1.0,
    /// additively: a bundle without it replays the defaults, which are exactly
    /// the fixed inputs the receipt vectors use).
    #[serde(default)]
    pub audit: AuditSpec,
    pub groups: Vec<CaseGroup>,
}

/// Everything a receipt needs that is neither the policy nor the action, fixed
/// in the bundle so four SDKs produce the *same* receipt for a case rather than
/// four receipts that merely describe the same decision.
///
/// Every field has a default, and the defaults are the fixed inputs of
/// `fixtures/receipts/expected/README.md`, so an older bundle (no `audit` key)
/// and a newer one agree on what to replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditSpec {
    /// Evaluation time: RFC 3339 UTC, millisecond precision, `Z` suffix.
    pub clock: String,
    /// `time_source` recorded in every receipt.
    pub time_source: String,
    /// `enforcement.mode`; the outcome is the one implied by the decision.
    pub enforcement_mode: String,
    /// The actor every receipt names.
    pub actor: Actor,
    /// Receipt-id seed of the bundle's **first** case. Each case adds one, in
    /// bundle order (every action of every group, rejected policies included),
    /// so a case's receipt id is
    /// `deterministic_uuid_v7(clock millis, index_base + position)`.
    ///
    /// A single-case bundle carved out of a larger one sets this to that
    /// case's position, which is what makes the second pass that fetches full
    /// receipts reproduce the very receipt the first pass hashed.
    pub index_base: u64,
    /// When true a harness reports the whole canonical receipt per case
    /// (`results.<case>.receipt`), not just its hash.
    pub emit_receipts: bool,
}

impl Default for AuditSpec {
    fn default() -> Self {
        Self {
            clock: AUDIT_CLOCK.to_string(),
            time_source: "trusted".to_string(),
            enforcement_mode: "enforce".to_string(),
            actor: Actor {
                agent_id: Some("fixture-agent".to_string()),
                session_id: Some("fixture-session".to_string()),
                principal: Some("fixture@hushspec.dev".to_string()),
                runtime: Some("hushspec-conformance/0.2".to_string()),
            },
            index_base: 0,
            emit_receipts: false,
        }
    }
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

impl AuditSpec {
    /// The evaluation time as a `chrono` instant.
    ///
    /// # Errors
    ///
    /// The clock is not RFC 3339. Fail-closed: a bundle whose clock cannot be
    /// read has no reproducible receipts, so callers must not fall back to
    /// "now".
    pub fn clock_datetime(&self) -> Result<chrono::DateTime<chrono::Utc>, String> {
        chrono::DateTime::parse_from_rfc3339(&self.clock)
            .map(|instant| instant.with_timezone(&chrono::Utc))
            .map_err(|error| format!("audit.clock {:?} is not RFC 3339: {error}", self.clock))
    }

    /// The evaluation time in milliseconds since the Unix epoch: the receipt
    /// id's 48-bit timestamp.
    ///
    /// # Errors
    ///
    /// As [`AuditSpec::clock_datetime`], plus a clock before the epoch.
    pub fn clock_millis(&self) -> Result<u64, String> {
        let millis = self.clock_datetime()?.timestamp_millis();
        u64::try_from(millis).map_err(|_| format!("audit.clock {:?} predates 1970", self.clock))
    }
}

impl CaseBundle {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// The 0-based position of a case key in the bundle, counting every action
    /// of every group in order. `index_base + position` seeds that case's
    /// receipt id in every SDK.
    #[must_use]
    pub fn case_position(&self, case_key: &str) -> Option<u64> {
        let mut position = 0u64;
        for group in &self.groups {
            for case in &group.actions {
                if format!("{}/{}", group.id, case.id) == case_key {
                    return Some(position);
                }
                position += 1;
            }
        }
        None
    }

    /// The group, action and bundle-order position behind a `gNNNN/aNNNN`
    /// case key, or `None` when this bundle never produced it.
    #[must_use]
    pub fn find_case(&self, case_key: &str) -> Option<(&CaseGroup, &CaseAction, u64)> {
        let (group_id, case_id) = case_key.split_once('/')?;
        let mut position = 0u64;
        for group in &self.groups {
            for case in &group.actions {
                if group.id == group_id && case.id == case_id {
                    return Some((group, case, position));
                }
                position += 1;
            }
        }
        None
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
            audit: AuditSpec::default(),
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

    /// [`CaseBundle::single_case`] replayed as if it were case `position` of a
    /// larger bundle, with the full receipt requested.
    ///
    /// This is how a receipt divergence is turned into a readable diff: the
    /// first pass compares hashes, and this bundle re-runs the one case that
    /// disagreed under the same receipt id, so the receipts it brings back are
    /// the receipts that were hashed.
    #[must_use]
    pub fn single_case_at(
        policy: serde_json::Value,
        action: serde_json::Value,
        audit: &AuditSpec,
        position: u64,
    ) -> Self {
        let mut bundle = CaseBundle::single_case(policy, action);
        bundle.audit = AuditSpec {
            index_base: audit.index_base.saturating_add(position),
            emit_receipts: true,
            ..audit.clone()
        };
        bundle
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
            audit: AuditSpec::default(),
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

    /// The `audit` block is additive: a bundle written before it existed still
    /// parses, and replays the very inputs the receipt vectors fix. Were it
    /// required instead, every stored bundle artifact would stop replaying.
    #[test]
    fn a_bundle_without_audit_replays_the_fixed_inputs() {
        let json = r#"{"hushspec_diff":"0.1.0","seed":1,"generated_by":"t","groups":[]}"#;
        let bundle = CaseBundle::from_json(json).expect("older bundles still parse");
        assert_eq!(bundle.audit, AuditSpec::default());
        assert_eq!(bundle.audit.clock, AUDIT_CLOCK);
        assert_eq!(bundle.audit.time_source, "trusted");
        assert_eq!(bundle.audit.enforcement_mode, "enforce");
        assert_eq!(
            bundle.audit.actor.agent_id.as_deref(),
            Some("fixture-agent")
        );
        assert!(!bundle.audit.emit_receipts);
        assert_eq!(
            bundle.audit.clock_millis().expect("clock parses"),
            AUDIT_CLOCK_MILLIS
        );
    }

    #[test]
    fn a_partial_audit_block_fills_in_the_rest() {
        let json = r#"{"hushspec_diff":"0.1.0","seed":1,"generated_by":"t",
            "audit":{"emit_receipts":true,"index_base":12},"groups":[]}"#;
        let bundle = CaseBundle::from_json(json).expect("parses");
        assert!(bundle.audit.emit_receipts);
        assert_eq!(bundle.audit.index_base, 12);
        assert_eq!(bundle.audit.clock, AUDIT_CLOCK);
    }

    #[test]
    fn an_unreadable_clock_fails_closed() {
        let audit = AuditSpec {
            clock: "yesterday".to_string(),
            ..AuditSpec::default()
        };
        assert!(audit.clock_millis().is_err());
    }

    #[test]
    fn case_positions_seed_receipt_ids_in_bundle_order() {
        let bundle = CaseBundle::from_json(include_str!("../testdata/sample-bundle.json"))
            .expect("sample bundle parses");
        assert_eq!(bundle.case_position("g0001/a0001"), Some(0));
        assert_eq!(bundle.case_position("g0001/a0002"), Some(1));
        assert_eq!(bundle.case_position("g0002/a0001"), Some(2));
        assert_eq!(bundle.case_position("g9999/a9999"), None);

        // A carved-out single case keeps the receipt id it had in the bundle.
        let carved = CaseBundle::single_case_at(
            bundle.groups[1].policy.clone(),
            bundle.groups[1].actions[0].action.clone(),
            &bundle.audit,
            2,
        );
        assert_eq!(carved.audit.index_base, 2);
        assert!(carved.audit.emit_receipts);
        assert_eq!(carved.audit.clock, bundle.audit.clock);
    }

    #[test]
    fn parses_sample_testdata() {
        let bundle = CaseBundle::from_json(include_str!("../testdata/sample-bundle.json"))
            .expect("sample bundle parses");
        assert_eq!(bundle.case_count(), 4);
        assert_eq!(bundle.groups.len(), 2);
    }
}
