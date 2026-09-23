use hushspec::report::{ControlEvidenceRow, ControlsEvidence, FrameworkEvidence, Report};
use hushspec::{DecisionReceipt, HushSpec, RuleTraceEntry};
use std::collections::BTreeSet;

/// Does a control mapping's `rule_paths` entry cover this trace entry?
///
/// A mapping that names a rule block (`rules`, `rules.egress`) covers every
/// entry that block recorded, exactly as `h2h lint` counts coverage. A deeper
/// mapping (`rules.egress.block`) is only evidenced by an entry whose recorded
/// `rule_path` is at or under it -- otherwise a report would credit
/// `rules.egress.block` for an evaluation that matched the allowlist.
pub(crate) fn mapping_covers(
    doc: &serde_json::Value,
    rule_path: &str,
    entry: &RuleTraceEntry,
) -> bool {
    let depth = rule_path.split('.').count();
    if rule_path.starts_with("rules") && depth <= 2 && !rule_path.contains('[') {
        return crate::controls::path_covers_block(
            doc,
            rule_path,
            &format!("rules.{}", entry.rule_block),
        );
    }
    entry
        .rule_path
        .as_deref()
        .is_some_and(|recorded| path_at_or_under(recorded, rule_path))
}

fn path_at_or_under(recorded: &str, prefix: &str) -> bool {
    recorded == prefix
        || (recorded.len() > prefix.len()
            && recorded.starts_with(prefix)
            && matches!(recorded.as_bytes()[prefix.len()], b'.' | b'['))
}

pub(crate) fn build_control_evidence(
    source: &str,
    spec: &HushSpec,
    content_hash: &str,
    receipts: &[&DecisionReceipt],
    report: &Report,
) -> ControlsEvidence {
    let doc = crate::controls::document_json(spec);
    let mappings = spec
        .metadata
        .as_ref()
        .map(|metadata| metadata.controls.as_slice())
        .unwrap_or_default();

    // Only receipts evaluated under this exact policy can evidence its
    // mappings; anything else would credit a control with an evaluation that
    // ran under different rules.
    let matching: Vec<&&DecisionReceipt> = receipts
        .iter()
        .filter(|receipt| receipt.policy.content_hash == content_hash)
        .collect();
    let mut frameworks: Vec<FrameworkEvidence> = Vec::new();
    let mut mapped_blocks: BTreeSet<String> = BTreeSet::new();
    for mapping in mappings {
        let mut row = ControlEvidenceRow {
            control_id: mapping.control_id.clone(),
            rule_paths: mapping.rule_paths.clone(),
            rule_blocks: Vec::new(),
            receipts: 0,
            evaluated: 0,
            fired: 0,
            denied: 0,
            last_seen: None,
        };
        let mut blocks: BTreeSet<String> = BTreeSet::new();
        for receipt in &matching {
            let mut touched = false;
            for entry in &receipt.rule_trace {
                if !mapping
                    .rule_paths
                    .iter()
                    .any(|path| mapping_covers(&doc, path, entry))
                {
                    continue;
                }
                touched = true;
                blocks.insert(entry.rule_block.clone());
                if entry.evaluated {
                    row.evaluated += 1;
                }
                match entry.outcome {
                    hushspec::receipt::RuleOutcome::Deny => {
                        row.fired += 1;
                        row.denied += 1;
                    }
                    hushspec::receipt::RuleOutcome::Warn => row.fired += 1,
                    _ => {}
                }
            }
            if touched {
                row.receipts += 1;
                if row
                    .last_seen
                    .as_ref()
                    .is_none_or(|seen| receipt.timestamp > *seen)
                {
                    row.last_seen = Some(receipt.timestamp.clone());
                }
            }
        }
        mapped_blocks.extend(blocks.iter().cloned());
        row.rule_blocks = blocks.into_iter().collect();

        match frameworks
            .iter_mut()
            .find(|group| group.framework == mapping.framework)
        {
            Some(group) => group.controls.push(row),
            None => frameworks.push(FrameworkEvidence {
                framework: mapping.framework.clone(),
                registered: crate::generated_frameworks::framework(&mapping.framework).is_some(),
                controls: vec![row],
            }),
        }
    }

    let unmapped_fired_rule_blocks: Vec<String> = report
        .rule_blocks
        .iter()
        .filter(|row| row.fired > 0 && !mapped_blocks.contains(&row.rule_block))
        .map(|row| row.rule_block.clone())
        .collect();

    ControlsEvidence {
        policy_source: source.to_owned(),
        policy_content_hash: content_hash.to_owned(),
        receipts_matching_policy: matching.len() as u64,
        frameworks,
        unmapped_fired_rule_blocks,
    }
}
