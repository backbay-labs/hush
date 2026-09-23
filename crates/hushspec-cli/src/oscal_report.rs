use crate::oscal_context::{ValidatedAssessmentContext, validate_oscal};
use crate::report_evidence::model::{EvidenceCode, EvidenceError, VerificationResult};
use crate::report_evidence::output::OutputArtifact;
use crate::report_evidence::snapshot::sha256_bytes;
use hushspec::report::Report;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

fn invalid(message: &str) -> EvidenceError {
    EvidenceError::new(EvidenceCode::ContextInvalid, message)
}

/// Content-derived pseudorandom UUIDs keep repeated exports byte-stable.
fn stable_uuid(key: &str) -> String {
    let digest = sha256_bytes(key.as_bytes());
    let hex = &digest[7..39];
    let variant = (u8::from_str_radix(&hex[16..17], 16).expect("hex digest") & 3) | 8;
    format!(
        "{}-{}-4{}-{variant:x}{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

fn unreserved(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

fn output_directory(path: &Path) -> Result<std::path::PathBuf, EvidenceError> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .map_err(|_| invalid("OSCAL output directory must exist"))
}

fn relative_ap(ap: &Path, directory: &Path) -> Result<String, EvidenceError> {
    let base: Vec<_> = directory.components().collect();
    let target: Vec<_> = ap.components().collect();
    let common = base.iter().zip(&target).take_while(|(a, b)| a == b).count();
    if common == 0 {
        return Err(invalid(
            "assessment plan must share a filesystem root with the output",
        ));
    }
    let mut segments: Vec<String> = base[common..].iter().map(|_| "..".into()).collect();
    for component in &target[common..] {
        let text = component
            .as_os_str()
            .to_str()
            .filter(|text| unreserved(text))
            .ok_or_else(|| {
                invalid("assessment plan reference requires URI-unreserved path components")
            })?;
        segments.push(text.into());
    }
    let href = segments.join("/");
    if href.is_empty() || directory.join(&href).canonicalize().ok().as_deref() != Some(ap) {
        return Err(invalid("assessment plan reference does not resolve"));
    }
    Ok(href)
}

fn property(name: &str, value: impl ToString) -> Value {
    json!({"name":name,"ns":"https://hushspec.org/ns/oscal","value":value.to_string()})
}

pub(crate) fn render_oscal(
    report: &Report,
    verification: &VerificationResult,
    context: &ValidatedAssessmentContext,
    native: &OutputArtifact,
    sidecar: &OutputArtifact,
    output_path: &Path,
) -> Result<Value, EvidenceError> {
    let directory = output_directory(output_path)?;
    let ap_href = relative_ap(context.ap_path(), &directory)?;
    let mut resources = Vec::new();
    let mut references = Vec::new();
    for (name, artifact) in [
        ("Native receipt report", native),
        ("Strict verification sidecar", sidecar),
    ] {
        if output_directory(&artifact.path)? != directory {
            return Err(invalid("all OSCAL packet outputs must share a directory"));
        }
        let filename = artifact
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| unreserved(name))
            .ok_or_else(|| invalid("output resource basenames must be URI-unreserved ASCII"))?;
        let digest = sha256_bytes(&artifact.bytes);
        let uuid = stable_uuid(&format!("resource:{filename}:{digest}"));
        references.push(json!({"href":format!("#{uuid}"),"description":name}));
        resources.push(json!({"uuid":uuid,"title":name,"rlinks":[{"href":filename,"media-type":"application/json","hashes":[{"algorithm":"SHA-256","value":digest.trim_start_matches("sha256:")}]}]}));
    }
    if sha256_bytes(&native.bytes) != verification.report_sha256 {
        return Err(invalid("native report digest differs from verification"));
    }
    let packet_id = format!(
        "{}:{}:{}",
        verification.report_sha256,
        sha256_bytes(&sidecar.bytes),
        context.digests().join(":")
    );
    let mut observations = Vec::new();
    for stream in &verification.streams {
        for (index, interval) in stream.intervals.iter().enumerate() {
            let mut mapped = Vec::new();
            for framework in interval
                .controls
                .iter()
                .flat_map(|controls| &controls.frameworks)
            {
                for row in &framework.controls {
                    if !context.control_ids().contains(&row.control_id) {
                        return Err(invalid(
                            "policy-mapped control is not selected by the assessment plan",
                        ));
                    }
                    mapped.push(format!(
                        "{}/{}: receipts={}, evaluated={}, fired={}, denied={}",
                        framework.framework,
                        row.control_id,
                        row.receipts,
                        row.evaluated,
                        row.fired,
                        row.denied
                    ));
                }
            }
            if interval.receipts == 0 {
                continue;
            }
            let totals = interval
                .observed_totals
                .as_ref()
                .filter(|totals| totals.receipts == interval.receipts)
                .ok_or_else(|| invalid("verified interval counts are unavailable"))?;
            let description = format!(
                "Stream {}, policy {}, interval {}. {} recorded receipt(s): allow={}, warn={}, deny={}; allowed={}, confirmed={}, blocked={}, would_block={}; enforce={}, monitor={}. Mapped rule observations: {}. Counts describe recorded evaluations and dispositions, not objective satisfaction or all attempted actions.",
                stream.id,
                interval.policy_content_hash,
                index + 1,
                interval.receipts,
                totals.by_decision.allow,
                totals.by_decision.warn,
                totals.by_decision.deny,
                totals.by_outcome.allowed,
                totals.by_outcome.confirmed,
                totals.by_outcome.blocked,
                totals.by_outcome.would_block,
                totals.by_mode.enforce,
                totals.by_mode.monitor,
                if mapped.is_empty() {
                    "no resolved control mapping".into()
                } else {
                    mapped.join("; ")
                }
            );
            let sources: Vec<_> = verification
                .sources
                .iter()
                .filter(|source| source.stream_id == stream.id)
                .collect();
            observations.push(json!({
                "uuid":stable_uuid(&format!("observation:{packet_id}:{}:{index}", stream.id)),
                "title":format!("Recorded policy interval {} in {}", index + 1, stream.id),
                "description":description,"methods":["EXAMINE"],"collected":verification.verified_at,
                "subjects":context.subjects(),"relevant-evidence":references,
                "props":[property("policy-content-hash", &interval.policy_content_hash),
                    property("interval-first", serde_json::to_string(&interval.first).map_err(|_| invalid("cannot encode interval position"))?), property("interval-last", serde_json::to_string(&interval.last).map_err(|_| invalid("cannot encode interval position"))?),
                    property("source-identities", serde_json::to_string(&sources).map_err(|_| invalid("cannot encode source identities"))?),
                    property("authenticity", serde_json::to_string(&stream.authenticity).map_err(|_| invalid("cannot encode authenticity"))?),
                    property("continuity", serde_json::to_string(&stream.continuity).map_err(|_| invalid("cannot encode continuity"))?),
                    property("completeness", serde_json::to_string(&stream.completeness).map_err(|_| invalid("cannot encode completeness"))?),
                    property("policy-origin", serde_json::to_string(&stream.policy_origin).map_err(|_| invalid("cannot encode policy origin"))?)],
                "remarks":verification.limitations.join(" ")
            }));
        }
    }
    let mut result = json!({"uuid":stable_uuid(&format!("result:{packet_id}")),"title":"Recorded HushSpec evaluations",
        "description":format!("{} receipt(s) in the selected window. Examination of authenticated records only; no assessment findings or satisfaction decisions.",report.totals.receipts),
        "start":verification.window.since,"end":verification.window.until,
        "reviewed-controls":context.reviewed_controls(),"remarks":verification.limitations.join(" ")});
    if !observations.is_empty() {
        result["observations"] = Value::Array(observations);
    }
    let document = json!({"assessment-results":{
        "uuid":stable_uuid(&format!("assessment:{packet_id}")),
        "metadata":{"title":"HushSpec receipt-derived observations","last-modified":verification.verified_at,"version":env!("CARGO_PKG_VERSION"),"oscal-version":"1.1.2",
            "props": [property("assessment-context-sha256",context.digests()[0]),property("assessment-plan-sha256",context.digests()[1]),property("system-security-plan-sha256",context.digests()[2]),property("resolved-catalog-sha256",context.digests()[3])]},
        "import-ap":{"href":ap_href},"results":[result],"back-matter":{"resources":resources}
    }});
    validate_oscal(&document, "oscal_assessment-results_schema.json")?;
    validate_references(&document, context)?;
    Ok(document)
}

fn validate_references(
    document: &Value,
    context: &ValidatedAssessmentContext,
) -> Result<(), EvidenceError> {
    let ar = &document["assessment-results"];
    let resources: BTreeSet<_> = ar["back-matter"]["resources"]
        .as_array()
        .expect("schema checked")
        .iter()
        .map(|resource| resource["uuid"].as_str().expect("schema checked"))
        .collect();
    for result in ar["results"].as_array().expect("schema checked") {
        if result["reviewed-controls"] != *context.reviewed_controls() {
            return Err(invalid("generated scope differs from assessment plan"));
        }
        if let Some(observations) = result["observations"].as_array() {
            for observation in observations {
                if observation["subjects"] != json!(context.subjects()) {
                    return Err(invalid("generated subjects differ from assessment plan"));
                }
                for reference in observation["relevant-evidence"]
                    .as_array()
                    .expect("generated references")
                {
                    if !reference["href"]
                        .as_str()
                        .and_then(|href| href.strip_prefix('#'))
                        .is_some_and(|id| resources.contains(id))
                    {
                        return Err(invalid("generated evidence reference does not resolve"));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_uuids_are_stable_and_well_formed() {
        let id = stable_uuid("observation:pilot/tool-access");
        assert_eq!(id, stable_uuid("observation:pilot/tool-access"));
        assert_ne!(id, stable_uuid("observation:other"));
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(
            parts.iter().map(|part| part.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(["8", "9", "a", "b"].contains(&&parts[3][0..1]));
    }
}
