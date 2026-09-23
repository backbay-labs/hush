use crate::report_evidence::json::parse_json;
use crate::report_evidence::model::*;
use crate::report_evidence::snapshot::{
    InputBudget, Snapshot, resolve_local, snapshot_with_handle,
};
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct ValidatedAssessmentContext {
    manifest_sha256: String,
    ap_sha256: String,
    ssp_sha256: String,
    catalog_sha256: String,
    ap_path: PathBuf,
    input_paths: Vec<PathBuf>,
    reviewed_controls: Value,
    subjects: Vec<Value>,
    control_ids: BTreeSet<String>,
}

impl ValidatedAssessmentContext {
    pub(crate) fn digests(&self) -> [&str; 4] {
        [
            &self.manifest_sha256,
            &self.ap_sha256,
            &self.ssp_sha256,
            &self.catalog_sha256,
        ]
    }
    pub(crate) fn ap_path(&self) -> &Path {
        &self.ap_path
    }
    pub(crate) fn input_paths(&self) -> &[PathBuf] {
        &self.input_paths
    }
    pub(crate) fn reviewed_controls(&self) -> &Value {
        &self.reviewed_controls
    }
    pub(crate) fn subjects(&self) -> &[Value] {
        &self.subjects
    }
    pub(crate) fn control_ids(&self) -> &BTreeSet<String> {
        &self.control_ids
    }
}

fn invalid(message: &str) -> EvidenceError {
    EvidenceError::new(EvidenceCode::ContextInvalid, message)
}

fn schema_bytes(name: &str) -> Option<&'static [u8]> {
    match name {
        "oscal_assessment-plan_schema.json" => Some(include_bytes!(
            "../schemas/oscal/v1.1.2/oscal_assessment-plan_schema.json"
        )),
        "oscal_assessment-results_schema.json" => Some(include_bytes!(
            "../schemas/oscal/v1.1.2/oscal_assessment-results_schema.json"
        )),
        "oscal_ssp_schema.json" => Some(include_bytes!(
            "../schemas/oscal/v1.1.2/oscal_ssp_schema.json"
        )),
        "oscal_catalog_schema.json" => Some(include_bytes!(
            "../schemas/oscal/v1.1.2/oscal_catalog_schema.json"
        )),
        _ => None,
    }
}

pub(crate) fn validate_oscal(value: &Value, schema: &str) -> Result<(), EvidenceError> {
    let schema: Value = serde_json::from_slice(
        schema_bytes(schema).ok_or_else(|| invalid("unknown pinned schema"))?,
    )
    .map_err(|_| invalid("invalid embedded OSCAL schema"))?;
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .should_validate_formats(true)
        .compile(&schema)
        .map_err(|error| invalid(&format!("cannot compile pinned OSCAL schema: {error}")))?;
    if !compiled.is_valid(value) {
        return Err(invalid("document does not match pinned OSCAL 1.1.2 schema"));
    }
    Ok(())
}

fn context_artifact(
    root: &Path,
    reference: &ArtifactRef,
    limits: &Limits,
    budget: &mut InputBudget,
) -> Result<(Snapshot, same_file::Handle), EvidenceError> {
    let path = resolve_local(root, &reference.path).map_err(|_| {
        invalid("context artifact must be a local file beneath the manifest directory")
    })?;
    let (snapshot, identity) = snapshot_with_handle(&path, &reference.path, limits, budget)?;
    if snapshot.sha256 != reference.sha256 {
        return Err(EvidenceError::new(
            EvidenceCode::InputDigestMismatch,
            "context artifact digest does not match manifest",
        )
        .at(&reference.path, None));
    }
    Ok((snapshot, identity))
}

fn document(snapshot: &Snapshot, schema: &str, root_key: &str) -> Result<Value, EvidenceError> {
    let value = parse_json(&snapshot.bytes, MAX_DEPTH)
        .map_err(|_| invalid("ambiguous or malformed context JSON"))?;
    validate_oscal(&value, schema)?;
    if value[root_key]["metadata"]["oscal-version"] != "1.1.2" {
        return Err(invalid("context requires OSCAL 1.1.2 documents"));
    }
    Ok(value[root_key].clone())
}

fn check_reference(
    source: &Snapshot,
    href: &Value,
    target: &Snapshot,
) -> Result<(), EvidenceError> {
    let href = href
        .as_str()
        .ok_or_else(|| invalid("missing local reference"))?;
    if href.contains('%') {
        return Err(invalid("encoded references are unsupported"));
    }
    let resolved =
        resolve_local(source.path.parent().expect("snapshot parent"), href).map_err(|_| {
            invalid("reference must be local without URL, query, fragment or traversal")
        })?;
    if resolved != target.path {
        return Err(invalid(
            "reference does not name the exact declared context artifact",
        ));
    }
    Ok(())
}

fn catalog_controls(value: &Value, ids: &mut BTreeSet<String>) -> Result<(), EvidenceError> {
    if let Some(controls) = value.get("controls").and_then(Value::as_array) {
        for control in controls {
            let id = control["id"]
                .as_str()
                .ok_or_else(|| invalid("catalog control lacks ID"))?;
            if !ids.insert(id.into()) {
                return Err(invalid("duplicate catalog control ID"));
            }
            catalog_controls(control, ids)?;
        }
    }
    if let Some(groups) = value.get("groups").and_then(Value::as_array) {
        for group in groups {
            catalog_controls(group, ids)?;
        }
    }
    Ok(())
}

pub(crate) fn load_context(
    path: &Path,
    limits: &Limits,
    budget: &mut InputBudget,
) -> Result<ValidatedAssessmentContext, EvidenceError> {
    let (manifest, manifest_id) = snapshot_with_handle(path, "assessment context", limits, budget)?;
    let context: AssessmentContext =
        parse_document(&manifest.bytes, "assessment-context-experimental")
            .map_err(|_| invalid("invalid assessment context manifest"))?;
    let root = manifest.path.parent().expect("snapshot parent");
    let (ap, ap_id) = context_artifact(root, &context.assessment_plan, limits, budget)?;
    let (ssp, ssp_id) = context_artifact(root, &context.system_security_plan, limits, budget)?;
    let (catalog, catalog_id) = context_artifact(root, &context.resolved_catalog, limits, budget)?;
    let mut identities = HashSet::new();
    for identity in [manifest_id, ap_id, ssp_id, catalog_id] {
        if !identities.insert(identity) {
            return Err(invalid("duplicate physical context artifact"));
        }
    }
    let ap_doc = document(&ap, "oscal_assessment-plan_schema.json", "assessment-plan")?;
    let ssp_doc = document(&ssp, "oscal_ssp_schema.json", "system-security-plan")?;
    let catalog_doc = document(&catalog, "oscal_catalog_schema.json", "catalog")?;
    check_reference(&ap, &ap_doc["import-ssp"]["href"], &ssp)?;
    check_reference(&ssp, &ssp_doc["import-profile"]["href"], &catalog)?;
    let mut catalog_ids = BTreeSet::new();
    catalog_controls(&catalog_doc, &mut catalog_ids)?;
    let reviewed = &ap_doc["reviewed-controls"];
    if reviewed.get("control-objective-selections").is_some() {
        return Err(invalid("objective selections are unsupported"));
    }
    let selections = reviewed["control-selections"]
        .as_array()
        .filter(|list| list.len() == 1)
        .ok_or_else(|| invalid("one explicit control selection is required"))?;
    let selection = &selections[0];
    if selection.get("include-all").is_some() || selection.get("exclude-controls").is_some() {
        return Err(invalid("include-all and exclusions are unsupported"));
    }
    let selected = selection["include-controls"]
        .as_array()
        .filter(|list| !list.is_empty())
        .ok_or_else(|| invalid("nonempty explicit control selection is required"))?;
    let mut control_ids = BTreeSet::new();
    for selected in selected {
        if selected.as_object().is_none_or(|object| object.len() != 1) {
            return Err(invalid("implicit child control selections are unsupported"));
        }
        let id = selected["control-id"]
            .as_str()
            .ok_or_else(|| invalid("selected control lacks ID"))?;
        if !catalog_ids.contains(id) || !control_ids.insert(id.into()) {
            return Err(invalid("unknown or repeated selected control"));
        }
    }
    let components = ssp_doc["system-implementation"]["components"]
        .as_array()
        .ok_or_else(|| invalid("SSP components are required"))?;
    let mut component_ids = BTreeSet::new();
    for component in components {
        let id = component["uuid"]
            .as_str()
            .ok_or_else(|| invalid("component lacks UUID"))?;
        if !component_ids.insert(id) {
            return Err(invalid("duplicate SSP component UUID"));
        }
    }
    let declarations = ap_doc["assessment-subjects"]
        .as_array()
        .filter(|list| !list.is_empty())
        .ok_or_else(|| invalid("explicit component assessment subjects required"))?;
    let mut subjects = Vec::new();
    let mut subject_ids = BTreeSet::new();
    for declaration in declarations {
        if declaration["type"] != "component"
            || declaration.get("include-all").is_some()
            || declaration.get("exclude-subjects").is_some()
        {
            return Err(invalid("only explicit component subjects are supported"));
        }
        for subject in declaration["include-subjects"]
            .as_array()
            .filter(|list| !list.is_empty())
            .ok_or_else(|| invalid("component subjects cannot be empty"))?
        {
            let id = subject["subject-uuid"]
                .as_str()
                .ok_or_else(|| invalid("subject lacks UUID"))?;
            if subject["type"] != "component"
                || !component_ids.contains(id)
                || !subject_ids.insert(id)
            {
                return Err(invalid("unknown, repeated or non-component subject"));
            }
            subjects.push(subject.clone());
        }
    }
    Ok(ValidatedAssessmentContext {
        input_paths: vec![manifest.path, ap.path.clone(), ssp.path, catalog.path],
        manifest_sha256: manifest.sha256,
        ap_sha256: ap.sha256,
        ssp_sha256: ssp.sha256,
        catalog_sha256: catalog.sha256,
        ap_path: ap.path,
        reviewed_controls: reviewed.clone(),
        subjects,
        control_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_evidence::snapshot::sha256_bytes;
    use serde_json::json;

    fn package() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let source =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/assurance/oscal");
        for name in ["context.json", "ap.json", "ssp.json", "catalog.json"] {
            std::fs::copy(source.join(name), dir.path().join(name)).unwrap();
        }
        dir
    }

    fn mutate(dir: &std::path::Path, name: &str, change: impl FnOnce(&mut serde_json::Value)) {
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap();
        change(&mut value);
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(dir.join(name), &bytes).unwrap();
        let mut context: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("context.json")).unwrap()).unwrap();
        let field = match name {
            "ap.json" => "assessment_plan",
            "ssp.json" => "system_security_plan",
            _ => "resolved_catalog",
        };
        context[field]["sha256"] = sha256_bytes(&bytes).into();
        std::fs::write(
            dir.join("context.json"),
            serde_json::to_vec(&context).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn valid_local_context_preserves_assessor_scope() {
        let dir = package();
        let result = load_context(
            &dir.path().join("context.json"),
            &Limits::default(),
            &mut InputBudget::default(),
        )
        .unwrap();
        assert_eq!(
            result.control_ids(),
            &BTreeSet::from(["tool-access".to_owned()])
        );
        assert_eq!(
            result.subjects()[0]["subject-uuid"],
            "00000000-0000-4000-8000-000000000001"
        );
        assert_eq!(
            result.reviewed_controls()["control-selections"][0]["include-controls"][0]["control-id"],
            "tool-access"
        );
    }

    #[test]
    fn malformed_or_unsupported_context_never_becomes_validated() {
        for case in [
            "url",
            "fragment",
            "wrong-ssp",
            "profile",
            "missing-control",
            "duplicate-control",
            "unknown-component",
            "include-all",
            "exclude",
            "objective",
            "non-component",
            "schema",
            "invalid-time",
            "duplicate-catalog",
            "unicode-invalid",
        ] {
            let dir = package();
            std::fs::copy(dir.path().join("ssp.json"), dir.path().join("other.json")).unwrap();
            let name = match case {
                "profile" => "ssp.json",
                "duplicate-catalog" | "unicode-invalid" => "catalog.json",
                _ => "ap.json",
            };
            mutate(dir.path(), name, |value| {
                match case {
                "url" => value["assessment-plan"]["import-ssp"]["href"] = json!("https://example.invalid/ssp.json"),
                "fragment" => value["assessment-plan"]["import-ssp"]["href"] = json!("#"),
                "wrong-ssp" => value["assessment-plan"]["import-ssp"]["href"] = json!("other.json"),
                "profile" => value["system-security-plan"]["import-profile"]["href"] = json!("other.json"),
                "missing-control" => value["assessment-plan"]["reviewed-controls"]["control-selections"][0]["include-controls"][0]["control-id"] = json!("absent"),
                "duplicate-control" => value["assessment-plan"]["reviewed-controls"]["control-selections"][0]["include-controls"].as_array_mut().unwrap().push(json!({"control-id":"tool-access"})),
                "unknown-component" => value["assessment-plan"]["assessment-subjects"][0]["include-subjects"][0]["subject-uuid"] = json!("00000000-0000-4000-8000-000000000099"),
                "include-all" => value["assessment-plan"]["reviewed-controls"]["control-selections"][0] = json!({"include-all":{}}),
                "exclude" => value["assessment-plan"]["reviewed-controls"]["control-selections"][0]["exclude-controls"] = json!([{"control-id":"tool-access"}]),
                "objective" => value["assessment-plan"]["reviewed-controls"]["control-objective-selections"] = json!([{"include-all":{}}]),
                "non-component" => value["assessment-plan"]["assessment-subjects"][0]["type"] = json!("user"),
                "schema" => value["assessment-plan"]["uuid"] = json!("not-a-uuid"),
                "invalid-time" => value["assessment-plan"]["metadata"]["last-modified"] = json!("2026-02-30T12:00:00Z"),
                "duplicate-catalog" => value["catalog"]["groups"] = json!([{"id":"group","title":"Group","controls":[{"id":"tool-access","title":"Duplicate"}]}]),
                _ => value["catalog"]["controls"][0]["id"] = json!("bad token with spaces"),
            }
            });
            assert_eq!(
                load_context(
                    &dir.path().join("context.json"),
                    &Limits::default(),
                    &mut InputBudget::default()
                )
                .unwrap_err()
                .code,
                EvidenceCode::ContextInvalid,
                "{case}"
            );
        }
    }

    #[test]
    fn upstream_bytes_and_unicode_patterns_are_preserved() {
        for line in include_str!("../schemas/oscal/v1.1.2/SHA256SUMS").lines() {
            let (digest, name) = line.split_once("  ").unwrap();
            let bytes = match name {
                "LICENSE.md" => include_bytes!("../schemas/oscal/v1.1.2/LICENSE.md").as_slice(),
                _ => schema_bytes(name).unwrap(),
            };
            assert_eq!(sha256_bytes(bytes), format!("sha256:{digest}"));
            if name != "LICENSE.md" {
                assert_eq!(
                    validate_oscal(&json!({}), name).unwrap_err().message,
                    "document does not match pinned OSCAL 1.1.2 schema"
                );
            }
        }
        let mut catalog: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/assurance/oscal/catalog.json"
        ))
        .unwrap();
        catalog["catalog"]["controls"][0]["id"] = json!("contrôle-東京");
        validate_oscal(&catalog, "oscal_catalog_schema.json").unwrap();
        catalog["catalog"]["controls"][0]["id"] = json!("💣");
        assert_eq!(
            validate_oscal(&catalog, "oscal_catalog_schema.json")
                .unwrap_err()
                .code,
            EvidenceCode::ContextInvalid
        );
    }

    #[test]
    fn context_digest_and_shared_input_budget_are_enforced() {
        let dir = package();
        std::fs::write(dir.path().join("ap.json"), b"changed").unwrap();
        assert_eq!(
            load_context(
                &dir.path().join("context.json"),
                &Limits::default(),
                &mut InputBudget::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::InputDigestMismatch
        );
        let dir = package();
        let mut budget = InputBudget {
            bytes: Limits::default().total_bytes,
            artifacts: 5,
        };
        assert_eq!(
            load_context(
                &dir.path().join("context.json"),
                &Limits::default(),
                &mut budget
            )
            .unwrap_err()
            .code,
            EvidenceCode::LimitExceeded
        );
    }

    #[cfg(unix)]
    #[test]
    fn context_cannot_escape_through_a_symlink() {
        let dir = package();
        let external = tempfile::tempdir().unwrap();
        std::fs::rename(dir.path().join("ap.json"), external.path().join("ap.json")).unwrap();
        std::os::unix::fs::symlink(external.path().join("ap.json"), dir.path().join("ap.json"))
            .unwrap();
        assert_eq!(
            load_context(
                &dir.path().join("context.json"),
                &Limits::default(),
                &mut InputBudget::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::ContextInvalid
        );
    }
}
