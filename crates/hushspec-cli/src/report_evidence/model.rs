use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path};

pub(crate) const MAX_DEPTH: usize = 64;
pub(crate) const MAX_STREAMS: usize = 64;
pub(crate) const MAX_ARTIFACTS: usize = 1024;
pub(crate) const MAX_RECORDS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvidenceCode {
    Configuration,
    Malformed,
    LimitExceeded,
    InputDigestMismatch,
    SignatureInvalid,
    UnauthorizedKey,
    DuplicateReceipt,
    ChainInvalid,
    PolicyMismatch,
    BoundaryMismatch,
    OutputConflict,
    ContextInvalid,
    Io,
}

#[derive(Debug)]
pub(crate) struct EvidenceError {
    pub(crate) code: EvidenceCode,
    pub(crate) source: Option<String>,
    pub(crate) line: Option<usize>,
    pub(crate) message: String,
}

impl EvidenceError {
    pub(crate) fn new(code: EvidenceCode, message: impl Into<String>) -> Self {
        Self {
            code,
            source: None,
            line: None,
            message: message.into(),
        }
    }
    pub(crate) fn at(mut self, source: impl Into<String>, line: Option<usize>) -> Self {
        self.source = Some(source.into());
        self.line = line;
        self
    }
    pub(crate) fn exit_code(&self) -> i32 {
        match self.code {
            EvidenceCode::InputDigestMismatch
            | EvidenceCode::SignatureInvalid
            | EvidenceCode::UnauthorizedKey
            | EvidenceCode::DuplicateReceipt
            | EvidenceCode::ChainInvalid
            | EvidenceCode::PolicyMismatch
            | EvidenceCode::BoundaryMismatch => 1,
            _ => 2,
        }
    }
}
impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.code)?;
        if let Some(source) = &self.source {
            write!(f, " [{source}")?;
            if let Some(line) = self.line {
                write!(f, ":{line}")?;
            }
            write!(f, "]")?;
        }
        write!(f, ": {}", self.message)
    }
}
impl std::error::Error for EvidenceError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactRef {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Window {
    pub(crate) since: String,
    pub(crate) until: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicySpec {
    pub(crate) content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) artifact: Option<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) signature: Option<ArtifactRef>,
    pub(crate) allowed_signer_key_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StreamKind {
    SignedReceipts,
    SignedLog,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamSpec {
    pub(crate) id: String,
    pub(crate) kind: StreamKind,
    pub(crate) files: Vec<ArtifactRef>,
    pub(crate) allowed_signer_key_ids: Vec<String>,
    pub(crate) allowed_policy_hashes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Requirements {
    pub(crate) boundary_inventory: bool,
    pub(crate) policy_signatures: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceProfile {
    pub(crate) profile_version: String,
    pub(crate) run_id: String,
    pub(crate) window: Window,
    pub(crate) policies: Vec<PolicySpec>,
    pub(crate) streams: Vec<StreamSpec>,
    pub(crate) requirements: Requirements,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inventory: Option<ArtifactRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogBoundary {
    pub(crate) start_prev_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) initial_policy_hash: Option<String>,
    pub(crate) end_file_sha256: String,
    pub(crate) end_seq: u64,
    pub(crate) end_entry_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryStream {
    pub(crate) id: String,
    pub(crate) file_sha256s: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) log: Option<LogBoundary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoundaryInventory {
    pub(crate) inventory_version: String,
    pub(crate) run_id: String,
    pub(crate) window: Window,
    pub(crate) acquired_from: String,
    pub(crate) streams: Vec<InventoryStream>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PropertyStatus {
    Verified,
    NotEstablished,
    NotApplicable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PropertyResult {
    pub(crate) status: PropertyStatus,
    pub(crate) scope: String,
    pub(crate) basis: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Position {
    pub(crate) file_sha256: String,
    pub(crate) line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) seq: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyInterval {
    pub(crate) policy_content_hash: String,
    pub(crate) first: Position,
    pub(crate) last: Position,
    pub(crate) receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) controls: Option<hushspec::report::ControlsEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamResult {
    pub(crate) id: String,
    pub(crate) kind: StreamKind,
    pub(crate) authenticity: PropertyResult,
    pub(crate) continuity: PropertyResult,
    pub(crate) completeness: PropertyResult,
    pub(crate) policy_binding: PropertyResult,
    pub(crate) policy_origin: PropertyResult,
    pub(crate) signatures_verified: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) first: Option<Position>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last: Option<Position>,
    pub(crate) intervals: Vec<PolicyInterval>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceResult {
    pub(crate) stream_id: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) records: u64,
    pub(crate) signer_key_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Verifier {
    pub(crate) name: String,
    pub(crate) version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerificationResult {
    pub(crate) verification_version: String,
    pub(crate) run_id: String,
    pub(crate) window: Window,
    pub(crate) verified_at: String,
    pub(crate) verifier: Verifier,
    pub(crate) profile_sha256: String,
    pub(crate) keyring_sha256: String,
    pub(crate) report_sha256: String,
    pub(crate) sources: Vec<SourceResult>,
    pub(crate) streams: Vec<StreamResult>,
    pub(crate) limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inventory_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssessmentContext {
    pub(crate) hushspec_assessment_context: String,
    pub(crate) assessment_plan: ArtifactRef,
    pub(crate) system_security_plan: ArtifactRef,
    pub(crate) resolved_catalog: ArtifactRef,
}

#[derive(Clone, Debug)]
pub(crate) struct Limits {
    pub(crate) file_bytes: u64,
    pub(crate) total_bytes: u64,
    pub(crate) line_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            file_bytes: 16_777_216,
            total_bytes: 67_108_864,
            line_bytes: 1_048_576,
        }
    }
}
impl Limits {
    pub(crate) fn validate(&self) -> Result<(), EvidenceError> {
        if self.line_bytes == 0
            || self.line_bytes > 16_777_216
            || self.line_bytes > self.file_bytes
            || self.file_bytes > self.total_bytes
            || self.total_bytes > 1_073_741_824
        {
            return Err(EvidenceError::new(
                EvidenceCode::Configuration,
                "limits require 0 < line <= file <= total; line <= 16 MiB and total <= 1 GiB",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_schema(value: &serde_json::Value, name: &str) -> Result<(), EvidenceError> {
    let compiled = schema_validator(name)?;
    if !compiled.is_valid(value) {
        return Err(EvidenceError::new(
            EvidenceCode::Malformed,
            format!("document does not match {name} schema"),
        ));
    }
    Ok(())
}

pub(crate) fn schema_validator(name: &str) -> Result<jsonschema::JSONSchema, EvidenceError> {
    let schema = crate::generated_schemas::schema_body(name).ok_or_else(|| {
        EvidenceError::new(EvidenceCode::Configuration, "missing embedded schema")
    })?;
    let schema: serde_json::Value = serde_json::from_str(schema)
        .map_err(|_| EvidenceError::new(EvidenceCode::Configuration, "invalid embedded schema"))?;
    jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&schema)
        .map_err(|_| {
            EvidenceError::new(
                EvidenceCode::Configuration,
                "cannot compile embedded schema",
            )
        })
}

pub(crate) fn parse_document<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    schema: &str,
) -> Result<T, EvidenceError> {
    let value = super::json::parse_json(bytes, MAX_DEPTH)?;
    validate_schema(&value, schema)?;
    serde_json::from_value(value)
        .map_err(|_| EvidenceError::new(EvidenceCode::Malformed, "invalid document shape"))
}

pub(crate) fn parse_profile(bytes: &[u8]) -> Result<EvidenceProfile, EvidenceError> {
    let profile: EvidenceProfile = parse_document(bytes, "evidence-profile-experimental")?;
    profile.validate()?;
    Ok(profile)
}

pub(crate) fn local_path(path: &str) -> Result<(), EvidenceError> {
    if path.is_empty()
        || path.contains([':', '#', '?', '\0', '\\'])
        || Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(EvidenceError::new(
            EvidenceCode::Configuration,
            "artifact path must be relative and local without parent traversal",
        ));
    }
    Ok(())
}

impl EvidenceProfile {
    pub(crate) fn artifacts(&self) -> impl Iterator<Item = &ArtifactRef> {
        self.streams
            .iter()
            .flat_map(|s| &s.files)
            .chain(
                self.policies
                    .iter()
                    .flat_map(|p| p.artifact.iter().chain(p.signature.iter())),
            )
            .chain(self.inventory.iter())
    }
    pub(crate) fn validate(&self) -> Result<(), EvidenceError> {
        let fail = |message| EvidenceError::new(EvidenceCode::Configuration, message);
        if self.window.since > self.window.until {
            return Err(fail("window is reversed"));
        }
        let hashes: BTreeSet<_> = self.policies.iter().map(|p| &p.content_hash).collect();
        if hashes.len() != self.policies.len() {
            return Err(fail("duplicate policy hash"));
        }
        let mut ids = BTreeSet::new();
        for stream in &self.streams {
            if !ids.insert(&stream.id) {
                return Err(fail("duplicate stream ID"));
            }
            if stream
                .allowed_policy_hashes
                .iter()
                .any(|hash| !hashes.contains(hash))
            {
                return Err(fail("stream authorizes an undeclared policy"));
            }
        }
        let mut paths = BTreeSet::new();
        for artifact in self.artifacts() {
            local_path(&artifact.path)?;
            if !paths.insert(&artifact.path) {
                return Err(fail("duplicate artifact path"));
            }
        }
        for policy in &self.policies {
            if (self.requirements.policy_signatures || policy.signature.is_some())
                && (policy.artifact.is_none()
                    || policy.signature.is_none()
                    || policy.allowed_signer_key_ids.is_empty())
            {
                return Err(fail(
                    "policy origin verification requires artifact, signature and authorized keys",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn shape() -> Value {
        serde_json::from_str(include_str!(
            "../../../../fixtures/assurance/profile-shape.json"
        ))
        .unwrap()
    }

    #[test]
    fn closed_profile_rejects_structural_and_semantic_errors() {
        let valid = shape();
        assert!(parse_profile(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (pointer, replacement, code) in [
            ("/profile_version", json!("0.2.0"), EvidenceCode::Malformed),
            ("/streams/0/files", json!([]), EvidenceCode::Malformed),
            (
                "/streams/0/allowed_signer_key_ids",
                json!([]),
                EvidenceCode::Malformed,
            ),
            (
                "/window/until",
                json!("2026-09-14T00:00:00.000Z"),
                EvidenceCode::Configuration,
            ),
            (
                "/streams/0/files/0/path",
                json!("../escape"),
                EvidenceCode::Configuration,
            ),
            (
                "/streams/0/allowed_policy_hashes/0",
                json!(format!("sha256:{}", "a".repeat(64))),
                EvidenceCode::Configuration,
            ),
        ] {
            let mut value = valid.clone();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert_eq!(
                parse_profile(&serde_json::to_vec(&value).unwrap())
                    .unwrap_err()
                    .code,
                code,
                "{pointer}"
            );
        }
        for (field, value) in [("inventory", Value::Null), ("unknown", json!(true))] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert_eq!(
                parse_profile(&serde_json::to_vec(&invalid).unwrap())
                    .unwrap_err()
                    .code,
                EvidenceCode::Malformed
            );
        }
        let mut duplicate = valid.clone();
        let mut stream = duplicate["streams"][0].clone();
        stream["files"][0]["path"] = json!("different.jsonl");
        duplicate["streams"].as_array_mut().unwrap().push(stream);
        assert_eq!(
            parse_profile(&serde_json::to_vec(&duplicate).unwrap())
                .unwrap_err()
                .code,
            EvidenceCode::Configuration
        );
        let mut missing_signers = valid;
        missing_signers["requirements"]["policy_signatures"] = json!(true);
        assert_eq!(
            parse_profile(&serde_json::to_vec(&missing_signers).unwrap())
                .unwrap_err()
                .code,
            EvidenceCode::Configuration
        );
    }

    #[test]
    fn limits_are_positive_ordered_and_operator_bounded() {
        assert!(Limits::default().validate().is_ok());
        for limits in [
            Limits {
                file_bytes: 0,
                ..Limits::default()
            },
            Limits {
                total_bytes: 1,
                ..Limits::default()
            },
            Limits {
                line_bytes: 16_777_217,
                file_bytes: 33_554_432,
                ..Limits::default()
            },
            Limits {
                file_bytes: 1_073_741_825,
                total_bytes: 1_073_741_825,
                ..Limits::default()
            },
        ] {
            assert_eq!(
                limits.validate().unwrap_err().code,
                EvidenceCode::Configuration
            );
        }
    }

    #[test]
    fn companion_contracts_reject_nulls_unknown_members_and_versions() {
        let profile = shape();
        let artifact = profile["streams"][0]["files"][0].clone();
        let inventory = json!({
            "inventory_version":"0.1.0", "run_id":"shape-only", "window":profile["window"],
            "acquired_from":"operator checkpoint", "streams":[{"id":"agent-1", "file_sha256s":[artifact["sha256"]]}]
        });
        let context = json!({"hushspec_assessment_context":"0.1.0",
            "assessment_plan":artifact, "system_security_plan":artifact, "resolved_catalog":artifact});
        let property = json!({"status":"not-established", "scope":"supplied files", "basis":[]});
        let verification = json!({"verification_version":"0.1.0", "run_id":"shape-only",
            "window":profile["window"], "verified_at":"2026-09-15T12:00:00.000Z",
            "verifier":{"name":"h2h","version":"1.0.0"},
            "profile_sha256":artifact["sha256"], "keyring_sha256":artifact["sha256"], "report_sha256":artifact["sha256"],
            "sources":[{"stream_id":"agent-1","path":"evidence.jsonl","sha256":artifact["sha256"],"records":1,"signer_key_ids":profile["streams"][0]["allowed_signer_key_ids"]}],
            "streams":[{"id":"agent-1","kind":"signed-receipts","authenticity":property,
                "continuity":property,"completeness":property,"policy_binding":property,"policy_origin":property,
                "signatures_verified":1,"intervals":[]}],
            "limitations":["Shape example, not verified evidence"]});
        for (schema, version_key, value) in [
            (
                "evidence-inventory-experimental",
                "inventory_version",
                inventory.clone(),
            ),
            (
                "assessment-context-experimental",
                "hushspec_assessment_context",
                context.clone(),
            ),
            (
                "evidence-verification-experimental",
                "verification_version",
                verification.clone(),
            ),
        ] {
            validate_schema(&value, schema).unwrap();
            for (key, replacement) in [(version_key, json!("0.2.0")), ("unknown", json!(true))] {
                let mut invalid = value.clone();
                invalid[key] = replacement;
                assert_eq!(
                    validate_schema(&invalid, schema).unwrap_err().code,
                    EvidenceCode::Malformed
                );
            }
            for key in value.as_object().unwrap().keys() {
                let mut invalid = value.clone();
                invalid[key] = serde_json::Value::Null;
                assert_eq!(
                    validate_schema(&invalid, schema).unwrap_err().code,
                    EvidenceCode::Malformed,
                    "{schema}/{key}"
                );
            }
        }
        let decoded: BoundaryInventory = parse_document(
            &serde_json::to_vec(&inventory).unwrap(),
            "evidence-inventory-experimental",
        )
        .unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), inventory);
        let decoded: AssessmentContext = parse_document(
            &serde_json::to_vec(&context).unwrap(),
            "assessment-context-experimental",
        )
        .unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), context);
        let decoded: VerificationResult = parse_document(
            &serde_json::to_vec(&verification).unwrap(),
            "evidence-verification-experimental",
        )
        .unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), verification);
    }

    #[test]
    fn verification_basis_can_name_all_declared_policy_artifacts() {
        let schema: Value = serde_json::from_str(
            crate::generated_schemas::schema_body("evidence-verification-experimental").unwrap(),
        )
        .unwrap();
        let property_schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "$ref":"#/$defs/PropertyResult", "$defs":schema["$defs"]});
        let validator = jsonschema::JSONSchema::compile(&property_schema).unwrap();
        // 1024 policy declarations can each need an artifact, signature and
        // origin limitation. A relative path may itself contain 4096 characters.
        let basis = PropertyResult {
            status: PropertyStatus::Verified,
            scope: "declared policies".into(),
            basis: vec![format!("{} ({})", "p".repeat(4096), "sha256:1".repeat(10)); 3072],
        };
        assert!(validator.is_valid(&serde_json::to_value(basis).unwrap()));
    }
}
