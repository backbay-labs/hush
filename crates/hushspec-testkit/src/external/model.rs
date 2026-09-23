//! Closed experimental wire models. Schema validation precedes deserialization.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::report::Implementation;

pub const PROTOCOL: &str = "0.1.0";
pub const MIB: usize = 1024 * 1024;
pub const MAX_REQUEST: usize = 16 * MIB;
pub const MAX_CASES: usize = 10_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCodes {
    Registry,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineProfile {
    pub protocol: String,
    pub implementation: Implementation,
    pub executable: LocalFile,
    pub args: Vec<String>,
    pub error_codes: ErrorCodes,
    #[serde(default)]
    pub materials: Vec<LocalFile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Parse,
    Validate,
    Merge,
    Resolve,
    Evaluate,
    Canonicalize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    pub run_id: String,
    pub case_id: String,
    pub operation: Operation,
    pub input_sha256: String,
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Ok {
        value: Value,
    },
    Rejected {
        phase: Phase,
        diagnostic: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    Unsupported,
    Error {
        diagnostic: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Parse,
    Validate,
    Resolve,
    Canonicalize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub protocol: String,
    pub run_id: String,
    pub case_id: String,
    pub operation: Operation,
    pub input_sha256: String,
    pub result: Observation,
}

impl Response {
    pub fn check_binding(&self, request: &Request) -> Result<(), String> {
        if self.protocol != request.protocol
            || self.run_id != request.run_id
            || self.case_id != request.case_id
            || self.operation != request.operation
            || self.input_sha256 != request.input_sha256
        {
            return Err("response binding does not match dispatched request".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLimits {
    pub timeout_ms: u64,
    pub total_timeout_ms: u64,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub total_output_bytes: usize,
    pub total_request_bytes: usize,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 2000,
            total_timeout_ms: 300_000,
            stdout_bytes: MIB,
            stderr_bytes: MIB / 4,
            total_output_bytes: 64 * MIB,
            total_request_bytes: 64 * MIB,
        }
    }
}

impl ProcessLimits {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=30_000).contains(&self.timeout_ms)
            || !(1..=3_600_000).contains(&self.total_timeout_ms)
            || !(1..=16 * MIB).contains(&self.stdout_bytes)
            || !(1..=16 * MIB).contains(&self.stderr_bytes)
            || !(1..=256 * MIB).contains(&self.total_output_bytes)
            || !(1..=256 * MIB).contains(&self.total_request_bytes)
        {
            return Err("external process limits outside supported range".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub path: String,
    pub category: String,
    pub level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedCase {
    pub case_id: String,
    pub operation: Operation,
    pub input_sha256: String,
    pub slots: Vec<Slot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStatus {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub failure: Option<String>,
    pub elapsed_ms: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseExecution {
    pub case_id: String,
    pub request: Artifact,
    pub input: Artifact,
    pub stdout: Artifact,
    pub stderr: Artifact,
    pub process: ProcessStatus,
    pub protocol_failure: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_attempt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Qualified,
    NotQualified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub protocol: String,
    pub run_id: String,
    pub implementation: Implementation,
    pub requested_level: u8,
    pub outcome: Outcome,
    pub abort_reason: Option<String>,
    pub generated_at: String,
    pub declared_build_context: BuildContext,
    pub controller: Artifact,
    pub engine: Artifact,
    pub profile: Artifact,
    pub manifest: Artifact,
    pub corpus: Vec<Artifact>,
    pub builtins: Vec<Artifact>,
    pub declared_materials: Vec<Artifact>,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub os: String,
    pub architecture: String,
    pub limits: ProcessLimits,
    pub planned: Vec<PlannedCase>,
    pub unattempted: Vec<Slot>,
    pub cases: Vec<CaseExecution>,
    pub report: Artifact,
    pub limitations: Vec<String>,
}
