//! External controller orchestration. No reference-engine operations or fallback.
use super::{
    corpus::{plan_cases_with_limits, slot_result},
    json,
    model::*,
    output::Packet,
    process::{ProcessCapture, run_process},
    score::score,
    snapshot::*,
};
use crate::{
    manifest::digest_bytes,
    report::{self, Status},
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct ExternalOptions {
    pub profile: PathBuf,
    pub fixtures: PathBuf,
    pub output: PathBuf,
    pub level: u8,
    pub limits: ProcessLimits,
    pub context: BuildContext,
}
pub struct RunOutcome {
    pub qualified: bool,
    pub report_path: PathBuf,
}

fn output_destination(out: &Path, fixtures: &Path) -> Result<PathBuf, String> {
    if std::fs::symlink_metadata(out).is_ok() {
        return Err("output already exists; nothing was replaced".into());
    }
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|e| format!("output parent: {e}"))?;
    if !parent.is_dir() {
        return Err("output parent is not a directory".into());
    }
    if parent.starts_with(fixtures.canonicalize().map_err(|e| e.to_string())?) {
        return Err("output must not be inside the input corpus".into());
    }
    Ok(parent.join(out.file_name().ok_or("output directory name is missing")?))
}
fn unique(snapshot: &Snapshot, seen: &mut BTreeSet<(u64, u64)>) -> Result<(), String> {
    if !seen.insert(snapshot.identity()) {
        return Err(format!("physical input alias: {}", snapshot.label));
    }
    Ok(())
}
fn fresh_id() -> Result<String, String> {
    let mut bytes = [0; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| e.to_string())?;
    Ok(digest_bytes(&bytes))
}

pub fn run_external(options: ExternalOptions) -> Result<RunOutcome, String> {
    if !cfg!(target_os = "linux") {
        return Err("external conformance currently requires Linux".into());
    }
    options.limits.validate()?;
    if options.level > 3 {
        return Err("supported target levels are 0 through 3".into());
    }
    if let Some(sha) = &options.context.source_sha
        && (!(sha.len() == 40 || sha.len() == 64)
            || !sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err("source SHA must be 40 or 64 lowercase hex digits".into());
    }
    for value in [&options.context.ci_run, &options.context.ci_attempt]
        .into_iter()
        .flatten()
    {
        if value.is_empty() || value.len() > 128 {
            return Err("invalid declared CI context".into());
        }
    }
    let out = output_destination(&options.output, &options.fixtures)?;
    let profile_snapshot = snapshot_file(&options.profile, "profile", MIB)?;
    let profile: EngineProfile = json::decode(&profile_snapshot.bytes, "engine-profile")?;
    if profile
        .args
        .iter()
        .any(|s| s.len() > 4096 || s.contains('\0'))
    {
        return Err("invalid argument byte length or NUL".into());
    }
    let base = options.profile.parent().unwrap_or(Path::new("."));
    let engine_snapshot = snapshot_file(&base.join(&profile.executable.path), "engine", 128 * MIB)?;
    if engine_snapshot.sha256 != profile.executable.sha256 {
        return Err("engine digest mismatch".into());
    }
    validate_engine_image(&engine_snapshot.bytes)?;
    let corpus = snapshot_corpus(&options.fixtures)?;
    let controller_snapshot = snapshot_controller()?;
    let mut seen = BTreeSet::new();
    for snapshot in [
        &profile_snapshot,
        &engine_snapshot,
        &controller_snapshot,
        &corpus.manifest_snapshot,
    ]
    .into_iter()
    .chain(corpus.files.values())
    {
        unique(snapshot, &mut seen)?;
    }
    let mut materials = Vec::new();
    let mut material_bytes = 0;
    for declared in &profile.materials {
        let captured = snapshot_file(&base.join(&declared.path), &declared.path, 16 * MIB)?;
        unique(&captured, &mut seen)?;
        material_bytes += captured.bytes.len();
        if captured.sha256 != declared.sha256 || material_bytes > 16 * MIB {
            return Err("build material digest or total size mismatch".into());
        }
        materials.push(captured);
    }
    let plan = plan_cases_with_limits(&corpus, options.level, &options.limits)?;
    let run_id = fresh_id()?;
    let mut requests = Vec::new();
    let mut planned = Vec::new();
    let mut request_bytes = 0usize;
    for case in &plan.cases {
        let input = serde_json::to_vec(&case.input).map_err(|e| e.to_string())?;
        let request = Request {
            protocol: PROTOCOL.into(),
            run_id: run_id.clone(),
            case_id: case.id.clone(),
            operation: case.operation,
            input_sha256: digest_bytes(&input),
            input: case.input.clone(),
        };
        let bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        json::validate(
            &serde_json::to_value(&request).map_err(|e| e.to_string())?,
            "engine-request",
        )?;
        request_bytes = request_bytes
            .checked_add(bytes.len() + input.len())
            .ok_or("request byte count overflow")?;
        if bytes.len() > MAX_REQUEST || request_bytes > options.limits.total_request_bytes {
            return Err("retained request/input byte limit exceeded".into());
        }
        planned.push(PlannedCase {
            case_id: case.id.clone(),
            operation: case.operation,
            input_sha256: request.input_sha256.clone(),
            slots: case.expectations.iter().map(|e| e.slot.clone()).collect(),
        });
        requests.push((request, input, bytes));
    }
    let staging = tempfile::Builder::new()
        .prefix(".hush-conformance-")
        .tempdir_in(out.parent().ok_or("missing output parent")?)
        .map_err(|e| e.to_string())?;
    let mut packet = Packet::new(staging.path().join("packet"))?;
    let controller = packet.put("images/controller", &controller_snapshot.bytes)?;
    let engine = packet.put("images/engine", &engine_snapshot.bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            packet.root.join("images/engine"),
            std::fs::Permissions::from_mode(0o500),
        )
        .map_err(|e| e.to_string())?;
    }
    let profile_artifact = packet.put("inputs/profile.json", &profile_snapshot.bytes)?;
    let manifest = packet.put("inputs/manifest.json", &corpus.manifest_snapshot.bytes)?;
    let mut corpus_artifacts = Vec::new();
    for snapshot in corpus.files.values() {
        corpus_artifacts.push(packet.put(&format!("inputs/{}", snapshot.label), &snapshot.bytes)?);
    }
    let mut builtins = Vec::new();
    for (name, source) in &plan.builtins {
        builtins.push(packet.put(
            &format!(
                "inputs/builtins/{}.yaml",
                name.trim_start_matches("builtin:")
            ),
            source.as_bytes(),
        )?);
    }
    let mut declared_materials = Vec::new();
    for (index, snapshot) in materials.iter().enumerate() {
        declared_materials
            .push(packet.put(&format!("inputs/materials/{index:04}"), &snapshot.bytes)?);
    }
    let cwd = staging.path().join("work");
    std::fs::create_dir(&cwd).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_millis(options.limits.total_timeout_ms);
    let mut output_bytes = 0usize;
    let mut results = Vec::new();
    let mut cases = Vec::new();
    let mut abort_reason = None;
    for (index, (case, (request, input, bytes))) in plan.cases.iter().zip(&requests).enumerate() {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        if remaining == 0 || output_bytes >= options.limits.total_output_bytes {
            abort_reason = Some("total dispatch time or output budget exhausted".into());
            break;
        }
        let mut limits = options.limits.clone();
        limits.timeout_ms = limits.timeout_ms.min(remaining);
        limits.total_output_bytes -= output_bytes;
        let prefix = format!("cases/{index:05}");
        let request_artifact = packet.put(&format!("{prefix}/request.json"), bytes)?;
        let input_artifact = packet.put(&format!("{prefix}/input.json"), input)?;
        let capture = run_process(
            &packet.root.join("images/engine"),
            &profile.args,
            bytes,
            &cwd,
            &limits,
        )
        .unwrap_or_else(|failure| ProcessCapture {
            stdout: vec![],
            stderr: vec![],
            exit_code: None,
            signal: None,
            failure: Some(failure),
            elapsed_ms: 0,
            truncated: false,
        });
        output_bytes += capture.stdout.len() + capture.stderr.len();
        let stdout = packet.put(&format!("{prefix}/stdout"), &capture.stdout)?;
        let stderr = packet.put(&format!("{prefix}/stderr"), &capture.stderr)?;
        let mut protocol_failure = None;
        if let Some(failure) = &capture.failure {
            abort_reason = Some(failure.clone());
        } else {
            let scored =
                json::decode::<Response>(&capture.stdout, "engine-response").and_then(|response| {
                    response.check_binding(request)?;
                    score(case, &response, profile.error_codes)
                });
            match scored {
                Ok(scored) => results.extend(scored),
                Err(error) => {
                    protocol_failure = Some(error.clone());
                    abort_reason = Some(error);
                }
            }
        }
        if let Some(error) = &abort_reason {
            results.extend(
                case.expectations
                    .iter()
                    .map(|e| slot_result(&e.slot, Status::Fail, error)),
            );
        }
        cases.push(CaseExecution {
            case_id: case.id.clone(),
            request: request_artifact,
            input: input_artifact,
            stdout,
            stderr,
            process: ProcessStatus {
                exit_code: capture.exit_code,
                signal: capture.signal,
                failure: capture.failure,
                elapsed_ms: capture.elapsed_ms,
                truncated: capture.truncated,
            },
            protocol_failure,
        });
        if abort_reason.is_some() {
            break;
        }
    }
    let results = plan.complete_results(&results)?;
    let generated_at = report::now_rfc3339();
    let report = report::build_from_snapshot(
        profile.implementation.clone(),
        &corpus.manifest,
        corpus.manifest_snapshot.sha256.clone(),
        results,
        generated_at.clone(),
    )?;
    report::validate(&report)?;
    let qualified = abort_reason.is_none()
        && report
            .highest_level
            .is_some_and(|level| level >= options.level);
    let report_artifact = packet.put(
        "report.json",
        &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )?;
    let record = ExecutionRecord {
        protocol: PROTOCOL.into(),
        run_id,
        implementation: profile.implementation,
        requested_level: options.level,
        outcome: if qualified { Outcome::Qualified } else { Outcome::NotQualified },
        abort_reason,
        generated_at,
        declared_build_context: options.context,
        controller,
        engine,
        profile: profile_artifact,
        manifest,
        corpus: corpus_artifacts,
        builtins,
        declared_materials,
        args: profile.args,
        environment: BTreeMap::from([
            ("LANG".into(), "C".into()),
            ("LC_ALL".into(), "C".into()),
            ("TZ".into(), "UTC".into()),
        ]),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        limits: options.limits,
        planned,
        unattempted: plan.unattempted.iter().map(|r| Slot {
            path: r.path.clone(),
            category: r.category.clone(),
            level: r.level.unwrap_or(5),
        }).collect(),
        cases,
        report: report_artifact,
        limitations: vec!["Unsigned execution record; digest binding is not authenticated producer provenance.".into(),
            "Implementation identity and build/source/CI context are operator declarations, not build attestation.".into(),
            "Approved static engine executable only; no sandbox, honesty or independent-authorship claim.".into(),
            "L4/L5 qualification and independent-engine adoption are not established by this run.".into()],
    };
    let value = serde_json::to_value(&record).map_err(|e| e.to_string())?;
    json::validate(&value, "conformance-execution")?;
    packet.verify()?;
    packet.put(
        "execution.json",
        &serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
    )?;
    packet.publish(&out)?;
    Ok(RunOutcome {
        qualified,
        report_path: out.join("report.json"),
    })
}
