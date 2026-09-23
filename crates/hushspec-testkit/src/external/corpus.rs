//! Snapshot-only case planning. Expectations are data, never reference verdicts.
use super::{
    json as wire,
    model::{MAX_CASES, MAX_REQUEST, Operation, PROTOCOL, Phase, ProcessLimits, Request, Slot},
    snapshot::CorpusSnapshot,
};
use crate::report::{Status, VectorResult};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub enum Assertion {
    Accept,
    ParseUnconstrained,
    Reject {
        phases: Vec<Phase>,
        code: Option<String>,
        message: Option<String>,
    },
    Document(Value),
    Fields(Value),
    ValueAt {
        path: Vec<String>,
        value: Value,
    },
}
#[derive(Debug, Clone)]
pub struct Expectation {
    pub slot: Slot,
    pub assertion: Assertion,
}
#[derive(Debug, Clone)]
pub struct Case {
    pub id: String,
    pub operation: Operation,
    pub input: Value,
    pub expectations: Vec<Expectation>,
}
#[derive(Debug)]
pub struct Plan {
    pub cases: Vec<Case>,
    pub unattempted: Vec<VectorResult>,
    pub builtins: BTreeMap<String, String>,
    retained_request_bytes: usize,
    request_budget: usize,
}

pub fn slot_result(slot: &Slot, status: Status, message: impl Into<String>) -> VectorResult {
    VectorResult {
        path: slot.path.clone(),
        category: slot.category.clone(),
        level: Some(slot.level),
        status,
        message: Some(message.into()),
        parser_failure: slot.level == 0 && status == Status::Fail,
    }
}

impl Plan {
    /// Reject invented/duplicate slots; missing slots remain explicitly unattempted.
    pub fn complete_results(&self, observed: &[VectorResult]) -> Result<Vec<VectorResult>, String> {
        let mut slots = BTreeMap::new();
        for c in &self.cases {
            for e in &c.expectations {
                if slots
                    .insert(
                        e.slot.path.clone(),
                        slot_result(&e.slot, Status::NotAttempted, "case was not dispatched"),
                    )
                    .is_some()
                {
                    return Err("duplicate planned result slot".into());
                }
            }
        }
        let mut fixed = BTreeSet::new();
        for r in &self.unattempted {
            if slots.insert(r.path.clone(), r.clone()).is_some() {
                return Err("duplicate unattempted result slot".into());
            }
            fixed.insert(&r.path);
        }
        let mut seen = BTreeSet::new();
        for r in observed {
            let expected = slots
                .get_mut(&r.path)
                .ok_or_else(|| format!("foreign result slot {}", r.path))?;
            if !seen.insert(&r.path)
                || r.category != expected.category
                || r.level != expected.level
                || (fixed.contains(&r.path) && r.status != Status::NotAttempted)
            {
                return Err(format!("invalid or duplicate result slot {}", r.path));
            }
            *expected = r.clone();
        }
        Ok(slots.into_values().collect())
    }
}

fn text(snapshot: &CorpusSnapshot, path: &str) -> Result<String, String> {
    let file = snapshot
        .files
        .get(path)
        .ok_or_else(|| format!("missing fixture dependency {path}"))?;
    String::from_utf8(file.bytes.clone()).map_err(|e| format!("{path}: {e}"))
}
fn data(text: &str) -> Result<Value, String> {
    wire::parse_yaml(text.as_bytes())
}
fn slot(path: impl Into<String>, category: &str, level: u8) -> Slot {
    Slot {
        path: path.into(),
        category: category.into(),
        level,
    }
}
fn one(
    id: String,
    category: &str,
    level: u8,
    operation: Operation,
    input: Value,
    assertion: Assertion,
) -> Case {
    Case {
        expectations: vec![Expectation {
            slot: slot(id.clone(), category, level),
            assertion,
        }],
        id,
        operation,
        input,
    }
}
fn add(plan: &mut Plan, case: Case, level: u8) -> Result<(), String> {
    if case.expectations.iter().any(|e| e.slot.level <= level) {
        if plan.cases.len() >= MAX_CASES {
            return Err("oversized external case plan".into());
        }
        let input = serde_json::to_vec(&case.input).map_err(|e| e.to_string())?;
        // Both generated identifiers are 64 ASCII bytes. Serialize the real
        // envelope with a null placeholder to count its exact overhead without
        // cloning the potentially large policy/dependency map again.
        let envelope = Request {
            protocol: PROTOCOL.into(),
            run_id: "0".repeat(64),
            case_id: case.id.clone(),
            operation: case.operation,
            input_sha256: "0".repeat(64),
            input: Value::Null,
        };
        let overhead = serde_json::to_vec(&envelope)
            .map_err(|e| e.to_string())?
            .len()
            - 4;
        let request_bytes = input
            .len()
            .checked_add(overhead)
            .ok_or("request byte count overflow")?;
        let retained = plan
            .retained_request_bytes
            .checked_add(request_bytes)
            .and_then(|n| n.checked_add(input.len()))
            .ok_or("request byte count overflow")?;
        if request_bytes > MAX_REQUEST || retained > plan.request_budget {
            return Err("retained request/input byte limit exceeded".into());
        }
        plan.retained_request_bytes = retained;
        plan.cases.push(case);
    } else {
        for e in case.expectations {
            plan.unattempted.push(slot_result(
                &e.slot,
                Status::NotAttempted,
                "above requested level",
            ));
        }
    }
    Ok(())
}

fn mandatory_parse_rejection(path: &str) -> bool {
    // These committed vectors specifically exercise Core 2.4/Level 0. Registry
    // codes intentionally do not determine whether semantic validation is early.
    matches!(
        path.rsplit('/').next().unwrap_or(""),
        "missing-version.yaml"
            | "yaml-alias.yaml"
            | "yaml-duplicate-key.yaml"
            | "yaml-merge-key.yaml"
            | "yaml-multi-doc.yaml"
    )
}
fn rejection(phases: Vec<Phase>) -> Assertion {
    Assertion::Reject {
        phases,
        code: None,
        message: None,
    }
}

fn document_cases(
    snapshot: &CorpusSnapshot,
    plan: &mut Plan,
    path: &str,
    valid: bool,
    target: u8,
) -> Result<(), String> {
    let input = json!({"policy":text(snapshot,path)?});
    let category = if valid { "valid" } else { "invalid" };
    let parse = if valid {
        Assertion::Accept
    } else if mandatory_parse_rejection(path) {
        rejection(vec![Phase::Parse])
    } else {
        Assertion::ParseUnconstrained
    };
    add(
        plan,
        one(
            format!("{path}#parse"),
            category,
            0,
            Operation::Parse,
            input.clone(),
            parse,
        ),
        target,
    )?;
    let validation = if valid {
        Assertion::Accept
    } else {
        let sidecar = crate::expect::sidecar_path(std::path::Path::new(path))
            .to_string_lossy()
            .into_owned();
        let expected_value = data(&text(snapshot, &sidecar)?)?;
        wire::validate_at(&expected_value, "error-codes", "ExpectedError")?;
        let expected: crate::expect::ExpectedError =
            serde_json::from_value(expected_value).map_err(|e| e.to_string())?;
        if !expected.reject
            || expected.code.len() != 4
            || !expected.code.starts_with('E')
            || !expected.code[1..].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!("malformed refusal sidecar {sidecar}"));
        }
        Assertion::Reject {
            phases: vec![Phase::Parse, Phase::Validate],
            code: Some(expected.code),
            message: expected.message_contains,
        }
    };
    add(
        plan,
        one(
            format!("{path}#validate"),
            category,
            1,
            Operation::Validate,
            input,
            validation,
        ),
        target,
    )?;
    Ok(())
}

fn builtin_documents() -> BTreeMap<String, String> {
    hushspec::BUILTIN_NAMES
        .iter()
        .filter_map(|name| {
            hushspec::load_builtin(name).map(|s| (format!("builtin:{name}"), s.to_string()))
        })
        .collect()
}
fn documents_for_policy(policy: &Value, plan: &Plan) -> Value {
    if policy.get("extends").is_some() {
        json!(plan.builtins)
    } else {
        json!({})
    }
}

fn evaluator_cases(
    snapshot: &CorpusSnapshot,
    plan: &mut Plan,
    path: &str,
    category: &str,
    target: u8,
) -> Result<(), String> {
    let suite = data(&text(snapshot, path)?)?;
    wire::validate(&suite, "evaluator-test").map_err(|e| format!("{path}: {e}"))?;
    let policy = serde_json::to_string(&suite["policy"]).map_err(|e| e.to_string())?;
    for (index, vector) in suite["cases"]
        .as_array()
        .ok_or("missing evaluator cases")?
        .iter()
        .enumerate()
    {
        let mut action = vector["action"].clone();
        if action.get("context").is_none()
            && let Some(context) = vector.get("context")
        {
            action["context"] = context.clone();
        }
        let mut expected = vector["expect"].clone();
        let fields = expected
            .as_object_mut()
            .ok_or("expected result must be an object")?;
        for field in ["rule_trace", "receipt"] {
            if fields.remove(field).is_some() {
                plan.unattempted.push(slot_result(
                    &slot(format!("{path}#{index}/{field}"), "evaluation-evidence", 4),
                    Status::NotAttempted,
                    "external L4 evidence assertions are not implemented",
                ));
            }
        }
        let input = json!({"policy":policy,"action":action,"source":path,"documents":documents_for_policy(&suite["policy"],plan)});
        add(
            plan,
            one(
                format!("{path}#{index}/evaluate"),
                category,
                3,
                Operation::Evaluate,
                input,
                Assertion::Fields(expected),
            ),
            target,
        )?;
    }
    Ok(())
}

fn raw_cases(
    snapshot: &CorpusSnapshot,
    plan: &mut Plan,
    path: &str,
    target: u8,
) -> Result<(), String> {
    let source = &snapshot.files.get(path).ok_or("missing raw corpus")?.bytes;
    let cases = wire::parse_json(source)?;
    let cases = cases
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("raw corpus must be a nonempty array")?;
    let mut ids = BTreeSet::new();
    for v in cases {
        let object = v.as_object().ok_or("raw case must be an object")?;
        if object.keys().any(|k| {
            !matches!(
                k.as_str(),
                "id" | "yaml" | "accept" | "value_path" | "value" | "canonical" | "decision"
            )
        }) {
            return Err("unknown raw case field".into());
        }
        let id = v["id"]
            .as_str()
            .filter(|s| !s.is_empty() && !s.contains('#'))
            .ok_or("missing raw case id")?;
        if !ids.insert(id) {
            return Err("duplicate raw case id".into());
        }
        let policy = v["yaml"].as_str().ok_or("raw case yaml must be a string")?;
        let accept = v["accept"]
            .as_bool()
            .ok_or("raw acceptance must be boolean")?;
        if v.get("value_path").is_some() != v.get("value").is_some()
            || (!accept
                && ["value_path", "canonical", "decision"]
                    .iter()
                    .any(|k| v.get(k).is_some()))
        {
            return Err("inconsistent raw case assertions".into());
        }
        let input = json!({"policy":policy});
        let mut c = one(
            format!("{path}#{id}/parse"),
            "raw-yaml",
            0,
            Operation::Parse,
            input.clone(),
            if accept {
                Assertion::Accept
            } else {
                rejection(vec![Phase::Parse])
            },
        );
        let assertion = if let Some(p) = v.get("value_path") {
            let path: Vec<String> = serde_json::from_value(p.clone()).map_err(|e| e.to_string())?;
            if path.is_empty() {
                return Err("empty raw value path".into());
            }
            Assertion::ValueAt {
                path,
                value: v["value"].clone(),
            }
        } else if accept {
            Assertion::Accept
        } else {
            rejection(vec![Phase::Parse])
        };
        if target >= 1 {
            c.expectations.push(Expectation {
                slot: slot(format!("{path}#{id}/value"), "raw-yaml", 1),
                assertion,
            });
        } else {
            plan.unattempted.push(slot_result(
                &slot(format!("{path}#{id}/value"), "raw-yaml", 1),
                Status::NotAttempted,
                "above requested level",
            ));
        }
        add(plan, c, target)?;
        if let Some(canonical) = v.get("canonical") {
            let canonical = canonical
                .as_str()
                .ok_or("canonical assertion must be text")?;
            // These literal canonical observations can run at L3, but all other
            // L4 requirements remain unattempted. They never grant Level 4.
            let case = one(
                format!("{path}#{id}/canonical"),
                "raw-yaml-canonical",
                4,
                Operation::Canonicalize,
                input,
                Assertion::Fields(
                    json!({"canonical":canonical,"content_hash":format!("sha256:{}",crate::manifest::digest_bytes(canonical.as_bytes()))}),
                ),
            );
            if target == 3 {
                add(plan, case, 4)?;
            } else {
                add(plan, case, target)?;
            }
        }
        if let Some(decision) = v.get("decision") {
            if !matches!(decision.as_str(), Some("allow" | "warn" | "deny")) {
                return Err("invalid raw decision".into());
            }
            let input = json!({"policy":policy,"source":path,"documents":{},"action":{"type":"egress","target":"example.com","context":{"counters":{"requests":9}}}});
            add(
                plan,
                one(
                    format!("{path}#{id}/evaluate"),
                    "raw-yaml-evaluation",
                    3,
                    Operation::Evaluate,
                    input,
                    Assertion::Fields(json!({"decision":decision})),
                ),
                target,
            )?;
        }
    }
    Ok(())
}

fn merge_cases(
    snapshot: &CorpusSnapshot,
    plan: &mut Plan,
    dir: &str,
    target: u8,
) -> Result<(), String> {
    let prefix = format!("{dir}/");
    let base = text(snapshot, &format!("{dir}/base.yaml"))?;
    let meta = if snapshot.files.contains_key(&format!("{dir}/fixture.yaml")) {
        data(&text(snapshot, &format!("{dir}/fixture.yaml"))?)?
    } else {
        json!({})
    };
    wire::validate_at(&meta, "merge-vector", "FixtureManifest")?;
    let mut documents = serde_json::Map::new();
    for path in snapshot.files.keys().filter(|p| p.starts_with(&prefix)) {
        let relative = &path[prefix.len()..];
        if !relative.contains('/')
            && (relative.ends_with(".yaml") || relative.ends_with(".yml"))
            && !relative.starts_with("expected-")
            && relative != "fixture.yaml"
            && !relative.ends_with(".expect.yaml")
        {
            documents.insert(relative.into(), json!(text(snapshot, path)?));
        }
    }
    let children: Vec<_> = documents
        .keys()
        .filter(|p| p.starts_with("child-"))
        .cloned()
        .collect();
    if children.is_empty() {
        return Err(format!("merge directory {dir} has no children"));
    }
    for child in children {
        let child_text = documents[&child].as_str().ok_or("child source not text")?;
        let child_data = data(child_text)?;
        let pinned = child_data["extends"]
            .as_str()
            .is_some_and(|r| r.contains("#sha256:"));
        let reject = meta["reject"] == true
            || snapshot.files.contains_key(&format!("{dir}/expect-reject"))
            || meta["cases"][&child]["reject"] == true
            || meta["cases"][child.trim_end_matches(".yaml")]["reject"] == true;
        let assertion = if reject {
            let cycle = dir.ends_with("/extends-cycle");
            Assertion::Reject {
                phases: if pinned {
                    vec![Phase::Resolve]
                } else {
                    vec![Phase::Parse, Phase::Validate, Phase::Resolve]
                },
                code: cycle.then(|| "cycle".into()),
                message: None,
            }
        } else {
            let expected = text(
                snapshot,
                &format!("{dir}/{}", child.replacen("child-", "expected-", 1)),
            )?;
            Assertion::Document(data(&expected)?)
        };
        let (op, input) = if pinned {
            (
                Operation::Resolve,
                json!({"policy":child_text,"source":child,"documents":documents}),
            )
        } else {
            (Operation::Merge, json!({"base":base,"child":child_text}))
        };
        add(
            plan,
            one(
                format!("{dir}/{child}#compose"),
                "merge",
                2,
                op,
                input,
                assertion,
            ),
            target,
        )?;
    }
    Ok(())
}

fn resolution_counterexamples(plan: &mut Plan, target: u8) -> Result<(), String> {
    // Literal witnesses supplement the hash-oriented L4 resolve corpus. They
    // are controller inputs, whose provenance is the captured controller image.
    for strategy in ["deep_merge", "merge", "replace"] {
        let base = "hushspec: '1.0.0'\nrules:\n  egress:\n    allow: [good.example]\n";
        let middle = "hushspec: '1.0.0'\nextends: ./base.yaml\nname: middle\n";
        let policy =
            format!("hushspec: '1.0.0'\nextends: mid\nmerge_strategy: {strategy}\nname: child\n");
        let expected = if strategy == "replace" {
            json!({"hushspec":"1.0.0","name":"child"})
        } else {
            json!({"hushspec":"1.0.0","name":"child","rules":{"egress":{"allow":["good.example"]}}})
        };
        add(
            plan,
            one(
                format!("controller/resolve#{strategy}"),
                "resolve-l2",
                2,
                Operation::Resolve,
                json!({"policy":policy,"source":"child.yaml","documents":{"base.yaml":base,"mid.yaml":middle}}),
                Assertion::Document(expected),
            ),
            target,
        )?;
    }
    for (name, policy, documents, reason) in [
        (
            "alias-cycle",
            "hushspec: '1.0.0'\nextends: ./root.yaml\n",
            json!({"root.yaml":"hushspec: '1.0.0'\nextends: ./root.yaml\n"}),
            "cycle",
        ),
        (
            "missing",
            "hushspec: '1.0.0'\nextends: absent\n",
            json!({}),
            "not_found",
        ),
    ] {
        add(
            plan,
            one(
                format!("controller/resolve#{name}"),
                "resolve-l2",
                2,
                Operation::Resolve,
                json!({"policy":policy,"source":"root.yaml","documents":documents}),
                Assertion::Reject {
                    phases: vec![Phase::Resolve],
                    code: Some(reason.into()),
                    message: None,
                },
            ),
            target,
        )?;
    }
    Ok(())
}

pub fn plan_cases(snapshot: &CorpusSnapshot, target: u8) -> Result<Plan, String> {
    plan_cases_with_limits(snapshot, target, &ProcessLimits::default())
}

pub fn plan_cases_with_limits(
    snapshot: &CorpusSnapshot,
    target: u8,
    limits: &ProcessLimits,
) -> Result<Plan, String> {
    limits.validate()?;
    if target > 3 {
        return Err("external controller currently targets levels 0 through 3".into());
    }
    let mut plan = Plan {
        cases: Vec::new(),
        unattempted: Vec::new(),
        builtins: builtin_documents(),
        retained_request_bytes: 0,
        request_budget: limits.total_request_bytes,
    };
    let mut merge_dirs = BTreeSet::new();
    for entry in &snapshot.manifest.files {
        let level = match entry.category.as_str() {
            "doc" | "integration" => 0,
            "valid" | "invalid" | "expect" | "raw-yaml" => 1,
            "merge" => 2,
            "evaluation" | "library-suite" => 3,
            "canonical" | "resolve" | "receipt" | "receipt-expected" | "report" => 4,
            "bundle" | "log" | "log-schema" | "receipt-signed" | "signing" => 5,
            other => return Err(format!("unsupported category {other}")),
        };
        if entry.level != level {
            return Err(format!("{}: category/level mismatch", entry.path));
        }
        match entry.category.as_str() {
            "valid" | "invalid" => document_cases(
                snapshot,
                &mut plan,
                &entry.path,
                entry.category == "valid",
                target,
            )?,
            "evaluation" | "library-suite" => {
                evaluator_cases(snapshot, &mut plan, &entry.path, &entry.category, target)?
            }
            "raw-yaml" => raw_cases(snapshot, &mut plan, &entry.path, target)?,
            "merge" => {
                merge_dirs.insert(entry.path.rsplit_once('/').ok_or("invalid merge path")?.0);
            }
            "expect" | "doc" | "integration" => {}
            _ => plan.unattempted.push(slot_result(
                &slot(&entry.path, &entry.category, entry.level),
                Status::NotAttempted,
                "external controller does not implement this evidence category",
            )),
        }
    }
    for dir in merge_dirs {
        merge_cases(snapshot, &mut plan, dir, target)?;
    }
    resolution_counterexamples(&mut plan, target)?;
    if plan.cases.is_empty() || plan.cases.len() > MAX_CASES {
        return Err("empty or oversized external case plan".into());
    }
    let mut ids = BTreeSet::new();
    for case in &plan.cases {
        if !ids.insert(&case.id) {
            return Err("duplicate case ID".into());
        }
        for expected in &case.expectations {
            if let Assertion::Document(document) = &expected.assertion {
                super::score::normalize_document(document, true)
                    .map_err(|e| format!("{}: malformed expected document: {e}", case.id))?;
            }
        }
    }
    plan.complete_results(&[])?;
    Ok(plan)
}
