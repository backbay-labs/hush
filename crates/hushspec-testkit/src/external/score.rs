//! Controller-owned comparisons with literal corpus expectations.
use super::{
    corpus::{Assertion, Case, slot_result},
    json,
    model::{ErrorCodes, Observation, Operation, Phase, Response},
};
use crate::report::{Status, VectorResult};
use serde_json::{Map, Value};

fn empty(value: &Value) -> bool {
    match value {
        Value::Object(m) => m.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

fn project(
    value: &Value,
    schema: &Value,
    root: &Value,
    whole: &Value,
    depth: usize,
    top: bool,
    resolved: bool,
) -> Result<Value, String> {
    if depth > 128 {
        return Err("schema projection depth exceeded".into());
    }
    if let Some(reference) = schema["$ref"].as_str() {
        if let Some(pointer) = reference.strip_prefix('#') {
            let target = root
                .pointer(pointer)
                .ok_or_else(|| format!("missing schema reference {reference}"))?;
            return project(value, target, root, whole, depth + 1, top, resolved);
        }
        let target = whole["$defs"]
            .as_object()
            .and_then(|defs| defs.values().find(|v| v["$id"] == reference))
            .ok_or_else(|| format!("unbound schema resource {reference}"))?;
        return project(value, target, target, whole, depth + 1, top, resolved);
    }
    if let Some(object) = value.as_object() {
        if let Some(properties) = schema["properties"].as_object() {
            let mut result = Map::new();
            for (key, property) in properties {
                if top && resolved && matches!(key.as_str(), "extends" | "merge_strategy") {
                    continue;
                }
                let Some(present) = object.get(key) else {
                    if let Some(default) = property.get("default") {
                        result.insert(key.clone(), default.clone());
                    }
                    continue;
                };
                let projected =
                    project(present, property, root, whole, depth + 1, false, resolved)?;
                let required = schema["required"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v == key));
                let preserve_match = key == "match" && schema == &root["$defs"]["OriginProfile"];
                if empty(&projected)
                    && property.get("default").is_none()
                    && !required
                    && !preserve_match
                {
                    continue;
                }
                result.insert(key.clone(), projected);
            }
            return Ok(Value::Object(result));
        }
        if schema["additionalProperties"].is_object() {
            return object
                .iter()
                .map(|(key, value)| {
                    Ok((
                        key.clone(),
                        project(
                            value,
                            &schema["additionalProperties"],
                            root,
                            whole,
                            depth + 1,
                            false,
                            resolved,
                        )?,
                    ))
                })
                .collect::<Result<Map<_, _>, String>>()
                .map(Value::Object);
        }
    }
    if let Some(items) = value.as_array()
        && schema["items"].is_object()
    {
        return items
            .iter()
            .map(|v| project(v, &schema["items"], root, whole, depth + 1, false, resolved))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    Ok(value.clone())
}

/// Schema defaults and canonical empty-container presence only. No policy
/// parser, evaluator, merger, resolver or reference canonicalizer is invoked.
/// Resolution instructions are checked before projection, never stripped to
/// turn an incorrectly unresolved engine observation into a passing result.
pub fn normalize_document(document: &Value, resolved: bool) -> Result<Value, String> {
    json::validate(document, "core")?;
    if resolved && (document.get("extends").is_some() || document.get("merge_strategy").is_some()) {
        return Err("resolved observation retains resolution fields".into());
    }
    let body = crate::generated_schemas::schema_body("core").ok_or("missing core schema")?;
    let schema: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    project(document, &schema, &schema, &schema, 0, true, resolved)
}

fn equivalent(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => {
            let integer = |n: &serde_json::Number| {
                n.as_i64()
                    .map(i128::from)
                    .or_else(|| n.as_u64().map(i128::from))
            };
            match (integer(a), integer(b)) {
                (Some(a), Some(b)) => a == b,
                (Some(i), None) => (i as f64) as i128 == i && Some(i as f64) == b.as_f64(),
                (None, Some(i)) => (i as f64) as i128 == i && a.as_f64() == Some(i as f64),
                (None, None) => a.as_f64() == b.as_f64(),
            }
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|x| equivalent(v, x)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equivalent(a, b))
        }
        _ => a == b,
    }
}
fn fields_match(expected: &Value, actual: &Value) -> bool {
    if let Some(fields) = expected.as_object() {
        fields
            .iter()
            .all(|(k, v)| actual.get(k).is_some_and(|a| fields_match(v, a)))
    } else {
        equivalent(expected, actual)
    }
}

fn check_shape(operation: Operation, value: &Value) -> Result<(), String> {
    let object = value.as_object().ok_or("observation must be an object")?;
    match operation {
        Operation::Evaluate => {
            if object.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "decision" | "matched_rule" | "reason" | "origin_profile" | "posture"
                )
            }) {
                return Err("unknown evaluation observation field".into());
            }
            json::validate_at(value, "evaluator-test", "ExpectedResult")
        }
        Operation::Canonicalize => {
            if object.len() != 2
                || value["canonical"].as_str().is_none()
                || !value["content_hash"].as_str().is_some_and(|h| {
                    h.strip_prefix("sha256:")
                        .is_some_and(super::snapshot::valid_digest)
                })
            {
                return Err("malformed canonical observation".into());
            }
            Ok(())
        }
        Operation::Merge | Operation::Resolve => normalize_document(value, true).map(|_| ()),
        Operation::Parse | Operation::Validate => {
            if value["hushspec"].as_str().is_none() {
                return Err("parsed observation must identify its hushspec version".into());
            }
            Ok(())
        }
    }
}

pub fn score(
    case: &Case,
    response: &Response,
    codes: ErrorCodes,
) -> Result<Vec<VectorResult>, String> {
    if response.case_id != case.id || response.operation != case.operation {
        return Err("case binding mismatch".into());
    }
    if let Observation::Error { diagnostic } = &response.result {
        return Err(format!("engine internal error: {diagnostic}"));
    }
    if let Observation::Ok { value } = &response.result {
        check_shape(case.operation, value)?;
    }
    let mut results = Vec::new();
    for expected in &case.expectations {
        if matches!(response.result, Observation::Unsupported) {
            results.push(slot_result(
                &expected.slot,
                Status::NotAttempted,
                "engine does not support this operation",
            ));
            continue;
        }
        let passed = match (&expected.assertion, &response.result) {
            (Assertion::ParseUnconstrained, Observation::Ok { .. }) => true,
            (
                Assertion::ParseUnconstrained,
                Observation::Rejected {
                    phase: Phase::Parse,
                    ..
                },
            ) => true,
            (Assertion::Accept, Observation::Ok { value }) => {
                normalize_document(value, false).is_ok()
            }
            (
                Assertion::Reject {
                    phases,
                    code: expected_code,
                    message,
                },
                Observation::Rejected {
                    phase,
                    code,
                    diagnostic,
                },
            ) => {
                let enforce_code = expected_code.is_some()
                    && (codes == ErrorCodes::Registry
                        || code.is_some()
                        || expected_code.as_ref().is_some_and(|c| !c.starts_with('E')));
                let enforce_message = expected_code.is_none() || enforce_code;
                phases.contains(phase)
                    && (!enforce_code || code == expected_code)
                    && (!enforce_message || message.as_ref().is_none_or(|m| diagnostic.contains(m)))
            }
            (Assertion::Document(expected), Observation::Ok { value }) => equivalent(
                &normalize_document(expected, true)?,
                &normalize_document(value, true)?,
            ),
            (Assertion::Fields(expected), Observation::Ok { value }) => {
                fields_match(expected, value)
            }
            (
                Assertion::ValueAt {
                    path,
                    value: expected,
                },
                Observation::Ok { value },
            ) => {
                let mut actual = Some(value);
                for component in path {
                    actual = actual.and_then(|v| {
                        if v.is_array() {
                            component.parse::<usize>().ok().and_then(|i| v.get(i))
                        } else {
                            v.get(component)
                        }
                    });
                }
                actual.is_some_and(|v| equivalent(expected, v))
            }
            _ => false,
        };
        results.push(slot_result(
            &expected.slot,
            if passed { Status::Pass } else { Status::Fail },
            if passed {
                "observation matches corpus assertion"
            } else {
                "observation does not match corpus assertion"
            },
        ));
    }
    Ok(results)
}
