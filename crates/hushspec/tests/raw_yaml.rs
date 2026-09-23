use hushspec::{HushSpec, canonical_json, content_hash, evaluate};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn raw_yaml_core_scalars() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("../../../fixtures/core/raw-yaml/scalars.json")).unwrap();
    let mut failures = Vec::new();
    for vector in vectors {
        let name = vector["id"].as_str().unwrap();
        let parsed = HushSpec::parse(vector["yaml"].as_str().unwrap());
        if parsed.is_ok() != vector["accept"].as_bool().unwrap() {
            failures.push(format!("{name}: {parsed:?}"));
            continue;
        }
        let Ok(policy) = parsed else { continue };
        let canonical = canonical_json(&policy).unwrap();
        let mut value: Value = serde_json::from_str(&canonical).unwrap();
        for key in vector["value_path"].as_array().unwrap() {
            value = if value.is_array() {
                value[key.as_str().unwrap().parse::<usize>().unwrap()].clone()
            } else {
                value[key.as_str().unwrap()].clone()
            };
        }
        let expected = &vector["value"];
        let equal = if value.is_number() && expected.is_number() {
            value.as_f64() == expected.as_f64()
        } else {
            &value == expected
        };
        if !equal {
            failures.push(format!("{name}: got {value}, expected {expected}"));
        }
        if let Some(expected) = vector["canonical"].as_str() {
            assert_eq!(canonical, expected, "{name}");
            assert_eq!(
                content_hash(&policy).unwrap(),
                format!("sha256:{:x}", Sha256::digest(expected.as_bytes())),
                "{name}"
            );
        }
        if let Some(expected) = vector["decision"].as_str() {
            let action = serde_json::from_value(serde_json::json!({"type":"egress", "target":"example.com", "context":{"counters":{"requests":9}}})).unwrap();
            assert_eq!(
                serde_json::to_value(evaluate(&policy, &action)).unwrap()["decision"],
                expected,
                "{name}"
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
