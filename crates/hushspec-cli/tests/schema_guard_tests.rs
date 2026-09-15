use std::fs;

#[test]
fn every_schema_meta_validates_and_id_matches_filename() {
    let schema_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");
    let mut checked = 0;
    for entry in fs::read_dir(schema_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let raw = fs::read_to_string(&path).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();

        // Draft 2020-12 meta-validation: compiling IS validating the schema itself.
        // should_validate_formats is inert here (no instance is ever validated --
        // only the schema document's own structure is checked by compiling it),
        // but it is set explicitly anyway for consistency with the other
        // JSONSchema::compile call sites in this crate, all of which assert
        // formats deliberately rather than relying on the draft's default.
        jsonschema::JSONSchema::options()
            .should_validate_formats(true)
            .compile(&doc)
            .unwrap_or_else(|e| panic!("{} is not a valid schema: {e}", path.display()));

        let file = path.file_name().unwrap().to_string_lossy();
        let want_id = format!("https://hushspec.dev/schemas/{file}");
        assert_eq!(
            doc["$id"].as_str(),
            Some(want_id.as_str()),
            "{} has wrong $id",
            path.display()
        );
        assert_eq!(
            doc["$schema"].as_str(),
            Some("https://json-schema.org/draft/2020-12/schema"),
            "{} wrong draft",
            path.display()
        );
        checked += 1;
    }
    assert_eq!(checked, 11, "expected the 11 published schemas");
}

/// The framework registry is normative input to lint L013 and to the embedded
/// `generated_frameworks.rs`, so it is validated against its own published
/// schema here rather than only being read at generation time.
#[test]
fn framework_registry_validates_against_its_schema() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let schema_raw = fs::read_to_string(format!(
        "{root}/schemas/hushspec-framework-registry.v0.schema.json"
    ))
    .expect("framework registry schema is readable");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_raw).expect("framework registry schema is JSON");
    let compiled = jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&schema)
        .expect("framework registry schema compiles");

    let registry_raw = fs::read_to_string(format!("{root}/spec/registries/frameworks.yaml"))
        .expect("framework registry is readable");
    let registry: serde_json::Value =
        serde_yaml::from_str(&registry_raw).expect("framework registry is YAML");

    if let Err(errors) = compiled.validate(&registry) {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!("spec/registries/frameworks.yaml fails its schema: {messages:?}");
    }
}

/// Every `control_id_pattern` in the registry must compile with the same regex
/// engine lint L013 uses, must be anchored at both ends (so a partial match
/// cannot silently accept a malformed control id), and the ids must be sorted
/// and unique so the embedded table is stable.
#[test]
fn framework_registry_patterns_compile_and_are_anchored() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let raw = fs::read_to_string(format!("{root}/spec/registries/frameworks.yaml")).unwrap();
    let registry: serde_json::Value = serde_yaml::from_str(&raw).unwrap();
    let frameworks = registry["frameworks"].as_array().expect("frameworks list");

    let mut ids: Vec<&str> = Vec::new();
    for entry in frameworks {
        let id = entry["id"].as_str().expect("id is a string");
        let pattern = entry["control_id_pattern"]
            .as_str()
            .expect("control_id_pattern is a string");

        regex::Regex::new(pattern).unwrap_or_else(|e| {
            panic!("{id}: control_id_pattern {pattern:?} does not compile: {e}")
        });
        assert!(
            pattern.starts_with('^') && pattern.ends_with('$'),
            "{id}: control_id_pattern {pattern:?} must be anchored",
        );
        ids.push(id);
    }

    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids, sorted, "framework ids must be sorted and unique");
    assert!(!ids.is_empty(), "the registry must not be empty");
}
