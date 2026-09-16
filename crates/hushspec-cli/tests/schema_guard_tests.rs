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
    // A floor, not an exact count: the published set grows, and this test is
    // here to catch a schema that does not meta-validate or whose `$id` drifts
    // from its file name, never to fail every PR that adds one. The exact set
    // is enforced by `generated_schemas_match_the_schemas_directory` in
    // `cmd_schema.rs`, which compares the embedded module with the directory.
    assert!(
        checked >= 15,
        "expected at least the 15 published schemas, found {checked}"
    );
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

/// The bundle schema is the one published schema whose root describes only
/// half the document: the payload is base64, so the statement it decodes to
/// lives in `$defs/Statement` and is validated separately (bundle spec 5.2
/// check 1). Both halves must compile on their own, and the published
/// vectors must satisfy both -- otherwise `h2h schema bundle` would hand a
/// consumer a schema that cannot validate the bundles this repository ships.
#[test]
fn the_bundle_schema_validates_the_published_vectors() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let raw = fs::read_to_string(format!("{root}/schemas/hushspec-bundle.v0.schema.json"))
        .expect("the bundle schema is published");
    let document: serde_json::Value = serde_json::from_str(&raw).expect("it is JSON");

    // The body `h2h schema bundle` prints is the published file, byte for byte.
    assert_eq!(
        embedded_schema_body("bundle"),
        raw,
        "the embedded bundle schema has drifted from schemas/; \
         run scripts/generate_cli_schemas.py"
    );

    let envelope = jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&document)
        .expect("the envelope schema compiles");

    // `$defs/Statement` promoted to a root, with the definitions carried
    // along so its internal `#/$defs/...` references still resolve.
    let mut statement_document = document["$defs"]["Statement"].clone();
    statement_document["$schema"] = document["$schema"].clone();
    statement_document["$defs"] = document["$defs"].clone();
    let statement_schema = jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&statement_document)
        .expect("the statement schema compiles");

    let mut checked = 0;
    for entry in fs::read_dir(format!("{root}/fixtures/bundle/bundles"))
        .expect("fixtures/bundle/bundles is readable")
    {
        let path = entry.unwrap().path();
        let instance: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        if let Err(errors) = envelope.validate(&instance) {
            let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            panic!(
                "{} is not a valid DSSE envelope: {messages:?}",
                path.display()
            );
        }

        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let statement: serde_json::Value =
            serde_json::from_slice(&decode_base64(instance["payload"].as_str().unwrap())).unwrap();
        // One vector deliberately carries a predicate type 0.1 does not define.
        let expected = name != "malformed-predicate-type.bundle.json";
        assert_eq!(
            statement_schema.validate(&statement).is_ok(),
            expected,
            "{}: statement validation should {}",
            path.display(),
            if expected { "pass" } else { "fail" }
        );
        checked += 1;
    }
    assert_eq!(checked, 6, "expected the 6 published bundle vectors");
}

/// The schema body the CLI embeds, read through the same table `h2h schema`
/// uses. Shelled out to rather than imported because an integration test
/// cannot reach a binary crate's private modules.
fn embedded_schema_body(name: &str) -> String {
    let output = assert_cmd::Command::cargo_bin("h2h")
        .expect("the h2h binary is built")
        .arg("schema")
        .arg(name)
        .output()
        .expect("h2h schema runs");
    assert!(output.status.success(), "h2h schema {name} failed");
    String::from_utf8(output.stdout).expect("the schema body is UTF-8")
}

/// Standard base64 with padding.
fn decode_base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes().filter(|byte| *byte != b'=') {
        let value = ALPHABET.iter().position(|c| *c == byte).expect("base64") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}
