use std::fs;

/// The three extension schemas the core schema composes, as
/// `(extensions key, embedded $defs name, published file name)`.
const EMBEDDED_EXTENSIONS: [(&str, &str, &str); 3] = [
    (
        "posture",
        "PostureExtension",
        "hushspec-posture.v0.schema.json",
    ),
    (
        "origins",
        "OriginsExtension",
        "hushspec-origins.v0.schema.json",
    ),
    (
        "detection",
        "DetectionExtension",
        "hushspec-detection.v0.schema.json",
    ),
];

/// Vectors the YAML profile refuses before there is a document to validate:
/// anchors and aliases, merge keys, duplicate keys, and multi-document
/// streams are properties of the YAML *text* (core spec 2.4), and a JSON
/// Schema only ever sees the loaded document. The parser rejects them; this
/// file makes no claim about them.
const PROFILE_ONLY_VECTORS: [&str; 4] = [
    "yaml-alias.yaml",
    "yaml-duplicate-key.yaml",
    "yaml-merge-key.yaml",
    "yaml-multi-doc.yaml",
];

/// Vectors whose refusal no JSON Schema can express, each for a reason the
/// vocabulary has no keyword for: referential integrity between two members
/// of a document, uniqueness by a field of a list entry, a lookup in the IANA
/// time zone database, the HushSpec regex profile, and a recursion depth
/// bound. They are validated by the SDKs after parsing; here they are
/// asserted to *pass*, so that a schema change which does become able to
/// express one fails this test until the name is removed.
const BEYOND_SCHEMA_VECTORS: [&str; 6] = [
    "bad-initial.yaml",
    "duplicate-ids.yaml",
    "duplicate-pattern-names.yaml",
    "regex-mid-pattern-flag.yaml",
    "when-bad-timezone.yaml",
    "when-too-deep.yaml",
];

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

/// The core schema is a compound schema document: each `extensions` key is a
/// `$ref` to its companion schema's own `$id`, and the companion documents
/// are carried verbatim in `$defs` so those references resolve with no
/// network access. A copy that drifts from the published file would validate
/// policies against a schema nobody publishes, so it is compared here.
#[test]
fn the_core_schema_embeds_the_companion_schemas_verbatim() {
    let core = core_schema();
    let extensions = &core["$defs"]["Extensions"];

    for (key, def_name, file_name) in EMBEDDED_EXTENSIONS {
        let published = read_schema(file_name);
        let expected_id = format!("https://hushspec.dev/schemas/{file_name}");

        assert_eq!(
            extensions["properties"][key]["$ref"].as_str(),
            Some(expected_id.as_str()),
            "extensions.{key} must reference the {key} schema by its $id"
        );
        assert_eq!(
            extensions["properties"][key]["unevaluatedProperties"],
            serde_json::Value::Bool(false),
            "extensions.{key} must stay closed to unevaluated keys"
        );
        assert_eq!(
            core["$defs"][def_name], published,
            "$defs/{def_name} has drifted from schemas/{file_name}; \
             copy the published file back over it"
        );
        assert_eq!(
            published["$id"].as_str(),
            Some(expected_id.as_str()),
            "{file_name} does not declare the $id the core schema references"
        );
    }

    // The keys the composition covers are exactly the keys `extensions`
    // accepts, so no extension can be declared without being validated.
    let mut declared: Vec<&str> = extensions["properties"]
        .as_object()
        .expect("Extensions declares properties")
        .keys()
        .map(String::as_str)
        .collect();
    declared.sort_unstable();
    let mut composed = EMBEDDED_EXTENSIONS.map(|(key, _, _)| key).to_vec();
    composed.sort_unstable();
    assert_eq!(
        declared, composed,
        "every extension key must be composed from a companion schema"
    );
}

/// The published policy vectors, validated against the composed core schema.
///
/// Composition is what makes this meaningful for the extension vectors:
/// while `extensions.posture` was a bare `type: object`, every one of them
/// satisfied the schema regardless of content.
#[test]
fn the_core_schema_accepts_the_valid_vectors_and_refuses_the_invalid_ones() {
    let root = repo_root();
    let schema = compile(&core_schema());

    let mut accepted = 0;
    let mut refused = 0;
    let mut tolerated: Vec<String> = Vec::new();

    for family in ["core", "posture", "origins", "detection"] {
        for (kind, expect_valid) in [("valid", true), ("invalid", false)] {
            let dir = format!("{root}/fixtures/{family}/{kind}");
            for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{dir} is readable: {e}")) {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if !name.ends_with(".yaml") || name.ends_with(".expect.yaml") {
                    continue;
                }
                if PROFILE_ONLY_VECTORS.contains(&name.as_str()) {
                    continue;
                }

                let text = fs::read_to_string(&path).unwrap();
                let document: serde_json::Value = serde_yaml::from_str(&text)
                    .unwrap_or_else(|e| panic!("{} is not YAML: {e}", path.display()));
                let valid = schema.is_valid(&document);

                if expect_valid {
                    if let Err(errors) = schema.validate(&document) {
                        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
                        panic!("{} must satisfy the schema: {messages:?}", path.display());
                    }
                    accepted += 1;
                } else if BEYOND_SCHEMA_VECTORS.contains(&name.as_str()) {
                    assert!(
                        valid,
                        "{} is listed as beyond JSON Schema but the schema now refuses it; \
                         drop it from the list",
                        path.display()
                    );
                    tolerated.push(name);
                } else {
                    assert!(!valid, "{} must be refused by the schema", path.display());
                    refused += 1;
                }
            }
        }
    }

    assert!(accepted > 0 && refused > 0, "no vectors were checked");
    tolerated.sort();
    assert_eq!(
        tolerated,
        BEYOND_SCHEMA_VECTORS.to_vec(),
        "every listed name must still be a published vector"
    );
}

/// What the composition exists for: an unknown key inside an extension block
/// is a rejection, not an annotation (core spec 2.1 and 9.5).
#[test]
fn an_unknown_key_inside_an_extension_block_is_refused() {
    let schema = compile(&core_schema());

    for (key, ..) in EMBEDDED_EXTENSIONS {
        let document = serde_json::json!({
            "hushspec": "0.1.0",
            "extensions": { key: { "bogus": 1 } },
        });
        assert!(
            !schema.is_valid(&document),
            "extensions.{key}.bogus must be refused"
        );
    }
}

fn repo_root() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

fn read_schema(file_name: &str) -> serde_json::Value {
    let root = repo_root();
    let raw = fs::read_to_string(format!("{root}/schemas/{file_name}"))
        .unwrap_or_else(|e| panic!("{file_name} is readable: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{file_name} is JSON: {e}"))
}

fn core_schema() -> serde_json::Value {
    read_schema("hushspec-core.v0.schema.json")
}

fn compile(document: &serde_json::Value) -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(document)
        .expect("the core schema compiles")
}

/// The prepared SchemaStore catalog entries must satisfy the shape
/// `src/api/json/catalog.json` accepts, and must point at schemas this
/// repository actually publishes.
///
/// A catalog entry carries a `name`, a `description`, an HTTPS `url`, and
/// either a `fileMatch` list or a `versions` map; the array is sorted by
/// `name` and rejects any other key. An entry that drifts from that is a
/// submission that bounces, and an entry whose `url` names a schema the site
/// does not serve is a 404 in every editor that consults the catalog.
#[test]
fn the_schemastore_entries_match_the_catalog_entry_shape() {
    let root = repo_root();
    let raw = fs::read_to_string(format!("{root}/docs/schemastore-entry.json"))
        .expect("the prepared entry is readable");
    let document: serde_json::Value = serde_json::from_str(&raw).expect("it is JSON");

    let entries = document["schemas"]
        .as_array()
        .expect("the file wraps the entries in a `schemas` array");
    assert!(
        !entries.is_empty(),
        "at least the core schema must be listed"
    );

    let published: Vec<String> = fs::read_dir(format!("{root}/schemas"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            (path.extension()? == "json").then(|| {
                format!(
                    "https://hushspec.dev/schemas/{}",
                    path.file_name().unwrap().to_string_lossy()
                )
            })
        })
        .collect();

    let mut names: Vec<&str> = Vec::new();
    for entry in entries {
        let object = entry.as_object().expect("an entry is an object");
        for key in object.keys() {
            assert!(
                matches!(key.as_str(), "name" | "description" | "fileMatch" | "url"),
                "{key} is not a catalog entry key"
            );
        }

        let name = object["name"].as_str().expect("name is a string");
        assert!(!name.is_empty(), "an entry needs a name");
        assert!(
            object["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{name} needs a description"
        );

        let url = object["url"].as_str().expect("url is a string");
        assert!(url.starts_with("https://"), "{name}: {url} must be HTTPS");
        assert!(
            published.contains(&url.to_string()),
            "{name}: {url} is not a schema this repository publishes"
        );

        let patterns = object["fileMatch"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} needs a fileMatch list"));
        assert!(!patterns.is_empty(), "{name}: fileMatch must not be empty");
        let mut seen: Vec<&str> = patterns
            .iter()
            .map(|pattern| pattern.as_str().expect("a pattern is a string"))
            .collect();
        let count = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), count, "{name}: fileMatch has a duplicate");

        names.push(name);
    }

    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "the catalog array is sorted by name");

    // The policy schema is the entry the whole submission exists for.
    assert!(
        names.contains(&"HushSpec"),
        "the core policy schema must be listed"
    );
}

/// An origins profile overlay narrows the base rule it composes with; it must
/// not be able to switch one off, or to introduce a control the base rule
/// does not have.
///
/// `enabled` and `when` gate a rule *block* and belong to the base policy. An
/// overlay that declared `enabled` would let an origin profile disable a
/// control the base policy applies -- the opposite of what an overlay is for,
/// since allowlists intersect and blocklists union (origins spec 4). Every
/// overlay key must also name a property of the base block, so the overlay
/// can only ever tighten something that already exists.
#[test]
fn the_origins_overlays_narrow_a_base_rule_and_cannot_disable_it() {
    let origins = read_schema("hushspec-origins.v0.schema.json");
    let core = core_schema();

    for (overlay_def, base_def) in [("ToolAccessRule", "ToolAccess"), ("EgressRule", "Egress")] {
        let overlay = origins["$defs"][overlay_def]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("origins $defs/{overlay_def} declares properties"));
        let base = core["$defs"][base_def]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("core $defs/{base_def} declares properties"));

        for gate in ["enabled", "when"] {
            assert!(
                !overlay.contains_key(gate),
                "origins $defs/{overlay_def} must not declare `{gate}`: \
                 an overlay narrows a base rule, it does not gate one"
            );
        }
        for key in overlay.keys() {
            assert!(
                base.contains_key(key),
                "origins $defs/{overlay_def}.{key} has no counterpart in \
                 core $defs/{base_def}"
            );
        }
        assert!(
            !overlay.is_empty(),
            "origins $defs/{overlay_def} overlays nothing"
        );
    }
}
