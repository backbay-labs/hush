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
        jsonschema::JSONSchema::compile(&doc)
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
    assert_eq!(checked, 7, "expected the 7 published schemas");
}
