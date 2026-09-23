//! The `.v0.` document-format schemas are frozen (versioning spec 9): they
//! describe documents that declare a 0.x `hushspec` version and are not
//! edited after 1.0.0. `schemas/frozen-v0.json` records the digest of each,
//! and this test refuses any change to them. A schema change belongs in the
//! `.v1.` file with the same name.

use hushspec::canonical::digest;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMAS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");
const FROZEN_COMMENT: &str = "Frozen 0.x lineage.";

fn frozen_manifest() -> serde_json::Map<String, Value> {
    let raw = fs::read_to_string(Path::new(SCHEMAS).join("frozen-v0.json")).unwrap();
    let manifest: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(manifest["frozen_lineage"], "0.x");
    manifest["files"]
        .as_object()
        .expect("frozen-v0.json lists files")
        .clone()
}

fn schema_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(SCHEMAS)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("hushspec-") && name.ends_with(".schema.json"))
        })
        .collect();
    files.sort();
    files
}

fn file_name(path: &Path) -> &str {
    path.file_name().and_then(|name| name.to_str()).unwrap()
}

#[test]
fn frozen_v0_schemas_match_their_recorded_digests() {
    let manifest = frozen_manifest();
    assert_eq!(
        manifest.len(),
        16,
        "sixteen document-format schemas are frozen"
    );
    for (name, expected) in &manifest {
        let path = Path::new(SCHEMAS).join(name);
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            digest(&raw),
            expected.as_str().unwrap(),
            "{name} is frozen; publish the change in the .v1. file instead"
        );
        let schema: Value = serde_json::from_str(&raw).unwrap();
        let comment = schema["$comment"].as_str().unwrap_or_default();
        assert!(
            comment.starts_with(FROZEN_COMMENT),
            "{name} must say it is frozen in its $comment"
        );
    }
}

#[test]
fn every_document_format_v0_schema_is_frozen_and_has_a_v1_successor() {
    let manifest = frozen_manifest();
    let names: BTreeSet<String> = schema_files()
        .iter()
        .map(|path| file_name(path).to_string())
        .collect();
    let mut document_v0 = BTreeSet::new();
    for name in &names {
        if name.starts_with("hushspec-registry-") {
            assert!(
                name.ends_with(".v0.schema.json"),
                "{name}: registry schemas keep the .v0. name"
            );
            continue;
        }
        if let Some(stem) = name.strip_suffix(".v0.schema.json") {
            document_v0.insert(name.clone());
            let successor = format!("{stem}.v1.schema.json");
            assert!(
                names.contains(&successor),
                "{name} has no {successor} successor"
            );
        }
    }
    let frozen: BTreeSet<String> = manifest.keys().cloned().collect();
    assert_eq!(
        document_v0, frozen,
        "every document-format .v0. schema is listed in frozen-v0.json"
    );
}

#[test]
fn v1_schemas_carry_v1_ids_and_are_not_marked_frozen() {
    for path in schema_files() {
        let name = file_name(&path);
        if !name.ends_with(".v1.schema.json") {
            continue;
        }
        let schema: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            schema["$id"].as_str().unwrap(),
            format!("https://hushspec.org/schemas/{name}"),
            "{name}: $id names the v1 file"
        );
        assert!(
            schema.get("$comment").is_none(),
            "{name}: the current lineage carries no frozen marker"
        );
    }
}
