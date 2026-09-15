//! The normative canonical-form vectors (canonical spec 6 and 7).
//!
//! Every file under `fixtures/core/hash/` pairs a resolved document with the
//! exact canonical text and content hash a conformant implementation MUST
//! produce. `scripts/canonical_json.py` generated them; this suite is the
//! Rust half of the four-SDK conformance requirement.

use hushspec::canonical::{canonical_json_value, content_hash_value, digest};
use hushspec::{HushSpec, create_composite_loader, resolve_with_loader};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Vector format version (`schemas/hushspec-hash-vector.v0.schema.json`).
const VECTOR_VERSION: &str = "0.1.0";

/// Every vector in `fixtures/core/hash/`; keep in step with the table in
/// `fixtures/core/hash/README.md`.
const EXPECTED_VECTOR_COUNT: usize = 13;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HashVector {
    hushspec_hash_vector: String,
    description: String,
    /// Informational: the unresolved document `policy` was produced from.
    /// Never canonicalized directly (canonical spec 7).
    #[serde(default)]
    source: Option<serde_json::Value>,
    policy: serde_json::Value,
    canonical: String,
    content_hash: String,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/core/hash")
        .canonicalize()
        .expect("the hash vector directory exists")
}

fn load_vectors() -> Vec<(PathBuf, HashVector)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(vectors_dir())
        .expect("the hash vector directory is readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let vector: HashVector = serde_yaml::from_str(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(
                vector.hushspec_hash_vector,
                VECTOR_VERSION,
                "{}: unsupported vector version",
                path.display()
            );
            assert!(
                !vector.description.is_empty(),
                "{}: vectors must say what they exercise",
                path.display()
            );
            (path, vector)
        })
        .collect()
}

/// The document a vector canonicalizes: `policy`, already resolved. A vector
/// that still declared `extends` would be canonicalizing a fragment
/// (canonical spec 2.1), so resolve it through the same composite loader the
/// SDKs use before projecting.
fn resolved_policy(path: &Path, policy: &serde_json::Value) -> serde_json::Value {
    if policy.get("extends").is_none() {
        return policy.clone();
    }
    let spec = parse_policy(path, policy);
    let resolved = resolve_with_loader(&spec, None, &create_composite_loader())
        .unwrap_or_else(|error| panic!("{}: failed to resolve: {error}", path.display()));
    serde_json::to_value(&resolved)
        .unwrap_or_else(|error| panic!("{}: failed to re-encode: {error}", path.display()))
}

fn parse_policy(path: &Path, policy: &serde_json::Value) -> HushSpec {
    let yaml = serde_yaml::to_string(policy)
        .unwrap_or_else(|error| panic!("{}: failed to re-encode: {error}", path.display()));
    HushSpec::parse(&yaml)
        .unwrap_or_else(|error| panic!("{}: failed to parse: {error}", path.display()))
}

/// Report the first differing byte rather than two 2 KB strings.
fn assert_canonical_eq(path: &Path, description: &str, expected: &str, actual: &str) {
    if expected == actual {
        return;
    }
    let offset = expected
        .bytes()
        .zip(actual.bytes())
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| expected.len().min(actual.len()));
    let window = |text: &str| {
        let start = offset.saturating_sub(40);
        let end = (offset + 40).min(text.len());
        text.get(start..end).unwrap_or(text).to_string()
    };
    panic!(
        "{}: canonical form mismatch ({description})\n  first difference at byte {offset}\n  expected ...{}...\n  actual   ...{}...\n  expected len {} actual len {}",
        path.display(),
        window(expected),
        window(actual),
        expected.len(),
        actual.len(),
    );
}

#[test]
fn every_vector_reproduces_its_canonical_form_and_content_hash() {
    let vectors = load_vectors();
    assert_eq!(
        vectors.len(),
        EXPECTED_VECTOR_COUNT,
        "fixtures/core/hash/ gained or lost vectors; update EXPECTED_VECTOR_COUNT and the README table"
    );

    for (path, vector) in &vectors {
        let document = resolved_policy(path, &vector.policy);

        let canonical = canonical_json_value(&document)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_canonical_eq(path, &vector.description, &vector.canonical, &canonical);

        let hash = content_hash_value(&document)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            hash,
            vector.content_hash,
            "{}: content_hash mismatch",
            path.display()
        );
        // The hash is defined over the canonical bytes, not recomputed from
        // the document a second time (canonical spec 5).
        assert_eq!(hash, digest(&vector.canonical), "{}", path.display());
    }
}

/// `extends-resolved.yaml` carries the unresolved child in `source`. Resolving
/// it through the composite loader must land on the same identity as the
/// `policy` the vector pins -- the end-to-end path a caller actually takes.
#[test]
fn resolving_a_vector_source_reaches_the_pinned_content_hash() {
    let mut checked = 0;
    for (path, vector) in load_vectors() {
        let Some(source) = &vector.source else {
            continue;
        };
        let spec = parse_policy(&path, source);
        assert!(
            spec.extends.is_some(),
            "{}: `source` is only meaningful for an unresolved document",
            path.display()
        );
        let resolved = resolve_with_loader(&spec, None, &create_composite_loader())
            .unwrap_or_else(|error| panic!("{}: failed to resolve: {error}", path.display()));
        assert_eq!(
            hushspec::content_hash(&resolved).expect("the resolved document canonicalizes"),
            vector.content_hash,
            "{}: resolving `source` did not reproduce the vector's identity",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no vector exercises `source`");
}

/// Canonicalizing an unresolved document is a conformance failure
/// (canonical spec 2.1), on both entry points.
#[test]
fn an_unresolved_document_has_no_canonical_form() {
    let yaml = "hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n";
    let spec = HushSpec::parse(yaml).expect("parses");
    assert!(hushspec::canonical_json(&spec).is_err());
    assert!(hushspec::content_hash(&spec).is_err());

    let document: serde_json::Value = serde_yaml::from_str(yaml).expect("parses as a value tree");
    assert!(canonical_json_value(&document).is_err());
    assert!(content_hash_value(&document).is_err());
}

/// Every shipped ruleset must have a stable identity once resolved: the same
/// digest through both entry points, and a well-formed wire value.
#[test]
fn builtin_rulesets_canonicalize_through_both_entry_points() {
    for name in hushspec::BUILTIN_NAMES {
        let yaml = hushspec::load_builtin(name)
            .unwrap_or_else(|| panic!("{name} is a builtin but did not load"));
        let spec = HushSpec::parse(yaml).unwrap_or_else(|error| panic!("{name}: {error}"));
        let resolved = resolve_with_loader(&spec, Some(name), &create_composite_loader())
            .unwrap_or_else(|error| panic!("{name}: {error}"));

        let typed =
            hushspec::content_hash(&resolved).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(typed.starts_with("sha256:"), "{name}: {typed}");
        assert_eq!(typed.len(), "sha256:".len() + 64, "{name}: {typed}");

        let document = serde_json::to_value(&resolved).expect("re-encodes");
        assert_eq!(
            content_hash_value(&document).unwrap_or_else(|error| panic!("{name}: {error}")),
            typed,
            "{name}: the two entry points disagree"
        );
    }
}
