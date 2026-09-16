//! Resolution vectors (core spec 2.3, receipt spec 4.2): digest pins and
//! chain provenance, under `fixtures/core/resolve/`.
//!
//! Each vector is an inline leaf document whose `extends` references only
//! builtins, so every SDK resolves it with its embedded rulesets and no
//! filesystem. The expectation is either the resolved content hash plus the
//! chain links (root first, the leaf recorded as `memory`), or a rejection
//! reason. This file generates the vectors (`HUSHSPEC_UPDATE_RESOLVE_VECTORS=1`)
//! and checks the committed ones against the resolver; the reader itself is
//! `hushspec_testkit::resolve_vector`, shared with the conformance runner.

use std::fs;
use std::path::{Path, PathBuf};

use hushspec::{
    HushSpec, ResolveError, ResolveOptions, create_composite_loader, resolve_with_options,
};
use hushspec_testkit::resolve_vector::{
    ResolveExpect, ResolveLink, ResolveVector, VECTORS_VERSION, chain_of, check,
};

fn repo_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).to_path_buf()
}

fn vectors_dir() -> PathBuf {
    repo_root().join("fixtures/core/resolve")
}

fn own_hash_of_builtin(name: &str) -> String {
    let spec = HushSpec::parse(hushspec::load_builtin(name).unwrap()).unwrap();
    hushspec::own_content_hash(&spec, &format!("builtin:{name}")).unwrap()
}

/// Vector definitions: name, description, leaf YAML, expected rejection
/// (or `None` for a resolution whose hashes are filled in on generation).
fn definitions() -> Vec<(&'static str, &'static str, String, Option<&'static str>)> {
    let default_own = own_hash_of_builtin("default");
    vec![
        (
            "no-extends",
            "a document with no extends resolves to itself: one chain link, the leaf, recorded as memory",
            "hushspec: \"0.1.0\"\nname: leaf-only\nrules:\n  egress:\n    allow: [\"api.example.com\"]\n    default: block\n".to_string(),
            None,
        ),
        (
            "chain-builtin",
            "extends a builtin: the chain lists the builtin's own hash first and the leaf's own hash last; content_hash is the merged document's",
            "hushspec: \"0.1.0\"\nname: child\nextends: \"builtin:default\"\nrules:\n  egress:\n    allow: [\"custom.example.com\"]\n    default: block\n".to_string(),
            None,
        ),
        (
            "chain-two-hops",
            "a policy that extends a builtin yields two links, root first",
            "hushspec: \"0.1.0\"\nname: grandchild\nextends: \"builtin:ai-agent\"\nrules:\n  tool_access:\n    block: [\"deploy\"]\n    default: allow\n".to_string(),
            None,
        ),
        (
            "pin-valid",
            "core 2.3: a #sha256: pin naming the base's own content hash is accepted and the chain is unchanged by it",
            format!("hushspec: \"0.1.0\"\nname: pinned\nextends: \"builtin:default#{default_own}\"\nrules:\n  egress:\n    allow: [\"custom.example.com\"]\n    default: block\n"),
            None,
        ),
        (
            "pin-mismatch",
            "core 2.3: a pin that does not match the base's own content hash is rejected with digest_mismatch, whether or not signatures are required",
            "hushspec: \"0.1.0\"\nname: mispinned\nextends: \"builtin:default#sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n".to_string(),
            Some("digest_mismatch"),
        ),
        (
            "pin-malformed",
            "core 2.3: a fragment that is not sha256:<64 lowercase hex> is rejected before anything is loaded",
            "hushspec: \"0.1.0\"\nname: badpin\nextends: \"builtin:default#sha256:ABC\"\n".to_string(),
            Some("invalid_pin"),
        ),
        (
            "unknown-builtin",
            "a reference no loader can serve is rejected, never resolved as the leaf alone",
            "hushspec: \"0.1.0\"\nname: dangling\nextends: \"builtin:no-such-ruleset\"\n".to_string(),
            Some("not_found"),
        ),
    ]
}

fn generate() -> Vec<(String, ResolveVector)> {
    let loader = create_composite_loader();
    definitions()
        .into_iter()
        .map(|(name, description, yaml, rejects)| {
            let policy: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
            let expect = match rejects {
                Some(reason) => ResolveExpect {
                    resolves: Some(false),
                    content_hash: None,
                    chain: None,
                    rejects: Some(reason.to_string()),
                },
                None => {
                    let spec = HushSpec::parse(&yaml).unwrap();
                    let resolution =
                        resolve_with_options(&spec, None, &loader, &ResolveOptions::default())
                            .unwrap_or_else(|e| panic!("{name}: {e}"));
                    ResolveExpect {
                        resolves: Some(true),
                        content_hash: Some(resolution.content_hash.clone()),
                        chain: Some(chain_of(&resolution)),
                        rejects: None,
                    }
                }
            };
            (
                format!("{name}.yaml"),
                ResolveVector {
                    hushspec_resolve: VECTORS_VERSION.to_string(),
                    description: description.to_string(),
                    policy,
                    expect,
                },
            )
        })
        .collect()
}

#[test]
fn resolve_vectors_are_current_and_pass() {
    let update = update_requested("HUSHSPEC_UPDATE_RESOLVE_VECTORS");
    let generated = generate();
    if update {
        fs::create_dir_all(vectors_dir()).unwrap();
        for (file, vector) in &generated {
            fs::write(
                vectors_dir().join(file),
                serde_yaml::to_string(vector).unwrap(),
            )
            .unwrap();
        }
    }
    let mut problems = Vec::new();
    for (file, vector) in &generated {
        let path = vectors_dir().join(file);
        match fs::read_to_string(&path) {
            Ok(text) => {
                let expected = serde_yaml::to_string(vector).unwrap();
                if text != expected {
                    problems.push(format!("{file} differs from the generated vector"));
                }
            }
            Err(_) => problems.push(format!("{file} is missing")),
        }
    }
    assert!(
        problems.is_empty(),
        "resolve vectors drifted (run with HUSHSPEC_UPDATE_RESOLVE_VECTORS=1 after a deliberate change):\n{}",
        problems.join("\n")
    );

    let mut count = 0;
    for entry in fs::read_dir(vectors_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        let vector: ResolveVector = serde_yaml::from_str(&fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        check(&vector).unwrap_or_else(|message| panic!("{}: {message}", path.display()));
        count += 1;
    }
    assert!(
        count >= 7,
        "expected at least 7 resolve vectors, found {count}"
    );
}

/// A vector that says it resolves and also names a rejection describes nothing
/// a runner can check, so the reader refuses it rather than reading one field
/// and ignoring the other.
#[test]
fn a_vector_that_contradicts_itself_is_refused() {
    let mut vector = generate().remove(0).1;
    assert_eq!(vector.expect.resolves, Some(true));
    vector.expect.rejects = Some("not_found".to_string());
    let message = check(&vector).expect_err("a self-contradicting vector is not a vector");
    assert!(message.contains("expect.resolves"), "{message}");

    vector.expect.rejects = None;
    vector.expect.resolves = Some(false);
    let message = check(&vector).expect_err("a self-contradicting vector is not a vector");
    assert!(message.contains("expect.resolves"), "{message}");
}

/// The rejection vocabulary is closed. A failure it does not name is a failure
/// the runner reports, never one it quietly relabels.
#[test]
fn a_failure_the_vocabulary_does_not_name_has_no_reason_code() {
    use hushspec_testkit::resolve_vector::reason_code;

    assert_eq!(reason_code(&ResolveError::MaxDepth), Some("max_depth"));
    assert_eq!(
        reason_code(&ResolveError::Parse {
            path: "p.yaml".to_string(),
            message: "bad".to_string(),
        }),
        None
    );
}

#[test]
fn pins_satisfy_a_signature_requirement_for_that_hop() {
    // With signatures required and no keyring, a pinned builtin hop passes
    // (builtins are never verified anyway) but a memory leaf cannot be
    // verified, so resolution fails closed on the leaf.
    let default_own = own_hash_of_builtin("default");
    let spec = HushSpec::parse(&format!(
        "hushspec: \"0.1.0\"\nextends: \"builtin:default#{default_own}\"\n"
    ))
    .unwrap();
    let loader = create_composite_loader();
    let options = ResolveOptions {
        require_signature: true,
        ..ResolveOptions::default()
    };
    let error = resolve_with_options(&spec, None, &loader, &options).unwrap_err();
    assert!(
        matches!(&error, ResolveError::SignatureRequired { document, .. } if document == "memory"),
        "{error}"
    );
}

/// Whether the caller asked for the committed vectors to be regenerated.
///
/// Only `1` and `true` count: `is_ok()` would make `VAR=0` regenerate, which
/// silently turns a verifying run into a rubber stamp.
fn update_requested(var: &str) -> bool {
    matches!(std::env::var(var).as_deref(), Ok("1") | Ok("true"))
}

/// The chain shape the vectors record is the resolution's own, so a change to
/// one is a change to the other.
#[test]
fn a_chain_is_recorded_hop_for_hop() {
    let spec = HushSpec::parse("hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n").unwrap();
    let resolution = resolve_with_options(
        &spec,
        None,
        &create_composite_loader(),
        &ResolveOptions::default(),
    )
    .unwrap();
    let recorded: Vec<ResolveLink> = chain_of(&resolution);
    assert_eq!(recorded.len(), resolution.chain.len());
    assert_eq!(recorded[0].source, "builtin:default");
}
