//! The merge-vector directory convention (`schemas/hushspec-merge-vector.v1.schema.json`).
//!
//! Merge vectors are a directory shape rather than a file format: a
//! `base.yaml`, one or more `child-<name>.yaml` overlays, and an
//! `expected-<name>.yaml` for each of them. This module is the Rust side of
//! that convention -- discovery, composition, and the refusal markers -- and
//! it can describe a directory as the descriptor object the schema validates,
//! so the prose, the schema, and the four runners cannot drift apart
//! silently.
//!
//! Portability: only two refusal markings are honoured by all four SDK
//! runners, so only those two are used here -- an `expect-reject` file in the
//! directory, or `reject: true` in the directory's `fixture.yaml`. Both are
//! directory-wide, which is why a refusal case lives in its own subdirectory
//! with its own `base.yaml`.

use std::path::{Path, PathBuf};

use hushspec::{HushSpec, merge};
use serde::Deserialize;
use serde_json::json;

/// The directory-wide refusal marker file.
pub const REJECT_MARKER: &str = "expect-reject";

/// The optional per-directory manifest.
pub const FIXTURE_MANIFEST: &str = "fixture.yaml";

/// The digest-pin marker inside an `extends` reference (core spec 2.3).
pub const DIGEST_PIN: &str = "#sha256:";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    reject: Option<bool>,
    #[serde(default)]
    cases: Option<std::collections::BTreeMap<String, ManifestCase>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestCase {
    #[serde(default)]
    reject: Option<bool>,
}

/// Whether a file in a merge directory is metadata rather than a vector.
#[must_use]
pub fn is_manifest(name: &str) -> bool {
    name == FIXTURE_MANIFEST || name == "fixture.yml" || name.ends_with(".fixture.yaml")
}

/// Whether a child sends its vector through the resolver: its `extends`
/// carries a `#sha256:` pin, and the pin is only checked while resolving.
#[must_use]
pub fn is_pinned(spec: &HushSpec) -> bool {
    spec.extends
        .as_deref()
        .is_some_and(|reference| reference.contains(DIGEST_PIN))
}

/// Whether a merge directory's vectors are expected to be refused.
#[must_use]
pub fn expects_reject(dir: &Path) -> bool {
    if dir.join(REJECT_MARKER).is_file() {
        return true;
    }
    read_manifest(dir).is_some_and(|manifest| manifest.reject == Some(true))
}

/// Whether one child is expected to be refused: the directory-wide marking,
/// or a per-child entry under `cases` (which only some runners honour, so a
/// portable vector does not rely on it).
#[must_use]
pub fn child_expects_reject(dir: &Path, child: &Path) -> bool {
    if expects_reject(dir) {
        return true;
    }
    let Some(manifest) = read_manifest(dir) else {
        return false;
    };
    let Some(cases) = manifest.cases else {
        return false;
    };
    let name = child.file_name().unwrap_or_default().to_string_lossy();
    let stem = child.file_stem().unwrap_or_default().to_string_lossy();
    [name.as_ref(), stem.as_ref()].iter().any(|key| {
        cases
            .get(*key)
            .is_some_and(|case| case.reject == Some(true))
    })
}

fn read_manifest(dir: &Path) -> Option<FixtureManifest> {
    let path = dir.join(FIXTURE_MANIFEST);
    let text = std::fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&text).ok()
}

/// A loader scoped to one merge directory.
///
/// It accepts the reference styles the corpus uses (`base`, `base.yaml`,
/// `./base.yaml`, any sibling file) and nothing outside the directory, so a
/// vector is portable across runners and cannot reach into the repository.
/// `builtin:` still goes to the built-in rulesets.
fn fixture_loader(
    dir: PathBuf,
) -> impl Fn(&str, Option<&str>) -> Result<hushspec::LoadedSpec, hushspec::ResolveError> {
    move |reference: &str, _from: Option<&str>| {
        if reference.starts_with("builtin:") {
            let composite = hushspec::create_composite_loader();
            return composite(reference, None);
        }
        for candidate in [
            reference.to_string(),
            format!("{reference}.yaml"),
            format!("{reference}.yml"),
        ] {
            let path = dir.join(candidate.trim_start_matches("./"));
            if !path.is_file() {
                continue;
            }
            let text =
                std::fs::read_to_string(&path).map_err(|error| hushspec::ResolveError::Read {
                    path: path.display().to_string(),
                    message: error.to_string(),
                })?;
            let spec = HushSpec::parse(&text).map_err(|error| hushspec::ResolveError::Parse {
                path: path.display().to_string(),
                message: error.to_string(),
            })?;
            return Ok(hushspec::LoadedSpec {
                source: path.display().to_string(),
                spec,
            });
        }
        Err(hushspec::ResolveError::NotFound {
            reference: reference.to_string(),
            message: format!("no such document inside {}", dir.display()),
        })
    }
}

/// Produce the document one `child-*.yaml` asserts.
///
/// A child that pins its base by digest goes through the resolver, so the pin
/// is actually checked and a chain of any length is followed; every other
/// child keeps the direct `merge(base, child)` the corpus has always been
/// checked with.
pub fn compose(base: &HushSpec, child_path: &Path) -> Result<HushSpec, String> {
    let dir = child_path
        .parent()
        .ok_or_else(|| "merge child has no directory".to_string())?
        .to_path_buf();
    let text = std::fs::read_to_string(child_path)
        .map_err(|error| format!("{}: {error}", child_path.display()))?;
    let child = HushSpec::parse(&text)
        .map_err(|error| format!("{}: failed to parse: {error}", child_path.display()))?;

    if !is_pinned(&child) {
        return Ok(merge(base, &child));
    }

    let loader = fixture_loader(dir);
    hushspec::resolve_with_options(
        &child,
        Some(&child_path.display().to_string()),
        &loader,
        &hushspec::ResolveOptions::default(),
    )
    .map(|resolution| resolution.spec)
    .map_err(|error| format!("{}: {error}", child_path.display()))
}

/// Describe a merge directory as the descriptor
/// `schemas/hushspec-merge-vector.v1.schema.json` validates.
pub fn describe(dir: &Path) -> Result<serde_json::Value, String> {
    let relative = crate::manifest::relative_fixture_path(dir)
        .ok_or_else(|| format!("{} is not under fixtures/", dir.display()))?;
    let rejects = expects_reject(dir);

    let mut children = Vec::new();
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|error| format!("{}: {error}", dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    names.sort();

    for path in names {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if !name.starts_with("child-") || is_manifest(&name) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let spec = HushSpec::parse(&text)
            .map_err(|error| format!("{}: failed to parse: {error}", path.display()))?;
        let expected = name.replacen("child-", "expected-", 1);
        let mut child = json!({
            "file": name,
            "expected": if rejects { serde_json::Value::Null } else { json!(expected) },
            "pinned": is_pinned(&spec),
        });
        if let Some(strategy) = spec.merge_strategy.as_ref() {
            let rendered = serde_json::to_value(strategy)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            child["merge_strategy"] = rendered;
        }
        children.push(child);
    }

    if children.is_empty() {
        return Err(format!("{relative}: no child-*.yaml vectors"));
    }

    let mut descriptor = json!({
        "directory": relative,
        "base": "base.yaml",
        "children": children,
    });
    if let Ok(manifest) = std::fs::read_to_string(dir.join(FIXTURE_MANIFEST)) {
        let parsed: serde_json::Value = serde_yaml::from_str(&manifest)
            .map_err(|error| format!("{}/{FIXTURE_MANIFEST}: {error}", relative))?;
        descriptor["manifest"] = parsed;
    }
    if rejects {
        descriptor["reject_marker"] = json!(if dir.join(REJECT_MARKER).is_file() {
            REJECT_MARKER
        } else {
            FIXTURE_MANIFEST
        });
    }
    Ok(descriptor)
}

/// Every merge vector directory under a fixtures tree: one holding a
/// `base.yaml` beside at least one `child-*.yaml`.
#[must_use]
pub fn discover(fixtures_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut stack = vec![fixtures_dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        let mut has_base = false;
        let mut has_child = false;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name == "base.yaml" {
                has_base = true;
            } else if name.starts_with("child-") && !is_manifest(&name) {
                has_child = true;
            }
        }
        if has_base && has_child {
            dirs.push(current);
        }
    }
    dirs.sort();
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::JSONSchema;

    fn fixtures_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    fn schema() -> JSONSchema {
        let body = crate::generated_schemas::schema_body("merge-vector")
            .expect("the merge-vector schema is embedded");
        let value: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
        JSONSchema::options()
            .should_validate_formats(true)
            .compile(&value)
            .expect("the merge-vector schema compiles")
    }

    /// Every merge vector directory in the corpus matches the convention the
    /// schema describes -- which is also what the four SDK runners implement.
    #[test]
    fn every_merge_vector_directory_matches_the_schema() {
        let compiled = schema();
        let dirs = discover(&fixtures_dir());
        assert!(
            dirs.len() >= 4,
            "expected the four module merge directories, found {}",
            dirs.len()
        );
        for dir in dirs {
            let descriptor = describe(&dir).unwrap_or_else(|error| panic!("{error}"));
            if let Err(errors) = compiled.validate(&descriptor) {
                let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
                panic!("{}: {}", dir.display(), messages.join(", "));
            }
        }
    }

    /// A merging vector has its `expected-*.yaml`; a refusing one does not.
    #[test]
    fn every_child_has_the_file_its_descriptor_promises() {
        for dir in discover(&fixtures_dir()) {
            let descriptor = describe(&dir).unwrap();
            for child in descriptor["children"].as_array().unwrap() {
                match child["expected"].as_str() {
                    Some(expected) => assert!(
                        dir.join(expected).is_file(),
                        "{}: {expected} is missing",
                        dir.display()
                    ),
                    None => assert!(
                        expects_reject(&dir),
                        "{}: a child with no expected document must be a refusal vector",
                        dir.display()
                    ),
                }
            }
        }
    }
}
