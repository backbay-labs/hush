//! The published conformance bundle: `hushspec-conformance-<version>.tar.gz`.
//!
//! A third party should be able to claim a conformance level from the
//! specification alone. That needs one downloadable artifact holding the
//! prose, the schemas, the vectors and the manifest that pins them -- which is
//! what this builds, and what `release.yml` attaches to every release.
//!
//! The bundle is reproducible: entries are emitted in sorted order with fixed
//! modes, zeroed mtimes and no owner names, and the gzip header carries no
//! timestamp. The same tree therefore produces the same bytes, so the digest
//! in an attestation means something.

use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;

use crate::manifest::Manifest;

/// Everything in the bundle, relative to the repository root. `fixtures/`
/// carries `MANIFEST.json` with it.
const DIRECTORIES: [&str; 3] = ["fixtures", "schemas", "spec"];

/// Fixed mode for every regular file: readable by everyone, writable by the
/// owner. A bundle must not depend on the umask of the machine that built it.
const FILE_MODE: u32 = 0o644;

/// The gzip "operating system" byte: 255, unknown. Anything else would record
/// the build machine in the artifact.
const GZIP_OS_UNKNOWN: u8 = 255;

/// The default artifact name for a corpus version.
#[must_use]
pub fn default_file_name(fixtures_version: &str) -> String {
    format!("hushspec-conformance-{fixtures_version}.tar.gz")
}

/// Build the bundle for the repository rooted at `root` and return its bytes.
pub fn build(root: &Path) -> Result<Vec<u8>, String> {
    let manifest = Manifest::load(&root.join("fixtures")).map_err(|error| error.to_string())?;
    let prefix = format!("hushspec-conformance-{}", manifest.fixtures_version);

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    entries.push((
        format!("{prefix}/README.md"),
        readme(&manifest.fixtures_version, manifest.files.len()).into_bytes(),
    ));

    for directory in DIRECTORIES {
        let source = root.join(directory);
        if !source.is_dir() {
            return Err(format!("{} is missing", source.display()));
        }
        for path in crate::manifest::walk(&source) {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("{}: {error}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes =
                std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            entries.push((format!("{prefix}/{relative}"), bytes));
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut archive = tar::Builder::new(Vec::new());
    for (name, bytes) in &entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(FILE_MODE);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(tar::EntryType::Regular);
        header
            .set_username("")
            .map_err(|error| format!("{name}: {error}"))?;
        header
            .set_groupname("")
            .map_err(|error| format!("{name}: {error}"))?;
        archive
            .append_data(&mut header, name, bytes.as_slice())
            .map_err(|error| format!("{name}: {error}"))?;
    }
    let tarball = archive
        .into_inner()
        .map_err(|error| format!("could not finish the archive: {error}"))?;

    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(GZIP_OS_UNKNOWN)
        .write(Vec::new(), Compression::default());
    encoder
        .write_all(&tarball)
        .map_err(|error| format!("could not compress the archive: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("could not finish the archive: {error}"))
}

/// Build the bundle and write it, returning the path written and its digest.
pub fn write(root: &Path, out: Option<&Path>) -> Result<(PathBuf, String), String> {
    let manifest = Manifest::load(&root.join("fixtures")).map_err(|error| error.to_string())?;
    let bytes = build(root)?;
    let path = out.map_or_else(
        || PathBuf::from(default_file_name(&manifest.fixtures_version)),
        Path::to_path_buf,
    );
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    std::fs::write(&path, &bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok((path, crate::manifest::digest_bytes(&bytes)))
}

fn readme(fixtures_version: &str, file_count: usize) -> String {
    format!(
        r#"# HushSpec conformance bundle {fixtures_version}

Everything needed to claim a HushSpec conformance level without cloning the
reference repository: the normative prose, the JSON Schemas, the {file_count}
test vectors, and the manifest that pins them.

```
README.md            this file
spec/                the normative specifications (core, canonical, receipt,
                     log, signing, bundle, and the extension modules) plus
                     spec/registries/, including the error-code registry
schemas/             JSON Schema 2020-12 documents, including
                     hushspec-conformance-report.v1.schema.json
fixtures/            the vectors, and MANIFEST.json describing every one of
                     them: path, sha256, category, module, and the
                     conformance level at which it becomes required
```

## Check the corpus first

Every vector's digest is in `fixtures/MANIFEST.json`. Verify them before you
run anything, so your results are about your implementation and not about a
corrupted download:

```bash
python3 - <<'PY'
import hashlib, json, pathlib
manifest = json.load(open("fixtures/MANIFEST.json"))
bad = [e["path"] for e in manifest["files"]
       if hashlib.sha256(pathlib.Path(e["path"]).read_bytes()).hexdigest() != e["sha256"]]
print("corpus ok" if not bad else "MISMATCH: " + ", ".join(bad))
PY
```

## Run it against your implementation

The levels are defined in `spec/hushspec-core.md` Section 8. Each level's
vectors are the manifest entries whose `level` is at or below it.

| Level | Name | What to run |
|---|---|---|
| 0 | Parser | every `valid/` document parses; every `invalid/` one is refused; raw-YAML parse acceptance matches `core/raw-yaml/scalars.json` |
| 1 | Validator | plus validation, error-code sidecars, and raw-YAML decoded-value cases |
| 2 | Merger | `*/merge/`: `base.yaml` + `child-*.yaml` must produce `expected-*.yaml` |
| 3 | Evaluator | `*/evaluation/*.test.yaml` plus raw-YAML decision cases |
| 4 | Auditor | `core/hash/`, raw-YAML canonical/hash cases, `core/resolve/`, `receipts/` including `receipts/expected/` |
| 5 | Attested | `signing/`, `log/` including `log/schema-vectors.json`, `bundle/`, `receipts/signed/` |

The file formats are schema'd: evaluator tests by
`hushspec-evaluator-test.v1.schema.json`, canonical-form vectors by
`hushspec-hash-vector.v1.schema.json`, merge vector directories by
`hushspec-merge-vector.v1.schema.json`, and the expected-error sidecars by
`hushspec-error-codes.v1.schema.json`.

## Report what you found

Emit a `hushspec-conformance-report.v1.schema.json` document. It must carry the
SHA-256 of the `fixtures/MANIFEST.json` in this bundle, which is what ties a
report to a corpus. `docs/src/reference/conformance-statement.md` in the
reference repository is the statement template that cites it.

This bundle is reproducible: the same corpus always produces the same bytes.
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// The point of the bundle: a release artifact whose digest an attestation
    /// can name. Two builds of one tree must be byte-identical.
    #[test]
    fn two_builds_of_the_same_tree_are_byte_identical() {
        let first = build(&repo_root()).expect("the bundle builds");
        let second = build(&repo_root()).expect("the bundle builds");
        assert_eq!(first, second, "the bundle is not reproducible");
        assert!(first.len() > 10_000, "the bundle looks empty");
    }

    #[test]
    fn the_bundle_carries_the_corpus_the_manifest_pins() {
        let bytes = build(&repo_root()).expect("the bundle builds");
        let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
        let mut archive = tar::Archive::new(decoder);
        let mut names: Vec<String> = archive
            .entries()
            .expect("entries")
            .map(|entry| {
                entry
                    .expect("entry")
                    .path()
                    .expect("path")
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        names.sort();

        let manifest = Manifest::load(&repo_root().join("fixtures")).expect("the manifest loads");
        let prefix = format!("hushspec-conformance-{}", manifest.fixtures_version);

        assert!(names.contains(&format!("{prefix}/README.md")));
        assert!(names.contains(&format!("{prefix}/fixtures/MANIFEST.json")));
        assert!(names.contains(&format!("{prefix}/spec/hushspec-core.md")));
        assert!(names.contains(&format!(
            "{prefix}/schemas/hushspec-conformance-report.v1.schema.json"
        )));
        for entry in &manifest.files {
            assert!(
                names.contains(&format!("{prefix}/{}", entry.path)),
                "{} is missing from the bundle",
                entry.path
            );
        }
    }

    /// Entry order and metadata are what make the bytes reproducible, so they
    /// are asserted rather than assumed.
    #[test]
    fn entries_are_sorted_and_carry_no_machine_metadata() {
        let bytes = build(&repo_root()).expect("the bundle builds");
        let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
        let mut archive = tar::Archive::new(decoder);
        let mut previous = String::new();
        for entry in archive.entries().expect("entries") {
            let entry = entry.expect("entry");
            let name = entry.path().expect("path").to_string_lossy().to_string();
            assert!(previous <= name, "{previous} came before {name}");
            previous = name;
            let header = entry.header();
            assert_eq!(header.mtime().unwrap(), 0);
            assert_eq!(header.uid().unwrap(), 0);
            assert_eq!(header.gid().unwrap(), 0);
            assert_eq!(header.mode().unwrap(), FILE_MODE);
        }
    }
}
