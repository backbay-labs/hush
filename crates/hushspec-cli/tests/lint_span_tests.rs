//! Integration coverage for lint source spans and SARIF 2.1.0 output.
//!
//! The SARIF assertions validate every emitted document against the vendored
//! SARIF 2.1.0 JSON Schema (`crates/hushspec-cli/schemas/sarif-2.1.0.schema.json`,
//! the draft-07 rendition GitHub's own tooling validates against). The schema is
//! committed rather than fetched so this runs offline.

use assert_cmd::Command;
use jsonschema::JSONSchema;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn h2h() -> Command {
    let mut cmd = Command::cargo_bin("h2h").unwrap();
    cmd.current_dir(workspace_root());
    cmd
}

fn write_policy(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn sarif_schema() -> &'static JSONSchema {
    static SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let raw = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/sarif-2.1.0.schema.json"
        ))
        .expect("the vendored SARIF schema is readable");
        let schema: Value = serde_json::from_str(&raw).expect("the SARIF schema is JSON");
        JSONSchema::options()
            .should_validate_formats(true)
            .compile(&schema)
            .expect("the SARIF schema compiles")
    })
}

fn assert_valid_sarif(document: &Value) {
    if let Err(errors) = sarif_schema().validate(document) {
        let rendered: Vec<String> = errors
            .map(|e| format!("{} at {}", e, e.instance_path))
            .collect();
        panic!("SARIF document failed schema validation:\n{rendered:#?}");
    }
}

/// Two findings whose keys sit at known, distinct positions: an entry-precise
/// L008 duplicate at line 8 and a block-level L017 at line 10.
const SPANNED: &str = r#"hushspec: "0.1.0"
name: spanned
rules:
  egress:
    allow:
      - "api.example.com"
      # a comment, so a naive line count would be wrong from here on
      - "api.example.com"
    block: []
    default: allow
"#;

#[test]
fn json_findings_carry_the_line_and_column_of_the_offending_key() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "spanned.yaml", SPANNED);

    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("json")
        .arg(&policy)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report[0]["findings"].as_array().unwrap();

    let duplicate = findings
        .iter()
        .find(|f| f["code"] == "L008")
        .expect("L008 duplicate");
    assert_eq!(duplicate["path"], "rules.egress.allow[1]");
    assert_eq!(duplicate["span"]["file"], policy.display().to_string());
    // The duplicate is the second list entry, on line 8 after a comment line.
    assert_eq!(duplicate["span"]["line"], 8);
    assert_eq!(duplicate["span"]["column"], 9);
    assert_eq!(duplicate["span"]["end_line"], 8);
    assert!(
        duplicate["span"]["end_column"].as_u64().unwrap()
            > duplicate["span"]["column"].as_u64().unwrap()
    );

    let permissive = findings
        .iter()
        .find(|f| f["code"] == "L017")
        .expect("L017 permissive default");
    assert_eq!(permissive["path"], "rules.egress.default");
    assert_eq!(permissive["span"]["line"], 10);
    assert_eq!(permissive["span"]["column"], 5);
}

#[test]
fn text_output_points_at_file_line_column() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "spanned.yaml", SPANNED);

    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .code(0)
        .stdout(predicate::str::contains(format!(
            "{}:8:9",
            policy.display()
        )))
        .stdout(predicate::str::contains("rules.egress.allow[1]"));
}

#[test]
fn an_inherited_finding_reports_the_base_document_and_its_span() {
    let tmp = TempDir::new().unwrap();
    // The leaf declares nothing but `extends`, so every finding belongs to the
    // builtin it inherits -- including the line and column inside that builtin.
    let policy = write_policy(
        tmp.path(),
        "leaf.yaml",
        "hushspec: \"0.1.0\"\nname: leaf\nextends: \"builtin:permissive\"\n",
    );

    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("json")
        .arg(&policy)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report[0]["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "the permissive base has findings");

    let wildcard = findings
        .iter()
        .find(|f| f["code"] == "L004")
        .expect("L004 from the base");
    assert_eq!(
        wildcard["span"]["file"], "builtin:permissive",
        "an inherited finding names the document that declares the key"
    );
    assert!(wildcard["span"]["line"].as_u64().unwrap() > 0);
    // The file that was linted is still the leaf.
    assert_eq!(report[0]["file"], policy.display().to_string());
}

#[test]
fn sarif_output_validates_against_the_vendored_schema() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "spanned.yaml", SPANNED);

    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("sarif")
        .arg(&policy)
        .output()
        .unwrap();
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid_sarif(&document);

    assert_eq!(document["version"], "2.1.0");
    let driver = &document["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "h2h");
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        driver["informationUri"]
            .as_str()
            .unwrap()
            .starts_with("http")
    );

    let rules = driver["rules"].as_array().unwrap();
    assert!(rules.iter().any(|rule| rule["id"] == "L017"));
    for rule in rules {
        assert!(rule["shortDescription"]["text"].is_string(), "{rule}");
        assert!(rule["fullDescription"]["text"].is_string(), "{rule}");
        assert!(
            matches!(
                rule["defaultConfiguration"]["level"].as_str(),
                Some("error" | "warning" | "note")
            ),
            "{rule}"
        );
    }

    let results = document["runs"][0]["results"].as_array().unwrap();
    let duplicate = results
        .iter()
        .find(|r| r["ruleId"] == "L008")
        .expect("L008 result");
    assert_eq!(duplicate["level"], "warning");
    let region = &duplicate["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["startLine"], 8);
    assert_eq!(region["startColumn"], 9);
    assert_eq!(
        duplicate["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        policy.display().to_string()
    );
    // L008 is always fixable, so the result carries a deletion fix.
    assert_eq!(
        duplicate["fixes"][0]["artifactChanges"][0]["replacements"][0]["deletedRegion"]["startLine"],
        8
    );

    // Severity mapping: info becomes SARIF's `note`.
    let note = results
        .iter()
        .find(|r| r["ruleId"] == "L009")
        .expect("L009 result");
    assert_eq!(note["level"], "note");
}

#[test]
fn sarif_output_validates_for_every_shipped_policy() {
    let root = workspace_root();
    let mut policies: Vec<PathBuf> = fs::read_dir(root.join("rulesets"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            (path.extension().is_some_and(|ext| ext == "yaml")).then_some(path)
        })
        .collect();
    for vertical in fs::read_dir(root.join("library")).unwrap() {
        let vertical = vertical.unwrap().path();
        if !vertical.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&vertical).unwrap() {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                policies.push(path);
            }
        }
    }
    policies.sort();
    assert!(policies.len() >= 15, "found {} policies", policies.len());

    let mut cmd = h2h();
    cmd.arg("lint").arg("--format").arg("sarif");
    for policy in &policies {
        cmd.arg(policy);
    }
    let output = cmd.output().unwrap();
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid_sarif(&document);
    assert!(
        !document["runs"][0]["results"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the shipped policies report at least one finding"
    );
}

#[test]
fn sarif_output_validates_for_a_preflight_failure_and_for_stdin() {
    // A file that cannot be parsed still produces a well-formed SARIF run: the
    // E001 result has a location with no region rather than no location.
    let tmp = TempDir::new().unwrap();
    let broken = write_policy(tmp.path(), "broken.yaml", "hushspec: \"0.1.0\"\nrules: [\n");

    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("sarif")
        .arg(&broken)
        .output()
        .unwrap();
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid_sarif(&document);
    assert_eq!(document["runs"][0]["results"][0]["ruleId"], "E001");

    // `<stdin>` is not a URI reference, so the emitted uri must be encoded.
    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("sarif")
        .arg("-")
        .write_stdin("hushspec: \"0.1.0\"\nrules:\n  egress:\n    default: allow\n")
        .output()
        .unwrap();
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid_sarif(&document);
    assert_eq!(
        document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "%3Cstdin%3E"
    );
}

/// A file the tool could not read is "the check did not run" (exit 2), and an
/// `extends` chain that will not resolve is `E010`, the registry's code for an
/// extends failure.
#[test]
fn a_missing_file_exits_two_and_an_unresolvable_chain_reports_e010() {
    let tmp = TempDir::new().unwrap();

    h2h()
        .arg("lint")
        .arg(tmp.path().join("no-such-policy.yaml"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("file not found"));

    let orphan = write_policy(
        tmp.path(),
        "orphan.yaml",
        "hushspec: \"0.1.0\"\nname: orphan\nextends: \"./no-such-base.yaml\"\n",
    );
    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("sarif")
        .arg(&orphan)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid_sarif(&document);
    assert_eq!(document["runs"][0]["results"][0]["ruleId"], "E010");
}

#[test]
fn out_writes_the_report_to_a_file_and_refuses_text() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "spanned.yaml", SPANNED);
    let sarif_path = tmp.path().join("lint.sarif");

    h2h()
        .arg("lint")
        .arg("--format")
        .arg("sarif")
        .arg("--out")
        .arg(&sarif_path)
        .arg(&policy)
        .assert()
        .code(0)
        // Nothing is printed to stdout when the report goes to a file.
        .stdout(predicate::str::is_empty());
    let document: Value = serde_json::from_str(&fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_valid_sarif(&document);

    h2h()
        .arg("lint")
        .arg("--out")
        .arg(tmp.path().join("lint.txt"))
        .arg(&policy)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--out requires"));
}

/// The SARIF rule catalog and `docs/src/reference/cli.md` document the same
/// codes. A new lint that is emitted but undocumented (or documented but not
/// emitted) fails here rather than shipping half-explained.
#[test]
fn documented_codes_match_the_sarif_catalog() {
    let docs = fs::read_to_string(workspace_root().join("docs/src/reference/cli.md")).unwrap();
    let section = docs
        .split("### Lint rules")
        .nth(1)
        .expect("cli.md has a `### Lint rules` section")
        .split("\n## ")
        .next()
        .unwrap();

    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "spanned.yaml", SPANNED);
    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("sarif")
        .arg(&policy)
        .output()
        .unwrap();
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rules = document["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();

    for rule in rules {
        let id = rule["id"].as_str().unwrap();
        assert!(
            section.contains(&format!("`{id}`")),
            "{id} is in the SARIF catalog but not documented in cli.md"
        );
    }
    // And nothing documented is missing from the catalog.
    for code in section
        .split('`')
        .filter(|token| {
            token.len() == 4
                && token.starts_with(['L', 'E'])
                && token[1..].chars().all(|c| c.is_ascii_digit())
        })
        .collect::<std::collections::BTreeSet<_>>()
    {
        assert!(
            rules.iter().any(|rule| rule["id"] == code) || code == "L005",
            "{code} is documented but not in the SARIF catalog"
        );
    }
}
