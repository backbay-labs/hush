use hushspec::{LoadedSpec, ResolveError, resolve_from_path, resolve_with_loader};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn resolve_from_path_merges_extends_chain() {
    let dir = temp_dir("resolve-chain");
    fs::write(
        dir.join("base.yaml"),
        r#"
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
"#,
    )
    .unwrap();
    fs::write(
        dir.join("child.yaml"),
        r#"
hushspec: "0.1.0"
extends: base.yaml
name: child
rules:
  egress:
    allow: [api.example.com]
    default: allow
"#,
    )
    .unwrap();

    let resolved = resolve_from_path(dir.join("child.yaml")).unwrap();
    assert!(resolved.extends.is_none());
    assert_eq!(resolved.name.as_deref(), Some("child"));
    let rules = resolved.rules.unwrap();
    let tool_access = rules.tool_access.unwrap();
    assert_eq!(tool_access.allow, vec!["read_file"]);
    assert_eq!(tool_access.default, hushspec::DefaultAction::Block);
    let egress = rules.egress.unwrap();
    assert_eq!(egress.allow, vec!["api.example.com"]);
    assert_eq!(egress.default, hushspec::DefaultAction::Allow);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn resolve_detects_cycles() {
    let dir = temp_dir("resolve-cycle");
    fs::write(
        dir.join("a.yaml"),
        r#"
hushspec: "0.1.0"
extends: b.yaml
"#,
    )
    .unwrap();
    fs::write(
        dir.join("b.yaml"),
        r#"
hushspec: "0.1.0"
extends: a.yaml
"#,
    )
    .unwrap();

    let error = resolve_from_path(dir.join("a.yaml")).unwrap_err();
    match error {
        ResolveError::Cycle { chain } => assert!(chain.contains("a.yaml")),
        other => panic!("expected cycle error, got {other:?}"),
    }

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn resolve_with_loader_uses_canonical_source_ids() {
    let child = hushspec::HushSpec::parse(
        r#"
hushspec: "0.1.0"
extends: parent
rules:
  egress:
    allow: [api.example.com]
    default: block
"#,
    )
    .unwrap();

    let resolved = resolve_with_loader(&child, Some("memory://child"), &|reference, _| {
        assert_eq!(reference, "parent");
        Ok(LoadedSpec {
            source: "memory://parent".to_string(),
            spec: hushspec::HushSpec::parse(
                r#"
hushspec: "0.1.0"
rules:
  egress:
    block: [api.example.com]
    default: allow
"#,
            )
            .unwrap(),
        })
    })
    .unwrap();

    assert!(resolved.extends.is_none());
    let egress = resolved.rules.unwrap().egress.unwrap();
    assert_eq!(egress.allow, vec!["api.example.com"]);
    assert!(egress.block.is_empty());
    assert_eq!(egress.default, hushspec::DefaultAction::Block);
}

fn temp_dir(prefix: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hushspec-{prefix}-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
