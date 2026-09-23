use hushspec::{DefaultAction, HushSpec, merge};

#[test]
fn merge_replace_uses_child() {
    let base = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: base
rules:
  egress:
    allow: ["a.com"]
    default: block
"#,
    )
    .unwrap();
    let child = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: child
extends: base
merge_strategy: replace
rules:
  tool_access:
    block: ["shell_exec"]
    default: allow
"#,
    )
    .unwrap();
    let merged = merge(&base, &child);
    assert_eq!(merged.name.as_deref(), Some("child"));
    // Core spec 2.3: resolution consumes both instructions, `replace`
    // included, so the document that comes out declares neither.
    assert!(merged.extends.is_none());
    assert!(merged.merge_strategy.is_none());
    assert!(merged.rules.as_ref().unwrap().egress.is_none());
    assert!(merged.rules.as_ref().unwrap().tool_access.is_some());
}

/// `merge` and `deep_merge` share `merge_rules` verbatim and differ only in
/// how they treat `extensions` (see `hushspec::merge`), so a rules-only
/// document cannot distinguish them; that distinction is covered in
/// `tests/extensions.rs`. What this pins is the rule-block behavior both
/// share: the child's block replaces the base's, and the base's other blocks
/// survive.
#[test]
fn child_rule_block_replaces_the_base_block_and_siblings_are_preserved() {
    let base = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
"#,
    )
    .unwrap();
    let child = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extends: base
rules:
  egress:
    allow: ["b.com"]
    default: allow
"#,
    )
    .unwrap();
    let merged = merge(&base, &child);
    assert!(merged.extends.is_none());
    let rules = merged.rules.as_ref().unwrap();
    let egress = rules.egress.as_ref().unwrap();
    assert_eq!(egress.allow, vec!["b.com"]);
    assert_eq!(egress.default, DefaultAction::Allow);
    assert!(
        rules.forbidden_paths.is_some(),
        "a block the child never mentions must survive the merge"
    );
}
