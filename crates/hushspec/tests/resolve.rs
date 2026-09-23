use hushspec::{
    BUILTIN_NAMES, LoadedSpec, ResolveError, ResolveOptions, create_composite_loader, load_builtin,
    own_content_hash, resolve_from_path, resolve_from_path_with_builtins,
    resolve_path_with_options, resolve_with_loader, validate,
};
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

/// Every embedded policy loads and parses, and names itself.
///
/// A `rulesets/` preset is named for the file (`strict`); a library policy is
/// embedded under `library/<vertical>/<name>` and names itself with the last
/// segment (`hipaa-base`), because the prefix is a location, not a rename.
#[test]
fn builtin_loader_resolves_every_embedded_policy() {
    assert!(
        BUILTIN_NAMES.len() > 6,
        "the vertical library should be embedded alongside the presets"
    );
    for name in BUILTIN_NAMES {
        let yaml = load_builtin(name);
        assert!(yaml.is_some(), "builtin '{name}' should be available");
        let spec = hushspec::HushSpec::parse(yaml.unwrap());
        assert!(spec.is_ok(), "builtin '{name}' should parse without error");
        let spec = spec.unwrap();
        let expected = name.rsplit('/').next().unwrap();
        assert_eq!(spec.name.as_deref(), Some(expected));
    }
}

/// The library is reachable by the reference an `extends` would use.
#[test]
fn builtin_loader_resolves_the_library_by_prefixed_name() {
    let yaml = load_builtin("builtin:library/healthcare/hipaa-base")
        .expect("the library is embedded as a builtin");
    let spec = hushspec::HushSpec::parse(yaml).expect("the library policy parses");
    assert_eq!(spec.name.as_deref(), Some("hipaa-base"));
    // The embedded leaf still declares its own base, so resolving it is what
    // materializes the full document.
    assert_eq!(spec.extends.as_deref(), Some("builtin:strict"));
}

#[test]
fn extends_builtin_default_end_to_end() {
    let dir = temp_dir("resolve-builtin");
    fs::write(
        dir.join("child.yaml"),
        r#"
hushspec: "0.1.0"
extends: builtin:default
name: my-custom-policy
rules:
  egress:
    allow: [custom.example.com]
    default: allow
"#,
    )
    .unwrap();

    let resolved = resolve_from_path_with_builtins(dir.join("child.yaml")).unwrap();
    assert!(resolved.extends.is_none());
    assert_eq!(resolved.name.as_deref(), Some("my-custom-policy"));

    let rules = resolved.rules.as_ref().unwrap();
    // Inherited from builtin:default
    assert!(rules.forbidden_paths.is_some());
    assert!(rules.secret_patterns.is_some());
    assert!(rules.tool_access.is_some());
    // Child's own rules
    let egress = rules.egress.as_ref().unwrap();
    assert!(egress.allow.contains(&"custom.example.com".to_string()));
    assert_eq!(egress.default, hushspec::DefaultAction::Allow);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn composite_loader_resolves_builtin_with_custom_loader() {
    let child = hushspec::HushSpec::parse(
        r#"
hushspec: "0.1.0"
extends: builtin:strict
name: custom
"#,
    )
    .unwrap();

    let loader = create_composite_loader();
    let resolved = resolve_with_loader(&child, Some("memory://child"), &loader).unwrap();
    assert!(resolved.extends.is_none());
    assert_eq!(resolved.name.as_deref(), Some("custom"));
    // Should have inherited from strict
    let rules = resolved.rules.as_ref().unwrap();
    let tool_access = rules.tool_access.as_ref().unwrap();
    assert_eq!(tool_access.default, hushspec::DefaultAction::Block);
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

/// Core spec 2.3: a document that declares `merge_strategy` without `extends`
/// never reaches `merge`, and resolution still hands back a document carrying
/// neither resolution instruction.
#[test]
fn resolution_drops_merge_strategy_from_a_one_hop_chain() {
    let dir = temp_dir("resolve-one-hop");
    fs::write(
        dir.join("leaf.yaml"),
        "hushspec: \"0.1.0\"\nname: leaf\nmerge_strategy: replace\n",
    )
    .unwrap();

    let resolved = resolve_from_path(dir.join("leaf.yaml")).unwrap();
    assert!(resolved.extends.is_none());
    assert!(resolved.merge_strategy.is_none());
}

/// Core spec 2.3 holds for every shape a chain can take, not just the shapes
/// the merge vectors cover: a built-in base, a hop pinned by digest, and three
/// hops each naming a strategy all end in a document that declares neither
/// resolution instruction and still validates.
#[test]
fn no_chain_shape_leaves_a_resolution_instruction_behind() {
    let dir = temp_dir("resolve-chain-shapes");

    let builtin_leaf = dir.join("builtin-leaf.yaml");
    fs::write(
        &builtin_leaf,
        "hushspec: \"0.1.0\"\nname: builtin-leaf\nextends: builtin:strict\nmerge_strategy: merge\n",
    )
    .unwrap();

    let root = dir.join("root.yaml");
    fs::write(
        &root,
        "hushspec: \"0.2.0\"\nname: root\nrules:\n  egress:\n    allow: [\"a.example.com\"]\n    default: block\n",
    )
    .unwrap();
    let root_pin = own_content_hash(&parse_file(&root), "root.yaml").unwrap();

    let mid = dir.join("mid.yaml");
    fs::write(
        &mid,
        format!(
            "hushspec: \"0.2.0\"\nname: mid\nextends: \"root.yaml#{root_pin}\"\nmerge_strategy: merge\nrules:\n  tool_access:\n    allow: [read_file]\n    default: block\n"
        ),
    )
    .unwrap();
    let mid_pin = own_content_hash(&parse_file(&mid), "mid.yaml").unwrap();

    let pinned_leaf = dir.join("pinned-leaf.yaml");
    fs::write(
        &pinned_leaf,
        format!(
            "hushspec: \"0.2.0\"\nname: pinned-leaf\nextends: \"mid.yaml#{mid_pin}\"\nmerge_strategy: deep_merge\n"
        ),
    )
    .unwrap();

    for (shape, path) in [
        ("builtin base", &builtin_leaf),
        ("digest-pinned hop", &mid),
        ("three hops", &pinned_leaf),
    ] {
        let resolution = resolve_path_with_options(path, &ResolveOptions::default())
            .unwrap_or_else(|error| panic!("{shape}: {error}"));
        assert!(
            resolution.spec.extends.is_none(),
            "{shape}: `extends` survived resolution"
        );
        assert!(
            resolution.spec.merge_strategy.is_none(),
            "{shape}: `merge_strategy` survived resolution"
        );
        let report = validate(&resolution.spec);
        assert!(
            report.is_valid(),
            "{shape}: the resolved document does not validate: {:?}",
            report.errors
        );
    }
}

fn parse_file(path: &PathBuf) -> hushspec::HushSpec {
    hushspec::HushSpec::parse(&fs::read_to_string(path).unwrap()).unwrap()
}

/// Core spec 2.3: a hop whose referrer pinned it by digest carries the
/// evidence on its chain link, and only that hop does. The flag is in-memory
/// evidence for a later re-check, so it stays out of every serialized form.
#[test]
fn a_pinned_hop_records_the_pin_and_never_serializes_it() {
    let dir = temp_dir("resolve-pin-evidence");

    let base = dir.join("base.yaml");
    fs::write(
        &base,
        "hushspec: \"0.2.0\"\nname: base\nrules:\n  tool_access:\n    allow: [read_file]\n    default: block\n",
    )
    .unwrap();
    let pin = own_content_hash(&parse_file(&base), "base.yaml").unwrap();

    let leaf = dir.join("leaf.yaml");
    fs::write(
        &leaf,
        format!("hushspec: \"0.2.0\"\nname: leaf\nextends: \"base.yaml#{pin}\"\n"),
    )
    .unwrap();

    let resolution = resolve_path_with_options(&leaf, &ResolveOptions::default()).unwrap();
    assert!(resolution.chain[0].pinned, "the pinned base is not marked");
    assert!(
        !resolution.chain[1].pinned,
        "nothing refers to the leaf, so nothing pins it"
    );

    let wire = serde_json::to_string(&resolution.chain).unwrap();
    assert!(
        !wire.contains("pinned"),
        "the pin flag reached the wire form: {wire}"
    );
}

/// A document wrapped as a one-link resolution was not loaded through a
/// reference, so nothing pinned it.
#[test]
fn a_wrapped_resolution_pins_nothing() {
    let spec = hushspec::HushSpec::parse("hushspec: \"0.2.0\"\nname: wrapped\n").unwrap();
    let resolution = hushspec::Resolution::from_resolved(&spec, None).unwrap();
    assert!(!resolution.chain[0].pinned);
}
