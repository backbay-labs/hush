use hushspec::{Decision, EvaluationAction, HushSpec, evaluate};

#[test]
fn input_inject_denies_unlisted_type() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: input-injection
rules:
  input_injection:
    enabled: true
    allowed_types:
      - keyboard
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "input_inject".into(),
            target: Some("mouse".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.input_injection.allowed_types")
    );
}

#[test]
fn computer_use_respects_remote_desktop_channel_blocks() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: remote-desktop
rules:
  computer_use:
    enabled: true
    mode: observe
    allowed_actions:
      - remote.clipboard
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "computer_use".into(),
            target: Some("remote.clipboard".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.remote_desktop_channels.clipboard")
    );
}

#[test]
fn origin_profile_tool_access_still_respects_base_blocklist() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: origin-tool-access
rules:
  tool_access:
    enabled: true
    allow:
      - "*"
    block:
      - dangerous_tool
    require_confirmation: []
    default: allow
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        tool_access:
          allow:
            - "*"
          block: []
          require_confirmation: []
          default: allow
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "tool_call".into(),
            target: Some("dangerous_tool".into()),
            origin: Some(hushspec::OriginContext {
                provider: Some("slack".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.tool_access.block")
    );
    assert_eq!(result.origin_profile.as_deref(), Some("slack"));
}

#[test]
fn origin_profile_egress_cannot_bypass_base_default_block() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: origin-egress
rules:
  egress:
    enabled: true
    allow:
      - api.safe.example.com
    block: []
    default: block
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        egress:
          allow: []
          block: []
          default: allow
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "egress".into(),
            target: Some("evil.example.com".into()),
            origin: Some(hushspec::OriginContext {
                provider: Some("slack".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    // The overlay says `default: allow` but the base says `block`; the base
    // determined the effective default, so its path is reported.
    assert_eq!(result.matched_rule.as_deref(), Some("rules.egress.default"));
    assert_eq!(result.origin_profile.as_deref(), Some("slack"));
}

#[test]
fn forbidden_path_exception_still_respects_path_allowlist() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: path-guards
rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/*.key"
    exceptions:
      - "/workspace/allowed.key"
  path_allowlist:
    enabled: true
    write:
      - "/workspace/reports/**"
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "file_write".into(),
            target: Some("/workspace/allowed.key".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.matched_rule.as_deref(), Some("rules.path_allowlist"));
}

#[test]
fn unknown_posture_state_fails_closed() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: posture-unknown-state
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access]
    transitions: []
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            url: None,
            network: None,
            timeout_ms: None,
            context: None,
            action_type: "file_read".into(),
            target: Some("/workspace/readme.md".into()),
            posture: Some(hushspec::PostureContext {
                current: Some("typo".into()),
                signal: None,
            }),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("extensions.posture.states.typo")
    );
    assert_eq!(
        result.reason.as_deref(),
        Some("unknown posture state 'typo'")
    );
}

/// Core spec 10.2: 1.0 freezes the 0.2 semantics without changing them, so
/// one document declared under either version validates alike and reaches the
/// same decision by the same rule, for every action the document can decide.
#[test]
fn a_one_point_zero_document_is_evaluated_as_a_zero_point_two_document() {
    let document = |version: &str| {
        format!(
            r#"
hushspec: "{version}"
name: version-equivalence
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
  egress:
    allow:
      - api.example.com
    default: block
  tool_access:
    block:
      - shell_exec
    default: allow
"#
        )
    };
    let actions = [
        ("file_read", "/home/agent/.ssh/id_ed25519"),
        ("egress", "api.example.com"),
        ("egress", "blocked.example.net"),
        ("tool_call", "shell_exec"),
    ];

    let zero = HushSpec::parse(&document("0.2.0")).expect("valid 0.2.0 spec");
    let one = HushSpec::parse(&document("1.0.0")).expect("valid 1.0.0 spec");
    assert!(
        hushspec::validate(&zero).is_valid(),
        "0.2.0 did not validate"
    );
    assert!(
        hushspec::validate(&one).is_valid(),
        "1.0.0 did not validate"
    );

    for (action_type, target) in actions {
        let action = EvaluationAction {
            action_type: action_type.into(),
            target: Some(target.into()),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&zero, &action),
            evaluate(&one, &action),
            "{action_type} {target} decided differently under 1.0.0"
        );
    }

    // A forbidden path is the case that would go unnoticed if the version
    // gate quietly skipped a block rather than accepting the document.
    let denied = evaluate(
        &one,
        &EvaluationAction {
            action_type: "file_read".into(),
            target: Some("/home/agent/.ssh/id_ed25519".into()),
            ..Default::default()
        },
    );
    assert_eq!(denied.decision, Decision::Deny);
    assert_eq!(
        denied.matched_rule.as_deref(),
        Some("rules.forbidden_paths.patterns")
    );

    // The `hushspec` field is part of the canonical form, so the two hashes
    // differ; what must not differ is the decisions they are hashes of.
    assert_ne!(
        hushspec::content_hash(&zero).expect("hashable"),
        hushspec::content_hash(&one).expect("hashable"),
        "two documents declaring different versions hashed the same"
    );
}
