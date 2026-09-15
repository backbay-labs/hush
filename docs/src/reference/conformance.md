# Conformance Levels

HushSpec defines four conformance levels. Each level subsumes all requirements of the levels below it.

For the current per-SDK status on `main`, see the
[SDK Conformance Matrix](sdk-conformance.md).

## Level 0: Parser

A Level 0 implementation can:

- Parse valid HushSpec YAML documents into a structured representation
- Reject syntactically invalid YAML
- Reject documents missing the required `hushspec` field

This is the minimum bar for any tool that reads HushSpec documents.

## Level 1: Validator

A Level 1 implementation additionally:

- Validates all field types and constraints (booleans are booleans, integers are integers)
- Rejects documents with unknown fields at any nesting level
- Validates enum values (`severity`, `mode`, `default`, `merge_strategy`)
- Enforces uniqueness constraints (e.g., secret pattern `name` fields)
- Validates numeric constraints (non-negative integers, positive ratios)
- Validates regex syntax in pattern fields

This level is required for linters, schema validators, and policy authoring tools.

## Level 2: Merger

A Level 2 implementation additionally:

- Resolves `extends` references (via at least one resolution strategy: filesystem, URL, registry, or built-in)
- Correctly implements all three merge strategies (`deep_merge`, `merge`, `replace`)
- Detects and rejects circular inheritance

This level is required for any tool that supports policy composition.

## Level 3: Evaluator

A Level 3 implementation additionally:

- Accepts an action (type + context) and a resolved HushSpec document
- Produces a correct structured evaluation result containing at least a final `allow`, `warn`, or `deny` decision
- Implements decision precedence (`deny` > `warn` > `allow`)
- Passes the published evaluator fixtures, which are themselves versioned and schema-validated

This is the full engine level. Clawdstrike is a Level 3 implementation.

## Fixture coverage

Every requirement below has at least one published vector; there are no gaps to
fill in later. Paths are relative to
[`fixtures/`](https://github.com/backbay-labs/hush/tree/main/fixtures), and
`fixtures/MANIFEST.json` pins each file's digest, category and level.

### Rule blocks (core section 3)

| Rule block | Spec | Vectors | Level |
|---|---|---|---|
| `forbidden_paths` | 3.2 | `core/evaluation/forbidden-paths`, `forbidden-paths-leading-globstar`, `path-normalization`, `path-normalization-lexical` | 3 |
| `path_allowlist` | 3.3 | `core/evaluation/no-early-return`, `rule-blocks-disabled` | 3 |
| `egress` | 3.6 | `core/evaluation/egress`, `egress-default-fail-closed`, `egress-normalization`, `egress-host-normalization` | 3 |
| `secret_patterns` | 3.4 | `core/evaluation/secret-patterns`, `secret-patterns-content-presence`, `secret-severity-mapping`, `severity-mapping`, `severity-precedence` | 3 |
| `patch_integrity` | 3.5 | `core/evaluation/patch-integrity`, `patch-integrity-defaults`, `patch-balance`, `patch-balance-zero` | 3 |
| `shell_commands` | 3.9 | `core/evaluation/shell-commands`, `regex-dialect` | 3 |
| `tool_access` | 3.7 | `core/evaluation/tool-access`, `tool-exact-match`, `tool-allowlist-deny`, `tool-glob-literal`, `tool-max-args-size` | 3 |
| `computer_use` | 3.8 | `core/evaluation/computer-use`, `computer-use-guardrail-deny` | 3 |
| `remote_desktop_channels` | 3.10 | `core/valid/remote-desktop-channels-rule`, `core/evaluation/rule-blocks-disabled` | 3 |
| `input_injection` | 3.10 | `core/evaluation/input-injection` | 3 |
| `browser_automation` | 3.11 | `core/evaluation/browser-automation` | 3 |
| `code_execution` | 3.12 | `core/evaluation/code-execution` | 3 |

### Cross-cutting evaluation behaviour

| Requirement | Spec | Vectors | Level |
|---|---|---|---|
| `enabled: false` on every block | 3.1, 6.1 | `core/evaluation/rule-blocks-disabled` (all twelve blocks) | 3 |
| `when` conditions, runtime `context` | 3.13 | `core/evaluation/conditions`; invalid: `core/invalid/when-*` | 3 |
| Decision precedence `deny` > `warn` > `allow` | 6.1 | `core/evaluation/decision-precedence`, `deny-over-warn-precedence`, `severity-precedence` | 3 |
| Secret severity mapping (`warn`/`error`/`critical`) | 3.4, 6.1 | `core/evaluation/secret-severity-mapping`, `severity-mapping` | 3 |
| No early return on an allowlist match | 6.1 | `core/evaluation/no-early-return` | 3 |
| Unknown action type denies | 5 | `core/evaluation/unknown-action` | 3 |
| `custom` action and the posture capability | 5, posture 3.3 | `core/evaluation/custom-action-capability` (with and without) | 3 |
| Host and path normalization | 3.14 | `core/evaluation/egress-normalization`, `egress-host-normalization`, `path-normalization`, `path-normalization-lexical` | 3 |
| Regex profile | 3.14 | `core/evaluation/regex-dialect`, `regex-ascii-classes`; invalid: `core/invalid/regex-mid-pattern-flag` | 3 |
| Content scanning on `egress` and `tool_call` | 3.4 | `core/evaluation/content-scan-egress-tool` | 3 |
| Version acceptance (`X.Y.*`) | 10 | `core/valid/version-patch-accept`; invalid: `core/invalid/float-version` | 1 |
| YAML profile | 2.4 | `core/invalid/yaml-alias`, `yaml-merge-key`, `yaml-duplicate-key`, `yaml-multi-doc`, `yaml-bool-yes` | 1 |
| Expected error codes on refusal | 8 (Level 1) | every `*/invalid/<name>.expect.yaml` sidecar | 1 |

### Merge and resolution

| Requirement | Spec | Vectors | Level |
|---|---|---|---|
| `deep_merge` (core and all three extensions) | 4.1 | `core/merge/child-deep-merge`, `posture/merge`, `origins/merge`, `detection/merge` | 2 |
| `merge` (core and all three extensions) | 4.1 | `core/merge/child-merge`, `posture/merge/child-merge`, `origins/merge/child-merge`, `detection/merge/child-merge` | 2 |
| `replace` (core and all three extensions) | 4.1 | `core/merge/child-replace`, `posture/merge/child-replace`, `origins/merge/child-replace`, `detection/merge/child-replace` | 2 |
| `metadata` merge behaviour | 2.5, 4.1 | `core/merge/metadata/` (replaced and inherited) | 2 |
| Circular inheritance is refused | 2.3 | `core/merge/extends-cycle/` | 2 |
| Multi-hop chain, folded root to leaf | 2.3, 4.2 | `core/merge/three-hop-chain/` and `core/evaluation/extends-three-hop-resolved` | 2, 3 |
| Digest pinning (`#sha256:`) | 2.3 | `core/resolve/pin-valid`, `pin-mismatch`, `pin-malformed` | 4 |
| Chain provenance and content hash | 2.3 | `core/resolve/chain-builtin`, `chain-two-hops`, `no-extends`, `unknown-builtin` | 4 |

### Extension modules

| Requirement | Spec | Vectors | Level |
|---|---|---|---|
| Posture states, transitions, budgets | posture 3 | `posture/evaluation/posture-transitions`, `empty-capabilities`, `unknown-state-fail-closed` | 3 |
| Origins matching, priority, tri-state overlay | origins 3 | `origins/evaluation/origin-matching`, `origin-priority`, `tied-profiles`, `tri-state-overlay`, `match-presence`, `default-behavior-deny` | 3 |
| Detection: prompt injection, jailbreak | detection 3.1, 3.2 | `detection/evaluation/prompt-injection`, `jailbreak` | 3 |
| Detection: `threat_intel` is declared, never auto-wired | detection 3.3 | `detection/evaluation/threat-intel` | 3 |

### Evidence chain

| Requirement | Spec | Vectors | Level |
|---|---|---|---|
| Canonical form and `content_hash` | canonical 7 | `core/hash/` (14 vectors) | 4 |
| Receipt format 0.2 | receipt 2 | `receipts/valid/`, `receipts/invalid/` | 4 |
| Recorded `rule_trace`, per-case receipts | receipt 4.3 | `receipts/expected/<module>/<fixture>/<case>.json` | 4 |
| Policy signing and verification | signing 2 | `signing/vectors.yaml` (16 cases) | 5 |
| Receipt signing | signing 8 | `receipts/signed/valid/`, `receipts/signed/invalid/` | 5 |
| Hash-linked log | log | `log/valid/`, `log/invalid/` | 5 |
| Policy bundle attestation | bundle 7 | `bundle/vectors.yaml` (8 cases) | 5 |
