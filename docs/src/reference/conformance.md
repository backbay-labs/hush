# Conformance Levels

HushSpec defines six conformance levels. Each level subsumes all requirements of
the levels below it, so a Level 4 implementation is also a Level 3 one. The
normative definitions are in
[`spec/hushspec-core.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-core.md)
section 8; this page is the reader's version, plus the vector coverage behind it.

For the current per-SDK status on `main`, see the
[SDK Conformance Matrix](sdk-conformance.md). To publish a claim of your own,
fill in the [Conformance Statement](conformance-statement.md) template.

To test an executable outside the built-in reference runner, use the experimental
[external engine controller](external-conformance.md). It binds L0-L3 results
to captured engine bytes and retains a verifiable execution packet.

## Claiming a level

## Quick Reference

| Level | Adds |
| --- | --- |
| L0 | YAML profile parsing |
| L1 | Closed schema and semantic validation |
| L2 | Inheritance and merge |
| L3 | Deterministic evaluation |
| L4 | Canonical policy identity and decision receipts |
| L5 | Signed provenance, evidence verification and bundles |

A higher level includes lower-level obligations. SDK feature availability and
external engine claims are different kinds of evidence.

### Claim Evidence

A claim is made against a specific corpus, not against "the fixtures". Every
file under `fixtures/` is inventoried in `fixtures/MANIFEST.json` with its
SHA-256, its category, and the level at which it becomes required, and a claim
names the corpus by the SHA-256 of that manifest.

The machine-readable form of a claim is a
[conformance report](json-schema.md): `hushspec-conformance-report.v1.schema.json`.
The reference runner writes one, and validates it against its own schema before
writing:

```bash
hushspec-testkit --fixtures fixtures --report report.json
```

`highest_level` in the report is the largest N for which levels 0 through N all
pass. A level with any unattempted vector reports `not_attempted`, which is
never a synonym for a pass. The runner diffs the manifest against what it
actually ran, so a vector the run missed is recorded as `not_attempted` rather
than left out of a report that still cites the manifest by digest.

Everything needed to do this without cloning the repository ships as
`hushspec-conformance-<version>.tar.gz`, attached to every release: the prose,
the schemas, the vectors, and the manifest.

## Level 0: Parser

A Level 0 implementation can:

- Parse valid HushSpec YAML documents into a structured representation
- Reject syntactically invalid YAML, and input violating the YAML profile of core spec 2.4 (aliases, merge keys, duplicate keys, multi-document streams, `yes`/`no` booleans)
- Reject documents missing the required `hushspec` field
- Meets every raw YAML parse-acceptance assertion in
  `fixtures/core/raw-yaml/scalars.json`; a missing or malformed raw corpus
  cannot establish a passing parser result

This is the minimum bar for any tool that reads HushSpec documents.

## Level 1: Validator

A Level 1 implementation additionally:

- Validates all field types and constraints (booleans are booleans, integers are integers)
- Rejects documents with unknown fields at any nesting level
- Validates enum values (`severity`, `mode`, `default`, `merge_strategy`)
- Enforces uniqueness constraints (e.g., secret pattern `name` fields)
- Validates numeric constraints (non-negative integers, positive ratios)
- Validates regex syntax in pattern fields against the profile of core spec 3.14
- Validates `when` conditions
- Decodes each accepted `fixtures/core/raw-yaml/scalars.json` value without
  rewriting the YAML source before it reaches the parser
- Rejects every `invalid/` vector, with the error code its `.expect.yaml`
  sidecar names -- and any `message_contains` substring it names -- if the
  implementation reports codes at all

This level is required for linters, schema validators, and policy authoring tools.

### Error codes

Every `fixtures/<module>/invalid/<name>.yaml` has a `<name>.expect.yaml`
sidecar naming the code its refusal must carry, drawn from
[`spec/registries/error-codes.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/error-codes.yaml):

```yaml
reject: true
code: "E001"
message_contains: "anchors are not allowed"
```

Without this, "the document was rejected" is a weak assertion: a vector that
tests the YAML profile passes just as well when the engine refuses it for an
unrelated reason.

All four reference SDK fixture runners assert the code and the
`message_contains` substring, not merely that the vector was rejected. The
spec's rule is the weaker one, and stays that way for third-party engines: an
implementation that reports no codes at all conforms at this level; one that
reports codes from the registry MUST report the registered one. Where each
SDK's codes come from is tabulated in the
[SDK API Contract](sdk-api.md#error-codes).

## Level 2: Merger

A Level 2 implementation additionally:

- Resolves `extends` references (via at least one resolution strategy: filesystem, URL, registry, or built-in)
- Correctly implements all three merge strategies (`deep_merge`, `merge`, `replace`)
- Detects and rejects circular inheritance

This level is required for any tool that supports policy composition.

## Level 3: Evaluator

A Level 3 implementation additionally:

- Accepts an action (type + inputs) and a resolved HushSpec document
- Produces a correct structured evaluation result containing at least a final `allow`, `warn`, or `deny` decision, under the semantics of core spec sections 3, 5 and 6 -- including the normalization and matching algorithms of section 3.14
- Implements aggregation and precedence per core spec 6.1 (`deny` > `warn` > `allow`) and denies unknown action types per section 5
- Passes every vector under `fixtures/<module>/evaluation/`: for each case the decision, plus each of `matched_rule`, `reason`, `origin_profile` and `posture` the case states. The vector format is `hushspec-evaluator-test.v1.schema.json`
- Reproduces the fixed `example.com`/`requests: 9` decision in each raw-YAML
  vector that declares one

This is the full engine level. All four HushSpec SDKs pass it, and go on to
Levels 4 and 5. Clawdstrike's conformance level is not qualified here: it needs
a pinned report from a harness that actually executes that engine. The bundled
reference runner cannot establish external-engine conformance by relabeling its report.

## Level 4: Auditor

Level 3 says an engine reaches the right decision. Level 4 says it can prove
which document it reached that decision under, and why, to someone who was not
there.

A Level 4 implementation additionally:

- Emits [decision receipts](../receipt-spec.md) at format 0.2 that validate
  against the published schema
- Computes `policy.content_hash` as the [canonical](../canonical-spec.md) hash of
  the *resolved* document, and reproduces every `fixtures/core/hash/` vector
  byte for byte
- **Records** `rule_trace` during evaluation rather than reconstructing it
  afterwards, and reproduces every committed receipt under
  `fixtures/receipts/expected/` after canonicalization
- Accepts every `fixtures/receipts/valid/` vector and rejects every
  `fixtures/receipts/invalid/` one
- Resolves `extends` with chain provenance and digest pinning, passing
  `fixtures/core/resolve/`
- Reproduces canonical JSON and content hashes for raw-YAML cases that declare
  a canonical output

Given a Level 4 receipt and the policy it names, a third party can recompute
the hash, replay the trace, and get the same answer.

## Level 5: Attested

Level 4 evidence is only as trustworthy as the document it was produced under.
Level 5 adds provenance: which policy was in force, who signed it, and whether
the record has been altered since.

A Level 5 implementation additionally:

- Is a conforming [signature](../signing-spec.md) verifier: every case in
  `fixtures/signing/vectors.yaml` returns `valid` or the exact reason code
- Verifies **on load**, so every hop of an `extends` chain is checked against
  the keyring or its digest pin, fails closed, and records the outcome in
  `receipt.policy.signature`
- Verifies a hash-linked log, identifying *which line* first breaks the chain
  for every `fixtures/log/invalid/` vector
- Refuses every schema-derived invalid entry in
  `fixtures/log/schema-vectors.json`
- Signs and verifies receipts (`fixtures/receipts/signed/`)
- Verifies policy bundles (`fixtures/bundle/vectors.yaml`)

An implementation may claim Level 5 for verification only: producing
signatures, logs and bundles is described by the same specifications, but
verification is what a relying party depends on.

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
| `computer_use` | 3.8 | `core/evaluation/computer-use` | 3 |
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
| Raw YAML scalar spelling and decoding | 2.4, canonical 4.3 | `core/raw-yaml/scalars.json` | 0 (parse acceptance), 1 (value), 3 (decision), 4 (canonical/hash) |
| Expected error codes on refusal | 8 (Level 1) | every `*/invalid/<name>.expect.yaml` sidecar | 1 |

### Merge and resolution

| Requirement | Spec | Vectors | Level |
|---|---|---|---|
| `deep_merge` (core and all three extensions) | 4.1 | `core/merge/child-deep-merge`, `posture/merge`, `origins/merge`, `detection/merge` | 2 |
| `merge` (core and all three extensions) | 4.1 | `core/merge/child-merge`, `posture/merge/child-merge`, `origins/merge/child-merge`, `detection/merge/child-merge` | 2 |
| `replace` (core and all three extensions) | 4.1 | `core/merge/child-replace`, `posture/merge/child-replace`, `origins/merge/child-replace`, `detection/merge/child-replace` | 2 |
| `metadata` merge behaviour | 2.5, 4.1 | `core/merge/metadata/` (replaced and inherited), `core/merge/metadata-replaces-whole/` (under `deep_merge`) | 2 |
| A resolved document declares no `extends` or `merge_strategy` | 2.3 | `core/merge/resolved-output-is-clean/` | 2 |
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
| Canonical form and `content_hash` | canonical 7 | `core/hash/` (16 vectors) | 4 |
| Receipt format 0.2 | receipt 2 | `receipts/valid/`, `receipts/invalid/` | 4 |
| Recorded `rule_trace`, per-case receipts | receipt 4.3 | `receipts/expected/<module>/<fixture>/<case>.json` | 4 |
| Policy signing and verification | signing 2 | `signing/vectors.yaml` (18 cases) | 5 |
| Receipt signing | signing 8 | `receipts/signed/valid/`, `receipts/signed/invalid/` | 5 |
| Hash-linked log | log | `log/valid/`, `log/invalid/` | 5 |
| Policy bundle attestation | bundle 7 | `bundle/vectors.yaml` (10 cases) | 5 |
