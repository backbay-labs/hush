# HushSpec Decision Receipt Specification

**Version:** 1.0.0
**Status:** Stable
**Date:** 2026-09-15
**Supersedes:** Receipt format 0.1 (schemas/hushspec-receipt.v1.schema.json as shipped with HushSpec 0.1.x)
**Companion to:** HushSpec Core 0.2.0, Canonical Form 0.2.0, Policy Signing 0.2

---

## 1. Introduction

A decision receipt is the unit of evidence in HushSpec. Every time an engine evaluates an action against a policy, it can emit one receipt that answers, for an auditor who was not there: which policy was in force, who was acting, what they tried to do, what the policy decided and why, which controls actually ran, and what the runtime did with the decision.

Receipt format 0.1 answered some of these. It lacked an actor, it identified the policy by a hash that differed per SDK, it reconstructed the rule trace after the fact, it did not record detections, and nothing tied one receipt to the next. Format 0.2 closes those gaps and is designed to be chained: the Receipt Log specification wraps 0.2 receipts in a hash-linked log.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

**Engine.** An implementation that evaluates actions (Core Section 8, Level 3).

**Enforcement point.** The component that acts on a decision at the tool boundary (a HushGuard, a proxy, a runtime hook). An engine may be used without one (`h2h eval`).

**Content hash.** As defined in the Canonical Form specification, Section 5: `sha256:` followed by 64 lowercase hex characters.

### 1.2 Design principles

1. **Evidence, not logs.** Every field exists because an auditor needs it. Free-form fields are limited to `reason` strings.
2. **Never the content.** A receipt records the hash and size of action content, never the content. A receipt log must be safe to hand to an auditor.
3. **Recorded, not reconstructed.** The rule trace is written by the evaluator as blocks run. Nothing in a receipt is inferred from the decision afterwards.
4. **One spelling per fact.** Timestamps have fixed precision, enums are closed, hashes are prefixed, ids are UUID v7. Two SDKs describing the same evaluation produce the same bytes after canonicalization.
5. **Chainable.** A receipt has a canonical form and a hash of its own (Section 6) so that a log can link receipts together.

---

## 2. Conformance

An engine conforms to this specification (Core conformance **Level 4, Auditor**, Core Section 8) if:

1. Every receipt it emits validates against `schemas/hushspec-receipt.v1.schema.json` at format version 0.2.
2. `policy.content_hash` equals the content hash of the resolved policy as defined by the Canonical Form specification.
3. `rule_trace` is recorded during evaluation and satisfies Section 4.3.
4. For every valid vector under `fixtures/receipts/valid/`, the engine's receipt parser accepts it, and for every vector under `fixtures/receipts/invalid/` it rejects it.
5. Its receipts round-trip: parsing a receipt it emitted and re-serializing in canonical form yields the same bytes (Section 6).

---

## 3. Document structure

A receipt is a JSON object. The schema is normative for types, enumerations, and required fields; this section gives the semantics.

| Field | Required | Section |
|---|---|---|
| `receipt_version` | yes | 3.1 |
| `receipt_id` | yes | 3.2 |
| `timestamp`, `time_source` | yes | 3.3 |
| `actor` | no | 4.1 |
| `policy` | yes | 4.2 |
| `action` | yes | 4.4 |
| `decision`, `matched_rule`, `reason` | `decision` yes | 4.5 |
| `rule_trace` | yes | 4.3 |
| `detection_trace` | no | 4.6 |
| `enforcement` | yes | 4.7 |
| `origin_profile`, `posture` | no | 4.8 |
| `duration_us` | no | 4.9 |

Unknown fields MUST be rejected (`additionalProperties: false` throughout).

### 3.1 `receipt_version`

The literal string `"0.2"`. Consumers MUST reject a receipt whose version they do not implement. The 0.1 format had no version field; a consumer distinguishes the two by the presence of `receipt_version`.

### 3.2 `receipt_id`

A UUID version 7 (RFC 9562) in lowercase hyphenated form. Version 7 embeds a millisecond timestamp in the high bits, so receipts sort by creation time lexically and a log reader can detect reordering without parsing timestamps. Engines MUST generate a fresh id per receipt and MUST NOT reuse ids across processes. Format 0.1 used version 4; the schema pattern now requires the version nibble to be `7`.

### 3.3 `timestamp` and `time_source`

`timestamp` is the evaluation time in RFC 3339, UTC, with **exactly** three fractional digits and a `Z` suffix: `2026-09-15T08:30:00.123Z`. Millisecond precision is fixed because 0.1 SDKs emitted milliseconds, microseconds, and nanoseconds for the same instant, which made receipts for the same evaluation hash differently.

`time_source` says how much to trust the timestamp:

| Value | Meaning |
|---|---|
| `system` | The local system clock, as read. |
| `monotonic_adjusted` | A monotonic clock re-based on the system clock once at startup; immune to clock steps during the run. |
| `trusted` | A time source the operator considers authoritative (disciplined NTP, a hardware clock, a signed time attestation). What qualifies is deployment policy. |
| `unknown` | The engine cannot characterize its clock. |

Engines MUST NOT claim `trusted` unless configured to; the default is `system`.

---

## 4. Field semantics

### 4.1 `actor`

Who the action was evaluated for. All four fields are optional strings because runtimes differ in what identity is available; an enforcement point SHOULD populate every field it knows:

- `agent_id`: a stable identifier of the agent (deployment name, bot id, model-instance id).
- `session_id`: the conversation, run, or job. Receipts from one session share it, which is how a report groups a session's evidence.
- `principal`: the human or service the agent acts on behalf of.
- `runtime`: the enforcing runtime and version, `name/version`.

An engine used without an enforcement point (a CLI evaluation) MAY omit `actor` entirely.

### 4.2 `policy`

Identity of the **resolved** policy the decision was evaluated against.

- `content_hash` (required): the resolved policy's content hash. This is the join key between receipts, signature envelopes (Signing Section 4), and policy bundles.
- `spec_version` (required): the policy's `hushspec` field.
- `name`: the policy's `name`, when present.
- `version`: the policy's `metadata.policy_version`, when present. An integer, never a string.
- `extends_chain`: when the policy had an `extends` reference, the chain of documents that were merged, root first and the leaf last. Each link records the `source` as the loader saw it (`builtin:strict`, a path, an `https:` URL) and the content hash of that document canonicalized **on its own**, with its own `extends` and `merge_strategy` stripped. An auditor can therefore verify that a specific base policy was in force without re-resolving. Absent when there was no `extends`.
- `signature`: the outcome of signature verification at load time (Signing Section 6). `verified` is true only when a signature was present, its key was in the trusted keyring, and every check passed; `key_id` names the key the envelope claimed; `reason` explains a failure. Absent when the runtime did not attempt verification. A runtime configured to require signatures MUST record `verified: false` and deny (see the `signature-failed` vector) rather than omit the field.

### 4.3 `rule_trace`

The heart of the receipt: which controls ran. Entries are appended by the evaluator as it evaluates, in evaluation order. Requirements:

1. Every rule block **applicable** to the action type (Core Section 5) MUST have exactly one entry. Blocks not applicable to the action type MUST NOT appear. (A `file_write` receipt lists `forbidden_paths`, `path_allowlist`, and `secret_patterns`; it never lists `egress`.)
2. An applicable block that was **inert** (absent from the policy, `enabled: false`, or a `when` condition that evaluated false) appears with `outcome: skip`, `evaluated: false`, and a `reason` naming why.
3. An applicable block that ran appears with `evaluated: true` and its own outcome (`allow`, `warn`, or `deny`) **before** aggregation. Under Core Section 6.1 every applicable block runs; a deny from one block never suppresses another block's entry.
4. `rule_path`, when present, is the specific rule that produced the outcome, using the same path grammar as `matched_rule` (`rules.<block>.<field>[<index or name>]`).
5. Engine stages that can decide an action outside the rule blocks appear under these `rule_block` ids, in this order, before any rule block:

| `rule_block` | When it appears |
|---|---|
| `panic` | Emergency panic mode is active (Core Section 6.2). Always `deny`; no rule blocks follow. |
| `unknown_action_type` | The action type is unknown or `custom` without a granting capability (Core Section 5). `deny`; no rule blocks follow. |
| `origin_profile` | The origins extension selected (or failed to select) a profile. `rule_path` names the profile; `deny` when `default_behavior: deny` matched nothing. |
| `posture_capability` | The posture state did not grant the action's required capability. `deny`. |
| `default` | Reserved for engines that record an explicit default-allow entry when no block applied. Optional. |

6. The twelve rule-block ids are the keys of `rules` exactly (`forbidden_paths`, not `rules.forbidden_paths`). Format 0.1 mixed both spellings.

The trace MUST be recorded, not derived: an engine that infers the trace from `matched_rule` after evaluation does not conform. (HushSpec 0.1 SDKs did this and, for example, reported `secret_patterns` as evaluated on paths where it had been short-circuited.)

### 4.4 `action`

The evaluated action, minus its content.

- `type` (required): the action type as evaluated, including unknown or custom types that were denied.
- `target`: the target string as supplied, **not** normalized. The evaluator normalizes internally (Core Sections 3.1, 3.3); the receipt keeps what the agent asked for, so an auditor sees `API.EXAMPLE.COM:443` if that is what was requested.
- `content_hash` and `content_size`: present whenever content was supplied. `content_hash` is `sha256:` over the UTF-8 bytes of the content as supplied. Content itself MUST NOT appear in a receipt; the schema has no field for it and unknown fields are rejected.
- `args_size`: the serialized size of tool-call arguments when the runtime measured it against `tool_access.max_args_size`.
- `origin` and `context`: the origin descriptor and runtime context supplied with the action, recorded as JSON objects with top-level members that are absent, `null`, `{}`, or `[]` removed (typed models differ in which empty members they materialize; the document the caller supplied did not have them). A runtime MAY redact context values it considers sensitive; it MUST then drop the key rather than substitute a placeholder.

### 4.5 `decision`, `matched_rule`, `reason`

`decision` is the evaluated policy decision per Core Section 6, independent of what the enforcement point did (that is `enforcement`). `matched_rule` is the rule path that determined it; it is absent for a default allow that no rule produced, and uses the reserved names `__hushspec_panic__`, `__unknown_action_type__`, and `__hushspec_policy_unverified__` for the corresponding engine stages. `reason` is a human-readable explanation and carries no normative weight.

### 4.6 `detection_trace`

Present when the evaluation ran the detection pipeline (Detection specification), even if no detector fired. Each entry names the detector (`detector_id`, stable across versions of the same detector, with a version suffix), its `category`, its normalized `score` in [0, 1], the `level` the score mapped to under the policy's thresholds, and `matched`, true when the finding contributed to the decision. Absent (not empty) when detection did not run.

### 4.7 `enforcement`

What the enforcement point did. **Required in 0.2.** A decision without a disposition is not evidence that a control operated, so a receipt must always say. `mode` is the effective mode after per-rule overrides and panic resolution (panic always enforces). `outcome` is one of `allowed`, `confirmed` (a warn approved through a confirmation channel), `blocked`, or `would_block` (monitor mode let a warn or deny proceed).

An engine used without an enforcement point records `mode: enforce` and the outcome implied by the decision (`allow` → `allowed`, `warn` and `deny` → `blocked`), because a warn with no confirmation channel is a deny (Core Section 6).

### 4.8 `origin_profile`, `posture`

`origin_profile` is the id of the origins profile selected during evaluation. `posture` records the posture state active during evaluation and the state after any signal-triggered transition. Both absent when the corresponding extension is not in the policy.

### 4.9 `duration_us`

Wall-clock evaluation time in microseconds, excluding receipt construction and serialization. Informational.

---

## 5. Relationship to the evaluation result

An engine's in-memory evaluation result (decision, matched rule, reason, origin profile, posture) and its recorded trace are the source of every receipt field in Section 4.3 through 4.8. The receipt adds identity (`actor`, `policy`), the action summary, time, and enforcement. Implementations SHOULD build the receipt from the same traced evaluation call that produced the decision, so the two can never disagree.

---

## 6. Canonical form and receipt hash

A receipt has a canonical form: the RFC 8785 serialization of the receipt object exactly as defined by the Canonical Form specification, Section 4 (key order by UTF-16 code units, no whitespace, ES6 numbers, JCS escapes). No projection step applies: receipts have no schema defaults to materialize and no resolution fields to strip, and every optional field is either present or absent.

The **receipt hash** is `sha256:` over the canonical form's UTF-8 bytes.

The receipt hash is what a log links. This specification deliberately does not define chaining fields (`seq`, `prev_hash`, `entry_hash`, a per-entry signature); those belong to the log-entry format (Receipt Log specification), which wraps a receipt rather than extending it, so that a receipt's own hash is stable regardless of which log it lands in. Receipt signing likewise signs the receipt hash from outside.

Because the hash covers every field, engines MUST NOT mutate a receipt after computing its hash. `duration_us` in particular is covered; an engine that wants an unhashed timing figure should log it elsewhere.

---

## 7. Migration from format 0.1

| 0.1 | 0.2 |
|---|---|
| No `receipt_version` | `receipt_version: "0.2"` required |
| `receipt_id` UUID v4 | UUID v7 |
| `timestamp` any RFC 3339 precision | exactly milliseconds, `Z` |
| no `time_source` | required |
| `hushspec_version` at top level | `policy.spec_version` |
| no `actor` | optional `actor` object |
| `policy.version` = the `hushspec` field (string) | `policy.spec_version`; `policy.version` is now the integer `metadata.policy_version` |
| `policy.content_hash` bare 64-hex, SDK-specific serialization | `sha256:` prefix, canonical form; required |
| no `extends_chain`, no `signature` | both optional |
| `action.content_redacted` boolean | replaced by `content_hash` and `content_size` |
| no `action.context`, `action.origin`, `args_size` | added |
| `rule_trace[].rule_block` mixed `rules.x` and `x` spellings; trace reconstructed | bare block ids from a closed enum; recorded during evaluation |
| `rule_trace[].matched_rule` | renamed `rule_path` |
| no `detection_trace` | added |
| `enforcement` optional, nullable | required, never null |
| `evaluation_duration_us` required | `duration_us` optional |
| nullable fields (`type: [..., "null"]`) | no nulls anywhere; absent means absent |

`schemas/hushspec-receipt.v1.schema.json` is the normative 0.2 schema. The expected receipts under `fixtures/receipts/expected/` are the vectors every engine reproduces.

---

## 8. Test vectors

`fixtures/receipts/valid/*.json` are receipts that MUST be accepted; `fixtures/receipts/invalid/*.json` MUST be rejected. Each file name says what it exercises. They validate against the 0.2 schema with any JSON Schema 2020-12 validator. The Rust test `crates/hushspec/tests/receipt.rs` walks both directories; `fixtures/receipts/expected/` additionally holds the receipt every SDK must produce, byte for byte after canonicalization, for each shared evaluation fixture case under fixed inputs.

| Valid vector | Exercises |
|---|---|
| `allow-egress` | The common case, every optional top-level field present. |
| `deny-secret-in-file-write` | Multi-block trace with a `skip` entry; content hash and size instead of content. |
| `warn-confirmed-tool-call` | `warn` decision confirmed by the enforcement point; `args_size`. |
| `monitor-would-block` | Monitor mode disposition. |
| `detection-trace-injection` | `detection_trace` with a matched and an unmatched detector; decision from the detection pipeline. |
| `extends-chain-signed` | `extends_chain` with two links; `policy.version`; verified signature. |
| `signature-failed` | Verification failure recorded and enforced; empty `rule_trace`. |
| `custom-action-denied` | `unknown_action_type` engine stage. |
| `panic-mode` | `panic` engine stage; `time_source: trusted`. |
| `origins-posture-context` | `origin_profile` and `posture_capability` stages; `action.origin` and `action.context`. |
| `default-allow-no-rule` | Allow with no `matched_rule`; only `runtime` in `actor`. |
| `minimal-required-only` | Exactly the required fields. |

| Invalid vector | Rejected because |
|---|---|
| `missing-receipt-version` | required field absent |
| `unsupported-receipt-version` | `"0.1"` is not `"0.2"` |
| `timestamp-second-precision`, `timestamp-microsecond-precision` | not millisecond precision |
| `bare-hex-content-hash`, `unknown-hash-algorithm` | not `sha256:` + 64 hex |
| `unknown-field-legacy-version` | 0.1's `hushspec_version` is an unknown field |
| `open-enum-outcome`, `open-enum-time-source` | value outside a closed enum |
| `rule-block-with-prefix` | `rules.egress` is not a block id |
| `receipt-id-uuid-v4` | version nibble is 4 |
| `missing-enforcement` | required in 0.2 |
| `action-carries-content` | receipts never carry content |
| `policy-version-not-integer` | `version` is an integer |

---

## 9. Security considerations

The security considerations for the whole specification family, including the shared threats this section relies on, are collected in `hushspec-security.md`.

- **Secrets.** The only fields that can carry agent-supplied text are `action.target`, `action.origin`, `action.context`, and `reason`. Runtimes SHOULD redact context values that may contain secrets and MUST never place content in any field.
- **Clock trust.** `time_source` lets an auditor discount timestamps from untrusted clocks, but ordering within a log comes from the log's sequence numbers, not from timestamps.
- **Trace completeness.** Because every applicable block appears in the trace, a receipt that lacks an expected block is itself evidence of a non-conformant engine.
- **Tampering.** A receipt on its own is not tamper-evident. Tamper evidence comes from the log chain and receipt signatures defined separately; this specification only guarantees that a receipt has one stable hash to chain or sign.
