# RFC 02: Audit Trail and Decision Receipts

**Status:** Historical design record (Draft)
**Authors:** Security Architecture Team
**Date:** 2026-03-15
**HushSpec Version:** 0.1.0
**Affects:** Core Specification (Section 6, Section 8), All SDKs (Rust, TypeScript, Python, Go)

---

> **Delivery status:** See [the delivery ledger](STATUS.md#numbered-plan-reconciliation). Receipt, log, signing, and sink artifacts exist on the open RFC 09 stack. The schema-invalid policy-event repair has a local verification record; retention/backend/collector scope and hosted evidence-chain qualification remain unestablished.

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Decision Receipt Format](#2-decision-receipt-format)
3. [Decision Log Specification](#3-decision-log-specification)
4. [Telemetry and Observability](#4-telemetry-and-observability)
5. [SDK Integration Design](#5-sdk-integration-design)
6. [Compliance Mapping](#6-compliance-mapping)
7. [Security Considerations](#7-security-considerations)
8. [Implementation Roadmap](#8-implementation-roadmap)
9. [Examples](#9-examples)

---

## 1. Executive Summary

### 1.1 Why Audit Trails Matter

AI agent runtimes are increasingly deployed in regulated environments -- healthcare systems, financial institutions, government agencies, and critical infrastructure. Every policy decision made by an agent's security boundary is a potential compliance event. When an agent is denied access to a file, allowed to make a network call, or warned before a tool invocation, that decision constitutes a security-relevant event that organizations need to record, query, and present to auditors.

Today, HushSpec defines *what* decisions are made (Section 6: Decision Types) and *how* those decisions are reached (Section 3: Rules, Section 6.1: Decision Precedence), but provides no standardized format for *recording* those decisions after the fact. This gap creates three categories of risk:

1. **Compliance failure.** Regulated organizations cannot demonstrate to auditors that their AI agent security policies were evaluated consistently. SOC2, HIPAA, and PCI-DSS all require evidence that access control decisions were logged and reviewable.

2. **Incident response blindness.** When a security incident involves an AI agent, responders need to reconstruct the full decision history: what was allowed, what was denied, which policies were active, and whether policy merges or extensions influenced the outcome. Without standardized receipts, this reconstruction depends on ad-hoc engine logging.

3. **Policy debugging difficulty.** Complex policy chains using `extends`, origin-aware profiles, and posture-based capability guards produce decisions that are difficult to trace. A standardized receipt format with full rule match chains makes policy behavior transparent and testable.

### 1.2 What Is Missing Today

The current `EvaluationResult` type (defined in `crates/hushspec/src/evaluate.rs` and mirrored in all SDKs) returns:

```
decision:        allow | warn | deny
matched_rule:    Optional<String>      (e.g., "rules.tool_access.block")
reason:          Optional<String>      (human-readable explanation)
origin_profile:  Optional<String>      (origin profile ID if applicable)
posture:         Optional<PostureResult> { current, next }
```

This is sufficient for enforcement -- the calling engine knows whether to proceed -- but insufficient for audit. It lacks:

- A unique receipt identifier for correlation across distributed systems
- Timestamps
- The input action that was evaluated (type, target, content hash)
- The policy document identity (name, version, content hash)
- The full rule evaluation trace (which rules were consulted, not just which one "won")
- The resolved extends chain
- Evaluation timing
- Structured warnings and advisory notes
- Redaction metadata (proof that sensitive content was not logged)
- Detection extension results (prompt injection scores, jailbreak risk levels, threat intel matches)
- Posture budget consumption state (how many of the allowed N operations have been used)
- Posture capability guard outcomes (when a posture state blocks an action type)

### 1.3 Proposed Solution

This RFC introduces three interconnected capabilities:

1. **Decision Receipt** -- a self-contained JSON document that fully describes a single evaluation decision, its inputs, the policy chain, the rule match trace, the detection extension evaluation results, and the posture budget state. Receipts are produced by the `evaluate()` function when audit mode is enabled.

2. **Decision Log** -- a structured, append-only log format (JSON Lines) for streaming receipts to persistent storage. The log format is compatible with OpenTelemetry log signal conventions and common SIEM ingestion pipelines. The log specification includes an AUDIT level for periodic aggregated summaries.

3. **Telemetry Hooks** -- a set of well-known metrics and event callbacks that engines can use to integrate with observability platforms (Prometheus, Datadog, Grafana, etc.) without coupling to a specific vendor. Metrics cover evaluation counts and latency, rule block match rates, detection scores, posture transitions, and budget consumption.

All three capabilities are opt-in. When disabled, the `evaluate()` function continues to return the current `EvaluationResult` with zero additional overhead. The receipt format is defined as a JSON Schema that becomes part of the HushSpec specification artifact set alongside `hushspec-core.v0.schema.json`.

---

## 2. Decision Receipt Format

### 2.1 Design Goals

- **Self-contained.** A receipt MUST contain enough context to understand the decision without access to the original policy document, rule definitions, or action payload.
- **Tamper-evident.** Receipts MAY include a digital signature or HMAC to detect post-hoc modification.
- **Redaction-safe.** Sensitive content (file bodies, secret pattern matches) MUST be represented as cryptographic hashes, never as cleartext.
- **Deterministic.** Given identical inputs (action, policy, timestamp, receipt ID), a conformant implementation MUST produce a byte-identical receipt (canonical JSON).

### 2.2 Receipt Structure

```
DecisionReceipt
  +-- receipt_id          (string, UUID v7)
  +-- receipt_version     (string, "0.1.0")
  +-- timestamp           (string, ISO 8601 with timezone)
  +-- duration_us         (integer, evaluation wall-clock time in microseconds)
  +-- action              (ActionSummary)
  |     +-- type          (string, action type enum)
  |     +-- target        (string | null, redacted if sensitive)
  |     +-- target_redacted (boolean, true when target was redacted)
  |     +-- content_hash  (string | null, SHA-256 of content if content was provided)
  |     +-- content_size  (integer | null, byte length of content)
  |     +-- args_size     (integer | null, argument payload size)
  |     +-- origin        (OriginSummary | null)
  |     +-- posture_input (PostureInput | null)
  +-- decision            (DecisionDetail)
  |     +-- outcome       (string, "allow" | "warn" | "deny")
  |     +-- matched_rule  (string | null)
  |     +-- reason        (string | null)
  +-- rule_trace          (array of RuleEvaluation)
  |     +-- [i].rule_block   (string, e.g., "forbidden_paths", "egress", "posture_capability")
  |     +-- [i].rule_path    (string, e.g., "rules.egress.block")
  |     +-- [i].enabled      (boolean)
  |     +-- [i].evaluated    (boolean, false if short-circuited)
  |     +-- [i].outcome      (string, "allow" | "warn" | "deny" | "skip")
  |     +-- [i].reason       (string | null)
  |     +-- [i].match_detail (MatchDetail | null)
  |           +-- pattern_index  (integer | null)
  |           +-- pattern_value  (string | null, the glob/regex that matched)
  |           +-- matched_target (string | null, redacted if sensitive)
  +-- detection_trace     (array of DetectionEvaluation | null)
  |     +-- [i].detector     (string, "prompt_injection" | "jailbreak" | "threat_intel")
  |     +-- [i].enabled      (boolean)
  |     +-- [i].score        (number | null, detector-reported score 0.0-1.0 or 0-100)
  |     +-- [i].level        (string | null, "safe" | "suspicious" | "high" | "critical")
  |     +-- [i].outcome      (string, "allow" | "warn" | "deny" | "skip")
  |     +-- [i].reason       (string | null)
  |     +-- [i].top_matches  (array of string | null, for threat_intel: top-k pattern names)
  +-- policy              (PolicySummary)
  |     +-- name          (string | null)
  |     +-- hushspec      (string, spec version)
  |     +-- content_hash  (string, SHA-256 of serialized resolved policy)
  |     +-- extends_chain (array of PolicyReference)
  |           +-- [i].source  (string, file path or reference)
  |           +-- [i].name    (string | null)
  |           +-- [i].hash    (string, SHA-256 of document)
  +-- origin_profile      (OriginProfileSummary | null)
  |     +-- id            (string)
  |     +-- match_score   (integer)
  +-- posture             (PostureResult | null)
  |     +-- current       (string)
  |     +-- next          (string)
  |     +-- budget_state  (BudgetState | null)
  |           +-- [key]   (BudgetEntry)
  |                 +-- limit     (integer)
  |                 +-- consumed  (integer)
  |                 +-- remaining (integer)
  +-- warnings            (array of string)
  +-- signature           (ReceiptSignature | null)
        +-- algorithm     (string, e.g., "hmac-sha256", "ed25519", "ecdsa-p256")
        +-- key_id        (string, identifier for the signing key)
        +-- value         (string, base64-encoded signature)
```

### 2.3 Field Specifications

#### 2.3.1 `receipt_id`

A UUID v7 (RFC 9562) string. UUID v7 is preferred over v4 because it embeds a millisecond-precision timestamp, enabling chronological sorting without a separate index. Implementations that cannot generate UUID v7 MAY fall back to UUID v4, but MUST NOT use sequential integers or other predictable identifiers.

Format: `xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx` (lowercase hex with hyphens).

#### 2.3.2 `receipt_version`

The version of the receipt format schema. This document defines version `"0.1.0"`. Receipt consumers MUST check this field and reject receipts with unsupported versions.

#### 2.3.3 `timestamp`

ISO 8601 timestamp with mandatory timezone offset or UTC designator. Implementations MUST use UTC and the `Z` suffix. Millisecond precision is REQUIRED; microsecond precision is RECOMMENDED.

Format: `2026-03-15T14:30:00.123Z`

#### 2.3.4 `duration_us`

Wall-clock time in microseconds from the start of `evaluate()` to decision output. This excludes receipt serialization time. Implementations SHOULD use monotonic clocks where available. A value of `0` indicates that timing was not measured.

#### 2.3.5 `action` (ActionSummary)

A summary of the evaluated action. The `content` field from the original `EvaluationAction` MUST NOT appear in the receipt. Instead, a SHA-256 hash of the content is recorded as `content_hash`, and the byte length as `content_size`. This prevents accidental logging of secrets, source code, or personally identifiable information.

The `target` field is included as-is for non-sensitive action types (`tool_call`, `egress`, `computer_use`). For file operations (`file_read`, `file_write`, `patch_apply`), the target path is included because it is necessary for audit reconstruction. Engines that consider file paths sensitive MAY apply additional redaction and MUST set a `"target_redacted": true` field when they do so.

The `origin` sub-object, when present, mirrors the `OriginContext` fields exactly -- these are metadata fields (provider, tenant, space) that are not secret.

#### 2.3.6 `decision` (DecisionDetail)

The final decision produced by precedence aggregation:

| Field | Description |
|-------|-------------|
| `outcome` | One of `"allow"`, `"warn"`, `"deny"`. |
| `matched_rule` | The rule path that determined the outcome (same as `EvaluationResult.matched_rule`). |
| `reason` | Human-readable explanation (same as `EvaluationResult.reason`). |

#### 2.3.7 `rule_trace` (Array of RuleEvaluation)

The rule trace is the central audit artifact. It records *every* rule block that was consulted during evaluation, not just the one that determined the final outcome. This enables auditors to answer questions like "was the egress rule even enabled when this tool call was allowed?"

Each entry in the array corresponds to a rule block evaluation:

| Field | Type | Description |
|-------|------|-------------|
| `rule_block` | string | The rule block name: `forbidden_paths`, `path_allowlist`, `egress`, `secret_patterns`, `patch_integrity`, `shell_commands`, `tool_access`, `computer_use`, `remote_desktop_channels`, `input_injection`, `posture_capability`. The `posture_capability` value is a synthetic rule block representing the posture extension's capability guard (see Section 3, spec). |
| `rule_path` | string | Fully qualified path to the matching rule element, e.g., `rules.egress.block`, `extensions.origins.profiles.slack-dm.egress.allow`. |
| `enabled` | boolean | Whether the rule block was enabled at evaluation time. |
| `evaluated` | boolean | Whether the rule block was actually evaluated. A rule block may be `enabled: true` but not evaluated because it does not apply to the action type (e.g., `egress` rules are not evaluated for `file_read` actions). A value of `false` with `enabled: true` indicates the rule was irrelevant to the action type. |
| `outcome` | string | `"allow"`, `"warn"`, `"deny"`, or `"skip"` (when `enabled` is false or the rule is not applicable to the action type). |
| `reason` | string or null | Explanation of the outcome. |
| `match_detail` | object or null | When a pattern or list match determined the outcome, this object records which pattern matched. |

The `match_detail` sub-object:

| Field | Type | Description |
|-------|------|-------------|
| `pattern_index` | integer or null | Zero-based index into the matching array (e.g., index in `forbidden_paths.patterns`). |
| `pattern_value` | string or null | The glob or regex pattern that matched. For secret patterns, this MUST be the pattern name, not the regex itself (the regex could leak information about what the system considers a secret). |
| `matched_target` | string or null | The target value that was matched against. For secret pattern matches, this MUST be `"[REDACTED]"`. For path matches, the path is included. |

The `rule_trace` array MUST be ordered by evaluation sequence -- the order in which the evaluator consulted rule blocks. For a `file_write` action, the typical order is: `posture_capability`, `forbidden_paths`, `path_allowlist`, `secret_patterns`.

**Short-circuit recording.** The reference evaluator short-circuits on the first deny (e.g., if `forbidden_paths` denies a `file_write`, `secret_patterns` is never evaluated). However, the rule trace MUST still include entries for rule blocks that were skipped due to short-circuiting. Skipped entries MUST have `evaluated: false` and `outcome: "skip"` with `reason: "short-circuited by prior deny"`. This enables auditors to see which rules *could have* applied but were not reached.

**Posture capability guard.** When the posture extension is active, the evaluator checks whether the current posture state includes the capability required for the action type *before* evaluating any rule blocks. If the capability is missing, the action is denied. This check appears as a `rule_trace` entry with `rule_block: "posture_capability"` and a `rule_path` of the form `extensions.posture.states.<state>.capabilities`. This entry always appears first in the trace when the posture extension is active.

#### 2.3.8 `detection_trace` (Array of DetectionEvaluation)

When the detection extension (`extensions.detection`) is active, evaluation may also consult content analysis guards (prompt injection, jailbreak, threat intelligence). Detection results are recorded in a separate `detection_trace` array because detection has fundamentally different semantics from rule evaluation: detectors produce continuous scores rather than discrete pattern matches, and they may invoke external services with non-trivial latency.

Each entry in the array corresponds to a detector evaluation:

| Field | Type | Description |
|-------|------|-------------|
| `detector` | string | The detector name: `"prompt_injection"`, `"jailbreak"`, `"threat_intel"`. |
| `enabled` | boolean | Whether the detector was enabled in the detection extension configuration. |
| `score` | number or null | The raw score produced by the detector. For `prompt_injection`, this is the detection level mapped to a numeric value. For `jailbreak`, this is the risk score (0-100). For `threat_intel`, this is the top similarity score (0.0-1.0). |
| `level` | string or null | The detection severity level: `"safe"`, `"suspicious"`, `"high"`, `"critical"`. Applicable to `prompt_injection` and derived from `jailbreak` scores based on configured thresholds. |
| `outcome` | string | `"allow"`, `"warn"`, `"deny"`, or `"skip"` (when disabled or not applicable). |
| `reason` | string or null | Explanation of the outcome, e.g., `"jailbreak score 85 exceeds block_threshold 80"`. |
| `top_matches` | array of string or null | For `threat_intel` detections: the top-k pattern names from the pattern database. Pattern content is never included -- only pattern names. Null for other detector types. |

The `detection_trace` array is null when the detection extension is not configured. When configured, it contains one entry per enabled detector. Detection outcomes are aggregated into the overall decision using the same precedence rules (deny > warn > allow).

**Redaction:** Detection trace entries MUST NOT contain the input content that was scanned. The `score` and `level` fields provide sufficient audit information. If a detector identifies specific match positions or offsets, those MUST NOT appear in the trace.

#### 2.3.9 `policy` (PolicySummary)

Identifies the policy document(s) that were active during evaluation.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string or null | The `name` field from the resolved policy. |
| `hushspec` | string | The `hushspec` version field from the resolved policy. |
| `content_hash` | string | SHA-256 hex digest of the canonical JSON serialization of the fully resolved policy document (after merge, with `extends` consumed). |
| `extends_chain` | array | Ordered list of policy documents in the inheritance chain, from root to leaf. Empty array if no `extends` was used. |

Each entry in `extends_chain`:

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | The source identifier (file path, URL, or reference name) as resolved by the engine. |
| `name` | string or null | The `name` field from that document. |
| `hash` | string | SHA-256 hex digest of the raw document content (pre-merge). |

This enables auditors to reconstruct the exact policy chain and verify that no policy document was modified between evaluations.

#### 2.3.10 `origin_profile` (OriginProfileSummary)

When origin-aware evaluation was used (the `origins` extension), this records which profile was selected:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | The `id` field of the matched `OriginProfile`. |
| `match_score` | integer | The numeric match score that caused this profile to be selected. |

#### 2.3.11 `posture` (PostureResult)

Mirrors the existing `PostureResult` type with an additional `budget_state` sub-object:

| Field | Type | Description |
|-------|------|-------------|
| `current` | string | The posture state at evaluation time. |
| `next` | string | The posture state after any signal-triggered transition. |
| `budget_state` | object or null | Current budget consumption for the active posture state. |

The `budget_state` object, when present, is keyed by budget key (e.g., `"tool_calls"`, `"egress_calls"`, `"shell_commands"`). Each entry records:

| Field | Type | Description |
|-------|------|-------------|
| `limit` | integer | The budget limit configured in the posture state. |
| `consumed` | integer | The number of budget units consumed so far in this session/context. |
| `remaining` | integer | `limit - consumed`. |

Budget state is engine-managed (the spec defines budget limits but not the consumption counter). Engines that track budgets SHOULD include budget state in receipts. Engines that do not track budgets MUST omit the `budget_state` field (set to null).

When a budget is exhausted (`remaining == 0`), the engine SHOULD trigger a `budget_exhausted` posture transition signal. This transition is visible in the `posture.next` field.

#### 2.3.12 `warnings`

An array of advisory strings for non-fatal conditions encountered during evaluation:

- `"regex compilation failed for pattern at index N; treated as non-match per fail-closed semantics"`
- `"posture state 'elevated' not found in posture extension; using initial state"`
- `"origin match score tie between profiles 'slack-dm' and 'slack-channel'; first match used"`

Warnings MUST NOT contain sensitive data. They are intended for policy debugging, not security event detail.

#### 2.3.13 `signature` (ReceiptSignature)

An OPTIONAL digital signature or HMAC over the receipt content (excluding the `signature` field itself). When present, it enables downstream consumers to verify receipt integrity.

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | string | The signing algorithm. Supported values: `"hmac-sha256"`, `"ed25519"`, `"ecdsa-p256"`. |
| `key_id` | string | An identifier for the signing key, enabling key rotation without ambiguity. |
| `value` | string | Base64-encoded (standard, with padding) signature bytes. |

**Algorithm guidance:**
- `"hmac-sha256"` -- Symmetric. Simplest to deploy. The signer and verifier share a secret key. Suitable for internal audit where the engine and the log consumer are in the same trust domain. Not suitable for non-repudiation.
- `"ed25519"` -- Asymmetric. RECOMMENDED for production deployments. The signing key is held only by the engine; the verification key can be distributed to any auditor. Provides non-repudiation.
- `"ecdsa-p256"` -- Asymmetric. RECOMMENDED when the deployment environment mandates NIST curves (FIPS 140-2/3 compliance, FedRAMP). Equivalent security properties to Ed25519 but with FIPS-certified implementations available in most HSMs.

The signature input is the canonical JSON serialization of the receipt with the `signature` field set to `null`. Canonical JSON uses sorted keys, no trailing commas, no whitespace outside strings, and UTF-8 encoding. Implementations MUST use this normalization to ensure signature verification is deterministic.

### 2.4 JSON Schema

The receipt format is defined by the following JSON Schema, to be published as `schemas/hushspec-receipt.v0.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://hushspec.dev/schemas/hushspec-receipt.v0.schema.json",
  "title": "HushSpec Decision Receipt v0",
  "description": "A self-contained record of a single HushSpec policy evaluation decision.",
  "type": "object",
  "required": [
    "receipt_id",
    "receipt_version",
    "timestamp",
    "duration_us",
    "action",
    "decision",
    "rule_trace",
    "policy",
    "warnings"
  ],
  "additionalProperties": false,
  "properties": {
    "receipt_id": {
      "type": "string",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
      "description": "UUID v7 (preferred) or v4 receipt identifier."
    },
    "receipt_version": {
      "type": "string",
      "const": "0.1.0",
      "description": "Receipt format version."
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp with mandatory UTC timezone (Z suffix)."
    },
    "duration_us": {
      "type": "integer",
      "minimum": 0,
      "description": "Evaluation wall-clock time in microseconds."
    },
    "action": {
      "$ref": "#/$defs/ActionSummary"
    },
    "decision": {
      "$ref": "#/$defs/DecisionDetail"
    },
    "rule_trace": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/RuleEvaluation"
      },
      "description": "Ordered trace of every rule block consulted during evaluation."
    },
    "detection_trace": {
      "oneOf": [
        {
          "type": "array",
          "items": { "$ref": "#/$defs/DetectionEvaluation" }
        },
        { "type": "null" }
      ],
      "default": null,
      "description": "Trace of detection extension evaluations (prompt injection, jailbreak, threat intel). Null when detection extension is not configured."
    },
    "policy": {
      "$ref": "#/$defs/PolicySummary"
    },
    "origin_profile": {
      "oneOf": [
        { "$ref": "#/$defs/OriginProfileSummary" },
        { "type": "null" }
      ],
      "default": null
    },
    "posture": {
      "oneOf": [
        { "$ref": "#/$defs/PostureResult" },
        { "type": "null" }
      ],
      "default": null
    },
    "warnings": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Advisory notes from evaluation (non-fatal)."
    },
    "signature": {
      "oneOf": [
        { "$ref": "#/$defs/ReceiptSignature" },
        { "type": "null" }
      ],
      "default": null
    }
  },
  "$defs": {
    "ActionSummary": {
      "type": "object",
      "required": ["type"],
      "additionalProperties": false,
      "properties": {
        "type": {
          "type": "string",
          "enum": [
            "file_read", "file_write", "egress", "shell_command",
            "tool_call", "patch_apply", "computer_use", "input_inject", "custom"
          ]
        },
        "target": { "type": ["string", "null"], "default": null },
        "target_redacted": { "type": "boolean", "default": false },
        "content_hash": { "type": ["string", "null"], "default": null },
        "content_size": { "type": ["integer", "null"], "minimum": 0, "default": null },
        "args_size": { "type": ["integer", "null"], "minimum": 0, "default": null },
        "origin": {
          "oneOf": [
            { "$ref": "#/$defs/OriginSummary" },
            { "type": "null" }
          ],
          "default": null
        },
        "posture_input": {
          "oneOf": [
            { "$ref": "#/$defs/PostureInput" },
            { "type": "null" }
          ],
          "default": null
        }
      }
    },
    "OriginSummary": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "provider": { "type": ["string", "null"] },
        "tenant_id": { "type": ["string", "null"] },
        "space_id": { "type": ["string", "null"] },
        "space_type": { "type": ["string", "null"] },
        "visibility": { "type": ["string", "null"] },
        "external_participants": { "type": ["boolean", "null"] },
        "tags": { "type": "array", "items": { "type": "string" }, "default": [] },
        "sensitivity": { "type": ["string", "null"] },
        "actor_role": { "type": ["string", "null"] }
      }
    },
    "PostureInput": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "current": { "type": ["string", "null"] },
        "signal": { "type": ["string", "null"] }
      }
    },
    "DecisionDetail": {
      "type": "object",
      "required": ["outcome"],
      "additionalProperties": false,
      "properties": {
        "outcome": {
          "type": "string",
          "enum": ["allow", "warn", "deny"]
        },
        "matched_rule": { "type": ["string", "null"], "default": null },
        "reason": { "type": ["string", "null"], "default": null }
      }
    },
    "RuleEvaluation": {
      "type": "object",
      "required": ["rule_block", "rule_path", "enabled", "evaluated", "outcome"],
      "additionalProperties": false,
      "properties": {
        "rule_block": { "type": "string" },
        "rule_path": { "type": "string" },
        "enabled": { "type": "boolean" },
        "evaluated": { "type": "boolean" },
        "outcome": {
          "type": "string",
          "enum": ["allow", "warn", "deny", "skip"]
        },
        "reason": { "type": ["string", "null"], "default": null },
        "match_detail": {
          "oneOf": [
            { "$ref": "#/$defs/MatchDetail" },
            { "type": "null" }
          ],
          "default": null
        }
      }
    },
    "MatchDetail": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "pattern_index": { "type": ["integer", "null"], "default": null },
        "pattern_value": { "type": ["string", "null"], "default": null },
        "matched_target": { "type": ["string", "null"], "default": null }
      }
    },
    "PolicySummary": {
      "type": "object",
      "required": ["hushspec", "content_hash"],
      "additionalProperties": false,
      "properties": {
        "name": { "type": ["string", "null"], "default": null },
        "hushspec": { "type": "string" },
        "content_hash": {
          "type": "string",
          "pattern": "^[0-9a-f]{64}$",
          "description": "SHA-256 hex digest of the resolved policy."
        },
        "extends_chain": {
          "type": "array",
          "items": { "$ref": "#/$defs/PolicyReference" },
          "default": []
        }
      }
    },
    "PolicyReference": {
      "type": "object",
      "required": ["source", "hash"],
      "additionalProperties": false,
      "properties": {
        "source": { "type": "string" },
        "name": { "type": ["string", "null"], "default": null },
        "hash": {
          "type": "string",
          "pattern": "^[0-9a-f]{64}$"
        }
      }
    },
    "OriginProfileSummary": {
      "type": "object",
      "required": ["id", "match_score"],
      "additionalProperties": false,
      "properties": {
        "id": { "type": "string" },
        "match_score": { "type": "integer", "minimum": 0 }
      }
    },
    "PostureResult": {
      "type": "object",
      "required": ["current", "next"],
      "additionalProperties": false,
      "properties": {
        "current": { "type": "string" },
        "next": { "type": "string" },
        "budget_state": {
          "oneOf": [
            { "$ref": "#/$defs/BudgetState" },
            { "type": "null" }
          ],
          "default": null
        }
      }
    },
    "BudgetState": {
      "type": "object",
      "description": "Budget consumption keyed by budget key (e.g., tool_calls, egress_calls).",
      "additionalProperties": {
        "$ref": "#/$defs/BudgetEntry"
      }
    },
    "BudgetEntry": {
      "type": "object",
      "required": ["limit", "consumed", "remaining"],
      "additionalProperties": false,
      "properties": {
        "limit": { "type": "integer", "minimum": 0 },
        "consumed": { "type": "integer", "minimum": 0 },
        "remaining": { "type": "integer", "minimum": 0 }
      }
    },
    "DetectionEvaluation": {
      "type": "object",
      "required": ["detector", "enabled", "outcome"],
      "additionalProperties": false,
      "properties": {
        "detector": {
          "type": "string",
          "enum": ["prompt_injection", "jailbreak", "threat_intel"]
        },
        "enabled": { "type": "boolean" },
        "score": { "type": ["number", "null"], "default": null },
        "level": {
          "type": ["string", "null"],
          "enum": ["safe", "suspicious", "high", "critical", null],
          "default": null
        },
        "outcome": {
          "type": "string",
          "enum": ["allow", "warn", "deny", "skip"]
        },
        "reason": { "type": ["string", "null"], "default": null },
        "top_matches": {
          "oneOf": [
            { "type": "array", "items": { "type": "string" } },
            { "type": "null" }
          ],
          "default": null
        }
      }
    },
    "ReceiptSignature": {
      "type": "object",
      "required": ["algorithm", "key_id", "value"],
      "additionalProperties": false,
      "properties": {
        "algorithm": {
          "type": "string",
          "enum": ["hmac-sha256", "ed25519", "ecdsa-p256"]
        },
        "key_id": { "type": "string" },
        "value": {
          "type": "string",
          "description": "Base64-encoded signature bytes."
        }
      }
    }
  }
}
```

---

## 3. Decision Log Specification

### 3.1 Format

Decision logs use the JSON Lines format (one JSON object per line, newline-delimited). Each line is a self-contained log entry that can be parsed independently. This format is compatible with:

- Fluent Bit / Fluentd ingestion
- AWS CloudWatch Logs Insights
- Google Cloud Logging structured payloads
- Splunk HTTP Event Collector (HEC)
- Elasticsearch / OpenSearch bulk ingestion
- OpenTelemetry Collector `filelog` receiver

Each log line is a JSON object with the following envelope:

```json
{
  "log_version": "0.1.0",
  "log_level": "DECISION",
  "service": "hushspec",
  "receipt": { ... },
  "metadata": { ... }
}
```

### 3.2 Log Levels

Three log levels are defined. Engines MUST support configuring which levels are emitted. The default SHOULD be `DECISION`.

| Level | Trigger | Description |
|-------|---------|-------------|
| `DECISION` | Every `evaluate()` call | Full receipt for every evaluation. High volume, full fidelity. |
| `DENY` | `evaluate()` returns `deny` or `warn` | Only denials and warnings are logged. Reduces volume in permissive environments. |
| `AUDIT` | Periodic or session-end | Aggregated summary: total evaluations, counts by decision, counts by rule block, time range. Not per-decision. |

### 3.3 Envelope Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `log_version` | string | REQUIRED | Log format version: `"0.1.0"`. |
| `log_level` | string | REQUIRED | One of `"DECISION"`, `"DENY"`, `"AUDIT"`. |
| `service` | string | REQUIRED | Fixed value `"hushspec"`. Enables filtering in multi-service log aggregators. |
| `receipt` | object | REQUIRED for `DECISION` and `DENY` | The full `DecisionReceipt` object as defined in Section 2. |
| `metadata` | object | OPTIONAL | Engine-specific metadata. |

### 3.4 Metadata Object

The `metadata` object is engine-defined and MAY contain:

| Field | Type | Description |
|-------|------|-------------|
| `engine_name` | string | Name of the enforcement engine (e.g., `"claude-code"`, `"aegis-proxy"`). |
| `engine_version` | string | Engine version. |
| `session_id` | string | Session or conversation identifier for grouping related decisions. |
| `request_id` | string | Upstream request identifier for distributed tracing correlation. |
| `trace_id` | string | OpenTelemetry trace ID (W3C Trace Context format, 32 hex chars). |
| `span_id` | string | OpenTelemetry span ID (16 hex chars). |
| `environment` | string | Deployment environment: `"production"`, `"staging"`, `"development"`. |
| `agent_id` | string | Identifier for the AI agent instance. |

Engines MUST NOT include secrets, API keys, or authentication tokens in metadata.

### 3.5 Log Entry JSON Schema

The log entry envelope is defined by the following JSON Schema, to be published as `schemas/hushspec-log-entry.v0.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://hushspec.dev/schemas/hushspec-log-entry.v0.schema.json",
  "title": "HushSpec Decision Log Entry v0",
  "description": "Envelope for a single decision log entry (JSON Lines format).",
  "type": "object",
  "required": ["log_version", "log_level", "service"],
  "additionalProperties": false,
  "properties": {
    "log_version": {
      "type": "string",
      "const": "0.1.0"
    },
    "log_level": {
      "type": "string",
      "enum": ["DECISION", "DENY", "AUDIT"]
    },
    "service": {
      "type": "string",
      "const": "hushspec"
    },
    "receipt": {
      "$ref": "hushspec-receipt.v0.schema.json",
      "description": "Full decision receipt. Required for DECISION and DENY levels."
    },
    "summary": {
      "$ref": "#/$defs/AuditSummary",
      "description": "Aggregated summary. Required for AUDIT level."
    },
    "metadata": {
      "$ref": "#/$defs/LogMetadata"
    }
  },
  "allOf": [
    {
      "if": {
        "properties": { "log_level": { "enum": ["DECISION", "DENY"] } },
        "required": ["log_level"]
      },
      "then": { "required": ["receipt"] }
    },
    {
      "if": {
        "properties": { "log_level": { "const": "AUDIT" } },
        "required": ["log_level"]
      },
      "then": { "required": ["summary"] }
    }
  ],
  "$defs": {
    "LogMetadata": {
      "type": "object",
      "properties": {
        "engine_name": { "type": "string" },
        "engine_version": { "type": "string" },
        "session_id": { "type": "string" },
        "request_id": { "type": "string" },
        "trace_id": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        "span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
        "environment": { "type": "string", "enum": ["production", "staging", "development"] },
        "agent_id": { "type": "string" }
      },
      "additionalProperties": true
    },
    "AuditSummary": {
      "type": "object",
      "required": ["period_start", "period_end", "total_evaluations", "decisions"],
      "additionalProperties": false,
      "properties": {
        "period_start": { "type": "string", "format": "date-time" },
        "period_end": { "type": "string", "format": "date-time" },
        "total_evaluations": { "type": "integer", "minimum": 0 },
        "decisions": {
          "type": "object",
          "properties": {
            "allow": { "type": "integer", "minimum": 0 },
            "warn": { "type": "integer", "minimum": 0 },
            "deny": { "type": "integer", "minimum": 0 }
          },
          "required": ["allow", "warn", "deny"],
          "additionalProperties": false
        },
        "by_action_type": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "allow": { "type": "integer", "minimum": 0 },
              "warn": { "type": "integer", "minimum": 0 },
              "deny": { "type": "integer", "minimum": 0 }
            },
            "additionalProperties": false
          }
        },
        "by_rule_block": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "evaluated": { "type": "integer", "minimum": 0 },
              "deny": { "type": "integer", "minimum": 0 },
              "warn": { "type": "integer", "minimum": 0 }
            },
            "additionalProperties": false
          }
        },
        "by_detector": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "evaluated": { "type": "integer", "minimum": 0 },
              "deny": { "type": "integer", "minimum": 0 },
              "warn": { "type": "integer", "minimum": 0 }
            },
            "additionalProperties": false
          }
        },
        "p50_duration_us": { "type": "integer", "minimum": 0 },
        "p95_duration_us": { "type": "integer", "minimum": 0 },
        "p99_duration_us": { "type": "integer", "minimum": 0 },
        "policy_hash": { "type": "string" },
        "policy_reloads": { "type": "integer", "minimum": 0 },
        "posture_transitions": { "type": "integer", "minimum": 0 }
      }
    }
  }
}
```

### 3.6 AUDIT Level Summary Format

When `log_level` is `"AUDIT"`, the `receipt` field is absent and the `summary` field is required:

```json
{
  "log_version": "0.1.0",
  "log_level": "AUDIT",
  "service": "hushspec",
  "summary": {
    "period_start": "2026-03-15T14:00:00.000Z",
    "period_end": "2026-03-15T14:05:00.000Z",
    "total_evaluations": 1247,
    "decisions": {
      "allow": 1189,
      "warn": 43,
      "deny": 15
    },
    "by_action_type": {
      "tool_call": { "allow": 892, "warn": 30, "deny": 3 },
      "file_read": { "allow": 201, "warn": 0, "deny": 5 },
      "file_write": { "allow": 56, "warn": 13, "deny": 4 },
      "egress": { "allow": 40, "warn": 0, "deny": 3 }
    },
    "by_rule_block": {
      "tool_access": { "evaluated": 925, "deny": 3, "warn": 30 },
      "forbidden_paths": { "evaluated": 262, "deny": 5, "warn": 0 },
      "secret_patterns": { "evaluated": 69, "deny": 4, "warn": 0 },
      "egress": { "evaluated": 43, "deny": 3, "warn": 0 },
      "posture_capability": { "evaluated": 1247, "deny": 2, "warn": 0 }
    },
    "by_detector": {
      "prompt_injection": { "evaluated": 312, "deny": 0, "warn": 5 },
      "jailbreak": { "evaluated": 312, "deny": 1, "warn": 3 },
      "threat_intel": { "evaluated": 0, "deny": 0, "warn": 0 }
    },
    "p50_duration_us": 12,
    "p95_duration_us": 45,
    "p99_duration_us": 120,
    "policy_hash": "a1b2c3d4e5f6...",
    "policy_reloads": 0,
    "posture_transitions": 3
  },
  "metadata": { ... }
}
```

### 3.7 Redaction Rules

Decision logs MUST NOT contain cleartext secrets. The following redaction rules are mandatory:

1. **Content fields.** The `content` field from `EvaluationAction` MUST NOT appear in log entries. Only `content_hash` (SHA-256) and `content_size` (byte length) are permitted.

2. **Secret pattern match details.** When a `secret_patterns` rule match contributes to a decision, the `match_detail.matched_target` field MUST be set to `"[REDACTED]"`. The pattern name is logged; the matched text is not.

3. **File content in patches.** For `patch_apply` actions, the `content_hash` represents the hash of the full patch. Individual line content from the patch MUST NOT appear in the log.

4. **Target path redaction.** Engines MAY configure target path redaction for environments where file paths are sensitive (e.g., paths containing customer identifiers). When redaction is applied, the `action.target_redacted` field MUST be set to `true` and the `action.target` field MUST contain a redacted placeholder (e.g., `"[path:sha256:a1b2c3...]"`).

5. **Origin metadata.** Origin fields (`provider`, `tenant_id`, `space_id`) are logged as-is by default. Engines operating in multi-tenant environments MAY redact `tenant_id` and MUST document when they do so.

### 3.8 Retention Recommendations

This specification does not mandate retention periods, as they are governed by organizational policy and applicable regulations. The following table provides guidance:

| Regulation | Minimum Retention | Recommended Retention | Notes |
|------------|------------------|-----------------------|-------|
| SOC2 Type II | 1 year | 2 years | Must cover the audit period. |
| HIPAA | 6 years | 7 years | From date of creation or last effective date. |
| PCI-DSS v4.0 | 1 year | 3 years | 3 months immediately available; 1 year total. |
| GDPR | Purpose-dependent | Minimize | Log only what is necessary; apply data minimization. |
| FedRAMP | 1 year online, 3 years total | 3 years | Per NIST 800-53 AU-11. |

Engines SHOULD provide log rotation and archival capabilities. Engines SHOULD support configurable retention periods. Compressed archival formats (gzip, zstd) are RECOMMENDED for long-term storage.

### 3.9 OpenTelemetry Log Signal Compatibility

Decision log entries map to the OpenTelemetry Log Data Model as follows:

| OTLP Field | Value |
|------------|-------|
| `Timestamp` | `receipt.timestamp` |
| `ObservedTimestamp` | Time the log entry was written (may differ from evaluation time). |
| `SeverityNumber` | `DECISION` -> `INFO (9)`, `DENY` -> `WARN (13)`, `AUDIT` -> `INFO (9)` |
| `SeverityText` | The `log_level` value. |
| `Body` | The full log entry JSON. |
| `Resource` | `service.name = "hushspec"`, `service.version = <engine version>` |
| `Attributes` | `hushspec.receipt_id`, `hushspec.decision`, `hushspec.action_type`, `hushspec.policy_hash` |
| `TraceId` | `metadata.trace_id` if present. |
| `SpanId` | `metadata.span_id` if present. |

---

## 4. Telemetry and Observability

### 4.1 Metric Definitions

Implementations SHOULD expose the following metrics. Metric names follow the OpenTelemetry semantic conventions for naming (dot-separated, lowercase).

#### 4.1.1 `hushspec.evaluate.total`

**Type:** Counter
**Unit:** evaluations
**Description:** Total number of `evaluate()` calls.

**Attributes:**

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `hushspec.decision` | string | The decision outcome. | `"allow"`, `"warn"`, `"deny"` |
| `hushspec.action_type` | string | The action type evaluated. | `"tool_call"`, `"egress"` |

**Use cases:**
- Alert when `deny` rate exceeds a threshold (possible misconfiguration or attack).
- Dashboard showing allow/deny ratio over time.
- Breakdown of action types to understand agent behavior.

#### 4.1.2 `hushspec.evaluate.duration_us`

**Type:** Histogram
**Unit:** microseconds
**Description:** Wall-clock time for each `evaluate()` call.

**Bucket boundaries (RECOMMENDED):** `[1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000]`

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `hushspec.action_type` | string | The action type evaluated. |

**Use cases:**
- Detect performance regressions in policy evaluation.
- Identify action types with disproportionately slow evaluation (e.g., complex regex in `secret_patterns`).
- SLO monitoring: p99 evaluation latency under 1ms.

#### 4.1.3 `hushspec.rule.match`

**Type:** Counter
**Unit:** matches
**Description:** Number of times a rule block produced a non-skip outcome.

**Attributes:**

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `hushspec.rule_block` | string | The rule block name. | `"forbidden_paths"`, `"egress"` |
| `hushspec.decision` | string | The outcome from this rule block. | `"allow"`, `"deny"` |

**Use cases:**
- Identify which rule blocks are most active (helps prioritize policy tuning).
- Detect rules that never fire (candidates for removal or review).
- Track deny hotspots by rule block.

#### 4.1.4 `hushspec.policy.load`

**Type:** Counter
**Unit:** loads
**Description:** Number of policy document load/parse operations.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `hushspec.status` | string | `"success"` or `"failure"`. |
| `hushspec.source` | string | The policy source identifier (file path or reference). |

**Use cases:**
- Alert on policy load failures (misconfiguration, missing files).
- Track policy loading frequency for cache optimization.

#### 4.1.5 `hushspec.policy.reload`

**Type:** Counter
**Unit:** reloads
**Description:** Number of policy document hot-reloads (when the engine detects a policy file change and re-parses).

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `hushspec.status` | string | `"success"` or `"failure"`. |

**Use cases:**
- Verify that policy hot-reload is functioning.
- Correlate policy reloads with changes in decision patterns.

#### 4.1.6 `hushspec.posture.transition`

**Type:** Counter
**Unit:** transitions
**Description:** Number of posture state transitions.

**Attributes:**

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `hushspec.posture.from` | string | The source posture state. | `"standard"`, `"restricted"` |
| `hushspec.posture.to` | string | The target posture state. | `"restricted"`, `"locked"` |
| `hushspec.posture.trigger` | string | The transition trigger. | `"any_violation"`, `"critical_violation"` |

**Use cases:**
- Alert on transitions to locked/restricted states (possible attack or malfunction).
- Track degradation frequency to assess policy strictness.
- Correlate posture transitions with deny rate changes.

#### 4.1.7 `hushspec.detection.total`

**Type:** Counter
**Unit:** detections
**Description:** Number of detection extension evaluations by detector type and outcome.

**Attributes:**

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `hushspec.detector` | string | The detector name. | `"prompt_injection"`, `"jailbreak"`, `"threat_intel"` |
| `hushspec.decision` | string | The detector outcome. | `"allow"`, `"warn"`, `"deny"` |
| `hushspec.detection.level` | string | The detection severity level. | `"safe"`, `"suspicious"`, `"high"`, `"critical"` |

**Use cases:**
- Track prompt injection attempt frequency.
- Alert when jailbreak detections exceed a threshold.
- Monitor threat intel screening hit rates.

#### 4.1.8 `hushspec.detection.score`

**Type:** Histogram
**Unit:** score (0-100 for jailbreak, 0.0-1.0 for threat_intel)
**Description:** Distribution of detection scores.

**Bucket boundaries (RECOMMENDED for jailbreak):** `[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]`
**Bucket boundaries (RECOMMENDED for threat_intel):** `[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]`

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `hushspec.detector` | string | The detector name. |

**Use cases:**
- Visualize score distributions to tune thresholds.
- Detect drift in detector behavior over time.

#### 4.1.9 `hushspec.budget.consumed`

**Type:** Gauge
**Unit:** units
**Description:** Current budget consumption level by budget key.

**Attributes:**

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `hushspec.budget.key` | string | The budget key. | `"tool_calls"`, `"egress_calls"` |
| `hushspec.posture.state` | string | The current posture state. | `"standard"` |

**Use cases:**
- Monitor budget utilization rates.
- Alert when budgets approach exhaustion.

#### 4.1.10 `hushspec.receipt.emit`

**Type:** Counter
**Unit:** receipts
**Description:** Number of decision receipts emitted to sinks.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `hushspec.sink` | string | The sink type: `"file"`, `"stdout"`, `"otlp"`, `"callback"`. |
| `hushspec.status` | string | `"success"` or `"failure"`. |

**Use cases:**
- Detect receipt delivery failures (full disk, network errors to OTLP collector).
- Measure audit trail completeness.

### 4.2 Prometheus Exposition Format

For engines that expose a Prometheus-compatible `/metrics` endpoint, the metrics above map directly:

```
# HELP hushspec_evaluate_total Total HushSpec evaluations
# TYPE hushspec_evaluate_total counter
hushspec_evaluate_total{decision="allow",action_type="tool_call"} 8923
hushspec_evaluate_total{decision="deny",action_type="tool_call"} 12
hushspec_evaluate_total{decision="warn",action_type="tool_call"} 156
hushspec_evaluate_total{decision="allow",action_type="egress"} 2341
hushspec_evaluate_total{decision="deny",action_type="egress"} 89

# HELP hushspec_evaluate_duration_us Evaluation duration in microseconds
# TYPE hushspec_evaluate_duration_us histogram
hushspec_evaluate_duration_us_bucket{action_type="tool_call",le="10"} 7200
hushspec_evaluate_duration_us_bucket{action_type="tool_call",le="50"} 8800
hushspec_evaluate_duration_us_bucket{action_type="tool_call",le="100"} 9050
hushspec_evaluate_duration_us_bucket{action_type="tool_call",le="+Inf"} 9091
hushspec_evaluate_duration_us_sum{action_type="tool_call"} 182340
hushspec_evaluate_duration_us_count{action_type="tool_call"} 9091

# HELP hushspec_rule_match_total Rule block match counts
# TYPE hushspec_rule_match_total counter
hushspec_rule_match_total{rule_block="forbidden_paths",decision="deny"} 45
hushspec_rule_match_total{rule_block="egress",decision="deny"} 89
hushspec_rule_match_total{rule_block="tool_access",decision="allow"} 8923

# HELP hushspec_policy_load_total Policy load operations
# TYPE hushspec_policy_load_total counter
hushspec_policy_load_total{status="success",source="/etc/hushspec/policy.yaml"} 3
hushspec_policy_load_total{status="failure",source="/etc/hushspec/policy.yaml"} 0

# HELP hushspec_posture_transition_total Posture state transitions
# TYPE hushspec_posture_transition_total counter
hushspec_posture_transition_total{from="standard",to="restricted",trigger="any_violation"} 7
hushspec_posture_transition_total{from="restricted",to="locked",trigger="critical_violation"} 1

# HELP hushspec_detection_total Detection extension evaluations
# TYPE hushspec_detection_total counter
hushspec_detection_total{detector="prompt_injection",decision="allow",level="safe"} 4521
hushspec_detection_total{detector="prompt_injection",decision="deny",level="critical"} 3
hushspec_detection_total{detector="jailbreak",decision="allow",level="safe"} 4499
hushspec_detection_total{detector="jailbreak",decision="warn",level="suspicious"} 18
hushspec_detection_total{detector="jailbreak",decision="deny",level="high"} 7

# HELP hushspec_detection_score Detection scores
# TYPE hushspec_detection_score histogram
hushspec_detection_score_bucket{detector="jailbreak",le="20"} 4100
hushspec_detection_score_bucket{detector="jailbreak",le="50"} 4450
hushspec_detection_score_bucket{detector="jailbreak",le="80"} 4517
hushspec_detection_score_bucket{detector="jailbreak",le="+Inf"} 4524

# HELP hushspec_budget_consumed Current budget consumption
# TYPE hushspec_budget_consumed gauge
hushspec_budget_consumed{budget_key="tool_calls",posture_state="standard"} 7
```

### 4.3 Event Types for Hooks and Callbacks

Engines SHOULD support an event callback mechanism. The following event types are defined:

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `on_evaluate` | After every `evaluate()` call | `DecisionReceipt` |
| `on_deny` | After an `evaluate()` call returns `deny` | `DecisionReceipt` |
| `on_warn` | After an `evaluate()` call returns `warn` | `DecisionReceipt` |
| `on_posture_transition` | After a posture state transition occurs | `{ receipt_id, from, to, trigger, timestamp }` |
| `on_detection` | After a detection extension produces `warn` or `deny` | `{ receipt_id, detector, score, level, outcome }` |
| `on_budget_exhausted` | After a posture budget reaches zero remaining | `{ receipt_id, budget_key, posture_state, limit }` |
| `on_policy_load` | After a policy document is loaded/parsed | `{ source, name, hash, success, error? }` |
| `on_policy_reload` | After a policy document is hot-reloaded | `{ source, name, old_hash, new_hash, success, error? }` |
| `on_receipt_error` | When receipt generation or delivery fails | `{ receipt_id, error, sink }` |

Callback implementations MUST NOT block the `evaluate()` call path. Callbacks SHOULD be invoked asynchronously or in a separate thread/goroutine/task. If a callback panics or throws, the error MUST be captured and reported via `on_receipt_error`; it MUST NOT affect the evaluation decision.

### 4.4 OpenTelemetry Integration

For full OpenTelemetry integration, engines SHOULD:

1. Create a span for each `evaluate()` call with span name `"hushspec.evaluate"`.
2. Set span attributes: `hushspec.action_type`, `hushspec.decision`, `hushspec.receipt_id`, `hushspec.policy_hash`.
3. Record the receipt as a span event named `"hushspec.decision"` with the receipt JSON as the event body.
4. Propagate `trace_id` and `span_id` into the receipt's `metadata` if the caller provides a trace context.
5. When detection extension evaluation occurs, create child spans for each detector with span name `"hushspec.detect.<detector>"` and attributes `hushspec.detector`, `hushspec.detection.score`, `hushspec.detection.level`, `hushspec.decision`.
6. When a posture transition occurs, record a span event named `"hushspec.posture.transition"` with attributes `hushspec.posture.from`, `hushspec.posture.to`, `hushspec.posture.trigger`.

This enables end-to-end distributed tracing from the application request through the security evaluation, including sub-millisecond visibility into detection latency and posture state changes.

---

## 5. SDK Integration Design

### 5.1 Design Principles

1. **Zero-cost when disabled.** Receipt generation MUST NOT allocate memory, compute hashes, or record timestamps when audit mode is off. The `evaluate()` function MUST remain as fast as it is today for engines that do not need receipts.

2. **Backward compatible.** The existing `evaluate()` function signature and return type MUST NOT change. Receipt generation is provided through a separate function or an options parameter.

3. **Sink-agnostic.** SDKs define a trait/interface for receipt consumers ("sinks"). The SDK ships with no built-in sinks. Reference sink implementations are provided as separate crates/packages.

4. **Thread-safe.** Receipt collectors MUST be safe to use from multiple threads/goroutines/tasks concurrently.

### 5.2 Rust SDK

#### 5.2.1 New Types

```rust
/// Configuration for receipt generation.
#[derive(Clone, Debug, Default)]
pub struct AuditConfig {
    /// Whether to generate receipts. Default: false.
    pub enabled: bool,
    /// Whether to record rule_trace (full trace). Default: true when enabled.
    pub record_trace: bool,
    /// Whether to record policy summary with extends chain. Default: true when enabled.
    pub record_policy: bool,
    /// Whether to record evaluation duration. Default: true when enabled.
    pub record_timing: bool,
    /// Signing configuration. Default: None (unsigned).
    pub signing: Option<SigningConfig>,
}

/// Configuration for receipt signing.
#[derive(Clone, Debug)]
pub struct SigningConfig {
    pub algorithm: SigningAlgorithm,
    pub key_id: String,
    pub key_material: Vec<u8>,  // Zeroized on drop
}

#[derive(Clone, Copy, Debug)]
pub enum SigningAlgorithm {
    HmacSha256,
    Ed25519,
    EcdsaP256,
}

/// A self-contained decision receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub receipt_id: String,
    pub receipt_version: String,
    pub timestamp: String,
    pub duration_us: u64,
    pub action: ActionSummary,
    pub decision: DecisionDetail,
    pub rule_trace: Vec<RuleEvaluation>,
    pub detection_trace: Option<Vec<DetectionEvaluation>>,
    pub policy: PolicySummary,
    pub origin_profile: Option<OriginProfileSummary>,
    pub posture: Option<PostureResultWithBudget>,
    pub warnings: Vec<String>,
    pub signature: Option<ReceiptSignature>,
}

/// Detection extension evaluation trace entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionEvaluation {
    pub detector: String,
    pub enabled: bool,
    pub score: Option<f64>,
    pub level: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub top_matches: Option<Vec<String>>,
}

/// Posture result with optional budget consumption state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureResultWithBudget {
    pub current: String,
    pub next: String,
    pub budget_state: Option<HashMap<String, BudgetEntry>>,
}

/// Budget consumption entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetEntry {
    pub limit: u64,
    pub consumed: u64,
    pub remaining: u64,
}

/// Trait for receipt consumers.
pub trait ReceiptSink: Send + Sync {
    fn emit(&self, receipt: &DecisionReceipt) -> Result<(), Box<dyn std::error::Error>>;
    fn flush(&self) -> Result<(), Box<dyn std::error::Error>>;
}
```

#### 5.2.2 New Functions

```rust
/// Evaluate with receipt generation.
pub fn evaluate_audited(
    spec: &HushSpec,
    action: &EvaluationAction,
    config: &AuditConfig,
) -> (EvaluationResult, Option<DecisionReceipt>)

/// Evaluate with receipt generation and policy context.
pub fn evaluate_audited_with_policy(
    spec: &HushSpec,
    action: &EvaluationAction,
    config: &AuditConfig,
    policy_context: &PolicyContext,
) -> (EvaluationResult, Option<DecisionReceipt>)

/// Pre-computed policy metadata for efficient receipt generation.
pub struct PolicyContext {
    pub name: Option<String>,
    pub hushspec_version: String,
    pub content_hash: String,
    pub extends_chain: Vec<PolicyReference>,
}

impl PolicyContext {
    /// Compute from a resolved HushSpec and its extends chain.
    pub fn from_resolved(spec: &HushSpec, chain: &[LoadedSpec]) -> Self { ... }
}
```

#### 5.2.3 Performance Strategy

When `AuditConfig::enabled` is `false`, `evaluate_audited()` calls `evaluate()` directly and returns `(result, None)`. No allocations, no timing, no hashing.

When enabled:
- `receipt_id` generation uses a thread-local UUID v7 generator (no syscall per receipt).
- `timestamp` uses `SystemTime::now()` once at evaluation start.
- `duration_us` uses `Instant::now()` for monotonic timing.
- `content_hash` is computed lazily only if the action has content.
- `policy.content_hash` is precomputed in `PolicyContext` and reused across evaluations (the policy does not change between reloads).
- `rule_trace` is built by instrumenting the existing evaluation functions with trace accumulation. The evaluator passes a `&mut Vec<RuleEvaluation>` through the call chain when audit is enabled.

#### 5.2.4 Reference Sink Implementations

These are provided as separate crates:

| Crate | Sink | Description |
|-------|------|-------------|
| `hushspec-sink-file` | `FileSink` | Appends JSON Lines to a file with rotation. |
| `hushspec-sink-stdout` | `StdoutSink` | Writes to stdout (for container environments). |
| `hushspec-sink-otlp` | `OtlpSink` | Sends logs via OTLP/gRPC or OTLP/HTTP. |
| `hushspec-sink-channel` | `ChannelSink` | Sends receipts to a `tokio::sync::mpsc` channel for in-process consumers. |

### 5.3 TypeScript SDK

#### 5.3.1 New Types

```typescript
export interface AuditConfig {
  enabled: boolean;
  recordTrace?: boolean;    // default: true
  recordPolicy?: boolean;   // default: true
  recordTiming?: boolean;   // default: true
  signing?: SigningConfig;
}

export interface SigningConfig {
  algorithm: 'hmac-sha256' | 'ed25519' | 'ecdsa-p256';
  keyId: string;
  keyMaterial: Uint8Array;
}

export interface DecisionReceipt {
  receipt_id: string;
  receipt_version: string;
  timestamp: string;
  duration_us: number;
  action: ActionSummary;
  decision: DecisionDetail;
  rule_trace: RuleEvaluation[];
  detection_trace: DetectionEvaluation[] | null;
  policy: PolicySummary;
  origin_profile: OriginProfileSummary | null;
  posture: PostureResultWithBudget | null;
  warnings: string[];
  signature: ReceiptSignature | null;
}

export interface DetectionEvaluation {
  detector: 'prompt_injection' | 'jailbreak' | 'threat_intel';
  enabled: boolean;
  score: number | null;
  level: 'safe' | 'suspicious' | 'high' | 'critical' | null;
  outcome: 'allow' | 'warn' | 'deny' | 'skip';
  reason: string | null;
  top_matches: string[] | null;
}

export interface PostureResultWithBudget {
  current: string;
  next: string;
  budget_state: Record<string, BudgetEntry> | null;
}

export interface BudgetEntry {
  limit: number;
  consumed: number;
  remaining: number;
}

export interface ReceiptSink {
  emit(receipt: DecisionReceipt): void | Promise<void>;
  flush(): void | Promise<void>;
}
```

#### 5.3.2 New Functions

```typescript
export function evaluateAudited(
  spec: HushSpec,
  action: EvaluationAction,
  config: AuditConfig,
): { result: EvaluationResult; receipt: DecisionReceipt | null };

export function evaluateAuditedWithPolicy(
  spec: HushSpec,
  action: EvaluationAction,
  config: AuditConfig,
  policyContext: PolicyContext,
): { result: EvaluationResult; receipt: DecisionReceipt | null };
```

#### 5.3.3 Performance Strategy

When `config.enabled` is `false`, `evaluateAudited()` delegates directly to the existing evaluate logic and returns `{ result, receipt: null }`.

When enabled:
- `receipt_id` uses `crypto.randomUUID()` (available in Node.js 19+ and all modern browsers).
- `timestamp` uses `new Date().toISOString()`.
- `duration_us` uses `performance.now()` (sub-millisecond resolution).
- `content_hash` uses `crypto.subtle.digest('SHA-256', ...)` or the Node.js `crypto` module.
- `PolicyContext` is precomputed once and passed to each evaluation call.

#### 5.3.4 Reference Sinks

Published as separate npm packages:

| Package | Sink | Description |
|---------|------|-------------|
| `@hushspec/sink-file` | `FileSink` | JSON Lines file output with rotation via `fs.appendFile`. |
| `@hushspec/sink-console` | `ConsoleSink` | Structured output via `console.log` (JSON). |
| `@hushspec/sink-otlp` | `OtlpSink` | OTLP export via `@opentelemetry/exporter-logs-otlp-http`. |
| `@hushspec/sink-callback` | `CallbackSink` | Invokes a user-provided async function per receipt. |

### 5.4 Python SDK

#### 5.4.1 New Types

```python
@dataclass
class AuditConfig:
    enabled: bool = False
    record_trace: bool = True
    record_policy: bool = True
    record_timing: bool = True
    signing: SigningConfig | None = None

@dataclass
class SigningConfig:
    algorithm: Literal["hmac-sha256", "ed25519", "ecdsa-p256"]
    key_id: str
    key_material: bytes

@dataclass
class DecisionReceipt:
    receipt_id: str
    receipt_version: str
    timestamp: str
    duration_us: int
    action: ActionSummary
    decision: DecisionDetail
    rule_trace: list[RuleEvaluation]
    detection_trace: list[DetectionEvaluation] | None
    policy: PolicySummary
    origin_profile: OriginProfileSummary | None
    posture: PostureResultWithBudget | None
    warnings: list[str]
    signature: ReceiptSignature | None

@dataclass
class DetectionEvaluation:
    detector: Literal["prompt_injection", "jailbreak", "threat_intel"]
    enabled: bool
    outcome: Literal["allow", "warn", "deny", "skip"]
    score: float | None = None
    level: Literal["safe", "suspicious", "high", "critical"] | None = None
    reason: str | None = None
    top_matches: list[str] | None = None

@dataclass
class PostureResultWithBudget:
    current: str
    next: str
    budget_state: dict[str, BudgetEntry] | None = None

@dataclass
class BudgetEntry:
    limit: int
    consumed: int
    remaining: int

class ReceiptSink(Protocol):
    def emit(self, receipt: DecisionReceipt) -> None: ...
    def flush(self) -> None: ...
```

#### 5.4.2 New Functions

```python
def evaluate_audited(
    spec: HushSpec,
    action: EvaluationAction,
    config: AuditConfig,
) -> tuple[EvaluationResult, DecisionReceipt | None]: ...

def evaluate_audited_with_policy(
    spec: HushSpec,
    action: EvaluationAction,
    config: AuditConfig,
    policy_context: PolicyContext,
) -> tuple[EvaluationResult, DecisionReceipt | None]: ...
```

#### 5.4.3 Performance Strategy

When `config.enabled` is `False`, the function delegates directly and returns `(result, None)`.

When enabled:
- `receipt_id` uses `uuid.uuid7()` (Python 3.13+) or falls back to `uuid.uuid4()`.
- `timestamp` uses `datetime.now(timezone.utc).isoformat()`.
- `duration_us` uses `time.perf_counter_ns() // 1000`.
- `content_hash` uses `hashlib.sha256()`.

#### 5.4.4 Reference Sinks

Published as optional extras in the `hushspec` package:

```
pip install hushspec[audit]          # Core audit types
pip install hushspec[sink-file]      # File sink
pip install hushspec[sink-otlp]      # OTLP sink
```

| Module | Sink | Description |
|--------|------|-------------|
| `hushspec.sinks.file` | `FileSink` | JSON Lines file output with `logging.handlers.RotatingFileHandler`. |
| `hushspec.sinks.stream` | `StreamSink` | Writes to any `IO[str]` (stdout, stderr, or custom stream). |
| `hushspec.sinks.otlp` | `OtlpSink` | Export via `opentelemetry-sdk` log exporter. |
| `hushspec.sinks.callback` | `CallbackSink` | Invokes a user-provided callable per receipt. |

### 5.5 Go SDK

#### 5.5.1 New Types

```go
type AuditConfig struct {
    Enabled      bool
    RecordTrace  bool  // default: true
    RecordPolicy bool  // default: true
    RecordTiming bool  // default: true
    Signing      *SigningConfig
}

type SigningConfig struct {
    Algorithm   string // "hmac-sha256", "ed25519", or "ecdsa-p256"
    KeyID       string
    KeyMaterial []byte
}

type DecisionReceipt struct {
    ReceiptID      string                   `json:"receipt_id"`
    ReceiptVersion string                   `json:"receipt_version"`
    Timestamp      string                   `json:"timestamp"`
    DurationUS     int64                    `json:"duration_us"`
    Action         ActionSummary            `json:"action"`
    Decision       DecisionDetail           `json:"decision"`
    RuleTrace      []RuleEvaluation         `json:"rule_trace"`
    DetectionTrace []DetectionEvaluation    `json:"detection_trace,omitempty"`
    Policy         PolicySummary            `json:"policy"`
    OriginProfile  *OriginProfileSummary    `json:"origin_profile,omitempty"`
    Posture        *PostureResultWithBudget `json:"posture,omitempty"`
    Warnings       []string                 `json:"warnings"`
    Signature      *ReceiptSignature        `json:"signature,omitempty"`
}

type DetectionEvaluation struct {
    Detector   string   `json:"detector"`
    Enabled    bool     `json:"enabled"`
    Score      *float64 `json:"score,omitempty"`
    Level      *string  `json:"level,omitempty"`
    Outcome    string   `json:"outcome"`
    Reason     *string  `json:"reason,omitempty"`
    TopMatches []string `json:"top_matches,omitempty"`
}

type PostureResultWithBudget struct {
    Current     string                  `json:"current"`
    Next        string                  `json:"next"`
    BudgetState map[string]BudgetEntry  `json:"budget_state,omitempty"`
}

type BudgetEntry struct {
    Limit     int64 `json:"limit"`
    Consumed  int64 `json:"consumed"`
    Remaining int64 `json:"remaining"`
}

type ReceiptSink interface {
    Emit(receipt *DecisionReceipt) error
    Flush() error
}
```

#### 5.5.2 New Functions

```go
func EvaluateAudited(
    spec *HushSpec,
    action *EvaluationAction,
    config *AuditConfig,
) (*EvaluationResult, *DecisionReceipt, error)

func EvaluateAuditedWithPolicy(
    spec *HushSpec,
    action *EvaluationAction,
    config *AuditConfig,
    policyCtx *PolicyContext,
) (*EvaluationResult, *DecisionReceipt, error)
```

#### 5.5.3 Performance Strategy

When `config == nil` or `config.Enabled == false`, the function calls `Evaluate()` directly and returns `(result, nil, nil)`.

When enabled:
- `ReceiptID` uses `github.com/google/uuid` with UUID v7 generation.
- `Timestamp` uses `time.Now().UTC().Format(time.RFC3339Nano)`.
- `DurationUS` uses `time.Since(start).Microseconds()`.
- `ContentHash` uses `crypto/sha256`.
- `PolicyContext` is precomputed via `NewPolicyContext(spec, chain)`.

#### 5.5.4 Reference Sinks

Published as sub-packages:

| Package | Sink | Description |
|---------|------|-------------|
| `hushspec/sinks/filesink` | `FileSink` | JSON Lines file output with size-based rotation. |
| `hushspec/sinks/stdoutsink` | `StdoutSink` | Writes to `os.Stdout`. |
| `hushspec/sinks/otlpsink` | `OtlpSink` | Export via `go.opentelemetry.io/otel` log bridge. |
| `hushspec/sinks/chansink` | `ChanSink` | Sends `*DecisionReceipt` to a `chan`. |

---

## 6. Compliance Mapping

### 6.1 SOC2 Trust Services Criteria

SOC2 audits evaluate controls across five trust service criteria. The decision receipt directly addresses the following:

| SOC2 Criterion | Requirement | Receipt Field(s) |
|----------------|-------------|-------------------|
| **CC6.1** Logical access security | Implement logical access controls | `decision.outcome`, `rule_trace`, `action.type`, `action.target` |
| **CC6.2** Authorization for access | Authorize access based on defined policies | `policy.content_hash`, `policy.extends_chain`, `decision.matched_rule` |
| **CC6.3** Removal of access | Deny unauthorized access | `decision.outcome == "deny"`, `rule_trace[].outcome == "deny"` |
| **CC7.1** Monitoring for anomalies | Monitor for indicators of compromise | `summary.decisions.deny` (AUDIT log level), `hushspec.evaluate.total` metric |
| **CC7.2** Incident response | Respond to identified incidents | `receipt_id` (correlation), `rule_trace` (root cause), `timestamp` (timeline) |
| **CC8.1** Change management | Manage changes to infrastructure | `policy.content_hash`, `policy.extends_chain[].hash`, `hushspec.policy.reload` metric |

**Evidence generation:** An auditor can query decision logs to produce evidence for each criterion:

- CC6.1: "Show all deny decisions for `file_read` actions in the past 30 days."
- CC6.2: "Show the policy document hash for all evaluations on date X and confirm it matches the approved policy hash."
- CC7.1: "Show the daily deny count over the audit period."

### 6.2 HIPAA Audit Trail Requirements

HIPAA Security Rule Section 164.312(b) requires audit controls that record and examine activity in systems containing ePHI. The receipt format satisfies this through:

| HIPAA Requirement | Implementation |
|-------------------|----------------|
| **164.312(b)** Audit controls | Decision log with `DECISION` level captures all access events. |
| **164.312(a)(1)** Access control | `decision.outcome`, `action.type`, `action.target` demonstrate access was controlled. |
| **164.312(a)(2)(i)** Unique user identification | `metadata.agent_id`, `action.origin.actor_role`, `action.origin.tenant_id`. |
| **164.312(a)(2)(iv)** Encryption and decryption | `signature` field provides integrity; engines MUST encrypt logs at rest. |
| **164.312(c)(1)** Integrity | `signature` field; `policy.content_hash` proves policy was not modified. |
| **164.312(d)** Authentication | `action.origin` fields carry identity context from the upstream system. |
| **164.312(e)(1)** Transmission security | Not addressed by the receipt format; engines MUST use TLS for OTLP export. |

**PHI protection:** The redaction rules in Section 3.7 ensure that file content (which may contain ePHI) is never logged. Only content hashes and file paths are recorded. Engines handling ePHI SHOULD enable target path redaction as well.

### 6.3 PCI-DSS v4.0 Logging Requirements

PCI-DSS v4.0 Requirement 10 mandates logging and monitoring of access to system components and cardholder data.

| PCI-DSS Requirement | Receipt Field(s) |
|----------------------|-------------------|
| **10.2.1** Audit logs capture individual user access | `action.type`, `action.target`, `metadata.agent_id` |
| **10.2.1.1** Individual user access to cardholder data | `action.target` (paths to cardholder data), `decision.outcome` |
| **10.2.1.2** Actions taken by individuals with admin access | `action.origin.actor_role`, `rule_trace` |
| **10.2.1.5** Changes to identification and authentication | `policy.content_hash` changes, `hushspec.policy.reload` metric |
| **10.2.2** Audit logs record: user ID, event type, date/time, success/fail, origination, identity/name of affected data | `metadata.agent_id` (user ID), `action.type` (event type), `timestamp` (date/time), `decision.outcome` (success/fail), `action.origin` (origination), `action.target` (affected data) |
| **10.3.1** Read access to audit logs is limited | Not addressed by format; engine responsibility. See Section 7.4. |
| **10.3.3** Audit logs are backed up and protected | Not addressed by format; engine responsibility. See Section 3.8. |
| **10.5.1** Retain audit log history for at least 12 months | Retention recommendations in Section 3.8. |

### 6.4 NIST 800-53 (FedRAMP)

For organizations operating under FedRAMP (which inherits NIST 800-53 controls), the receipt format maps to the AU (Audit and Accountability) control family:

| Control | Receipt Mapping |
|---------|-----------------|
| **AU-2** Audit events | All action types and decision outcomes are auditable events. |
| **AU-3** Content of audit records | `timestamp`, `action.type`, `action.target`, `decision.outcome`, `metadata.agent_id`, `metadata.session_id`. |
| **AU-3(1)** Additional audit information | `rule_trace`, `policy.extends_chain`, `posture`, `origin_profile`. |
| **AU-8** Time stamps | `timestamp` (UTC, millisecond precision). |
| **AU-9** Protection of audit information | `signature` field (integrity); storage security per Section 7.3. |
| **AU-10** Non-repudiation | `signature` with `ed25519` algorithm provides cryptographic non-repudiation. |
| **AU-11** Audit record retention | Retention recommendations per Section 3.8. |
| **AU-12** Audit record generation | `evaluate_audited()` generates receipts at the point of decision. |

---

## 7. Security Considerations

### 7.1 Receipt Integrity

Decision receipts are security evidence. If an attacker can modify receipts after generation, they can cover their tracks. The `signature` field provides tamper detection, but it is optional. This section specifies requirements for different threat models.

**Threat Model 1: Internal audit (low threat).**
Receipts are stored on a trusted filesystem. The `signature` field is not required. File permissions and OS-level access controls protect integrity.

**Threat Model 2: Shared infrastructure (medium threat).**
Receipts are stored in a shared log aggregator (Splunk, Elasticsearch). HMAC-SHA256 signing with a per-engine key is RECOMMENDED. The key is stored in a secrets manager (AWS Secrets Manager, HashiCorp Vault). Key rotation SHOULD occur at least quarterly.

**Threat Model 3: Adversarial environment (high threat).**
Receipts must be non-repudiable. Ed25519 signing with hardware-backed keys (HSM, YubiKey, TPM) is REQUIRED. Receipt transmission MUST use mutual TLS. Engines SHOULD implement append-only log storage (e.g., AWS QLDB, Azure Immutable Blob Storage, or a Merkle tree-based log).

**Signature Computation:**

1. Serialize the receipt to canonical JSON with `signature` set to `null`.
2. Compute the signature over the UTF-8 byte representation of the canonical JSON.
3. Set the `signature` field with the algorithm, key ID, and base64-encoded signature.

**Canonical JSON rules:**
- Object keys sorted lexicographically (byte order).
- No whitespace between tokens.
- No trailing commas.
- Strings use minimal escape sequences.
- Numbers use no unnecessary leading zeros or trailing zeros.
- UTF-8 encoding.

### 7.2 Sensitive Data in Receipts

Receipts MUST NOT contain cleartext secrets. The redaction rules in Section 3.7 are the primary defense. This section addresses additional scenarios:

**File paths as data.** In multi-tenant environments, file paths may contain tenant identifiers, customer names, or project codenames. Engines SHOULD provide a configurable path redaction function:

```
# Original path
/data/customers/acme-corp/medical-records/patient-123.json

# Redacted path (hash-based)
[path:sha256:a1b2c3d4...]

# Redacted path (structure-preserving)
/data/customers/[TENANT]/[CATEGORY]/[FILE]
```

**Tool names as data.** Tool names in `tool_call` actions may reveal internal system architecture. This is generally acceptable for audit purposes. Engines in highly sensitive environments MAY redact tool names.

**Origin metadata.** Fields like `tenant_id` and `space_id` are operational metadata, not secrets. They SHOULD be logged for audit correlation. If they are considered sensitive, engines MAY hash them.

**Regular expressions.** Secret detection regex patterns in `match_detail.pattern_value` could theoretically reveal what the system considers a secret. The specification requires using the pattern *name*, not the regex itself, in match details. This prevents regex leakage.

### 7.3 Storage Security

Engines MUST consider the following storage security requirements:

1. **Encryption at rest.** Decision log files MUST be encrypted at rest using AES-256-GCM or equivalent. For cloud storage, use the provider's server-side encryption (AWS SSE-S3, GCS CMEK, Azure SSE).

2. **Access control.** Decision log files MUST be readable only by authorized auditors and the engine's service account. On POSIX systems, file permissions SHOULD be `0600` or `0640` (owner read-write, group read).

3. **Append-only semantics.** Where the storage layer supports it, decision logs SHOULD be written to append-only storage. This prevents deletion or modification of historical records.

4. **Separation of duties.** The entity that generates receipts (the engine) SHOULD NOT have delete access to the log storage. This prevents a compromised engine from destroying evidence.

### 7.4 Access Control for Audit Logs

Decision logs contain operational metadata that may be useful to attackers (which tools are used, which domains are accessed, which file paths are sensitive). Access to audit logs MUST be restricted:

1. **Role-based access.** Define an "auditor" role with read-only access to decision logs. The "operator" role can configure log sinks but cannot read historical logs. The "engine" role can write logs but cannot read or delete them.

2. **Query restrictions.** When decision logs are stored in a queryable system (Elasticsearch, Splunk), implement row-level security or index-level permissions to prevent unauthorized queries.

3. **Log access auditing.** Access to decision logs SHOULD itself be audited. This creates a meta-audit trail that detects unauthorized log access.

---

## 8. Implementation Roadmap

### Phase 1: Receipt Format Specification and JSON Schema (Weeks 1-3)

**Deliverables:**
- `schemas/hushspec-receipt.v0.schema.json` -- the receipt JSON Schema as defined in Section 2.4, including the `detection_trace` and `budget_state` definitions.
- `schemas/hushspec-log-entry.v0.schema.json` -- the log entry envelope JSON Schema as defined in Section 3.5, including the AUDIT summary schema.
- Update `spec/hushspec-core.md` Section 8 (Conformance Levels) to define a new conformance level:
  - **Level 4: Auditor** -- A Level 4 implementation additionally generates decision receipts conforming to the receipt schema and supports at least one receipt sink.
- Conformance test fixtures for receipt validation (valid and invalid receipt documents).

**Acceptance criteria:**
- Both schemas pass JSON Schema meta-validation.
- At least 10 example receipt documents (covering allow, warn, deny, with and without extensions, including detection_trace and posture budget_state) validate against the schema.
- The specification prose is reviewed by at least two security engineers.

### Phase 2: Rust SDK Receipt Generation (Weeks 4-7)

**Deliverables:**
- `crates/hushspec/src/audit.rs` -- `AuditConfig`, `DecisionReceipt`, `PolicyContext`, and all supporting types.
- `crates/hushspec/src/audit_evaluate.rs` -- `evaluate_audited()` and `evaluate_audited_with_policy()` functions.
- `crates/hushspec/src/audit_sign.rs` -- Signature computation (HMAC-SHA256 and Ed25519).
- `crates/hushspec/src/audit_hash.rs` -- SHA-256 content hashing and canonical JSON serialization.
- Instrumentation of existing evaluation functions in `evaluate.rs` to optionally accumulate `RuleEvaluation` trace entries, including `posture_capability` guard entries and short-circuit recording.
- `crates/hushspec/src/audit_detection.rs` -- Detection trace generation for prompt injection, jailbreak, and threat intel detectors.
- `crates/hushspec/src/audit_budget.rs` -- Budget state snapshot generation.
- Unit tests with 100% branch coverage on receipt generation paths.
- Property tests for receipt serialization round-trips.
- Benchmark suite comparing `evaluate()` vs `evaluate_audited()` performance.

**Acceptance criteria:**
- `evaluate_audited()` with `AuditConfig { enabled: false }` has zero measurable overhead vs `evaluate()`.
- `evaluate_audited()` with full audit produces receipts that validate against the JSON Schema.
- Benchmark: receipt generation adds less than 10 microseconds per evaluation on commodity hardware.
- All existing tests continue to pass.

### Phase 3: TypeScript, Python, Go SDK Ports (Weeks 8-12)

**Deliverables per SDK:**
- Receipt types mirroring the Rust definitions.
- `evaluateAudited()` / `evaluate_audited()` / `EvaluateAudited()` functions.
- `PolicyContext` precomputation.
- Signature computation.
- Unit tests validating receipt schema conformance.

**Acceptance criteria:**
- All four SDKs produce byte-compatible receipts for identical inputs (proven via cross-language test vectors).
- Existing conformance test suite continues to pass.
- No new dependencies for the core audit types (signature computation may introduce a dependency on a crypto library).

### Phase 4: Telemetry Hooks (Weeks 13-15)

**Deliverables:**
- Event callback interfaces in all four SDKs (`ReceiptSink` trait/interface/protocol).
- Metric counter types (or integration guidance for each language's OpenTelemetry SDK).
- Decision log envelope types and serialization.
- AUDIT level summary aggregation logic.

**Acceptance criteria:**
- A callback sink receives receipts without blocking the evaluation path.
- Metrics increment correctly across concurrent evaluations.
- AUDIT summaries accurately reflect evaluation counts and timing percentiles.

### Phase 5: Reference Sink Implementations (Weeks 16-20)

**Deliverables:**
- File sinks for all four SDKs (with log rotation).
- Stdout/console sinks for all four SDKs.
- OTLP sinks for Rust and TypeScript (highest-priority languages).
- OTLP sinks for Python and Go.
- Integration tests with a local OpenTelemetry Collector.
- Documentation and examples for each sink.

**Acceptance criteria:**
- File sinks handle rotation at configurable size thresholds.
- OTLP sinks successfully export to an OpenTelemetry Collector and receipts appear in a downstream backend (Jaeger, Grafana Tempo, or similar).
- All sinks handle errors gracefully (full disk, network failure) without affecting evaluation.

---

## 9. Examples

### 9.1 Full Receipt: Allow Decision

A `tool_call` action for the `read_file` tool, evaluated against the `ai-agent` ruleset.

```json
{
  "receipt_id": "019502a4-3c7e-7bf2-a1d4-5e8f3b2c1d0a",
  "receipt_version": "0.1.0",
  "timestamp": "2026-03-15T14:32:07.123Z",
  "duration_us": 8,
  "action": {
    "type": "tool_call",
    "target": "read_file",
    "content_hash": null,
    "content_size": null,
    "args_size": 256,
    "origin": null,
    "posture_input": null
  },
  "decision": {
    "outcome": "allow",
    "matched_rule": "rules.tool_access.default",
    "reason": "tool matched default allow"
  },
  "rule_trace": [
    {
      "rule_block": "tool_access",
      "rule_path": "rules.tool_access",
      "enabled": true,
      "evaluated": true,
      "outcome": "allow",
      "reason": "tool matched default allow",
      "match_detail": null
    }
  ],
  "detection_trace": null,
  "policy": {
    "name": "ai-agent",
    "hushspec": "0.1.0",
    "content_hash": "7d3a1e48b2c0f5d9a6e8b4c1d3f2a5e7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
    "extends_chain": []
  },
  "origin_profile": null,
  "posture": null,
  "warnings": [],
  "signature": null
}
```

### 9.2 Full Receipt: Warn Decision

A `tool_call` action for the `git_push` tool, which requires confirmation.

```json
{
  "receipt_id": "019502a4-5d91-7c3f-b2e5-6f9a4c3d2e1b",
  "receipt_version": "0.1.0",
  "timestamp": "2026-03-15T14:32:08.456Z",
  "duration_us": 11,
  "action": {
    "type": "tool_call",
    "target": "git_push",
    "content_hash": null,
    "content_size": null,
    "args_size": 128,
    "origin": null,
    "posture_input": null
  },
  "decision": {
    "outcome": "warn",
    "matched_rule": "rules.tool_access.require_confirmation",
    "reason": "tool requires confirmation"
  },
  "rule_trace": [
    {
      "rule_block": "tool_access",
      "rule_path": "rules.tool_access",
      "enabled": true,
      "evaluated": true,
      "outcome": "warn",
      "reason": "tool requires confirmation",
      "match_detail": {
        "pattern_index": 0,
        "pattern_value": "git_push",
        "matched_target": "git_push"
      }
    }
  ],
  "detection_trace": null,
  "policy": {
    "name": "ai-agent",
    "hushspec": "0.1.0",
    "content_hash": "7d3a1e48b2c0f5d9a6e8b4c1d3f2a5e7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
    "extends_chain": []
  },
  "origin_profile": null,
  "posture": null,
  "warnings": [],
  "signature": null
}
```

### 9.3 Full Receipt: Deny Decision (Secret Detection)

A `file_write` action denied because the content contains an AWS access key.

```json
{
  "receipt_id": "019502a4-7ea3-7d50-c3f6-7a0b5d4e3f2c",
  "receipt_version": "0.1.0",
  "timestamp": "2026-03-15T14:32:09.789Z",
  "duration_us": 34,
  "action": {
    "type": "file_write",
    "target": "/src/config.js",
    "content_hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    "content_size": 42,
    "args_size": null,
    "origin": null,
    "posture_input": null
  },
  "decision": {
    "outcome": "deny",
    "matched_rule": "rules.secret_patterns.patterns.aws_access_key",
    "reason": "content matched secret pattern 'aws_access_key'"
  },
  "rule_trace": [
    {
      "rule_block": "forbidden_paths",
      "rule_path": "rules.forbidden_paths",
      "enabled": true,
      "evaluated": true,
      "outcome": "allow",
      "reason": "path did not match any forbidden pattern",
      "match_detail": null
    },
    {
      "rule_block": "secret_patterns",
      "rule_path": "rules.secret_patterns",
      "enabled": true,
      "evaluated": true,
      "outcome": "deny",
      "reason": "content matched secret pattern 'aws_access_key'",
      "match_detail": {
        "pattern_index": 0,
        "pattern_value": "aws_access_key",
        "matched_target": "[REDACTED]"
      }
    }
  ],
  "detection_trace": null,
  "policy": {
    "name": "ai-agent",
    "hushspec": "0.1.0",
    "content_hash": "7d3a1e48b2c0f5d9a6e8b4c1d3f2a5e7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
    "extends_chain": []
  },
  "origin_profile": null,
  "posture": null,
  "warnings": [],
  "signature": null
}
```

### 9.4 Full Receipt: Deny Decision with Policy Chain and Origin Profile

A `file_write` action denied by a child policy that extends a base policy, with origin-aware evaluation selecting a Slack DM profile.

```json
{
  "receipt_id": "019502a4-9fb4-7e61-d4a7-8b1c6e5f4a3d",
  "receipt_version": "0.1.0",
  "timestamp": "2026-03-15T14:32:10.012Z",
  "duration_us": 52,
  "action": {
    "type": "file_write",
    "target": "/etc/shadow",
    "content_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "content_size": 1024,
    "args_size": null,
    "origin": {
      "provider": "slack",
      "tenant_id": "T12345678",
      "space_id": "D98765432",
      "space_type": "dm",
      "visibility": "private",
      "external_participants": false,
      "tags": ["engineering"],
      "sensitivity": "high",
      "actor_role": "developer"
    },
    "posture_input": {
      "current": "standard",
      "signal": null
    }
  },
  "decision": {
    "outcome": "deny",
    "matched_rule": "rules.forbidden_paths.patterns",
    "reason": "path matched a forbidden pattern"
  },
  "rule_trace": [
    {
      "rule_block": "forbidden_paths",
      "rule_path": "rules.forbidden_paths",
      "enabled": true,
      "evaluated": true,
      "outcome": "deny",
      "reason": "path matched a forbidden pattern",
      "match_detail": {
        "pattern_index": null,
        "pattern_value": "/etc/shadow",
        "matched_target": "/etc/shadow"
      }
    }
  ],
  "detection_trace": null,
  "policy": {
    "name": "production-slack-policy",
    "hushspec": "0.1.0",
    "content_hash": "f47ac10b58cc4372a5670e02b2c3d479e3b0c44298fc1c149afbf4c8996fb924",
    "extends_chain": [
      {
        "source": "/etc/hushspec/base-policy.yaml",
        "name": "default",
        "hash": "7d3a1e48b2c0f5d9a6e8b4c1d3f2a5e7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4"
      },
      {
        "source": "/etc/hushspec/slack-policy.yaml",
        "name": "production-slack-policy",
        "hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
      }
    ]
  },
  "origin_profile": {
    "id": "slack-dm",
    "match_score": 18
  },
  "posture": {
    "current": "standard",
    "next": "standard"
  },
  "warnings": [],
  "signature": {
    "algorithm": "hmac-sha256",
    "key_id": "prod-signing-key-2026-q1",
    "value": "dGhpcyBpcyBhIGJhc2U2NC1lbmNvZGVkIEhNQUMgc2lnbmF0dXJl"
  }
}
```

### 9.5 Full Receipt: Deny Decision (Posture Capability Guard)

A `tool_call` action denied because the agent is in `locked` posture, which has no capabilities. Demonstrates posture capability guard appearing as the first rule_trace entry.

```json
{
  "receipt_id": "019502a4-b1c5-7f72-e5b8-9c2d7f6a5b4e",
  "receipt_version": "0.1.0",
  "timestamp": "2026-03-15T14:32:11.345Z",
  "duration_us": 4,
  "action": {
    "type": "tool_call",
    "target": "read_file",
    "content_hash": null,
    "content_size": null,
    "args_size": 64,
    "origin": null,
    "posture_input": {
      "current": "locked",
      "signal": "critical_violation"
    }
  },
  "decision": {
    "outcome": "deny",
    "matched_rule": "extensions.posture.states.locked.capabilities",
    "reason": "posture 'locked' does not allow capability 'tool_call'"
  },
  "rule_trace": [
    {
      "rule_block": "posture_capability",
      "rule_path": "extensions.posture.states.locked.capabilities",
      "enabled": true,
      "evaluated": true,
      "outcome": "deny",
      "reason": "posture 'locked' does not allow capability 'tool_call'",
      "match_detail": null
    },
    {
      "rule_block": "tool_access",
      "rule_path": "rules.tool_access",
      "enabled": true,
      "evaluated": false,
      "outcome": "skip",
      "reason": "short-circuited by prior deny",
      "match_detail": null
    }
  ],
  "detection_trace": null,
  "policy": {
    "name": "posture-aware-policy",
    "hushspec": "0.1.0",
    "content_hash": "2c5d8f1a3b4e6d7c9a0b1e2f3d4c5a6b7e8f9d0c1a2b3e4f5d6c7a8b9e0f1a2b",
    "extends_chain": []
  },
  "origin_profile": null,
  "posture": {
    "current": "locked",
    "next": "locked",
    "budget_state": null
  },
  "warnings": [],
  "signature": null
}
```

### 9.6 Full Receipt: Deny Decision (Detection Extension - Jailbreak)

A `tool_call` action denied because the detection extension identified a jailbreak attempt in the content. Demonstrates the `detection_trace` array with a score-based denial.

```json
{
  "receipt_id": "019502a4-c2d6-7083-f6c9-0d3e8a7b6c5f",
  "receipt_version": "0.1.0",
  "timestamp": "2026-03-15T14:32:12.678Z",
  "duration_us": 2340,
  "action": {
    "type": "tool_call",
    "target": "execute_prompt",
    "content_hash": "4a2b3c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f",
    "content_size": 4096,
    "args_size": 4200,
    "origin": {
      "provider": "slack",
      "tenant_id": "T12345678",
      "space_id": "C98765432",
      "space_type": "channel",
      "visibility": "internal",
      "external_participants": false,
      "tags": [],
      "sensitivity": null,
      "actor_role": "member"
    },
    "posture_input": {
      "current": "standard",
      "signal": null
    }
  },
  "decision": {
    "outcome": "deny",
    "matched_rule": "extensions.detection.jailbreak",
    "reason": "jailbreak score 85 exceeds block_threshold 80"
  },
  "rule_trace": [
    {
      "rule_block": "tool_access",
      "rule_path": "rules.tool_access",
      "enabled": true,
      "evaluated": true,
      "outcome": "allow",
      "reason": "tool is explicitly allowed",
      "match_detail": {
        "pattern_index": 0,
        "pattern_value": "execute_prompt",
        "matched_target": "execute_prompt"
      }
    }
  ],
  "detection_trace": [
    {
      "detector": "prompt_injection",
      "enabled": true,
      "score": null,
      "level": "suspicious",
      "outcome": "warn",
      "reason": "prompt injection detection level 'suspicious' meets warn_at_or_above threshold",
      "top_matches": null
    },
    {
      "detector": "jailbreak",
      "enabled": true,
      "score": 85,
      "level": "high",
      "outcome": "deny",
      "reason": "jailbreak score 85 exceeds block_threshold 80",
      "top_matches": null
    },
    {
      "detector": "threat_intel",
      "enabled": false,
      "score": null,
      "level": null,
      "outcome": "skip",
      "reason": "detector disabled",
      "top_matches": null
    }
  ],
  "policy": {
    "name": "detection-enabled-policy",
    "hushspec": "0.1.0",
    "content_hash": "8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
    "extends_chain": []
  },
  "origin_profile": null,
  "posture": {
    "current": "standard",
    "next": "standard",
    "budget_state": {
      "tool_calls": {
        "limit": 10,
        "consumed": 3,
        "remaining": 7
      }
    }
  },
  "warnings": [],
  "signature": null
}
```

### 9.7 Full Receipt: Allow Decision with Posture Budget Tracking

A `tool_call` action allowed with budget consumption visible in the receipt.

```json
{
  "receipt_id": "019502a4-d3e7-7194-a7da-1e4f9b8c7d6e",
  "receipt_version": "0.1.0",
  "timestamp": "2026-03-15T14:32:13.901Z",
  "duration_us": 9,
  "action": {
    "type": "tool_call",
    "target": "read_file",
    "content_hash": null,
    "content_size": null,
    "args_size": 128,
    "origin": null,
    "posture_input": {
      "current": "standard",
      "signal": null
    }
  },
  "decision": {
    "outcome": "allow",
    "matched_rule": "rules.tool_access.allow",
    "reason": "tool is explicitly allowed"
  },
  "rule_trace": [
    {
      "rule_block": "posture_capability",
      "rule_path": "extensions.posture.states.standard.capabilities",
      "enabled": true,
      "evaluated": true,
      "outcome": "allow",
      "reason": "posture 'standard' includes capability 'tool_call'",
      "match_detail": null
    },
    {
      "rule_block": "tool_access",
      "rule_path": "rules.tool_access",
      "enabled": true,
      "evaluated": true,
      "outcome": "allow",
      "reason": "tool is explicitly allowed",
      "match_detail": {
        "pattern_index": 0,
        "pattern_value": "read_file",
        "matched_target": "read_file"
      }
    }
  ],
  "detection_trace": null,
  "policy": {
    "name": "posture-aware-policy",
    "hushspec": "0.1.0",
    "content_hash": "2c5d8f1a3b4e6d7c9a0b1e2f3d4c5a6b7e8f9d0c1a2b3e4f5d6c7a8b9e0f1a2b",
    "extends_chain": []
  },
  "origin_profile": null,
  "posture": {
    "current": "standard",
    "next": "standard",
    "budget_state": {
      "tool_calls": {
        "limit": 10,
        "consumed": 8,
        "remaining": 2
      }
    }
  },
  "warnings": [],
  "signature": null
}
```

### 9.8 Example Telemetry Dashboard Queries

#### Grafana / PromQL: Deny Rate Over Time

```promql
# Deny rate as a percentage of all evaluations, 5-minute window
sum(rate(hushspec_evaluate_total{decision="deny"}[5m]))
/
sum(rate(hushspec_evaluate_total[5m]))
* 100
```

#### Grafana / PromQL: P99 Evaluation Latency by Action Type

```promql
histogram_quantile(0.99,
  sum(rate(hushspec_evaluate_duration_us_bucket[5m])) by (le, action_type)
)
```

#### Grafana / PromQL: Alert on Sudden Deny Spike

```promql
# Alert when deny rate exceeds 10% (compared to 1% baseline)
ALERT HushSpecHighDenyRate
  IF (
    sum(rate(hushspec_evaluate_total{decision="deny"}[5m]))
    /
    sum(rate(hushspec_evaluate_total[5m]))
  ) > 0.10
  FOR 5m
  LABELS { severity = "warning" }
  ANNOTATIONS {
    summary = "HushSpec deny rate exceeds 10%",
    description = "The deny rate has exceeded 10% for 5 minutes. This may indicate policy misconfiguration or an attack."
  }
```

#### Elasticsearch / Kibana: All Denials for a Specific Agent

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "receipt.decision.outcome": "deny" } },
        { "term": { "metadata.agent_id": "agent-prod-7b3c" } },
        { "range": { "receipt.timestamp": { "gte": "2026-03-15T00:00:00Z" } } }
      ]
    }
  },
  "sort": [{ "receipt.timestamp": "desc" }],
  "size": 100
}
```

#### Splunk: Top Denied Tools in the Last 24 Hours

```spl
index=hushspec_audit log_level="DENY"
| where receipt.action.type="tool_call"
| stats count by receipt.action.target
| sort -count
| head 20
```

### 9.9 Example SIEM Integration

#### Splunk HTTP Event Collector (HEC)

```bash
# Sink configuration (conceptual)
{
  "sink": "splunk_hec",
  "endpoint": "https://splunk.internal:8088/services/collector/event",
  "token": "${SPLUNK_HEC_TOKEN}",
  "index": "hushspec_audit",
  "sourcetype": "hushspec:decision",
  "batch_size": 100,
  "flush_interval_ms": 5000,
  "tls": {
    "verify": true,
    "ca_cert": "/etc/ssl/certs/internal-ca.pem"
  }
}
```

Each receipt is sent as a Splunk event:

```json
{
  "time": 1710509527.123,
  "host": "agent-host-01",
  "source": "hushspec",
  "sourcetype": "hushspec:decision",
  "index": "hushspec_audit",
  "event": {
    "log_version": "0.1.0",
    "log_level": "DECISION",
    "service": "hushspec",
    "receipt": { "...full receipt..." },
    "metadata": {
      "engine_name": "aegis",
      "engine_version": "2.1.0",
      "session_id": "sess-abc123",
      "environment": "production"
    }
  }
}
```

#### AWS CloudWatch Integration

Decision logs written as JSON Lines to stdout in a container environment are automatically captured by CloudWatch Logs. The structured JSON enables CloudWatch Logs Insights queries:

```
# CloudWatch Logs Insights query
fields @timestamp, receipt.decision.outcome, receipt.action.type, receipt.action.target
| filter receipt.decision.outcome = "deny"
| sort @timestamp desc
| limit 50
```

#### Datadog Integration

Datadog's log pipeline can parse HushSpec decision logs and extract facets:

```yaml
# Datadog log pipeline processing rule
- type: pipeline
  name: hushspec
  filter:
    query: "service:hushspec"
  processors:
    - type: attribute-remapper
      name: Map receipt_id to event ID
      sources: ["receipt.receipt_id"]
      target: "evt.id"
    - type: attribute-remapper
      name: Map decision to status
      sources: ["receipt.decision.outcome"]
      target: "status"
    - type: category-processor
      name: Set severity
      categories:
        - filter: "@receipt.decision.outcome:deny"
          name: "ERROR"
        - filter: "@receipt.decision.outcome:warn"
          name: "WARN"
        - filter: "@receipt.decision.outcome:allow"
          name: "INFO"
      target: "level"
```

---

## Appendix A: Interaction with Existing Specification Sections

This RFC introduces new concepts but does not modify existing specification semantics. The following specification sections are affected:

| Section | Change |
|---------|--------|
| Section 6 (Decision Types) | Add a note that decision receipts are the normative format for recording decisions. |
| Section 8 (Conformance Levels) | Add **Level 4: Auditor** conformance level. |
| Section 9 (Extensions) | Add a note under each extension (posture, origins, detection) that Level 4 implementations MUST include extension evaluation results in receipts when the extension is configured. Posture: budget_state in PostureResult, posture_capability in rule_trace. Origins: origin_profile and match_score. Detection: detection_trace with per-detector scores and outcomes. |

The `EvaluationResult` type is unchanged. `DecisionReceipt` is an enriched superset that wraps the evaluation result with audit context.

## Appendix B: Open Questions

1. **Should receipt generation be a specification requirement or a recommendation?** This RFC proposes a new conformance level (Level 4: Auditor), making it optional but standardized. An alternative is to make receipt generation REQUIRED for Level 3 (Evaluator) implementations.

2. **Should the receipt schema version be independent of the HushSpec version?** This RFC ties receipt version 0.1.0 to HushSpec 0.1.0. Future receipt format changes could be versioned independently.

3. **Should the specification define a standard receipt storage API?** This RFC defines the receipt format and the sink interface but does not specify a query API. A future RFC could define a standard query interface for receipt retrieval.

4. **How should receipts handle batch evaluation?** Some engines evaluate multiple actions in a single call (e.g., a file write that also triggers secret scanning and patch integrity checks). The current design generates one receipt per `evaluate()` call. Batch-aware receipt grouping could be a future extension.

5. **Should AUDIT summaries be part of the core specification or an engine concern?** This RFC includes them in the log specification. They could be moved to an informational appendix if the core specification wants to remain minimal.

6. **Should detection_trace be merged into rule_trace?** This RFC separates detection evaluations into a dedicated `detection_trace` array because detectors produce continuous scores (0-100, 0.0-1.0) rather than discrete pattern matches, and may invoke external services with significant latency. An alternative is to merge them into `rule_trace` with extended `match_detail` fields, keeping a single evaluation trace.

7. **How should receipt format handle custom/engine-specific detectors?** The current `detector` enum is limited to the three detection types defined in the detection extension schema. Engines may implement additional detectors (e.g., PII detection, toxicity screening). A future version could allow a `"custom"` detector type with an engine-defined `detector_name` field.

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Receipt** | A self-contained JSON document recording a single policy evaluation decision, its inputs, and its audit context. |
| **Sink** | A destination for decision receipts: file, stdout, OTLP endpoint, database, SIEM, or callback function. |
| **Rule trace** | The ordered sequence of rule block evaluations that contributed to a decision, including posture capability guards. |
| **Detection trace** | The ordered sequence of detection extension evaluations (prompt injection, jailbreak, threat intel) that contributed to a decision. Separate from the rule trace because detectors produce continuous scores rather than discrete pattern matches. |
| **Canonical JSON** | A deterministic JSON serialization with sorted keys and no extraneous whitespace, used for signature computation. |
| **Content hash** | A SHA-256 hex digest of file content or policy document content, used to reference content without including it. |
| **Policy context** | Precomputed metadata about a resolved policy document (hash, name, extends chain) that is reused across evaluations. |
| **Budget state** | A snapshot of posture budget consumption (limit, consumed, remaining) attached to a receipt when the posture extension defines budgets for the active state. |
| **Posture capability guard** | A pre-evaluation check that verifies the current posture state includes the capability required for the action type. Represented as a synthetic `posture_capability` entry in the rule trace. |
| **Short-circuit** | When a rule block produces a deny, subsequent rule blocks for the same action are not evaluated. Skipped rule blocks appear in the rule trace with `evaluated: false` and `outcome: "skip"`. |
