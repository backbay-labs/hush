# HushSpec Detection Extension Specification

**Version:** 1.0.0
**Status:** Stable
**Date:** 2026-09-15
**Companion to:** HushSpec Core v0.1.0

---

## 1. Overview

The Detection extension provides threshold configuration for content analysis guards: prompt injection detection, jailbreak detection, and threat intelligence screening. The actual detection algorithms are engine-specific -- this extension only declares thresholds, enablement flags, and resource limits.

Detection is declared under `extensions.detection` in a HushSpec document. When a conformant engine supports the detection extension, the declared thresholds govern when detection findings produce warnings or denials. Engines that do not support a particular detection capability SHOULD ignore the corresponding section and SHOULD document which detection capabilities they support.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2 Design Principle

This extension separates POLICY (thresholds, limits) from IMPLEMENTATION (algorithms, models). A HushSpec document with detection thresholds is portable across any engine that supports the detection extension, but the detection quality -- false positive rates, evasion resistance, latency -- depends entirely on the engine's implementation.

---

## 2. Schema

The detection extension is declared under `extensions.detection`:

```yaml
extensions:
  detection:
    prompt_injection:              # OPTIONAL. Prompt injection detection config.
      enabled: <bool>              # OPTIONAL. Default: true.
      warn_at_or_above: <level>    # OPTIONAL. Default: "suspicious".
      block_at_or_above: <level>   # OPTIONAL. Default: "high".
      max_scan_bytes: <integer>    # OPTIONAL. Default: 200000.
    jailbreak:                     # OPTIONAL. Jailbreak detection config.
      enabled: <bool>              # OPTIONAL. Default: true.
      block_threshold: <integer>   # OPTIONAL. Default: 80. Range: 0-100.
      warn_threshold: <integer>    # OPTIONAL. Default: 50. Range: 0-100.
      max_input_bytes: <integer>   # OPTIONAL. Default: 200000.
    threat_intel:                   # OPTIONAL. Threat intelligence screening.
      enabled: <bool>              # OPTIONAL. Default: false.
      pattern_db: <string>         # OPTIONAL. Path or "builtin:<name>".
      similarity_threshold: <number> # OPTIONAL. Default: 0.7. Range: 0.0-1.0.
      top_k: <integer>            # OPTIONAL. Default: 5.
```

All three subsections are independently optional. An empty `detection` object is valid and applies engine defaults for all subsections.

---

## 3. Prompt Injection Detection

The `prompt_injection` section configures detection of prompt injection attempts in agent inputs.

### 3.1 Fields

| Field               | Type    | Default        | Description                                          |
|---------------------|---------|----------------|------------------------------------------------------|
| `enabled`           | boolean | `true`         | Whether prompt injection detection is active.        |
| `warn_at_or_above`  | string  | `"suspicious"` | Minimum level that produces a warning.               |
| `block_at_or_above` | string  | `"high"`       | Minimum level that produces a denial.                |
| `max_scan_bytes`    | integer | `200000`       | Maximum input size to scan, in bytes.                |
| `heuristics`        | object  | --             | Configuration of the normative heuristic detector (Section 3.5): `enabled` (boolean, default `true`) and `min_score` (integer 0-100, default `0`). |

### 3.2 Detection Levels

Detection levels form an ordered severity scale:

| Level        | Ordinal | Description                                      |
|--------------|---------|--------------------------------------------------|
| `safe`       | 0       | No injection detected.                           |
| `suspicious` | 1       | Possible injection, low confidence.              |
| `high`       | 2       | Probable injection, high confidence.             |
| `critical`   | 3       | Definite injection, very high confidence.        |

The ordering is: `safe` < `suspicious` < `high` < `critical`.

### 3.3 Threshold Semantics

When the engine's detection algorithm produces a level for a given input:
- If the level is >= `block_at_or_above`, the decision is **deny**.
- If the level is >= `warn_at_or_above` but < `block_at_or_above`, the decision is **warn**.
- Otherwise, the decision is **allow**.

### 3.4 Scan Limits

Inputs exceeding `max_scan_bytes` are truncated to that length before scanning. Engines MAY choose to deny inputs exceeding the scan limit instead of truncating; this behavior is engine-specific and MUST be documented.

### 3.5 Heuristic Detector (`heuristic_injection@1`)

Section 7 allows an engine to bring its own prompt-injection model. This section defines one detector every conformant engine MUST implement exactly, so that a policy's thresholds mean the same thing everywhere and a receipt's `detection_trace` entry for `heuristic_injection@1` is reproducible by an auditor. It runs alongside whatever other prompt-injection detector the engine provides (the reference engine's `regex_injection@1`); each detector is scored against the same `warn_at_or_above` / `block_at_or_above` levels and each records its own trace entry.

#### 3.5.1 Configuration

`prompt_injection.heuristics.enabled` (default `true`) turns the detector off when `false`; it then records no trace entry. `prompt_injection.heuristics.min_score` (integer 0-100, default `0`) is a floor: an integer score below it is reported as `0` (no signal, no families). The detector runs only when `prompt_injection.enabled` is not `false` and the action carries content.

#### 3.5.2 Preprocessing

1. Truncate the content to `max_scan_bytes` bytes at a UTF-8 character boundary (Section 3.4).
2. Normalize the text to Unicode NFC.
3. Measure the `structural_uppercase` signal on the NFC text (before case folding): let `letters` be the number of ASCII letters and `upper` the number of ASCII uppercase letters; the signal is present when `letters >= 40` and `upper * 100 >= letters * 60`. Every ASCII letter counts, including letters inside encoded runs, so an uppercase-heavy base64 payload contributes both `encoded_payload` and `structural_uppercase`.
4. Fold ASCII letters to lowercase (only `A-Z`; no Unicode case folding).
5. Match every family's patterns against the folded text with unanchored search under the HushSpec regex profile (Core Section 3.14.3). The patterns below are the normative table, verbatim.

#### 3.5.3 Signal Families

| Family                   | Weight | Patterns (regex profile, matched against the folded text) |
|--------------------------|-------:|-----------------------------------------------------------|
| `instruction_override`   | 40     | `ignore (all \|any \|the \|every \|your )?(previous\|prior\|above\|earlier\|preceding) (instructions?\|prompts?\|rules\|guidance)` · `disregard (all \|any \|the \|your )?(system\|previous\|prior\|earlier\|above) (prompts?\|instructions?\|rules)` · `forget (all \|everything )?(you were told\|your instructions\|the instructions\|previous instructions\|prior instructions)` · `(new\|updated\|revised\|override) instructions?[ \t]*:` |
| `role_switch`            | 30     | `you are now (a\|an\|the\|my\|in) ` · `act as (a\|an\|the\|my\|if you were) ` · `pretend (to be\|you are\|that you are\|you have) ` · `from now on,? you (are\|will\|must\|should)` · `developer mode` · `do anything now` · `dan mode` |
| `delimiter_smuggling`    | 30     | `<\|(im_start\|im_end\|system\|endoftext)\|>` · `\[/?inst\]` · `##+[ \t]*(system\|assistant\|instructions)` · `(begin\|end) (system\|hidden\|secret) (prompt\|instructions)` · `<(system\|assistant)>` · `(---+\|===+\|` ``` `)[ \t]*(system\|assistant\|user)[ \t]*[:\n]` |
| `exfiltration_coercion`  | 35     | `(reveal\|print\|show\|output\|repeat\|display\|dump\|leak\|expose) (me )?(all )?(of )?(the \|your )?(hidden \|initial \|original \|secret \|system \|confidential \|full )?(system prompt\|prompt\|instructions\|rules\|configuration\|guidelines)` · `(send\|post\|upload\|exfiltrate\|forward) [^\n]{0,40} (to\|at) https?://` · `what (is\|are\|were) your (system prompt\|initial instructions\|hidden instructions\|original instructions)` |
| `encoded_payload`        | 15     | `[a-z0-9+/]{40,}={0,2}` · `(\\u[0-9a-f]{4}){4,}` · `(%[0-9a-f]{2}){8,}` |
| `structural_punctuation` | 10     | `[!?]{4,}` |
| `structural_uppercase`   | 10     | Computed in step 3 of Section 3.5.2, not a pattern. |

The machine-readable copy of this table is `HEURISTIC_FAMILIES` in the reference implementation (`crates/hushspec/src/detection.rs`); the two MUST stay identical, and every pattern MUST compile under the regex profile.

#### 3.5.4 Scoring

- A family contributes its weight **once** when any of its patterns matches (or, for `structural_uppercase`, when the signal is present), regardless of how many patterns or occurrences match.
- The integer score is the sum of contributing weights, clamped to `100`.
- If the integer score is below `heuristics.min_score`, it is reported as `0` with no contributing families.
- The receipt's `detection_trace` entry carries `detector_id` `heuristic_injection@1`, `category` `prompt_injection`, and `score` = integer score divided by 100 (so `40` is recorded as `0.4`); `level` follows the floors of Section 3.2 as applied to normalized scores (`0` → `none`, below `0.25` → `low`, then `suspicious` / `high` / `critical` at `0.25` / `0.5` / `0.75`), and `matched` is true when the score reached `warn_at_or_above`.
- Threshold semantics are those of Section 3.3, applied to each prompt-injection detector independently; the strictest contribution across detectors escalates the decision, and detection never weakens a policy decision.

Integer arithmetic throughout: no floating-point accumulation, so the score is bit-identical across languages.

#### 3.5.5 Non-goals

Multi-turn and crescendo attacks -- injection assembled across several messages -- are out of scope for this detector and for this specification version: detecting them requires conversation state, and HushSpec evaluates one action at a time. Engines MAY layer stateful detectors on top through the detector registry; their scores are engine-specific (Section 7).

#### 3.5.6 Test Vectors

`fixtures/detection/evaluation/heuristic-injection.test.yaml` (scores at family boundaries, clamping, the truncation edge, case folding, benign text scoring `0`, a weak signal below every threshold), `fixtures/detection/evaluation/heuristic-injection-min-score.test.yaml`, and `fixtures/detection/evaluation/heuristic-injection-disabled.test.yaml`, each pinning the exact `detection_trace`.

---

## 4. Jailbreak Detection

The `jailbreak` section configures detection of jailbreak attempts (prompts designed to bypass the model's safety training).

### 4.1 Fields

| Field              | Type    | Default  | Description                                           |
|--------------------|---------|----------|-------------------------------------------------------|
| `enabled`          | boolean | `true`   | Whether jailbreak detection is active.                |
| `block_threshold`  | integer | `80`     | Risk score at or above which the input is denied.     |
| `warn_threshold`   | integer | `50`     | Risk score at or above which a warning is produced.   |
| `max_input_bytes`  | integer | `200000` | Maximum input size to scan, in bytes.                 |

### 4.2 Risk Score

The risk score is an integer in the range 0 to 100 inclusive, where 0 indicates no jailbreak risk and 100 indicates maximum risk. The score is produced by the engine's detection algorithm; this specification does not prescribe how the score is computed.

### 4.3 Threshold Semantics

When the engine produces a risk score for a given input:
- If the score is >= `block_threshold`, the decision is **deny**.
- If the score is >= `warn_threshold` but < `block_threshold`, the decision is **warn**.
- Otherwise, the decision is **allow**.

### 4.4 Scan Limits

The same truncation behavior as prompt injection (Section 3.4) applies, using `max_input_bytes`.

---

## 5. Threat Intelligence Screening

The `threat_intel` section configures threat intelligence pattern matching, where inputs are compared against a database of known threat patterns using similarity scoring.

### 5.1 Fields

| Field                  | Type   | Default | Description                                                 |
|------------------------|--------|---------|-------------------------------------------------------------|
| `enabled`              | boolean| `false` | Whether threat intelligence screening is active.            |
| `pattern_db`           | string | --      | Path to pattern database or `"builtin:<name>"`.             |
| `similarity_threshold` | number | `0.7`   | Minimum similarity score (0.0-1.0) to consider a match.    |
| `top_k`                | integer| `5`     | Number of top matches to return in evidence.                |

### 5.2 Pattern Database

The `pattern_db` field specifies the source of threat patterns:
- **File path:** A relative or absolute path to a JSON file containing pattern entries. Path resolution is engine-specific.
- **Built-in prefix:** A string starting with `"builtin:"` references an engine-bundled pattern database (e.g., `"builtin:s2bench-v1"`). Available built-in databases are engine-specific.

If `enabled` is `true` and `pattern_db` is absent, the engine SHOULD use its default pattern database if one exists, or SHOULD produce a warning and treat the section as disabled.

### 5.3 Similarity Threshold

The `similarity_threshold` value is a floating-point number between 0.0 and 1.0 inclusive. It represents the minimum similarity score (e.g., cosine similarity of embeddings) required for a pattern match to be considered a finding. Lower thresholds produce more matches (higher recall, lower precision); higher thresholds produce fewer matches (lower recall, higher precision).

The similarity computation method (cosine similarity, Jaccard index, edit distance normalization, etc.) is engine-specific.

### 5.4 Top K

The `top_k` value controls how many of the highest-scoring matches are included in the evaluation evidence. This does not affect the deny/allow decision -- it only controls the richness of the audit trail.

### 5.5 Decision Semantics

Threat intelligence screening produces a **deny** if any pattern match exceeds the `similarity_threshold`. If no match exceeds the threshold, the decision is **allow**. There is no intermediate **warn** level for threat intelligence; engines that wish to support warn-level threat intelligence findings MAY do so as an engine-specific extension.

---

## 6. Validation Requirements

Conformant validators MUST enforce the following:

1. **Level enum values.** `warn_at_or_above` and `block_at_or_above` MUST each be one of `"safe"`, `"suspicious"`, `"high"`, or `"critical"`. Invalid values MUST cause document rejection.

2. **Level ordering.** `block_at_or_above` SHOULD be >= `warn_at_or_above` (using the ordinal ordering in Section 3.2). Validators SHOULD produce a warning if this constraint is violated, but MUST NOT reject the document.

3. **Threshold ordering.** `block_threshold` SHOULD be >= `warn_threshold`. Validators SHOULD produce a warning if this constraint is violated, but MUST NOT reject the document.

4. **Threshold range.** `block_threshold` and `warn_threshold` MUST be integers in the range 0 to 100 inclusive. Values outside this range MUST cause document rejection.

5. **Similarity threshold range.** `similarity_threshold` MUST be a number between 0.0 and 1.0 inclusive. Values outside this range MUST cause document rejection.

6. **Top K value.** `top_k` MUST be a positive integer (>= 1). Zero or negative values MUST cause document rejection.

7. **Byte limits.** `max_scan_bytes` and `max_input_bytes` MUST be positive integers (>= 1). Zero or negative values MUST cause document rejection.

8. **Unknown fields.** Unknown fields within detection subsection objects MUST cause document rejection.

9. **Heuristic floor.** `prompt_injection.heuristics.min_score` MUST be an integer in the range 0 to 100 inclusive. Values outside this range MUST cause document rejection.

---

## 7. Note on Portability

A HushSpec document with detection thresholds is portable across engines that support the detection extension. However:

- **Detection quality varies.** An engine using a simple regex-based prompt injection detector will produce different results than one using a fine-tuned transformer model, even with identical threshold configuration.
- **Score calibration varies.** A `block_threshold` of 80 may be conservative on one engine and aggressive on another, depending on how the engine calibrates its risk scores.
- **Not all engines support all subsections.** An engine may support prompt injection detection but not threat intelligence screening; the reference implementation registers no threat-intelligence detector, so a `threat_intel` subsection validates but produces no findings there. Engines MUST document which detection subsections they support.
- **One detector is exact.** `heuristic_injection@1` (Section 3.5) is fully specified and MUST score identically on every engine; it is the portable baseline a policy's prompt-injection thresholds can rely on.

Policy authors SHOULD test their detection thresholds against their target engine before deploying to production.

---

## 8. Merge Semantics

When a child document extends a base document that contains detection configuration, the following merge rules apply under `deep_merge` strategy:

### 8.1 Subsection Merge

Each detection subsection (`prompt_injection`, `jailbreak`, `threat_intel`) is merged independently. Within each subsection, child fields override base fields. Base fields not specified in the child are preserved.

### 8.2 Replace and Merge Strategies

Under `replace` strategy, the child's detection object entirely replaces the base's. Under `merge` strategy, the child's detection object entirely replaces the base's.

---

## 9. Detector Registry, Scores, and Traces

This section defines how detectors are identified, how their scores are normalized and mapped to levels, how thresholds turn levels into decisions, and what a receipt records. The registry `spec/registries/detectors.yaml` lists the categories and the reference implementation's detectors.

### 9.1 Detectors and Identifiers

A detector is a named scorer for one category. Its identifier is `<name>@<version>` (Grammars Section 11); the version suffix changes whenever the detector's scoring changes, so a receipt names exactly the behavior that produced a score. The reference implementation registers:

| Identifier | Category | Scoring |
|---|---|---|
| `regex_injection@1` | `prompt_injection` | Weighted phrase patterns; the weights are engine-defined. |
| `heuristic_injection@1` | `prompt_injection` | Section 3.5; fully specified, identical on every engine. |
| `regex_jailbreak@1` | `jailbreak` | Weighted phrase patterns; the weights are engine-defined. |
| `regex_exfiltration@1` | `data_exfiltration` | Registered; see Section 9.2. |

An engine MAY register further detectors under its own identifiers and MUST document their category and scoring. Every prompt-injection detector registered for a policy runs against the same truncated input and produces its own trace entry.

### 9.2 Categories

The categories are `prompt_injection` (Section 3), `jailbreak` (Section 4), and `data_exfiltration`. The `data_exfiltration` category exists so that receipts and registries can name it, but this version defines no configuration subsection for it: a detector in that category is registered by the reference implementation and contributes to neither decisions nor traces. A future minor version may add the subsection.

### 9.3 Score Normalization and Levels

Every detector reports a normalized score in the closed interval [0, 1]: the regex detectors sum the weights of their matching patterns and clamp at 1; the heuristic detector reports its integer score divided by 100 (Section 3.5); a jailbreak detector's score is its risk score (Section 4.2) divided by 100. The level recorded for a score is:

| Level | Score |
|---|---|
| `none` | exactly 0 |
| `low` | greater than 0 and below 0.25 |
| `suspicious` | at least 0.25 and below 0.5 |
| `high` | at least 0.5 and below 0.75 |
| `critical` | at least 0.75 |

The prompt-injection threshold levels of Section 3.2 map onto the same floors: `suspicious` is 0.25, `high` is 0.5, and `critical` is 0.75. The threshold vocabulary is coarser than the trace scale: a score whose trace level is `none` or `low` is `safe` for threshold purposes, and the other three names coincide.

### 9.4 Thresholds and Decisions

For each detector that ran, the engine compares its score with the policy's thresholds: a prompt-injection detector's score against the floors of `block_at_or_above` and `warn_at_or_above` (Section 3.3), a jailbreak detector's score multiplied by 100 against `block_threshold` and `warn_threshold` (Section 4.3). A score at or above the block threshold contributes `deny`; at or above the warn threshold, `warn`; otherwise nothing. The trace entry's `matched` is true exactly when the detector contributed. The detection pipeline's decision is the most restrictive contribution, and it is aggregated with the rule-block decision by Core Section 6.1: detection never weakens a decision a rule block made. A decision the pipeline produced carries `matched_rule` `detection` and a reason naming the category.

### 9.5 Input Truncation

Before any detector runs, the input is truncated to the category's byte budget (`max_scan_bytes` for prompt injection, `max_input_bytes` for jailbreak) at a UTF-8 boundary, so that a multi-byte scalar value is never split. Every detector in the category scans the same truncated input.

### 9.6 Trace Entries

A receipt's `detection_trace` (Receipt Section 4.6) carries one entry per detector that ran, in registration order, of the form `{detector_id, category, score, level, matched}`. The trace is present whenever the policy has a `detection` extension, even when it is empty.

Test vectors: `fixtures/detection/evaluation/`, `fixtures/receipts/expected/detection/`.

---

## Appendix A. Example

```yaml
hushspec: "0.1.0"
name: "detection-example"

extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: "suspicious"
      block_at_or_above: "high"
      max_scan_bytes: 500000

    jailbreak:
      enabled: true
      block_threshold: 85
      warn_threshold: 60
      max_input_bytes: 300000

    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.75
      top_k: 10
```

## Appendix B. Minimal Detection Configuration

```yaml
hushspec: "0.1.0"

extensions:
  detection:
    prompt_injection:
      enabled: true
    jailbreak:
      enabled: true
```

This enables both detectors with engine defaults for all thresholds.
