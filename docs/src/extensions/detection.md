# Detection Extension

The full normative specification is at [`spec/hushspec-detection.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-detection.md).

## Overview

The Detection extension configures thresholds for content analysis: prompt injection detection, jailbreak detection, and threat intelligence screening. `heuristic_injection@1` is fully specified and portable. Other registered detectors can use engine-specific algorithms and calibration; the distinction matters when interpreting a receipt.

Detection is declared under `extensions.detection` in a HushSpec document.

## Key Concepts

- **Prompt injection** detection uses a 4-level severity scale: `safe` < `suspicious` < `high` < `critical`. Thresholds control when findings produce warnings vs. denials.
- **Jailbreak** detection uses a 0-100 risk score. Separate `warn_threshold` and `block_threshold` values control decisions.
- **Threat intelligence** screening compares inputs against a pattern database using similarity scoring. Matches above `similarity_threshold` produce denials.

## Example

```yaml
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: "suspicious"
      block_at_or_above: "high"
      max_scan_bytes: 500000
      heuristics:          # the normative heuristic_injection@1 detector (spec 3.5)
        enabled: true
        min_score: 0

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

## Portability Note

`heuristic_injection@1` must produce identical scores on conformant engines.
Other detectors' quality and calibration are engine-specific. A jailbreak
`block_threshold` of 80 may be conservative on one engine and aggressive on
another. Test those thresholds against your target engine and retain detector
IDs in receipts. See [detection sections 3.5 and 7](../../../spec/hushspec-detection.md#35-heuristic-detector-heuristic_injection1).

## Minimal Configuration

Enable detection with engine defaults:

```yaml
extensions:
  detection:
    prompt_injection:
      enabled: true
    jailbreak:
      enabled: true
```

## Fields and Thresholds

The [complete field tables](../../../spec/hushspec-detection.md#2-schema) cover
scan bounds, prompt-injection levels, jailbreak thresholds, and threat-intel
database settings. Prompt-injection thresholds use `safe`, `suspicious`, `high`,
and `critical`; normalized trace levels also include `none` and `low`.
Jailbreak scores use integers 0-100. Threat-intel similarity uses 0-1 and an
engine-defined database and similarity algorithm. `top_k` limits retrieved
matches, not the security of the database.

## Exact Heuristic Scoring

For `heuristic_injection@1`, truncate at a UTF-8 boundary, normalize to NFC,
measure uppercase on that text, then lowercase ASCII letters only. Match the
seven fixed signal families in [section 3.5.3](../../../spec/hushspec-detection.md#353-signal-families).
Each family contributes its weight once; add integer weights, clamp to 100,
then apply `min_score` (below the floor becomes zero). The uppercase signal
requires at least 40 ASCII letters with at least 60 percent uppercase.
Encoded runs count toward that uppercase measure too.

Receipts divide the integer score by 100. The level floors are 0, 0.25, 0.5,
and 0.75, with `none` at zero and `low` below 0.25. Every detector is compared
independently with warning/block thresholds. The strictest contribution wins
and cannot weaken a core-rule denial. A disabled heuristic emits no trace.
This single-action detector does not cover multi-turn assembled attacks.

## Calibration and Examples

Begin with the minimal fragment above and test benign and adversarial owned
content. Lower thresholds increase sensitivity; they do not establish a
false-negative bound. The earlier example uses explicit thresholds and scan
limits; the [normative appendix](../../../spec/hushspec-detection.md#appendix-a-example)
provides another full configuration. Record truncation limits when interpreting
results: content beyond the scanned prefix has not been analyzed.

## Merge Rules

`deep_merge` merges each detection subsection's supplied fields while retaining
omitted fields. `merge` replaces the supplied detection block. See
[detection section 8](../../../spec/hushspec-detection.md#8-merge-semantics).
