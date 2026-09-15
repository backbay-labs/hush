# Detection Extension

The full normative specification is at [`spec/hushspec-detection.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-detection.md).

## Overview

The Detection extension configures thresholds for content analysis: prompt injection detection, jailbreak detection, and threat intelligence screening. This extension separates **policy** (thresholds, limits) from **implementation** (algorithms, models). The actual detection quality depends on the engine.

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

Detection thresholds are portable across engines, but detection quality is not. A `block_threshold` of 80 may be conservative on one engine and aggressive on another, depending on how risk scores are calibrated. Test thresholds against your target engine before deploying to production.

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
