from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    EvaluationResult,
    evaluate,
)
from hushspec.extensions import DetectionLevel, JailbreakDetection, PromptInjectionDetection
from hushspec.schema import HushSpec





class DetectionCategory(str, Enum):

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class MatchedPattern:
    name: str
    weight: float
    matched_text: Optional[str] = None


@dataclass
class DetectionResult:
    detector_name: str
    category: DetectionCategory
    score: float
    matched_patterns: list[MatchedPattern] = field(default_factory=list)
    explanation: Optional[str] = None





class Detector(ABC):

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def category(self) -> DetectionCategory: ...

    @abstractmethod
    def detect(self, input_text: str) -> DetectionResult: ...





class DetectorRegistry:

    def __init__(self) -> None:
        self._detectors: list[Detector] = []

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)

    @classmethod
    def with_defaults(cls) -> "DetectorRegistry":
        registry = cls()
        registry.register(RegexInjectionDetector())
        registry.register(RegexJailbreakDetector())
        registry.register(RegexExfiltrationDetector())
        return registry

    def detect_all(self, input_text: str) -> list[DetectionResult]:
        return [d.detect(input_text) for d in self._detectors]





@dataclass
class _DetectionPattern:
    name: str
    regex: re.Pattern[str]
    weight: float
    category: DetectionCategory





class RegexInjectionDetector(Detector):

    def __init__(self) -> None:
        self._patterns: list[_DetectionPattern] = [
            _DetectionPattern(
                name="ignore_instructions",
                regex=re.compile(
                    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="new_instructions",
                regex=re.compile(
                    r"(new|updated|revised)\s+instructions?\s*:", re.IGNORECASE
                ),
                weight=0.3,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="system_prompt_extract",
                regex=re.compile(
                    r"(reveal|show|display|print|output)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="role_override",
                regex=re.compile(
                    r"you\s+are\s+now\s+(a|an|the)\s+", re.IGNORECASE
                ),
                weight=0.3,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="pretend_mode",
                regex=re.compile(
                    r"(pretend|imagine|act\s+as\s+if|suppose)\s+(you|that|we)",
                    re.IGNORECASE,
                ),
                weight=0.2,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="delimiter_injection",
                regex=re.compile(
                    r"(---+|===+|```)\s*(system|assistant|user)\s*[:\n]",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="encoding_evasion",
                regex=re.compile(
                    r"(base64|rot13|hex|url.?encod|unicode)\s*(decod|encod|convert)",
                    re.IGNORECASE,
                ),
                weight=0.1,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
        ]

    @property
    def name(self) -> str:
        return "regex_injection"

    @property
    def category(self) -> DetectionCategory:
        return DetectionCategory.PROMPT_INJECTION

    def detect(self, input_text: str) -> DetectionResult:
        matched_patterns: list[MatchedPattern] = []
        total_weight = 0.0

        for pattern in self._patterns:
            m = pattern.regex.search(input_text)
            if m:
                total_weight += pattern.weight
                matched_patterns.append(
                    MatchedPattern(
                        name=pattern.name,
                        weight=pattern.weight,
                        matched_text=m.group(0),
                    )
                )

        score = min(total_weight, 1.0)

        explanation: Optional[str] = None
        if matched_patterns:
            names = ", ".join(p.name for p in matched_patterns)
            explanation = (
                f"matched {len(matched_patterns)} injection pattern(s): {names}"
            )

        return DetectionResult(
            detector_name=self.name,
            category=self.category,
            score=score,
            matched_patterns=matched_patterns,
            explanation=explanation,
        )


class RegexJailbreakDetector(Detector):

    def __init__(self) -> None:
        self._patterns: list[_DetectionPattern] = [
            _DetectionPattern(
                name="jailbreak_dan",
                regex=re.compile(
                    r"(DAN|do\s+anything\s+now|developer\s+mode|jailbreak)",
                    re.IGNORECASE,
                ),
                weight=0.5,
                category=DetectionCategory.JAILBREAK,
            ),
        ]

    @property
    def name(self) -> str:
        return "regex_jailbreak"

    @property
    def category(self) -> DetectionCategory:
        return DetectionCategory.JAILBREAK

    def detect(self, input_text: str) -> DetectionResult:
        matched_patterns: list[MatchedPattern] = []
        total_weight = 0.0

        for pattern in self._patterns:
            m = pattern.regex.search(input_text)
            if m:
                total_weight += pattern.weight
                matched_patterns.append(
                    MatchedPattern(
                        name=pattern.name,
                        weight=pattern.weight,
                        matched_text=m.group(0),
                    )
                )

        score = min(total_weight, 1.0)

        explanation: Optional[str] = None
        if matched_patterns:
            names = ", ".join(p.name for p in matched_patterns)
            explanation = (
                f"matched {len(matched_patterns)} jailbreak pattern(s): {names}"
            )

        return DetectionResult(
            detector_name=self.name,
            category=self.category,
            score=score,
            matched_patterns=matched_patterns,
            explanation=explanation,
        )





class RegexExfiltrationDetector(Detector):

    def __init__(self) -> None:
        self._patterns: list[_DetectionPattern] = [
            _DetectionPattern(
                name="ssn",
                # ASCII non-digit boundaries rather than \b: \b is a Unicode
                # word boundary in Python's re engine, so "café123-45-6789"
                # (a non-ASCII, non-digit char abutting the run) would fail
                # to match while it matches on RE2 (Go/Rust) and JS's \b
                # (both ASCII-only). Explicit (?:^|[^0-9])...(?:[^0-9]|$)
                # boundaries make ASCII-vs-Unicode word-boundary semantics
                # irrelevant and keep all four SDKs byte-identical. Must stay
                # lookaround-free (RE2 has none) -- see is_safe_regex.
                regex=re.compile(r"(?:^|[^0-9])\d{3}-\d{2}-\d{4}(?:[^0-9]|$)"),
                weight=0.8,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="credit_card",
                # Same ASCII-boundary fix as "ssn" above, and for the same
                # cross-engine \b-divergence reason.
                regex=re.compile(
                    r"(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)"
                ),
                weight=0.8,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="email_address",
                regex=re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
                ),
                weight=0.3,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="api_key_pattern",
                regex=re.compile(
                    r"(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*\S+",
                    re.IGNORECASE,
                ),
                weight=0.6,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="private_key",
                regex=re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
                weight=0.9,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
        ]

    @property
    def name(self) -> str:
        return "regex_exfiltration"

    @property
    def category(self) -> DetectionCategory:
        return DetectionCategory.DATA_EXFILTRATION

    def detect(self, input_text: str) -> DetectionResult:
        matched_patterns: list[MatchedPattern] = []
        total_weight = 0.0

        for pattern in self._patterns:
            m = pattern.regex.search(input_text)
            if m:
                total_weight += pattern.weight
                matched_patterns.append(
                    MatchedPattern(
                        name=pattern.name,
                        weight=pattern.weight,
                        matched_text=m.group(0),
                    )
                )

        score = min(total_weight, 1.0)

        explanation: Optional[str] = None
        if matched_patterns:
            names = ", ".join(p.name for p in matched_patterns)
            explanation = (
                f"matched {len(matched_patterns)} exfiltration pattern(s): {names}"
            )

        return DetectionResult(
            detector_name=self.name,
            category=self.category,
            score=score,
            matched_patterns=matched_patterns,
            explanation=explanation,
        )





@dataclass
class EvaluationWithDetection:
    evaluation: EvaluationResult
    detections: list[DetectionResult] = field(default_factory=list)
    detection_decision: Optional[Decision] = None



# evaluate_with_detection: spec-driven wiring
#
# Reads spec.extensions.detection and drives the built-in detectors from it
# (see the module docstring-style notes on each mapping below). This is the
# only supported entry point for detection-aware evaluation -- there is no
# injected registry/config parameter, because nothing in the codebase ever
# called this with anything other than a hand-built default registry, and a
# hidden knob nobody sets is worse than no knob. DetectorRegistry / Detector
# remain public for custom-detector use cases (e.g. wiring a bespoke
# threat_intel detector), just not through this function.



# Level floors for the prompt-injection mapping: a DetectionLevel names the
# *minimum* score that counts as having reached it. Must stay identical
# across all four SDKs.
_LEVEL_FLOORS: dict[DetectionLevel, float] = {
    DetectionLevel.SAFE: 0.0,
    DetectionLevel.SUSPICIOUS: 0.25,
    DetectionLevel.HIGH: 0.5,
    DetectionLevel.CRITICAL: 0.75,
}

_DEFAULT_MAX_SCAN_BYTES = 200_000
_DEFAULT_MAX_INPUT_BYTES = 200_000
_DEFAULT_PROMPT_INJECTION_WARN_AT = DetectionLevel.SUSPICIOUS
_DEFAULT_PROMPT_INJECTION_BLOCK_AT = DetectionLevel.HIGH
_DEFAULT_JAILBREAK_WARN_THRESHOLD = 50
_DEFAULT_JAILBREAK_BLOCK_THRESHOLD = 80

# Stateless singletons: detect() is a pure function of its input string, so
# the built-in detectors' compiled regex patterns are shared across every
# evaluate_with_detection() call instead of being recompiled each time.
_injection_detector = RegexInjectionDetector()
_jailbreak_detector = RegexJailbreakDetector()

_DECISION_RANK: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.DENY: 2,
}


def _stricter(left: Decision, right: Decision) -> Decision:
    return right if _DECISION_RANK[right] > _DECISION_RANK[left] else left


def _truncate_to_bytes(content: str, max_bytes: int) -> str:
    """Truncate *content* to at most *max_bytes* UTF-8 bytes.

    Slices on the UTF-8 byte boundary and discards a possibly-incomplete
    trailing multi-byte sequence (rather than raising), so truncation always
    yields a valid ``str``.
    """
    encoded = content.encode("utf-8")
    if len(encoded) <= max_bytes:
        return content
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _prompt_injection_contribution(
    config: PromptInjectionDetection, content: str
) -> tuple[DetectionResult, Optional[Decision]]:
    """Run the injection detector per the `prompt_injection:` mapping.

    Level floors: safe=0.0, suspicious=0.25, high=0.5, critical=0.75.
    ``block_at_or_above`` defaults to ``high``, ``warn_at_or_above`` defaults
    to ``suspicious``.
    """
    max_bytes = (
        config.max_scan_bytes
        if config.max_scan_bytes is not None
        else _DEFAULT_MAX_SCAN_BYTES
    )
    result = _injection_detector.detect(_truncate_to_bytes(content, max_bytes))

    block_at = (
        config.block_at_or_above
        if config.block_at_or_above is not None
        else _DEFAULT_PROMPT_INJECTION_BLOCK_AT
    )
    warn_at = (
        config.warn_at_or_above
        if config.warn_at_or_above is not None
        else _DEFAULT_PROMPT_INJECTION_WARN_AT
    )

    if result.score >= _LEVEL_FLOORS[block_at]:
        return result, Decision.DENY
    if result.score >= _LEVEL_FLOORS[warn_at]:
        return result, Decision.WARN
    return result, None


def _jailbreak_contribution(
    config: JailbreakDetection, content: str
) -> tuple[DetectionResult, Optional[Decision]]:
    """Run the jailbreak detector per the `jailbreak:` mapping.

    The detector's 0.0-1.0 score is compared directly (no rounding) against
    0-100 thresholds: ``block_threshold`` defaults to 80, ``warn_threshold``
    defaults to 50.
    """
    max_bytes = (
        config.max_input_bytes
        if config.max_input_bytes is not None
        else _DEFAULT_MAX_INPUT_BYTES
    )
    result = _jailbreak_detector.detect(_truncate_to_bytes(content, max_bytes))

    block_threshold = (
        config.block_threshold
        if config.block_threshold is not None
        else _DEFAULT_JAILBREAK_BLOCK_THRESHOLD
    )
    warn_threshold = (
        config.warn_threshold
        if config.warn_threshold is not None
        else _DEFAULT_JAILBREAK_WARN_THRESHOLD
    )
    percent = result.score * 100.0

    if percent >= block_threshold:
        return result, Decision.DENY
    if percent >= warn_threshold:
        return result, Decision.WARN
    return result, None


def evaluate_with_detection(
    spec: HushSpec, action: EvaluationAction
) -> EvaluationWithDetection:
    """Evaluate *action* against *spec*, then fold in the built-in content
    detectors configured under ``spec.extensions.detection``.

    Algorithm (see spec/ for the normative description):
      1. ``base = evaluate(spec, action)``.
      2. No ``detection`` extension -> exact no-op: return ``base`` untouched
         with no detections. Every pre-existing evaluation fixture/policy has
         no detection extension, so this must never perturb them.
      3. Empty ``action.content`` -> same no-op.
      4. Run the detectors configured in the extension (prompt_injection,
         jailbreak; threat_intel is never auto-wired -- see below), each
         contributing None/Warn/Deny. ``detection_decision`` is the
         strictest contribution across the detectors that ran.
      5. ``final_decision = strictest(base.decision, detection_decision)``,
         deny > warn > allow -- detection can only escalate, never weaken a
         policy decision.
      6. If detection escalated the decision, return a new EvaluationResult
         with ``matched_rule="detection"`` and a reason naming the category
         of the first detector (in run order) that forced the escalation;
         otherwise return ``base`` unchanged so a policy deny keeps its own
         matched_rule.
    """
    base = evaluate(spec, action)

    detection = spec.extensions.detection if spec.extensions is not None else None
    if detection is None:
        return EvaluationWithDetection(evaluation=base)

    content = action.content or ""
    if not content:
        return EvaluationWithDetection(evaluation=base)

    detections: list[DetectionResult] = []
    # (contribution, category) pairs in detector run order, used below to
    # find "the first detector that forced the escalation".
    contributions: list[tuple[Decision, str]] = []

    pi_config = detection.prompt_injection
    if pi_config is not None and pi_config.enabled is not False:
        result, contribution = _prompt_injection_contribution(pi_config, content)
        detections.append(result)
        if contribution is not None:
            contributions.append((contribution, "prompt_injection"))

    jb_config = detection.jailbreak
    if jb_config is not None and jb_config.enabled is not False:
        result, contribution = _jailbreak_contribution(jb_config, content)
        detections.append(result)
        if contribution is not None:
            contributions.append((contribution, "jailbreak"))

    # threat_intel is deliberately NOT auto-wired: the built-in engine ships
    # only regex detectors and has no pattern-db / similarity model to
    # satisfy detection.threat_intel. Satisfying it requires registering a
    # custom Detector through DetectorRegistry; no detector runs here.

    detection_decision: Optional[Decision] = None
    for contribution, _category in contributions:
        if (
            detection_decision is None
            or _DECISION_RANK[contribution] > _DECISION_RANK[detection_decision]
        ):
            detection_decision = contribution

    final_decision = (
        base.decision
        if detection_decision is None
        else _stricter(base.decision, detection_decision)
    )

    if final_decision != base.decision:
        category = next(
            cat for decision, cat in contributions if decision == detection_decision
        )
        evaluation = EvaluationResult(
            decision=final_decision,
            matched_rule="detection",
            reason=f"content flagged by {category} detection",
            origin_profile=base.origin_profile,
            posture=base.posture,
        )
    else:
        evaluation = base

    return EvaluationWithDetection(
        evaluation=evaluation,
        detections=detections,
        detection_decision=detection_decision,
    )
