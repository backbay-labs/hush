from __future__ import annotations

import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    EvaluationResult,
    TracedEvaluation,
)
from hushspec.conditions import Condition, RuntimeContext
from hushspec.extensions import DetectionLevel
from hushspec.regex_profile import compile_profile_regex
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
        registry.register(HeuristicInjectionDetector())
        registry.register(RegexJailbreakDetector())
        registry.register(RegexExfiltrationDetector())
        return registry

    def detect_all(self, input_text: str) -> list[DetectionResult]:
        return [d.detect(input_text) for d in self._detectors]

    def detector_for(self, category: DetectionCategory) -> Optional[Detector]:
        """The first registered detector of *category*, if any."""
        for detector in self._detectors:
            if detector.category == category:
                return detector
        return None

    def detectors_for(self, category: DetectionCategory) -> list[Detector]:
        """Every registered detector of *category*, in registration order.

        The prompt-injection pipeline runs all of them (the regex detector and
        the normative heuristic detector), each against the category's byte
        budget and thresholds.
        """
        return [d for d in self._detectors if d.category == category]


def default_detector_registry() -> "DetectorRegistry":
    """The built-in detectors, in the order their trace entries are recorded.

    The shared singleton behind every detection-aware evaluation; the
    detectors are stateless, so one registry serves the whole process.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = DetectorRegistry.with_defaults()
    return _default_registry


_default_registry: Optional["DetectorRegistry"] = None





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
                    r"ignore[ \t\n\r\f]+(all[ \t\n\r\f]+)?(previous|prior|above)[ \t\n\r\f]+(instructions|rules|prompts)",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="new_instructions",
                regex=re.compile(
                    r"(new|updated|revised)[ \t\n\r\f]+instructions?[ \t\n\r\f]*:", re.IGNORECASE
                ),
                weight=0.3,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="system_prompt_extract",
                regex=re.compile(
                    r"(reveal|show|display|print|output)[ \t\n\r\f]+(your|the)[ \t\n\r\f]+(system[ \t\n\r\f]+)?(prompt|instructions|rules)",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="role_override",
                regex=re.compile(
                    r"you[ \t\n\r\f]+are[ \t\n\r\f]+now[ \t\n\r\f]+(a|an|the)[ \t\n\r\f]+", re.IGNORECASE
                ),
                weight=0.3,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="pretend_mode",
                regex=re.compile(
                    r"(pretend|imagine|act[ \t\n\r\f]+as[ \t\n\r\f]+if|suppose)[ \t\n\r\f]+(you|that|we)",
                    re.IGNORECASE,
                ),
                weight=0.2,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="delimiter_injection",
                regex=re.compile(
                    r"(---+|===+|```)[ \t\n\r\f]*(system|assistant|user)[ \t\n\r\f]*[:\n]",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="encoding_evasion",
                regex=re.compile(
                    r"(base64|rot13|hex|url.?encod|unicode)[ \t\n\r\f]*(decod|encod|convert)",
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


# heuristic_injection@1 -- the normative detector of detection spec 3.5


#: Name of the normative heuristic detector (``heuristic_injection@1`` once
#: the id version suffix is appended).
HEURISTIC_DETECTOR_NAME = "heuristic_injection"

#: The signal families of ``heuristic_injection@1``, verbatim from detection
#: spec 3.5.3: ``(family, weight, patterns)``. Patterns are written in the
#: HushSpec regex profile (ASCII classes, no lookaround) and matched against
#: the NFC-normalized, ASCII-case-folded input, so they are lowercase. A
#: family contributes its weight at most once; the sum is clamped to 100.
#:
#: This table and the spec's MUST stay identical; so must every SDK's copy.
HEURISTIC_FAMILIES: tuple[tuple[str, int, tuple[str, ...]], ...] = (
    (
        "instruction_override",
        40,
        (
            r"ignore (all |any |the |every |your )?(previous|prior|above|earlier|preceding) (instructions?|prompts?|rules|guidance)",
            r"disregard (all |any |the |your )?(system|previous|prior|earlier|above) (prompts?|instructions?|rules)",
            r"forget (all |everything )?(you were told|your instructions|the instructions|previous instructions|prior instructions)",
            r"(new|updated|revised|override) instructions?[ \t]*:",
        ),
    ),
    (
        "role_switch",
        30,
        (
            r"you are now (a|an|the|my|in) ",
            r"act as (a|an|the|my|if you were) ",
            r"pretend (to be|you are|that you are|you have) ",
            r"from now on,? you (are|will|must|should)",
            r"developer mode",
            r"do anything now",
            r"dan mode",
        ),
    ),
    (
        "delimiter_smuggling",
        30,
        (
            r"<\|(im_start|im_end|system|endoftext)\|>",
            r"\[/?inst\]",
            r"##+[ \t]*(system|assistant|instructions)",
            r"(begin|end) (system|hidden|secret) (prompt|instructions)",
            r"<(system|assistant)>",
            r"(---+|===+|```)[ \t]*(system|assistant|user)[ \t]*[:\n]",
        ),
    ),
    (
        "exfiltration_coercion",
        35,
        (
            r"(reveal|print|show|output|repeat|display|dump|leak|expose) (me )?(all )?(of )?(the |your )?(hidden |initial |original |secret |system |confidential |full )?(system prompt|prompt|instructions|rules|configuration|guidelines)",
            r"(send|post|upload|exfiltrate|forward) [^\n]{0,40} (to|at) https?://",
            r"what (is|are|were) your (system prompt|initial instructions|hidden instructions|original instructions)",
        ),
    ),
    (
        "encoded_payload",
        15,
        (
            r"[a-z0-9+/]{40,}={0,2}",
            r"(\\u[0-9a-f]{4}){4,}",
            r"(%[0-9a-f]{2}){8,}",
        ),
    ),
    ("structural_punctuation", 10, (r"[!?]{4,}",)),
)

#: The computed ``structural_uppercase`` family (detection spec 3.5.2 step 3):
#: weight 10 when the NFC text has at least 40 ASCII letters and at least 60%
#: of them are uppercase. Measured before case folding, since folding erases
#: it.
HEURISTIC_UPPERCASE_WEIGHT = 10
HEURISTIC_UPPERCASE_MIN_LETTERS = 40
HEURISTIC_UPPERCASE_MIN_PERCENT = 60


def _uppercase_signal(text: str) -> bool:
    """``structural_uppercase``: >= 40 ASCII letters, >= 60% uppercase."""
    letters = 0
    upper = 0
    for char in text:
        if "a" <= char <= "z":
            letters += 1
        elif "A" <= char <= "Z":
            letters += 1
            upper += 1
    if letters < HEURISTIC_UPPERCASE_MIN_LETTERS:
        return False
    return upper * 100 >= letters * HEURISTIC_UPPERCASE_MIN_PERCENT


@dataclass
class _HeuristicFamily:
    name: str
    weight: int
    patterns: list[re.Pattern[str]]


class HeuristicInjectionDetector(Detector):
    """The normative heuristic prompt-injection detector (detection spec 3.5).

    Integer arithmetic over a fixed signal table, so every conformant engine
    reproduces the score exactly: the input (already truncated to the policy's
    ``max_scan_bytes``) is NFC-normalized, the uppercase signal is measured,
    the text is ASCII-case-folded, and each family whose pattern matches adds
    its weight once. The receipt carries ``score / 100``.
    """

    def __init__(self) -> None:
        self._families = [
            _HeuristicFamily(
                name=name,
                weight=weight,
                patterns=[compile_profile_regex(pattern) for pattern in patterns],
            )
            for name, weight, patterns in HEURISTIC_FAMILIES
        ]

    @property
    def name(self) -> str:
        return HEURISTIC_DETECTOR_NAME

    @property
    def category(self) -> DetectionCategory:
        return DetectionCategory.PROMPT_INJECTION

    def integer_score(self, input_text: str) -> tuple[int, list[MatchedPattern]]:
        """The spec's integer score in ``0..=100`` and the families that fired."""
        normalized = unicodedata.normalize("NFC", input_text)
        total = 0
        matched: list[MatchedPattern] = []

        if _uppercase_signal(normalized):
            total += HEURISTIC_UPPERCASE_WEIGHT
            matched.append(
                MatchedPattern(
                    name="structural_uppercase",
                    weight=HEURISTIC_UPPERCASE_WEIGHT / 100.0,
                    matched_text=None,
                )
            )

        # ASCII case folding only: `str.lower()` would fold Unicode too, which
        # the spec does not ask for and which no other SDK does.
        folded = _ascii_lower(normalized)
        for family in self._families:
            for pattern in family.patterns:
                found = pattern.search(folded)
                if found is None:
                    continue
                total += family.weight
                matched.append(
                    MatchedPattern(
                        name=family.name,
                        weight=family.weight / 100.0,
                        matched_text=found.group(0),
                    )
                )
                break  # a family contributes its weight once

        return min(total, 100), matched

    def detect(self, input_text: str) -> DetectionResult:
        score, matched_patterns = self.integer_score(input_text)
        explanation: Optional[str] = None
        if matched_patterns:
            names = ", ".join(p.name for p in matched_patterns)
            plural = "y" if len(matched_patterns) == 1 else "ies"
            explanation = (
                f"heuristic score {score}/100 from {len(matched_patterns)} "
                f"signal famil{plural}: {names}"
            )
        return DetectionResult(
            detector_name=self.name,
            category=self.category,
            score=score / 100.0,
            matched_patterns=matched_patterns,
            explanation=explanation,
        )


_ASCII_FOLD = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)


def _ascii_lower(text: str) -> str:
    """Fold ``A-Z`` to lowercase and leave every other code point alone."""
    return text.translate(_ASCII_FOLD)


def heuristic_integer(score: float) -> int:
    """The heuristic detector's integer score recovered from its normalized
    ``score / 100`` form (exact: the normalized value is always ``n / 100``).
    """
    return max(0, round(score * 100.0))


class RegexJailbreakDetector(Detector):

    def __init__(self) -> None:
        self._patterns: list[_DetectionPattern] = [
            _DetectionPattern(
                name="jailbreak_dan",
                regex=re.compile(
                    r"(DAN|do[ \t\n\r\f]+anything[ \t\n\r\f]+now|developer[ \t\n\r\f]+mode|jailbreak)",
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
                # ASCII non-digit boundaries rather than \b, which is a
                # Unicode word boundary in some regex engines and ASCII-only
                # in others: a non-ASCII char abutting the run (e.g.
                # "café123-45-6789") would then match in some engines and not
                # in others. Explicit (?:^|[^0-9])...(?:[^0-9]|$) boundaries
                # make word-boundary semantics irrelevant. The pattern must
                # stay lookaround-free -- see is_safe_regex.
                #
                # The body uses [0-9] rather than \d for the same reason: \d
                # is Unicode-aware in some engines, so a fullwidth or
                # Arabic-indic digit run would score as an SSN. It is not one.
                regex=re.compile(r"(?:^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?:[^0-9]|$)"),
                weight=0.8,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="credit_card",
                # Explicit ASCII boundaries, as for "ssn" above and for the
                # same reason.
                regex=re.compile(
                    r"(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)"
                ),
                weight=0.8,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="email_address",
                # Explicit ASCII boundaries, as for "ssn"/"credit_card"
                # above: under a Unicode \b, a non-ASCII letter abutting the
                # address (e.g. "café user@example.com" with no space) forms
                # no boundary, so the match would depend on the engine.
                regex=re.compile(
                    r"(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"
                    r"\.[A-Za-z]{2,}(?:[^A-Za-z0-9.-]|$)"
                ),
                weight=0.3,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="api_key_pattern",
                regex=re.compile(
                    r"(api[_\-]?key|secret[_\-]?key|access[_\-]?token)[ \t\n\r\f]*[:=][ \t\n\r\f]*[^ \t\n\r\f]+",
                    re.IGNORECASE,
                ),
                weight=0.6,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="private_key",
                regex=re.compile(r"-----BEGIN[ \t\n\r\f]+(RSA[ \t\n\r\f]+)?PRIVATE[ \t\n\r\f]+KEY-----"),
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


class DetectorLevel(str, Enum):
    """The level a normalized detector score maps to in a receipt's
    ``detection_trace`` (receipt spec section 4.6).

    ``none`` is a zero score, ``low`` a non-zero score below every threshold
    floor, and the rest follow the ``DetectionLevel`` floors of the
    prompt-injection mapping (0.25 / 0.5 / 0.75), applied to every detector's
    normalized 0-1 score whatever its own threshold spelling.
    """

    NONE = "none"
    LOW = "low"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "DetectorLevel":
        if score <= 0.0:
            return cls.NONE
        if score < _LEVEL_FLOORS[DetectionLevel.SUSPICIOUS]:
            return cls.LOW
        if score < _LEVEL_FLOORS[DetectionLevel.HIGH]:
            return cls.SUSPICIOUS
        if score < _LEVEL_FLOORS[DetectionLevel.CRITICAL]:
            return cls.HIGH
        return cls.CRITICAL


@dataclass
class DetectorEvaluation:
    """One detector's contribution, recorded as it ran (receipt spec 4.6)."""

    detector_id: str
    category: DetectionCategory
    score: float
    level: DetectorLevel
    matched: bool = False


#: Version suffix appended to a built-in detector's name to form its id.
DETECTOR_ID_VERSION = "@1"


@dataclass
class TracedEvaluationWithDetection:
    """A traced evaluation with the detection pipeline folded in."""

    #: The rule-block evaluation and its recorded trace, before detection.
    traced: "TracedEvaluation"
    #: The decision callers act on (base evaluation, possibly escalated).
    evaluation: EvaluationResult
    detections: list[DetectionResult] = field(default_factory=list)
    detection_decision: Optional[Decision] = None
    #: Per-detector receipt entries in run order. ``None`` when the pipeline did
    #: not run (no ``detection:`` extension); an empty list when it ran and
    #: nothing was enabled or there was no content to scan.
    detector_trace: Optional[list[DetectorEvaluation]] = None



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

# The detectors themselves are stateless -- detect() is a pure function of its
# input string -- so `default_detector_registry()` builds them once for the
# process and every evaluation reads them from there rather than recompiling
# their patterns.

#: Detection escalation ordering: detection can only raise a decision, never
#: weaken it. Kept separate from the rule-block ranks, which start at 1.
_DECISION_RANK: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.DENY: 2,
}


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
    return compiled_policy(spec).evaluate_with_detection(action)


def evaluate_with_detection_traced(
    spec: HushSpec,
    action: EvaluationAction,
    context: Optional[RuntimeContext] = None,
    conditions: Optional[dict[str, Condition]] = None,
) -> TracedEvaluationWithDetection:
    """:func:`evaluate_with_detection` with the recorded rule trace and the
    per-detector receipt entries a receipt's ``detection_trace`` carries.

    ``detector_trace`` is ``None`` when the pipeline did not run at all (the
    policy has no ``detection:`` extension) and a list -- possibly empty --
    whenever it did, which is exactly the presence rule of receipt spec 4.6.
    """
    return compiled_policy(spec).evaluate_with_detection_traced(
        action, context, conditions
    )


_compiled_policy = None


def compiled_policy(spec: HushSpec):
    """The cached compiled form of *spec* (see :mod:`hushspec.compiled`).

    Imported lazily: :mod:`hushspec.compiled` builds on this module.
    """
    global _compiled_policy
    if _compiled_policy is None:
        from hushspec.compiled import compiled_for_spec

        _compiled_policy = compiled_for_spec
    return _compiled_policy(spec)
