"""Extension types for HushSpec: posture, origins, detection.

All types mirror the Rust and TypeScript implementations exactly, using
snake_case field names matching the YAML schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from hushspec.rules import EgressRule, ToolAccessRule


# ============================================================
# Posture Extension
# ============================================================


class TransitionTrigger(str, Enum):
    """Event that triggers a posture state transition."""

    USER_APPROVAL = "user_approval"
    USER_DENIAL = "user_denial"
    CRITICAL_VIOLATION = "critical_violation"
    ANY_VIOLATION = "any_violation"
    TIMEOUT = "timeout"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PATTERN_MATCH = "pattern_match"


@dataclass
class PostureState:
    """A named security state with capabilities and budgets."""

    description: Optional[str] = None
    capabilities: list[str] = field(default_factory=list)
    budgets: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> PostureState:
        return cls(
            description=data.get("description"),
            capabilities=list(data.get("capabilities", [])),
            budgets=dict(data.get("budgets", {})),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.description is not None:
            d["description"] = self.description
        d["capabilities"] = self.capabilities
        if self.budgets:
            d["budgets"] = self.budgets
        return d


@dataclass
class PostureTransition:
    """A transition rule between posture states.

    Uses ``from_state`` instead of ``from`` (Python keyword).
    Serialized as ``from`` in YAML.
    """

    from_state: str
    to: str
    on: TransitionTrigger
    after: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> PostureTransition:
        # PyYAML interprets bare `on:` as boolean True (YAML 1.1 spec).
        # Look up both the string key "on" and the boolean key True.
        on_value = data.get("on", data.get(True))
        return cls(
            from_state=data["from"],
            to=data["to"],
            on=TransitionTrigger(on_value),
            after=data.get("after"),
        )

    def to_dict(self) -> dict:
        d: dict = {
            "from": self.from_state,
            "to": self.to,
            "on": self.on.value,
        }
        if self.after is not None:
            d["after"] = self.after
        return d


@dataclass
class PostureExtension:
    """Declarative state machine for capability and budget management."""

    initial: str
    states: dict[str, PostureState] = field(default_factory=dict)
    transitions: list[PostureTransition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> PostureExtension:
        states = {
            name: PostureState.from_dict(state_data)
            for name, state_data in data.get("states", {}).items()
        }
        transitions = [
            PostureTransition.from_dict(t) for t in data.get("transitions", [])
        ]
        return cls(
            initial=data["initial"],
            states=states,
            transitions=transitions,
        )

    def to_dict(self) -> dict:
        return {
            "initial": self.initial,
            "states": {name: state.to_dict() for name, state in self.states.items()},
            "transitions": [t.to_dict() for t in self.transitions],
        }


# ============================================================
# Origins Extension
# ============================================================


class OriginDefaultBehavior(str, Enum):
    """Behavior when no origin profile matches."""

    DENY = "deny"
    MINIMAL_PROFILE = "minimal_profile"


@dataclass
class OriginMatch:
    """Criteria for matching an origin context to a profile."""

    provider: Optional[str] = None
    tenant_id: Optional[str] = None
    space_id: Optional[str] = None
    space_type: Optional[str] = None
    visibility: Optional[str] = None
    external_participants: Optional[bool] = None
    tags: list[str] = field(default_factory=list)
    sensitivity: Optional[str] = None
    actor_role: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> OriginMatch:
        return cls(
            provider=data.get("provider"),
            tenant_id=data.get("tenant_id"),
            space_id=data.get("space_id"),
            space_type=data.get("space_type"),
            visibility=data.get("visibility"),
            external_participants=data.get("external_participants"),
            tags=list(data.get("tags", [])),
            sensitivity=data.get("sensitivity"),
            actor_role=data.get("actor_role"),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.provider is not None:
            d["provider"] = self.provider
        if self.tenant_id is not None:
            d["tenant_id"] = self.tenant_id
        if self.space_id is not None:
            d["space_id"] = self.space_id
        if self.space_type is not None:
            d["space_type"] = self.space_type
        if self.visibility is not None:
            d["visibility"] = self.visibility
        if self.external_participants is not None:
            d["external_participants"] = self.external_participants
        if self.tags:
            d["tags"] = self.tags
        if self.sensitivity is not None:
            d["sensitivity"] = self.sensitivity
        if self.actor_role is not None:
            d["actor_role"] = self.actor_role
        return d


@dataclass
class OriginDataPolicy:
    """Data handling policy for an origin."""

    allow_external_sharing: bool = False
    redact_before_send: bool = False
    block_sensitive_outputs: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> OriginDataPolicy:
        return cls(
            allow_external_sharing=data.get("allow_external_sharing", False),
            redact_before_send=data.get("redact_before_send", False),
            block_sensitive_outputs=data.get("block_sensitive_outputs", False),
        )

    def to_dict(self) -> dict:
        return {
            "allow_external_sharing": self.allow_external_sharing,
            "redact_before_send": self.redact_before_send,
            "block_sensitive_outputs": self.block_sensitive_outputs,
        }


@dataclass
class OriginBudgets:
    """Budget limits for an origin profile."""

    tool_calls: Optional[int] = None
    egress_calls: Optional[int] = None
    shell_commands: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> OriginBudgets:
        return cls(
            tool_calls=data.get("tool_calls"),
            egress_calls=data.get("egress_calls"),
            shell_commands=data.get("shell_commands"),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.tool_calls is not None:
            d["tool_calls"] = self.tool_calls
        if self.egress_calls is not None:
            d["egress_calls"] = self.egress_calls
        if self.shell_commands is not None:
            d["shell_commands"] = self.shell_commands
        return d


@dataclass
class BridgeTarget:
    """A permitted cross-origin target."""

    provider: Optional[str] = None
    space_type: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    visibility: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> BridgeTarget:
        return cls(
            provider=data.get("provider"),
            space_type=data.get("space_type"),
            tags=list(data.get("tags", [])),
            visibility=data.get("visibility"),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.provider is not None:
            d["provider"] = self.provider
        if self.space_type is not None:
            d["space_type"] = self.space_type
        if self.tags:
            d["tags"] = self.tags
        if self.visibility is not None:
            d["visibility"] = self.visibility
        return d


@dataclass
class BridgePolicy:
    """Cross-origin transition control."""

    allow_cross_origin: bool = False
    allowed_targets: list[BridgeTarget] = field(default_factory=list)
    require_approval: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> BridgePolicy:
        targets = [
            BridgeTarget.from_dict(t) for t in data.get("allowed_targets", [])
        ]
        return cls(
            allow_cross_origin=data.get("allow_cross_origin", False),
            allowed_targets=targets,
            require_approval=data.get("require_approval", False),
        )

    def to_dict(self) -> dict:
        d: dict = {
            "allow_cross_origin": self.allow_cross_origin,
            "require_approval": self.require_approval,
        }
        if self.allowed_targets:
            d["allowed_targets"] = [t.to_dict() for t in self.allowed_targets]
        return d


@dataclass
class OriginProfile:
    """An origin profile with match rules and security overrides.

    Uses ``match_rules`` instead of ``match`` (Python keyword).
    Serialized as ``match`` in YAML.
    """

    id: str
    match_rules: Optional[OriginMatch] = None
    posture: Optional[str] = None
    tool_access: Optional[ToolAccessRule] = None
    egress: Optional[EgressRule] = None
    data: Optional[OriginDataPolicy] = None
    budgets: Optional[OriginBudgets] = None
    bridge: Optional[BridgePolicy] = None
    explanation: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> OriginProfile:
        return cls(
            id=data["id"],
            match_rules=(
                OriginMatch.from_dict(data["match"])
                if "match" in data
                else None
            ),
            posture=data.get("posture"),
            tool_access=(
                ToolAccessRule.from_dict(data["tool_access"])
                if "tool_access" in data
                else None
            ),
            egress=(
                EgressRule.from_dict(data["egress"])
                if "egress" in data
                else None
            ),
            data=(
                OriginDataPolicy.from_dict(data["data"])
                if "data" in data
                else None
            ),
            budgets=(
                OriginBudgets.from_dict(data["budgets"])
                if "budgets" in data
                else None
            ),
            bridge=(
                BridgePolicy.from_dict(data["bridge"])
                if "bridge" in data
                else None
            ),
            explanation=data.get("explanation"),
        )

    def to_dict(self) -> dict:
        d: dict = {"id": self.id}
        if self.match_rules is not None:
            d["match"] = self.match_rules.to_dict()
        if self.posture is not None:
            d["posture"] = self.posture
        if self.tool_access is not None:
            d["tool_access"] = self.tool_access.to_dict()
        if self.egress is not None:
            d["egress"] = self.egress.to_dict()
        if self.data is not None:
            d["data"] = self.data.to_dict()
        if self.budgets is not None:
            d["budgets"] = self.budgets.to_dict()
        if self.bridge is not None:
            d["bridge"] = self.bridge.to_dict()
        if self.explanation is not None:
            d["explanation"] = self.explanation
        return d


@dataclass
class OriginsExtension:
    """Origin-aware policy projection with match-based profiles."""

    default_behavior: Optional[OriginDefaultBehavior] = None
    profiles: list[OriginProfile] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> OriginsExtension:
        default_behavior = None
        if "default_behavior" in data:
            default_behavior = OriginDefaultBehavior(data["default_behavior"])
        profiles = [OriginProfile.from_dict(p) for p in data.get("profiles", [])]
        return cls(
            default_behavior=default_behavior,
            profiles=profiles,
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.default_behavior is not None:
            d["default_behavior"] = self.default_behavior.value
        if self.profiles:
            d["profiles"] = [p.to_dict() for p in self.profiles]
        return d


# ============================================================
# Detection Extension
# ============================================================


class DetectionLevel(str, Enum):
    """Ordered severity level for detection results.

    The ordering is: SAFE < SUSPICIOUS < HIGH < CRITICAL.
    """

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, DetectionLevel):
            return NotImplemented
        return _DETECTION_LEVEL_ORDER[self] < _DETECTION_LEVEL_ORDER[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, DetectionLevel):
            return NotImplemented
        return _DETECTION_LEVEL_ORDER[self] <= _DETECTION_LEVEL_ORDER[other]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, DetectionLevel):
            return NotImplemented
        return _DETECTION_LEVEL_ORDER[self] > _DETECTION_LEVEL_ORDER[other]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, DetectionLevel):
            return NotImplemented
        return _DETECTION_LEVEL_ORDER[self] >= _DETECTION_LEVEL_ORDER[other]


_DETECTION_LEVEL_ORDER = {
    DetectionLevel.SAFE: 0,
    DetectionLevel.SUSPICIOUS: 1,
    DetectionLevel.HIGH: 2,
    DetectionLevel.CRITICAL: 3,
}


@dataclass
class PromptInjectionDetection:
    """Prompt injection detection thresholds."""

    enabled: Optional[bool] = None
    warn_at_or_above: Optional[DetectionLevel] = None
    block_at_or_above: Optional[DetectionLevel] = None
    max_scan_bytes: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> PromptInjectionDetection:
        return cls(
            enabled=data.get("enabled"),
            warn_at_or_above=(
                DetectionLevel(data["warn_at_or_above"])
                if "warn_at_or_above" in data
                else None
            ),
            block_at_or_above=(
                DetectionLevel(data["block_at_or_above"])
                if "block_at_or_above" in data
                else None
            ),
            max_scan_bytes=data.get("max_scan_bytes"),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.enabled is not None:
            d["enabled"] = self.enabled
        if self.warn_at_or_above is not None:
            d["warn_at_or_above"] = self.warn_at_or_above.value
        if self.block_at_or_above is not None:
            d["block_at_or_above"] = self.block_at_or_above.value
        if self.max_scan_bytes is not None:
            d["max_scan_bytes"] = self.max_scan_bytes
        return d


@dataclass
class JailbreakDetection:
    """Jailbreak detection thresholds."""

    enabled: Optional[bool] = None
    block_threshold: Optional[int] = None
    warn_threshold: Optional[int] = None
    max_input_bytes: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> JailbreakDetection:
        return cls(
            enabled=data.get("enabled"),
            block_threshold=data.get("block_threshold"),
            warn_threshold=data.get("warn_threshold"),
            max_input_bytes=data.get("max_input_bytes"),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.enabled is not None:
            d["enabled"] = self.enabled
        if self.block_threshold is not None:
            d["block_threshold"] = self.block_threshold
        if self.warn_threshold is not None:
            d["warn_threshold"] = self.warn_threshold
        if self.max_input_bytes is not None:
            d["max_input_bytes"] = self.max_input_bytes
        return d


@dataclass
class ThreatIntelDetection:
    """Threat intelligence screening configuration."""

    enabled: Optional[bool] = None
    pattern_db: Optional[str] = None
    similarity_threshold: Optional[float] = None
    top_k: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> ThreatIntelDetection:
        return cls(
            enabled=data.get("enabled"),
            pattern_db=data.get("pattern_db"),
            similarity_threshold=data.get("similarity_threshold"),
            top_k=data.get("top_k"),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.enabled is not None:
            d["enabled"] = self.enabled
        if self.pattern_db is not None:
            d["pattern_db"] = self.pattern_db
        if self.similarity_threshold is not None:
            d["similarity_threshold"] = self.similarity_threshold
        if self.top_k is not None:
            d["top_k"] = self.top_k
        return d


@dataclass
class DetectionExtension:
    """Detection engine threshold configuration."""

    prompt_injection: Optional[PromptInjectionDetection] = None
    jailbreak: Optional[JailbreakDetection] = None
    threat_intel: Optional[ThreatIntelDetection] = None

    @classmethod
    def from_dict(cls, data: dict) -> DetectionExtension:
        return cls(
            prompt_injection=(
                PromptInjectionDetection.from_dict(data["prompt_injection"])
                if "prompt_injection" in data
                else None
            ),
            jailbreak=(
                JailbreakDetection.from_dict(data["jailbreak"])
                if "jailbreak" in data
                else None
            ),
            threat_intel=(
                ThreatIntelDetection.from_dict(data["threat_intel"])
                if "threat_intel" in data
                else None
            ),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.prompt_injection is not None:
            d["prompt_injection"] = self.prompt_injection.to_dict()
        if self.jailbreak is not None:
            d["jailbreak"] = self.jailbreak.to_dict()
        if self.threat_intel is not None:
            d["threat_intel"] = self.threat_intel.to_dict()
        return d


# ============================================================
# Extensions Container
# ============================================================


@dataclass
class Extensions:
    """Optional extension modules for advanced features."""

    posture: Optional[PostureExtension] = None
    origins: Optional[OriginsExtension] = None
    detection: Optional[DetectionExtension] = None

    @classmethod
    def from_dict(cls, data: dict) -> Extensions:
        return cls(
            posture=(
                PostureExtension.from_dict(data["posture"])
                if "posture" in data
                else None
            ),
            origins=(
                OriginsExtension.from_dict(data["origins"])
                if "origins" in data
                else None
            ),
            detection=(
                DetectionExtension.from_dict(data["detection"])
                if "detection" in data
                else None
            ),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.posture is not None:
            d["posture"] = self.posture.to_dict()
        if self.origins is not None:
            d["origins"] = self.origins.to_dict()
        if self.detection is not None:
            d["detection"] = self.detection.to_dict()
        return d
