"""HushSpec: Portable specification for AI agent security rules."""

from hushspec.extensions import (
    BridgePolicy,
    BridgeTarget,
    DetectionExtension,
    DetectionLevel,
    Extensions,
    JailbreakDetection,
    OriginBudgets,
    OriginDataPolicy,
    OriginDefaultBehavior,
    OriginMatch,
    OriginProfile,
    OriginsExtension,
    PostureExtension,
    PostureState,
    PostureTransition,
    PromptInjectionDetection,
    ThreatIntelDetection,
    TransitionTrigger,
)
from hushspec.merge import merge
from hushspec.parse import parse, parse_or_raise
from hushspec.rules import (
    ComputerUseMode,
    ComputerUseRule,
    DefaultAction,
    EgressRule,
    ForbiddenPathsRule,
    InputInjectionRule,
    PatchIntegrityRule,
    PathAllowlistRule,
    RemoteDesktopChannelsRule,
    Rules,
    SecretPattern,
    SecretPatternsRule,
    Severity,
    ShellCommandsRule,
    ToolAccessRule,
)
from hushspec.schema import HushSpec, MergeStrategy
from hushspec.validate import ValidationError, ValidationResult, validate
from hushspec.version import HUSHSPEC_VERSION, SUPPORTED_VERSIONS, is_supported

__version__ = HUSHSPEC_VERSION

__all__ = [
    # Schema
    "HushSpec",
    "MergeStrategy",
    # Rules
    "Rules",
    "ForbiddenPathsRule",
    "PathAllowlistRule",
    "EgressRule",
    "SecretPatternsRule",
    "SecretPattern",
    "PatchIntegrityRule",
    "ShellCommandsRule",
    "ToolAccessRule",
    "ComputerUseRule",
    "ComputerUseMode",
    "RemoteDesktopChannelsRule",
    "InputInjectionRule",
    "Severity",
    "DefaultAction",
    # Extensions
    "Extensions",
    "PostureExtension",
    "PostureState",
    "PostureTransition",
    "TransitionTrigger",
    "OriginsExtension",
    "OriginDefaultBehavior",
    "OriginProfile",
    "OriginMatch",
    "OriginDataPolicy",
    "OriginBudgets",
    "BridgePolicy",
    "BridgeTarget",
    "DetectionExtension",
    "DetectionLevel",
    "PromptInjectionDetection",
    "JailbreakDetection",
    "ThreatIntelDetection",
    # Parse
    "parse",
    "parse_or_raise",
    # Validate
    "validate",
    "ValidationResult",
    "ValidationError",
    # Merge
    "merge",
    # Version
    "HUSHSPEC_VERSION",
    "SUPPORTED_VERSIONS",
    "is_supported",
]
