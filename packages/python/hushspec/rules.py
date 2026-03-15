"""Core security rule types for HushSpec.

All types mirror the Rust and TypeScript implementations exactly, using
snake_case field names matching the YAML schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# --- Shared Types ---


class Severity(str, Enum):
    """Severity level for secret pattern matches."""

    CRITICAL = "critical"
    ERROR = "error"
    WARN = "warn"


class DefaultAction(str, Enum):
    """Default action when no allow/block rule matches."""

    ALLOW = "allow"
    BLOCK = "block"


class ComputerUseMode(str, Enum):
    """CUA enforcement mode."""

    OBSERVE = "observe"
    GUARDRAIL = "guardrail"
    FAIL_CLOSED = "fail_closed"


# --- Rule 1: Forbidden Paths ---


@dataclass
class ForbiddenPathsRule:
    """Block access to sensitive filesystem paths by glob pattern."""

    enabled: bool = True
    patterns: list[str] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> ForbiddenPathsRule:
        return cls(
            enabled=data.get("enabled", True),
            patterns=list(data.get("patterns", [])),
            exceptions=list(data.get("exceptions", [])),
        )

    def to_dict(self) -> dict:
        d: dict = {"enabled": self.enabled}
        if self.patterns:
            d["patterns"] = self.patterns
        if self.exceptions:
            d["exceptions"] = self.exceptions
        return d


# --- Rule 2: Path Allowlist ---


@dataclass
class PathAllowlistRule:
    """Allowlist-based path access control for read, write, and patch operations."""

    enabled: bool = False
    read: list[str] = field(default_factory=list)
    write: list[str] = field(default_factory=list)
    patch: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> PathAllowlistRule:
        return cls(
            enabled=data.get("enabled", False),
            read=list(data.get("read", [])),
            write=list(data.get("write", [])),
            patch=list(data.get("patch", [])),
        )

    def to_dict(self) -> dict:
        d: dict = {"enabled": self.enabled}
        if self.read:
            d["read"] = self.read
        if self.write:
            d["write"] = self.write
        if self.patch:
            d["patch"] = self.patch
        return d


# --- Rule 3: Egress ---


@dataclass
class EgressRule:
    """Network egress control by domain pattern."""

    enabled: bool = True
    allow: list[str] = field(default_factory=list)
    block: list[str] = field(default_factory=list)
    default: DefaultAction = DefaultAction.BLOCK

    @classmethod
    def from_dict(cls, data: dict) -> EgressRule:
        default_str = data.get("default", "block")
        return cls(
            enabled=data.get("enabled", True),
            allow=list(data.get("allow", [])),
            block=list(data.get("block", [])),
            default=DefaultAction(default_str),
        )

    def to_dict(self) -> dict:
        d: dict = {"enabled": self.enabled, "default": self.default.value}
        if self.allow:
            d["allow"] = self.allow
        if self.block:
            d["block"] = self.block
        return d


# --- Rule 4: Secret Patterns ---


@dataclass
class SecretPattern:
    """A named regex pattern for secret detection."""

    name: str
    pattern: str
    severity: Severity
    description: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> SecretPattern:
        return cls(
            name=data["name"],
            pattern=data["pattern"],
            severity=Severity(data["severity"]),
            description=data.get("description"),
        )

    def to_dict(self) -> dict:
        d: dict = {
            "name": self.name,
            "pattern": self.pattern,
            "severity": self.severity.value,
        }
        if self.description is not None:
            d["description"] = self.description
        return d


@dataclass
class SecretPatternsRule:
    """Detect secrets in file content using named regex patterns."""

    enabled: bool = True
    patterns: list[SecretPattern] = field(default_factory=list)
    skip_paths: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> SecretPatternsRule:
        patterns = [SecretPattern.from_dict(p) for p in data.get("patterns", [])]
        return cls(
            enabled=data.get("enabled", True),
            patterns=patterns,
            skip_paths=list(data.get("skip_paths", [])),
        )

    def to_dict(self) -> dict:
        d: dict = {"enabled": self.enabled}
        if self.patterns:
            d["patterns"] = [p.to_dict() for p in self.patterns]
        if self.skip_paths:
            d["skip_paths"] = self.skip_paths
        return d


# --- Rule 5: Patch Integrity ---


@dataclass
class PatchIntegrityRule:
    """Validate patch/diff safety with size limits and forbidden patterns."""

    enabled: bool = True
    max_additions: int = 1000
    max_deletions: int = 500
    forbidden_patterns: list[str] = field(default_factory=list)
    require_balance: bool = False
    max_imbalance_ratio: float = 10.0

    @classmethod
    def from_dict(cls, data: dict) -> PatchIntegrityRule:
        return cls(
            enabled=data.get("enabled", True),
            max_additions=data.get("max_additions", 1000),
            max_deletions=data.get("max_deletions", 500),
            forbidden_patterns=list(data.get("forbidden_patterns", [])),
            require_balance=data.get("require_balance", False),
            max_imbalance_ratio=data.get("max_imbalance_ratio", 10.0),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "max_additions": self.max_additions,
            "max_deletions": self.max_deletions,
            "forbidden_patterns": self.forbidden_patterns,
            "require_balance": self.require_balance,
            "max_imbalance_ratio": self.max_imbalance_ratio,
        }


# --- Rule 6: Shell Commands ---


@dataclass
class ShellCommandsRule:
    """Block dangerous shell commands by regex pattern."""

    enabled: bool = True
    forbidden_patterns: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> ShellCommandsRule:
        return cls(
            enabled=data.get("enabled", True),
            forbidden_patterns=list(data.get("forbidden_patterns", [])),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "forbidden_patterns": self.forbidden_patterns,
        }


# --- Rule 7: Tool Access ---


@dataclass
class ToolAccessRule:
    """Control tool/MCP invocations with allow/block lists."""

    enabled: bool = True
    allow: list[str] = field(default_factory=list)
    block: list[str] = field(default_factory=list)
    require_confirmation: list[str] = field(default_factory=list)
    default: DefaultAction = DefaultAction.ALLOW
    max_args_size: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> ToolAccessRule:
        default_str = data.get("default", "allow")
        return cls(
            enabled=data.get("enabled", True),
            allow=list(data.get("allow", [])),
            block=list(data.get("block", [])),
            require_confirmation=list(data.get("require_confirmation", [])),
            default=DefaultAction(default_str),
            max_args_size=data.get("max_args_size"),
        )

    def to_dict(self) -> dict:
        d: dict = {
            "enabled": self.enabled,
            "default": self.default.value,
        }
        if self.allow:
            d["allow"] = self.allow
        if self.block:
            d["block"] = self.block
        if self.require_confirmation:
            d["require_confirmation"] = self.require_confirmation
        if self.max_args_size is not None:
            d["max_args_size"] = self.max_args_size
        return d


# --- Rule 8: Computer Use ---


@dataclass
class ComputerUseRule:
    """Control computer use agent (CUA) actions."""

    enabled: bool = False
    mode: ComputerUseMode = ComputerUseMode.GUARDRAIL
    allowed_actions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> ComputerUseRule:
        mode_str = data.get("mode", "guardrail")
        return cls(
            enabled=data.get("enabled", False),
            mode=ComputerUseMode(mode_str),
            allowed_actions=list(data.get("allowed_actions", [])),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "mode": self.mode.value,
            "allowed_actions": self.allowed_actions,
        }


# --- Rule 9: Remote Desktop Channels ---


@dataclass
class RemoteDesktopChannelsRule:
    """Control remote desktop side channels."""

    enabled: bool = False
    clipboard: bool = False
    file_transfer: bool = False
    audio: bool = True
    drive_mapping: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> RemoteDesktopChannelsRule:
        return cls(
            enabled=data.get("enabled", False),
            clipboard=data.get("clipboard", False),
            file_transfer=data.get("file_transfer", False),
            audio=data.get("audio", True),
            drive_mapping=data.get("drive_mapping", False),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "clipboard": self.clipboard,
            "file_transfer": self.file_transfer,
            "audio": self.audio,
            "drive_mapping": self.drive_mapping,
        }


# --- Rule 10: Input Injection ---


@dataclass
class InputInjectionRule:
    """Control input injection capabilities."""

    enabled: bool = False
    allowed_types: list[str] = field(default_factory=list)
    require_postcondition_probe: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> InputInjectionRule:
        return cls(
            enabled=data.get("enabled", False),
            allowed_types=list(data.get("allowed_types", [])),
            require_postcondition_probe=data.get("require_postcondition_probe", False),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "allowed_types": self.allowed_types,
            "require_postcondition_probe": self.require_postcondition_probe,
        }


# --- Rules Container ---


@dataclass
class Rules:
    """Container for all core security rules."""

    forbidden_paths: Optional[ForbiddenPathsRule] = None
    path_allowlist: Optional[PathAllowlistRule] = None
    egress: Optional[EgressRule] = None
    secret_patterns: Optional[SecretPatternsRule] = None
    patch_integrity: Optional[PatchIntegrityRule] = None
    shell_commands: Optional[ShellCommandsRule] = None
    tool_access: Optional[ToolAccessRule] = None
    computer_use: Optional[ComputerUseRule] = None
    remote_desktop_channels: Optional[RemoteDesktopChannelsRule] = None
    input_injection: Optional[InputInjectionRule] = None

    @classmethod
    def from_dict(cls, data: dict) -> Rules:
        return cls(
            forbidden_paths=(
                ForbiddenPathsRule.from_dict(data["forbidden_paths"])
                if "forbidden_paths" in data
                else None
            ),
            path_allowlist=(
                PathAllowlistRule.from_dict(data["path_allowlist"])
                if "path_allowlist" in data
                else None
            ),
            egress=(
                EgressRule.from_dict(data["egress"]) if "egress" in data else None
            ),
            secret_patterns=(
                SecretPatternsRule.from_dict(data["secret_patterns"])
                if "secret_patterns" in data
                else None
            ),
            patch_integrity=(
                PatchIntegrityRule.from_dict(data["patch_integrity"])
                if "patch_integrity" in data
                else None
            ),
            shell_commands=(
                ShellCommandsRule.from_dict(data["shell_commands"])
                if "shell_commands" in data
                else None
            ),
            tool_access=(
                ToolAccessRule.from_dict(data["tool_access"])
                if "tool_access" in data
                else None
            ),
            computer_use=(
                ComputerUseRule.from_dict(data["computer_use"])
                if "computer_use" in data
                else None
            ),
            remote_desktop_channels=(
                RemoteDesktopChannelsRule.from_dict(data["remote_desktop_channels"])
                if "remote_desktop_channels" in data
                else None
            ),
            input_injection=(
                InputInjectionRule.from_dict(data["input_injection"])
                if "input_injection" in data
                else None
            ),
        )

    def to_dict(self) -> dict:
        d: dict = {}
        if self.forbidden_paths is not None:
            d["forbidden_paths"] = self.forbidden_paths.to_dict()
        if self.path_allowlist is not None:
            d["path_allowlist"] = self.path_allowlist.to_dict()
        if self.egress is not None:
            d["egress"] = self.egress.to_dict()
        if self.secret_patterns is not None:
            d["secret_patterns"] = self.secret_patterns.to_dict()
        if self.patch_integrity is not None:
            d["patch_integrity"] = self.patch_integrity.to_dict()
        if self.shell_commands is not None:
            d["shell_commands"] = self.shell_commands.to_dict()
        if self.tool_access is not None:
            d["tool_access"] = self.tool_access.to_dict()
        if self.computer_use is not None:
            d["computer_use"] = self.computer_use.to_dict()
        if self.remote_desktop_channels is not None:
            d["remote_desktop_channels"] = self.remote_desktop_channels.to_dict()
        if self.input_injection is not None:
            d["input_injection"] = self.input_injection.to_dict()
        return d
