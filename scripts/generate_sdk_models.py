#!/usr/bin/env python3
"""Generate Rust, Python, and Go HushSpec model types from one model spec."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

PY_OUTPUT = ROOT / "packages" / "python" / "hushspec" / "generated_models.py"
RS_OUTPUT = ROOT / "crates" / "hushspec" / "src" / "generated_models.rs"
GO_OUTPUT = ROOT / "packages" / "go" / "hushspec" / "generated_models.go"


ENUMS = [
    {"name": "MergeStrategy", "values": ["replace", "merge", "deep_merge"], "default": "deep_merge"},
    {"name": "Severity", "values": ["critical", "error", "warn"]},
    {"name": "DefaultAction", "values": ["allow", "block"]},
    {"name": "ComputerUseMode", "values": ["observe", "guardrail", "fail_closed"], "default": "guardrail"},
    {
        "name": "TransitionTrigger",
        "values": [
            "user_approval",
            "user_denial",
            "critical_violation",
            "any_violation",
            "timeout",
            "budget_exhausted",
            "pattern_match",
        ],
    },
    {"name": "OriginDefaultBehavior", "values": ["deny", "minimal_profile"], "default": "deny"},
    {"name": "DetectionLevel", "values": ["safe", "suspicious", "high", "critical"]},
]


def camel(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def field(
    name: str,
    field_type: object,
    *,
    required: bool = False,
    default: object | None = None,
    wire: str | None = None,
    py_name: str | None = None,
    rs_name: str | None = None,
    go_name: str | None = None,
    go_pointer: bool = False,
    emit_empty: bool = False,
) -> dict:
    return {
        "name": name,
        "type": field_type,
        "required": required,
        "default": default,
        "wire": wire or name,
        "py_name": py_name or name,
        "rs_name": rs_name or name,
        "go_name": go_name or camel(name),
        "go_pointer": go_pointer,
        "emit_empty": emit_empty,
    }


def list_of(item: object) -> dict:
    return {"kind": "list", "item": item}


def map_of(value: object) -> dict:
    return {"kind": "map", "value": value}


STRUCTS = [
    {
        "name": "HushSpec",
        "fields": [
            field("hushspec", "string", required=True, go_name="HushSpecVersion"),
            field("name", "string"),
            field("description", "string"),
            field("extends", "string"),
            field("merge_strategy", "MergeStrategy"),
            field("rules", "Rules"),
            field("extensions", "Extensions"),
        ],
    },
    {
        "name": "Rules",
        "derive_default": True,
        "fields": [
            field("forbidden_paths", "ForbiddenPathsRule"),
            field("path_allowlist", "PathAllowlistRule"),
            field("egress", "EgressRule"),
            field("secret_patterns", "SecretPatternsRule"),
            field("patch_integrity", "PatchIntegrityRule"),
            field("shell_commands", "ShellCommandsRule"),
            field("tool_access", "ToolAccessRule"),
            field("computer_use", "ComputerUseRule"),
            field("remote_desktop_channels", "RemoteDesktopChannelsRule"),
            field("input_injection", "InputInjectionRule"),
        ],
    },
    {
        "name": "ForbiddenPathsRule",
        "fields": [
            field("enabled", "bool", default=True),
            field("patterns", list_of("string"), default=[], emit_empty=False),
            field("exceptions", list_of("string"), default=[], emit_empty=False),
        ],
    },
    {
        "name": "PathAllowlistRule",
        "fields": [
            field("enabled", "bool", default=False),
            field("read", list_of("string"), default=[], emit_empty=False),
            field("write", list_of("string"), default=[], emit_empty=False),
            field("patch", list_of("string"), default=[], emit_empty=False),
        ],
    },
    {
        "name": "EgressRule",
        "fields": [
            field("enabled", "bool", default=True),
            field("allow", list_of("string"), default=[], emit_empty=False),
            field("block", list_of("string"), default=[], emit_empty=False),
            field("default", "DefaultAction", default=("enum", "DefaultAction", "block")),
        ],
    },
    {
        "name": "SecretPattern",
        "fields": [
            field("name", "string", required=True),
            field("pattern", "string", required=True),
            field("severity", "Severity", required=True),
            field("description", "string"),
        ],
    },
    {
        "name": "SecretPatternsRule",
        "fields": [
            field("enabled", "bool", default=True),
            field("patterns", list_of("SecretPattern"), default=[], emit_empty=False),
            field("skip_paths", list_of("string"), default=[], emit_empty=False),
        ],
    },
    {
        "name": "PatchIntegrityRule",
        "fields": [
            field("enabled", "bool", default=True),
            field("max_additions", "count", default=1000),
            field("max_deletions", "count", default=500),
            field("forbidden_patterns", list_of("string"), default=[], emit_empty=False),
            field("require_balance", "bool", default=False),
            field("max_imbalance_ratio", "float", default=10.0, go_pointer=True),
        ],
    },
    {
        "name": "ShellCommandsRule",
        "fields": [
            field("enabled", "bool", default=True),
            field("forbidden_patterns", list_of("string"), default=[], emit_empty=False),
        ],
    },
    {
        "name": "ToolAccessRule",
        "fields": [
            field("enabled", "bool", default=True),
            field("allow", list_of("string"), default=[], emit_empty=False),
            field("block", list_of("string"), default=[], emit_empty=False),
            field("require_confirmation", list_of("string"), default=[], emit_empty=False),
            field("default", "DefaultAction", default=("enum", "DefaultAction", "allow")),
            field("max_args_size", "count", go_pointer=True),
        ],
    },
    {
        "name": "ComputerUseRule",
        "fields": [
            field("enabled", "bool", default=False),
            field("mode", "ComputerUseMode", default=("enum", "ComputerUseMode", "guardrail")),
            field("allowed_actions", list_of("string"), default=[], emit_empty=False),
        ],
    },
    {
        "name": "RemoteDesktopChannelsRule",
        "fields": [
            field("enabled", "bool", default=False),
            field("clipboard", "bool", default=False),
            field("file_transfer", "bool", default=False),
            field("audio", "bool", default=True),
            field("drive_mapping", "bool", default=False),
        ],
    },
    {
        "name": "InputInjectionRule",
        "fields": [
            field("enabled", "bool", default=False),
            field("allowed_types", list_of("string"), default=[], emit_empty=False),
            field("require_postcondition_probe", "bool", default=False),
        ],
    },
    {
        "name": "Extensions",
        "derive_default": True,
        "fields": [
            field("posture", "PostureExtension"),
            field("origins", "OriginsExtension"),
            field("detection", "DetectionExtension"),
        ],
    },
    {
        "name": "PostureExtension",
        "fields": [
            field("initial", "string", required=True),
            field("states", map_of("PostureState"), required=True, emit_empty=True),
            field("transitions", list_of("PostureTransition"), required=True, emit_empty=True),
        ],
    },
    {
        "name": "PostureState",
        "fields": [
            field("description", "string"),
            field("capabilities", list_of("string"), default=[], emit_empty=False),
            field("budgets", map_of("signed"), default={}, emit_empty=False),
        ],
    },
    {
        "name": "PostureTransition",
        "fields": [
            field("from", "string", required=True, py_name="from_state"),
            field("to", "string", required=True),
            field("on", "TransitionTrigger", required=True),
            field("after", "string", go_pointer=True),
        ],
    },
    {
        "name": "OriginsExtension",
        "fields": [
            field("default_behavior", "OriginDefaultBehavior", go_pointer=True),
            field("profiles", list_of("OriginProfile"), default=[], emit_empty=False),
        ],
    },
    {
        "name": "OriginProfile",
        "fields": [
            field("id", "string", required=True, go_name="ID"),
            field("match", "OriginMatch", py_name="match_rules", rs_name="match_rules", go_name="Match"),
            field("posture", "string", go_pointer=True),
            field("tool_access", "ToolAccessRule"),
            field("egress", "EgressRule"),
            field("data", "OriginDataPolicy"),
            field("budgets", "OriginBudgets"),
            field("bridge", "BridgePolicy"),
            field("explanation", "string", go_pointer=True),
        ],
    },
    {
        "name": "OriginMatch",
        "fields": [
            field("provider", "string"),
            field("tenant_id", "string", go_name="TenantID"),
            field("space_id", "string", go_name="SpaceID"),
            field("space_type", "string"),
            field("visibility", "string"),
            field("external_participants", "bool", go_pointer=True),
            field("tags", list_of("string"), default=[], emit_empty=False),
            field("sensitivity", "string"),
            field("actor_role", "string"),
        ],
    },
    {
        "name": "OriginDataPolicy",
        "fields": [
            field("allow_external_sharing", "bool", default=False, go_pointer=True),
            field("redact_before_send", "bool", default=False, go_pointer=True),
            field("block_sensitive_outputs", "bool", default=False, go_pointer=True),
        ],
    },
    {
        "name": "OriginBudgets",
        "fields": [
            field("tool_calls", "count", go_pointer=True),
            field("egress_calls", "count", go_pointer=True),
            field("shell_commands", "count", go_pointer=True),
        ],
    },
    {
        "name": "BridgePolicy",
        "fields": [
            field("allow_cross_origin", "bool", default=False, go_pointer=True),
            field("allowed_targets", list_of("BridgeTarget"), default=[], emit_empty=False),
            field("require_approval", "bool", default=False, go_pointer=True),
        ],
    },
    {
        "name": "BridgeTarget",
        "fields": [
            field("provider", "string"),
            field("space_type", "string"),
            field("tags", list_of("string"), default=[], emit_empty=False),
            field("visibility", "string"),
        ],
    },
    {
        "name": "DetectionExtension",
        "fields": [
            field("prompt_injection", "PromptInjectionDetection"),
            field("jailbreak", "JailbreakDetection"),
            field("threat_intel", "ThreatIntelDetection"),
        ],
    },
    {
        "name": "PromptInjectionDetection",
        "fields": [
            field("enabled", "bool", go_pointer=True),
            field("warn_at_or_above", "DetectionLevel", go_pointer=True),
            field("block_at_or_above", "DetectionLevel", go_pointer=True),
            field("max_scan_bytes", "count", go_pointer=True),
        ],
    },
    {
        "name": "JailbreakDetection",
        "fields": [
            field("enabled", "bool", go_pointer=True),
            field("block_threshold", "count", go_pointer=True),
            field("warn_threshold", "count", go_pointer=True),
            field("max_input_bytes", "count", go_pointer=True),
        ],
    },
    {
        "name": "ThreatIntelDetection",
        "fields": [
            field("enabled", "bool", go_pointer=True),
            field("pattern_db", "string", go_pointer=True, go_name="PatternDB"),
            field("similarity_threshold", "float", go_pointer=True),
            field("top_k", "count", go_pointer=True),
        ],
    },
]


SCALARS = {
    "string": {"py": "str", "rs": "String", "go": "string"},
    "bool": {"py": "bool", "rs": "bool", "go": "bool"},
    "count": {"py": "int", "rs": "usize", "go": "int"},
    "signed": {"py": "int", "rs": "i64", "go": "int"},
    "float": {"py": "float", "rs": "f64", "go": "float64"},
}


ENUM_MAP = {enum["name"]: enum for enum in ENUMS}
STRUCT_MAP = {struct["name"]: struct for struct in STRUCTS}


def upper_snake(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")


def py_type(type_info: object, optional: bool = False) -> str:
    base = render_type(type_info, "py")
    return f"{base} | None" if optional else base


def rs_type(type_info: object, optional: bool = False) -> str:
    base = render_type(type_info, "rs")
    return f"Option<{base}>" if optional else base


def go_type(field_info: dict) -> str:
    base = render_type(field_info["type"], "go")
    if field_info["go_pointer"] and not is_collection(field_info["type"]):
        return f"*{base}"
    if is_struct(field_info["type"]) and not field_info["required"]:
        return f"*{base}"
    return base


def render_type(type_info: object, language: str) -> str:
    if isinstance(type_info, dict):
        if type_info["kind"] == "list":
            inner = render_type(type_info["item"], language)
            return {
                "py": f"list[{inner}]",
                "rs": f"Vec<{inner}>",
                "go": f"[]{inner}",
            }[language]
        if type_info["kind"] == "map":
            inner = render_type(type_info["value"], language)
            return {
                "py": f"dict[str, {inner}]",
                "rs": f"BTreeMap<String, {inner}>",
                "go": f"map[string]{inner}",
            }[language]
        raise ValueError(f"unsupported type info: {type_info}")
    if type_info in SCALARS:
        return SCALARS[type_info][language]
    return str(type_info)


def is_collection(type_info: object) -> bool:
    return isinstance(type_info, dict) and type_info["kind"] in {"list", "map"}


def is_struct(type_info: object) -> bool:
    return isinstance(type_info, str) and type_info in STRUCT_MAP


def is_enum(type_info: object) -> bool:
    return isinstance(type_info, str) and type_info in ENUM_MAP


def py_default(field_info: dict) -> str | None:
    default = field_info["default"]
    if default is None:
        if field_info["required"]:
            return None
        if is_collection(field_info["type"]):
            kind = field_info["type"]["kind"]
            return "field(default_factory=list)" if kind == "list" else "field(default_factory=dict)"
        return "None"
    if default == []:
        return "field(default_factory=list)"
    if default == {}:
        return "field(default_factory=dict)"
    if isinstance(default, tuple) and default[0] == "enum":
        return f"{default[1]}.{upper_snake(default[2])}"
    return repr(default)


def py_from_expr(field_info: dict, expr: str) -> str:
    type_info = field_info["type"]
    if isinstance(type_info, dict):
        if type_info["kind"] == "list":
            item = type_info["item"]
            return f"[{py_item_from_expr(item, 'item')} for item in {expr}]"
        return f"{{key: {py_item_from_expr(type_info['value'], 'item')} for key, item in ({expr}).items()}}"
    if is_enum(type_info):
        return f"{type_info}({expr})"
    if is_struct(type_info):
        return f"{type_info}.from_dict({expr})"
    return expr


def py_item_from_expr(type_info: object, expr: str) -> str:
    if is_enum(type_info):
        return f"{type_info}({expr})"
    if is_struct(type_info):
        return f"{type_info}.from_dict({expr})"
    return expr


def py_to_expr(field_info: dict, expr: str) -> str:
    type_info = field_info["type"]
    if isinstance(type_info, dict):
        if type_info["kind"] == "list":
            item = type_info["item"]
            return f"[{py_item_to_expr(item, 'item')} for item in {expr}]"
        return f"{{key: {py_item_to_expr(type_info['value'], 'item')} for key, item in {expr}.items()}}"
    if is_enum(type_info):
        return f"{expr}.value"
    if is_struct(type_info):
        return f"{expr}.to_dict()"
    return expr


def py_item_to_expr(type_info: object, expr: str) -> str:
    if is_enum(type_info):
        return f"{expr}.value"
    if is_struct(type_info):
        return f"{expr}.to_dict()"
    return expr


def render_python() -> str:
    lines = [
        '"""Code generated by scripts/generate_sdk_models.py. DO NOT EDIT."""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass, field",
        "from enum import Enum",
        "",
    ]

    for enum in ENUMS:
        lines.append(f"class {enum['name']}(str, Enum):")
        for value in enum["values"]:
            lines.append(f"    {upper_snake(value)} = {value!r}")
        lines.append("")

    for struct in STRUCTS:
        lines.append("@dataclass")
        lines.append(f"class {struct['name']}:")
        for field_info in struct["fields"]:
            annotation = py_type(field_info["type"], optional=not field_info["required"] and field_info["default"] is None and not is_collection(field_info["type"]))
            default = py_default(field_info)
            if default is None:
                lines.append(f"    {field_info['py_name']}: {annotation}")
            else:
                lines.append(f"    {field_info['py_name']}: {annotation} = {default}")
        if not struct["fields"]:
            lines.append("    pass")
        lines.extend(
            [
                "",
                "    @classmethod",
                f"    def from_dict(cls, data: dict) -> {struct['name']}:",
                "        return cls(",
            ]
        )
        for field_info in struct["fields"]:
            if field_info["required"] and is_collection(field_info["type"]):
                fallback = "[]" if field_info["type"]["kind"] == "list" else "{}"
                source = f"data.get({field_info['wire']!r}, {fallback})"
            else:
                source = f"data[{field_info['wire']!r}]" if field_info["required"] else f"data.get({field_info['wire']!r})"
            if field_info["default"] == []:
                value = py_from_expr(field_info, f"{source} or []")
            elif field_info["default"] == {}:
                value = py_from_expr(field_info, f"{source} or {{}}")
            elif field_info["default"] is not None and not isinstance(field_info["default"], tuple):
                value = py_from_expr(field_info, source if field_info["required"] else f"({source} if {source} is not None else {field_info['default']!r})")
            elif isinstance(field_info["default"], tuple) and field_info["default"][0] == "enum":
                fallback = f"{field_info['default'][1]}.{upper_snake(field_info['default'][2])}"
                value = py_from_expr(field_info, source if field_info["required"] else f"({source} if {source} is not None else {fallback}.value)")
            elif not field_info["required"] and not is_collection(field_info["type"]):
                value = f"({py_from_expr(field_info, source)} if {source} is not None else None)"
            else:
                value = py_from_expr(field_info, source)
            lines.append(f"            {field_info['py_name']}={value},")
        lines.extend(
            [
                "        )",
                "",
                "    def to_dict(self) -> dict:",
                "        data: dict = {}",
            ]
        )
        for field_info in struct["fields"]:
            expr = py_to_expr(field_info, f"self.{field_info['py_name']}")
            if not field_info["required"] and field_info["default"] is None and not is_collection(field_info["type"]):
                lines.append(f"        if self.{field_info['py_name']} is not None:")
                lines.append(f"            data[{field_info['wire']!r}] = {expr}")
            elif is_collection(field_info["type"]) and not field_info["emit_empty"]:
                lines.append(f"        if self.{field_info['py_name']}:")
                lines.append(f"            data[{field_info['wire']!r}] = {expr}")
            else:
                lines.append(f"        data[{field_info['wire']!r}] = {expr}")
        lines.extend(["        return data", ""])

    return "\n".join(lines).rstrip() + "\n"


RS_DEFAULTS = {
    True: ("default_true", "bool", "true"),
    1000: ("default_1000", "usize", "1000"),
    500: ("default_500", "usize", "500"),
    10.0: ("default_imbalance_ratio", "f64", "10.0"),
    ("enum", "DefaultAction", "block"): ("default_block", "DefaultAction", "DefaultAction::Block"),
    ("enum", "DefaultAction", "allow"): ("default_allow", "DefaultAction", "DefaultAction::Allow"),
    ("enum", "ComputerUseMode", "guardrail"): (
        "default_guardrail",
        "ComputerUseMode",
        "ComputerUseMode::Guardrail",
    ),
}


def rust_variant_name(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("_"))


def render_rust() -> str:
    lines = [
        "// Code generated by scripts/generate_sdk_models.py. DO NOT EDIT.",
        "use serde::{Deserialize, Serialize};",
        "use std::collections::BTreeMap;",
        "",
    ]

    for enum in ENUMS:
        derives = "Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize"
        if enum.get("default") is not None:
            derives = f"{derives}, Default"
        lines.append(f"#[derive({derives})]")
        lines.append('#[serde(rename_all = "snake_case")]')
        lines.append(f"pub enum {enum['name']} {{")
        for value in enum["values"]:
            variant = rust_variant_name(value)
            if enum.get("default") == value:
                lines.append("    #[default]")
            lines.append(f"    {variant},")
        lines.append("}")
        lines.append("")

    default_functions: dict[tuple, tuple[str, str, str]] = {}
    for struct in STRUCTS:
        derives = "Clone, Debug, PartialEq, Serialize, Deserialize"
        if struct.get("derive_default"):
            derives = f"{derives}, Default"
        lines.append(f"#[derive({derives})]")
        lines.append("#[serde(deny_unknown_fields)]")
        lines.append(f"pub struct {struct['name']} {{")
        for field_info in struct["fields"]:
            attrs = []
            if field_info["wire"] != field_info["rs_name"]:
                attrs.append(f'rename = "{field_info["wire"]}"')
            default = field_info["default"]
            if not field_info["required"] and default is None and not is_collection(field_info["type"]):
                attrs.append("default")
                attrs.append('skip_serializing_if = "Option::is_none"')
            else:
                try:
                    default_meta = RS_DEFAULTS.get(default)
                except TypeError:
                    default_meta = None
                if default_meta is not None:
                    default_functions[default] = default_meta
                    attrs.append(f'default = "{default_meta[0]}"')
                elif default == [] or default == {} or default is False or not field_info["required"]:
                    attrs.append("default")
            if attrs:
                lines.append(f"    #[serde({', '.join(attrs)})]")
            lines.append(
                f"    pub {field_info['rs_name']}: {rs_type(field_info['type'], optional=not field_info['required'] and field_info['default'] is None and not is_collection(field_info['type']))},"
            )
        lines.append("}")
        lines.append("")

    for _, (name, type_name, expr) in sorted(default_functions.items(), key=lambda item: item[1][0]):
        lines.append(f"fn {name}() -> {type_name} {{")
        lines.append(f"    {expr}")
        lines.append("}")
        lines.append("")

    content = "\n".join(lines).rstrip() + "\n"
    rustfmt = shutil.which("rustfmt")
    if rustfmt is None:
        return content
    result = subprocess.run(
        [rustfmt, "--emit", "stdout", "--edition", "2021"],
        input=content,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def render_go() -> str:
    lines = [
        "// Code generated by scripts/generate_sdk_models.py. DO NOT EDIT.",
        "",
        "package hushspec",
        "",
    ]

    for enum in ENUMS:
        lines.append(f"type {enum['name']} string")
        lines.append("")
        lines.append("const (")
        for value in enum["values"]:
            lines.append(
                f'\t{enum["name"]}{camel(value)} {enum["name"]} = "{value}"'
            )
        lines.append(")")
        lines.append("")

    for struct in STRUCTS:
        lines.append(f"type {struct['name']} struct {{")
        for field_info in struct["fields"]:
            tag_suffix = ",omitempty" if (not field_info["required"] or is_collection(field_info["type"])) else ""
            lines.append(
                f'\t{field_info["go_name"]} {go_type(field_info)} `yaml:"{field_info["wire"]}{tag_suffix}" json:"{field_info["wire"]}{tag_suffix}"`'
            )
        lines.append("}")
        lines.append("")

    content = "\n".join(lines).rstrip() + "\n"
    gofmt = shutil.which("gofmt")
    if gofmt is None:
        return content
    result = subprocess.run(
        [gofmt],
        input=content,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def write_or_check(path: Path, content: str, check: bool) -> list[str]:
    current = path.read_text() if path.exists() else None
    if current == content:
        return []
    if check:
        return [str(path.relative_to(ROOT))]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated files are out of date")
    args = parser.parse_args()

    stale: list[str] = []
    stale.extend(write_or_check(PY_OUTPUT, render_python(), args.check))
    stale.extend(write_or_check(RS_OUTPUT, render_rust(), args.check))
    stale.extend(write_or_check(GO_OUTPUT, render_go(), args.check))

    if stale:
        print("Generated model files are out of date:", file=sys.stderr)
        for path in stale:
            print(f"  {path}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
