from __future__ import annotations

from typing import Any, Callable, Optional
from urllib.parse import urlparse

from hushspec.evaluate import EvaluationAction, EvaluationResult, args_size_of
from hushspec.middleware import HushGuard


def extract_domain(url: str) -> str:
    """The host a URL names, or the raw value when it names none.

    Falling back to the raw string keeps the action evaluable: a policy's
    egress rules see *something* to match, so an unparseable destination is
    denied by a default-deny rule rather than quietly skipped.
    """
    if not isinstance(url, str):
        return str(url)
    try:
        return urlparse(url).hostname or url
    except ValueError:
        return url


def _path_action(action_type: str) -> Callable[[dict], EvaluationAction]:
    return lambda args: EvaluationAction(
        type=action_type, target=args.get("path", "")
    )


def _command_action(args: dict) -> EvaluationAction:
    return EvaluationAction(type="shell_command", target=args.get("command", ""))


def _fetch_action(args: dict) -> EvaluationAction:
    return EvaluationAction(type="egress", target=extract_domain(args.get("url", "")))


def _write_action(args: dict) -> EvaluationAction:
    return EvaluationAction(
        type="file_write",
        target=args.get("path", ""),
        content=args.get("content"),
    )


#: The MCP tools whose calls are a specific action rather than an opaque tool
#: call. Built once: this is the tool-call hot path.
_MAPPINGS: dict[str, Callable[[dict], EvaluationAction]] = {
    "read_file": _path_action("file_read"),
    "write_file": _write_action,
    "list_directory": _path_action("file_read"),
    "run_command": _command_action,
    "execute": _command_action,
    "fetch": _fetch_action,
    "http_request": _fetch_action,
}


def map_mcp_tool_call(
    tool_name: str,
    args: Optional[dict[str, Any]] = None,
) -> EvaluationAction:
    """Map one MCP tool call onto the action a policy evaluates."""
    args = args or {}
    mapper = _MAPPINGS.get(tool_name)
    if mapper is not None:
        return mapper(args)

    return EvaluationAction(
        type="tool_call",
        target=tool_name,
        # Core spec 3.7: the UTF-8 byte length of the canonical JSON.
        args_size=args_size_of(args) if args else None,
    )


def create_mcp_guard(
    guard: HushGuard,
) -> Callable[..., EvaluationResult]:
    """A handler that maps an MCP tool call and evaluates it against *guard*."""

    def handler(
        tool_name: str,
        args: Optional[dict[str, Any]] = None,
    ) -> EvaluationResult:
        action = map_mcp_tool_call(tool_name, args)
        return guard.evaluate(action)

    return handler
