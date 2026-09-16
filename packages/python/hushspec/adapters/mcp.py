from __future__ import annotations

from typing import Any, Callable, Optional

from hushspec.evaluate import EvaluationAction, EvaluationResult, args_size_of, normalize_host
from hushspec.middleware import HushGuard


def extract_domain(url: str) -> str:
    """The host a URL names, reduced as the evaluator reduces an egress target
    (core spec 3.14.2), or the raw value when it names none.

    Reducing here with the same algorithm the evaluator applies keeps a URL a
    browser would read one way from being read another way by a URL parser
    with different delimiter rules. Falling back to the raw string keeps the
    action evaluable: a policy's egress rules see *something* to match, so an
    unparseable destination is denied by a default-deny rule rather than
    quietly skipped.
    """
    if not isinstance(url, str):
        return str(url)
    return normalize_host(url) or url


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
    mapper = _MAPPINGS.get(tool_name)
    if mapper is not None:
        return mapper(args or {})

    return EvaluationAction(
        type="tool_call",
        target=tool_name,
        # Core spec 3.7: the UTF-8 byte length of the canonical JSON. A call
        # that carries an empty `arguments` object still carries arguments --
        # `{}` is two bytes -- and only a call with no `arguments` member at
        # all goes unmeasured, as it does in the TypeScript and Go adapters.
        args_size=None if args is None else args_size_of(args),
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
