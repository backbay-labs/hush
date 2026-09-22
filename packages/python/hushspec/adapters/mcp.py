from __future__ import annotations

from typing import Any, Optional

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


_FILE_READ_TOOLS = frozenset((
    "readfile", "read", "cat", "view", "viewfile", "listdirectory", "listdir", "ls",
))
_FILE_WRITE_TOOLS = frozenset((
    "writefile", "write", "createfile", "editfile", "edit", "appendfile", "strreplace",
))
_SHELL_TOOLS = frozenset((
    "bash", "sh", "shell", "exec", "execute", "executecommand", "runcommand", "terminal",
))
_EGRESS_TOOLS = frozenset((
    "fetch", "webfetch", "http", "httprequest", "httpfetch", "request", "apicall",
))
_PATH_KEYS = ("path", "filePath", "file_path", "file", "filename", "directory")
_CONTENT_KEYS = ("content", "contents", "text", "data", "new_str", "newStr")
_COMMAND_KEYS = ("command", "cmd", "script")
_URL_KEYS = ("url", "endpoint", "uri", "href")


def _normalize_tool_name(tool_name: str) -> str:
    return "".join(
        char for char in tool_name.lower()
        if char.isascii() and char.isalnum()
    )


def _first_string(args: dict[str, Any], keys: tuple[str, ...]) -> str:
    value = _first_optional_string(args, keys)
    return "" if value is None else value


def _first_optional_string(args: dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str):
            return value
    return None


def map_mcp_tool_call(
    tool_name: str,
    args: Optional[dict[str, Any]] = None,
) -> EvaluationAction:
    """Map one MCP tool call onto the action a policy evaluates."""
    fields = args or {}
    name = _normalize_tool_name(tool_name)
    size = None if args is None else args_size_of(args)
    if name in _FILE_READ_TOOLS:
        action = EvaluationAction(type="file_read", target=_first_string(fields, _PATH_KEYS))
    elif name in _FILE_WRITE_TOOLS:
        action = EvaluationAction(
            type="file_write",
            target=_first_string(fields, _PATH_KEYS),
            content=_first_optional_string(fields, _CONTENT_KEYS),
        )
    elif name in _SHELL_TOOLS:
        action = EvaluationAction(type="shell_command", target=_first_string(fields, _COMMAND_KEYS))
    elif name in _EGRESS_TOOLS:
        action = EvaluationAction(type="egress", target=extract_domain(_first_string(fields, _URL_KEYS)))
    else:
        action = EvaluationAction(type="tool_call", target=tool_name)
    action.args_size = size
    return action


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
