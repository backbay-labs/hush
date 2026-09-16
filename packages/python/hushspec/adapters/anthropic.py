"""Anthropic (Claude) tool-use adapter.

Maps a ``tool_use`` content block from a Claude response onto the action a
policy evaluates. The point of the mapping is that Claude's *built-in* tools
are not opaque tool calls: ``bash`` is a shell command, the text editor is a
file read or a file write, ``computer`` is computer use, and a fetch tool is
egress to a host. Evaluating them as bare ``tool_call``s would let a policy's
``forbidden_paths``, ``shell_commands`` and ``egress`` rules -- the ones that
actually protect the machine -- sit out every decision.

Nothing here imports ``anthropic``: a block is read structurally, so both the
raw dicts of the HTTP API and the SDK's objects work, and the SDK stays a
dependency of the application rather than of the policy engine.
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlparse

from hushspec.evaluate import EvaluationAction, args_size_of
from hushspec.middleware import HushGuard

__all__ = [
    "map_claude_tool_to_action",
    "create_secure_tool_handler",
]

#: Anthropic versions its built-in server tools with a date suffix
#: (``text_editor_20250124``). The suffix names a revision of the same tool, so
#: it is stripped before matching -- a tool released next quarter maps the same
#: way instead of silently falling back to an opaque ``tool_call``.
_DATED_SUFFIX = re.compile(r"_20\d{6}$")

_SHELL_TOOLS = frozenset(("bash", "terminal"))
_EDITOR_TOOLS = frozenset(
    ("str_replace_editor", "str_replace_based_edit_tool", "text_editor")
)
_COMPUTER_TOOLS = frozenset(("computer",))
_FETCH_TOOLS = frozenset(("web_fetch", "fetch"))

#: Editor commands that only read. Everything else an editor does writes.
_EDITOR_READ_COMMANDS = frozenset(("view",))


def _member(block: Any, name: str) -> Any:
    """Read a member from a dict-shaped block or an SDK object."""
    if isinstance(block, dict):
        return block.get(name)
    return getattr(block, name, None)


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _host(url: str) -> str:
    """The host a fetch would reach, or the raw value when there is none.

    Falling back to the raw string keeps the action evaluable: a policy's egress
    rules see *something* to match, and an unparseable destination is denied by
    a default-deny egress rule rather than quietly skipped.
    """
    try:
        return urlparse(url).hostname or url
    except ValueError:
        return url


def map_claude_tool_to_action(tool_use_block: Any) -> EvaluationAction:
    """Map one Claude ``tool_use`` block to the action a policy evaluates.

    ``tool_use_block`` is the block as the Messages API returns it --
    ``{"type": "tool_use", "id": ..., "name": ..., "input": {...}}`` -- or any
    object with the same ``name`` and ``input`` members.

    ==========================  ==========================================
    Tool                        Action
    ==========================  ==========================================
    ``bash`` / ``terminal``     ``shell_command``, target ``input.command``
    text editor, ``view``       ``file_read``, target ``input.path``
    text editor, anything else  ``file_write``, target ``input.path``,
                                content ``input.new_str`` / ``file_text``
    ``computer``                ``computer_use``, target ``input.action``
    ``web_fetch`` / ``fetch``   ``egress``, target = host of ``input.url``
    ``mcp__server__tool``       ``tool_call`` on the inner tool name
    anything else               ``tool_call``, target = the tool name
    ==========================  ==========================================

    Every mapping records ``args_size`` for a ``tool_call`` so a policy can
    bound argument payloads, and the write path passes the new text through as
    ``content`` so ``secret_patterns`` and the detection pipeline can see what
    is about to be written.
    """
    name = _text(_member(tool_use_block, "name"))
    tool_input = _member(tool_use_block, "input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    base = _DATED_SUFFIX.sub("", name)

    if base in _SHELL_TOOLS:
        return EvaluationAction(
            type="shell_command",
            target=_text(tool_input.get("command")),
        )

    if base in _EDITOR_TOOLS:
        command = _text(tool_input.get("command"))
        path = _text(tool_input.get("path"))
        if command in _EDITOR_READ_COMMANDS:
            return EvaluationAction(type="file_read", target=path)
        content = tool_input.get("new_str")
        if content is None:
            # `create` carries the whole file under `file_text`.
            content = tool_input.get("file_text")
        return EvaluationAction(
            type="file_write",
            target=path,
            content=content if isinstance(content, str) else None,
        )

    if base in _COMPUTER_TOOLS:
        return EvaluationAction(
            type="computer_use",
            target=_text(tool_input.get("action")),
        )

    if base in _FETCH_TOOLS:
        return EvaluationAction(
            type="egress",
            target=_host(_text(tool_input.get("url"))),
        )

    if name.startswith("mcp__"):
        # Claude namespaces MCP tools as `mcp__<server>__<tool>`; a policy's
        # tool_access rules are written against the tool's own name.
        parts = name.split("__")
        inner = "__".join(parts[2:]) if len(parts) >= 3 else name
        return EvaluationAction(
            type="tool_call",
            target=inner,
            args_size=args_size_of(tool_input),
        )

    return EvaluationAction(
        type="tool_call",
        target=name,
        args_size=args_size_of(tool_input),
    )


def create_secure_tool_handler(
    guard: HushGuard,
    handler: Callable[..., Any],
) -> Callable[..., Any]:
    """Wrap a tool handler so the policy decides before the tool runs.

    The returned callable takes the same arguments as *handler*, whose first
    argument is the ``tool_use`` block. It enforces first: a denial raises
    :class:`~hushspec.middleware.HushSpecDenied` and the handler is never
    invoked, so a blocked tool cannot have run before the decision was recorded.
    Catch it in the agent loop and return its message as the ``tool_result`` for
    that ``tool_use_id`` to let the model see why it was refused.
    """

    def secure(tool_use_block: Any, *args: Any, **kwargs: Any) -> Any:
        guard.enforce(map_claude_tool_to_action(tool_use_block))
        return handler(tool_use_block, *args, **kwargs)

    return secure
