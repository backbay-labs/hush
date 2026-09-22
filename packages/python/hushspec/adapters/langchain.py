from __future__ import annotations

from typing import Callable, Optional

from hushspec.middleware import HushGuard
from hushspec.adapters._decorator import ActionMapper, guarded_tool


def hush_tool(
    guard: HushGuard,
    tool_name: Optional[str] = None,
    action_type: str = "tool_call",
    action_mapper: Optional[ActionMapper] = None,
) -> Callable:
    """Decorator that wraps a LangChain tool function with HushSpec enforcement.

    Usage::

        guard = HushGuard.from_yaml(policy_yaml)

        @hush_tool(guard, tool_name="web_search")
        def web_search(query: str) -> str:
            ...

    If ``tool_name`` is omitted the wrapped function's ``__name__`` is used.
    Raises :class:`~hushspec.middleware.HushSpecDenied` when the policy denies
    the action.

    The wrapper keeps the wrapped function's signature and annotations:
    LangChain derives a tool's argument schema from them, so a wrapper that
    presented itself as ``(*args, **kwargs)`` would produce a tool with no
    typed arguments.

    ``tool_call`` actions use the configured tool name and the canonical size
    of the function's actual positional and keyword arguments. A different
    action type must provide ``action_mapper(args, kwargs)`` returning an
    :class:`~hushspec.evaluate.EvaluationAction`; the mapper is explicit
    because a Python function name cannot safely describe a command, path, or
    network destination.
    """
    return guarded_tool(guard, tool_name, action_type, action_mapper)
