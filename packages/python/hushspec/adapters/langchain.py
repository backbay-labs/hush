from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

from hushspec.evaluate import EvaluationAction
from hushspec.middleware import HushGuard


def hush_tool(
    guard: HushGuard,
    tool_name: Optional[str] = None,
    action_type: str = "tool_call",
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
    """

    def decorator(func: Callable) -> Callable:
        name = tool_name or getattr(func, "__name__", "unknown")

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            action = EvaluationAction(type=action_type, target=name)
            guard.enforce(action)
            return func(*args, **kwargs)

        return wrapper

    return decorator
