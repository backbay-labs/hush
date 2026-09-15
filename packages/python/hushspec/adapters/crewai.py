from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

from hushspec.evaluate import EvaluationAction
from hushspec.middleware import HushGuard


def secure_tool(
    guard: HushGuard,
    tool_name: Optional[str] = None,
    action_type: str = "tool_call",
) -> Callable:
    """Decorator for CrewAI tool functions with HushSpec enforcement.

    Usage::

        guard = HushGuard.from_yaml(policy_yaml)

        @secure_tool(guard, tool_name="web_search")
        def web_search(query: str) -> str:
            ...

    If ``tool_name`` is omitted the wrapped function's ``__name__`` is used.
    Raises :class:`~hushspec.middleware.HushSpecDenied` when the policy denies
    the action.

    The wrapper keeps the wrapped function's signature and annotations, which
    is what a framework reads to build the tool's argument schema.
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
