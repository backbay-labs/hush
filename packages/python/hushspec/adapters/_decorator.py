"""Shared implementation for framework function decorators.

The frameworks have different names for a decorated function, but their
security boundary is identical: derive an action from the invocation, enforce
it, and only then call the wrapped body.
"""

from __future__ import annotations

import inspect
from functools import wraps
from typing import Any, Callable, Optional, TypeAlias

from hushspec.evaluate import EvaluationAction, args_size_of
from hushspec.middleware import HushGuard


ActionMapper: TypeAlias = Callable[[tuple[Any, ...], dict[str, Any]], EvaluationAction]


def _is_bound_method_receiver(func: Callable[..., Any], value: Any) -> bool:
    """Whether ``value`` is the receiver passed by this decorated descriptor."""
    owner = value if isinstance(value, type) else type(value)
    name = getattr(func, "__name__", "")
    for candidate_owner in owner.__mro__:
        descriptor = candidate_owner.__dict__.get(name)
        if descriptor is None or isinstance(descriptor, staticmethod):
            continue
        wrapped = descriptor.__func__ if isinstance(descriptor, classmethod) else descriptor
        if getattr(wrapped, "__wrapped__", None) is func:
            return True
    return False


def _json_invocation_arguments(
    func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind a call to parameter names and omit a bound method's receiver."""
    bound = inspect.signature(func).bind(*args, **kwargs)
    bound.apply_defaults()
    values = dict(bound.arguments)
    first_parameter = next(iter(inspect.signature(func).parameters), None)
    if args and first_parameter is not None and _is_bound_method_receiver(func, args[0]):
        values.pop(first_parameter, None)
    return values


def _tool_call_action(
    name: str, func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> EvaluationAction:
    """Represent the actual Python invocation as a canonical JSON argument value."""
    size = args_size_of(_json_invocation_arguments(func, args, kwargs))
    if size is None:
        raise ValueError("tool call arguments must have a canonical JSON representation")
    return EvaluationAction(
        type="tool_call",
        target=name,
        args_size=size,
    )


def _mapped_action(
    *,
    name: str,
    func: Callable[..., Any],
    action_type: str,
    action_mapper: Optional[ActionMapper],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> EvaluationAction:
    if action_type == "tool_call":
        return _tool_call_action(name, func, args, kwargs)
    if action_mapper is None:
        raise ValueError("action_mapper is required for non-tool_call action types")
    action = action_mapper(args, kwargs)
    if not isinstance(action, EvaluationAction):
        raise ValueError("action_mapper must return an EvaluationAction")
    if action.type != action_type:
        raise ValueError("action_mapper returned an action with a different action type")
    if not isinstance(action.target, str) or not action.target:
        raise ValueError("action_mapper must return a non-empty action target")
    if action.content is not None and not isinstance(action.content, str):
        raise ValueError("action_mapper returned non-string action content")
    if action.args_size is not None and (
        not isinstance(action.args_size, int) or isinstance(action.args_size, bool) or action.args_size < 0
    ):
        raise ValueError("action_mapper returned an invalid args_size")
    return action


def guarded_tool(
    guard: HushGuard,
    tool_name: Optional[str],
    action_type: str,
    action_mapper: Optional[ActionMapper],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Build a decorator that preserves synchronous and coroutine functions."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        name = tool_name or getattr(func, "__name__", "unknown")

        def action_for(args: tuple[Any, ...], kwargs: dict[str, Any]) -> EvaluationAction:
            return _mapped_action(
                name=name,
                func=func,
                action_type=action_type,
                action_mapper=action_mapper,
                args=args,
                kwargs=kwargs,
            )

        if inspect.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                guard.enforce(action_for(args, kwargs))
                return await func(*args, **kwargs)

            return async_wrapper

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            guard.enforce(action_for(args, kwargs))
            return func(*args, **kwargs)

        return wrapper

    return decorator
