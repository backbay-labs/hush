from __future__ import annotations

import json
from typing import Callable

from hushspec.evaluate import EvaluationAction, EvaluationResult
from hushspec.middleware import HushGuard


def map_openai_tool_call(
    function_name: str,
    function_args: str | dict,
) -> EvaluationAction:
    """Map one OpenAI tool call onto the action a policy evaluates.

    ``args_size`` is the size of the arguments as they arrived, so a string
    payload is measured as its own bytes rather than as a re-serialization.
    Arguments that are not valid JSON raise: a tool call whose arguments
    cannot be read is not a call a policy should be asked to allow.
    """
    if isinstance(function_args, str):
        args_size = len(function_args)
        json.loads(function_args)
    else:
        args_size = len(json.dumps(function_args))

    return EvaluationAction(
        type="tool_call",
        target=function_name,
        args_size=args_size,
    )


def create_openai_guard(
    guard: HushGuard,
) -> Callable[..., EvaluationResult]:
    """A handler that maps an OpenAI tool call and evaluates it against *guard*."""

    def handler(
        function_name: str,
        function_args: str | dict,
    ) -> EvaluationResult:
        action = map_openai_tool_call(function_name, function_args)
        return guard.evaluate(action)

    return handler
