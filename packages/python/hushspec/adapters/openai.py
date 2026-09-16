from __future__ import annotations

import json
from typing import Callable

from hushspec.evaluate import EvaluationAction, EvaluationResult, args_size_of
from hushspec.middleware import HushGuard


def map_openai_tool_call(
    function_name: str,
    function_args: str | dict,
) -> EvaluationAction:
    """Map one OpenAI tool call onto the action a policy evaluates.

    ``args_size`` is the UTF-8 byte length of the canonical JSON of the
    arguments (core spec 3.7), so a string payload is decoded and measured in
    that one form rather than as the bytes OpenAI happened to send: the model
    may pad the JSON with whitespace or escape a character it need not, and
    neither changes the arguments a ``max_args_size`` rule is about.
    Arguments that are not valid JSON raise: a tool call whose arguments
    cannot be read is not a call a policy should be asked to allow.
    """
    if isinstance(function_args, str):
        function_args = json.loads(function_args)
    args_size = args_size_of(function_args)

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
