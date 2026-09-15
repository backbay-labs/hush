#!/usr/bin/env python3
"""Evaluation microbenchmark: compile-per-call vs a compiled policy.

Run from anywhere::

    python packages/python/bench/evaluate.py
    python packages/python/bench/evaluate.py --repeat 5 --iterations 4000

It times the same mixed action set three ways against ``rulesets/default.yaml``:

``evaluate(spec, action)``
    the free function every existing caller uses. It compiles the policy on
    first use and reuses it, so this is what a caller sees today.

``compiled.evaluate(action)``
    the same evaluation with the compile hoisted out by the caller.

``compile-per-call``
    one ``compile_policy()`` plus one evaluation per action: an upper bound on
    compiling per call, and the cost of a policy hot-swap. It is not what the
    pre-refactor evaluator cost -- that one rebuilt matchers lazily, per
    pattern it consulted, with nothing memoized. To measure that, point
    ``PYTHONPATH`` at an older checkout's ``packages/python`` and run this same
    file.

Reported as nanoseconds per evaluation, best of ``--repeat`` runs (the best run
is the one least disturbed by other work on the machine). Stdlib only: no
pytest-benchmark, no numpy.

The script runs against whatever ``hushspec`` is importable, so a before/after
comparison is ``PYTHONPATH=<old checkout>/packages/python python ...`` against
the same file; it degrades to the free-function numbers alone when the package
predates ``compile_policy``.
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if not any(Path(entry).resolve() == REPO_ROOT / "packages" / "python" for entry in sys.path):
    sys.path.append(str(REPO_ROOT / "packages" / "python"))

import hushspec  # noqa: E402
from hushspec import EvaluationAction, evaluate, parse_or_raise  # noqa: E402
from hushspec.resolve import resolve_or_raise  # noqa: E402

compile_policy = getattr(hushspec, "compile_policy", None)

POLICY = REPO_ROOT / "rulesets" / "default.yaml"

SECRET = "AKIAIOSFODNN7EXAMPLE"
PATCH = "--- a/x\n+++ b/x\n" + "".join(f"+line {i}\n-line {i}\n" for i in range(20))

#: A mix that reaches every rule block the default ruleset configures, with
#: both matching and non-matching targets so neither the early-out nor the
#: full-scan path dominates.
ACTIONS: list[EvaluationAction] = [
    EvaluationAction(type="file_read", target="/home/u/project/src/main.py"),
    EvaluationAction(type="file_read", target="/home/u/.ssh/id_rsa"),
    EvaluationAction(type="file_write", target="/home/u/project/out.txt", content="hello"),
    EvaluationAction(type="file_write", target="/home/u/project/cfg.env", content=SECRET),
    EvaluationAction(type="egress", target="https://api.openai.com/v1/messages"),
    EvaluationAction(type="egress", target="evil.example.com:443"),
    EvaluationAction(type="tool_call", target="read_file", args_size=128),
    EvaluationAction(type="tool_call", target="shell_exec", args_size=128),
    EvaluationAction(type="tool_call", target="git_push", args_size=128),
    EvaluationAction(type="shell_command", target="ls -la /home/u/project"),
    EvaluationAction(type="shell_command", target="rm -rf /"),
    EvaluationAction(type="patch_apply", target="/home/u/project/src/main.py", content=PATCH),
]


def _best(fn: Callable[[], None], iterations: int, repeat: int) -> float:
    """Nanoseconds per call, best of *repeat* runs of *iterations* calls."""
    if iterations < 1 or repeat < 1:
        raise ValueError("iterations and repeat must both be at least 1")
    fn()  # warm up
    best = math.inf
    for _ in range(repeat):
        start = time.perf_counter_ns()
        for _ in range(iterations):
            fn()
        best = min(best, time.perf_counter_ns() - start)
    return best / iterations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--policy", default=str(POLICY))
    args = parser.parse_args()

    policy_path = Path(args.policy).resolve()
    spec = resolve_or_raise(
        parse_or_raise(policy_path.read_text()), source=str(policy_path)
    )
    actions = ACTIONS
    count = len(actions)

    print(f"policy:  {args.policy}")
    print(f"actions: {count} per iteration, {args.iterations} iterations x {args.repeat} runs")
    print(
        f"python:  {sys.version.split()[0]}   "
        f"hushspec spec {hushspec.__version__}"
    )
    print()

    def free() -> None:
        for action in actions:
            evaluate(spec, action)

    warm = _best(free, args.iterations, args.repeat) / count
    print(f"evaluate(spec, action)          {warm:9.0f} ns/action")

    if compile_policy is None:
        print("compile_policy(): not available in this build")
        return 0

    compiled = compile_policy(spec)

    def hoisted() -> None:
        for action in actions:
            compiled.evaluate(action)

    hot = _best(hoisted, args.iterations, args.repeat) / count
    print(f"compiled.evaluate(action)       {hot:9.0f} ns/action")

    def cold() -> None:
        for action in actions:
            compile_policy(spec).evaluate(action)

    per_call = _best(cold, max(args.iterations // 20, 20), args.repeat) / count
    print(f"compile-per-call                {per_call:9.0f} ns/action")

    def compile_only() -> None:
        compile_policy(spec)

    compile_ns = _best(compile_only, max(args.iterations // 20, 20), args.repeat)
    print(f"compile_policy(spec)            {compile_ns:9.0f} ns/policy")
    print()
    print(f"compiled vs compile-per-call:   {per_call / hot:6.1f}x")
    print(f"compiled vs free function:      {warm / hot:6.2f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
