from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from trust import check_trust
from hushspec import (
    Actor, CallbackSink, EvaluationAction, HushGuard, compile_policy,
    parse_or_raise, resolve_file, validate,
)

policy_path = sys.argv[1] if len(sys.argv) > 1 else "policy.yaml"
document = parse_or_raise(Path(policy_path).read_text())
assert validate(document).is_valid
ok, resolved = resolve_file(policy_path)
assert ok, resolved
compiled = compile_policy(resolved)
check_trust(policy_path, resolved)
assert compiled.evaluate(EvaluationAction(type="tool_call", target="search")).decision.value == "allow"

receipts = []
options = dict(
    actor=Actor(agent_id="docs-agent", session_id="docs-session", principal="docs-user", runtime="docs/1.0.0"),
    sink=CallbackSink(receipts.append),
)
with TemporaryDirectory(prefix="hush-doc-effect-") as directory:
    output = Path(directory) / "effect.txt"
    dispatches = 0

    def dispatch(guard, tool):
        global dispatches
        outcome = guard.gate(EvaluationAction(type="tool_call", target=tool))
        if not outcome.proceed:
            return False
        with output.open("x") as file:
            file.write("confirmed once\n")
        dispatches += 1
        return True

    with HushGuard.from_file(policy_path, **options) as guard:
        assert not dispatch(guard, "deploy")
        assert not dispatch(guard, "write_file")
        assert dispatches == 0 and not output.exists()
    with HushGuard.from_file(policy_path, on_warn=lambda result, action: True, **options) as guard:
        assert dispatch(guard, "write_file")
        assert dispatches == 1
        assert output.read_text() == "confirmed once\n"
    assert receipts[-1].enforcement.outcome == "confirmed"
    assert receipts[-1].actor.agent_id == "docs-agent"
    try:
        HushGuard.from_yaml('hushspec: "1.0.0"\nunknown_rule: true\n')
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid policy was accepted")
print("PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused")
