# Python SDK

Use the Python SDK at a runtime boundary you own. This guide needs Python 3.10 or newer
and the [quickstart policy](../../../examples/quickstart/policy.yaml).

`parse` and `resolve_file` use `(ok, value_or_error)` tuples; `parse_or_raise` is the throwing variant. `validate(...).is_valid` is a property. `check` returns `bool`; `gate` returns an outcome with `proceed`. `enforce` raises `HushSpecDenied` before the handler.

## Install and run the complete example

Create an empty directory. Download these files, preserving the listed relative
paths, and place `policy.yaml` at the top of that directory:

- [requirements.txt](../../../examples/sdks/python/requirements.txt)
- [main.py](../../../examples/sdks/python/main.py)
- [trust.py](../../../examples/sdks/python/trust.py)

This example installs `hushspec[signing]==1.0.0`. The `signing` extra supplies the cryptography backend; without it, signing operations raise `SigningUnavailable`. On Windows activate the venv with `.venv\Scripts\Activate.ps1` instead.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python main.py policy.yaml
```

Expected output: `PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused`.
All effects are in a fresh temporary directory. No model API or credentials are
required, and the program cleans up its own synthetic output.

## Enforce before the effect

The example parses and validates the policy, resolves it, and compiles it once.
It then attaches a consistent actor and callback receipt sink to the guard.
The synthetic handler creates one file only after enforcement permits dispatch.

<!-- docs-file: sdk-python-dispatch docs/examples/sdks/python/main.py -->
```python
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
```

The `on_warn` / `onWarn` callback in this demonstration approves one synthetic
test action. A real integration must obtain approval from an authenticated
channel and bind it to the pending action. Do not replace approval with
unconditional `true` in a production agent.

## Signing and keyrings

The companion `trust.py` program is called by the main example. It
creates an ephemeral test key, signs the resolved document, verifies with an
explicit keyring, and rejects a different keyring. It prints no private key and
does not persist one. Production signing identities belong to the operator.

Signing and verification must refer to the same resolved policy used for
evaluation. See [signing](../../signing-spec.md), [bundles](../../bundle-spec.md),
and the [exact signing APIs](../../reference/sdk-api.md#signing-keyrings-receipt-signing).
A successful signature proves authenticity relative to your trust roots, not
that a tool obeyed the policy.

## Providers and reload

`HushGuard.from_provider(FileProvider(path))` loads once by default. Opt into `watch=True` or `poll=True`, not both. Use the guard as a context manager or call `close()` to stop its loop. Guard operations serialize. Confirmation handlers and custom sinks must not call or wait on the same guard.

Initial policy-load errors cannot fall back to a nonexistent policy. Ordinary
guard reload preserves the last good policy on a rejected update and reports
the error. It is not nonblocking: reload can wait for confirmation and receipt
delivery. See [hot reload](../hot-reload.md) for ordering and the distinct
experimental coordinator refusal contract.

## Receipts and failure handling

The callback sink makes receipt contents visible to the test. It is not durable
storage. Configure a chained file sink or another reviewed delivery path for
operational evidence, and handle `sink.error` through an observer.
A failed ordinary sink does not change the decision; if dispatch must require a
durable permit, use the separately bounded [experimental invocation workflow](../../reference/trusted-invocation.md).

Receipts record actor fields, policy hash, decision, trace and enforcement outcome.
They do not carry raw action content. The `confirmed` outcome distinguishes an
approved warning from a plain allow.

## API map and next steps

The [SDK API contract](../../reference/sdk-api.md) covers parse/validate,
resolve/merge, compile/evaluate, actors, receipts, sinks, signing, keyrings,
providers, panic mode and error conventions. For mapping effects, read
[MCP](../integrations/mcp.md) and [runtime integration](../runtime-integration.md).
Use [conformance](../../reference/conformance.md) to understand what a test
corpus establishes; this example is an integration regression, not an
independent conformance certificate.
