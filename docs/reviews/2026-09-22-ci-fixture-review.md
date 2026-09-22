# Hosted-CI fixture follow-up review

Scope: the two uncommitted test-only changes following hosted qualification of `295022c`: `packages/hushspec/tests/http-loader.test.ts` and the test module in `crates/hushspec/src/provider.rs`. The reviewer inspected the changes, surrounding fixture and production ordering, and the exact-head TypeScript and PR-coverage failure logs. No production behavior, dependency, configuration, timeout allowance, or assertion threshold changed.

## TypeScript residual connection budget

Hosted Node 20 reported `ECONNREFUSED 127.0.0.1` instead of the expected timeout. The old shared HTTPS fixture bound `localhost`, while this test deliberately pinned IPv4; its listener could select IPv6 instead. A functioning HTTPS fixture also allowed the handshake to complete and switch from the connection timer to the read timer, making it unsuitable for a connection-phase assertion.

The replacement binds a raw TCP listener explicitly to `127.0.0.1` and never completes TLS. Its advertised hostname remains `localhost`, so the actual loader still resolves through the controlled lookup and dials the pinned address. Accepted sockets are tracked and destroyed before closing the listener, and cleanup runs in `finally` after restoring timers.

The assertion still consumes 30 ms in DNS and requires rejection after the remaining 20 ms of the original 50 ms connection budget. It does not accept connection refusal, lengthen a timeout, or substitute a read-phase success condition.

The reviewer independently ran the complete HTTP-loader file under Node 20.20.2: 40 tests passed. The owner separately reports build, lint, all 43 files / 2,328 tests, and coverage passing on both Node 20.20.2 and Node 24.16.0.

## Rust watcher happy-path publication

Hosted PR coverage observed one error where the happy-path test asserted zero. The original `File::create` followed by `write_all` briefly published an empty watched file. The coordinator's controlled reproduction held that empty phase until the watcher reported an error, then failed the unchanged zero-error assertion with the same `1` versus `0` result; the diagnostic identified the missing `hushspec` field.

The repaired happy-path test writes and syncs a same-directory `NamedTempFile`, then atomically persists it over the watched path. The two policies differ in length, so detection does not rely on the removed short sleep producing a distinguishable timestamp. The initial file is still created before watching begins.

The test now waits for the initial and replacement `on_change` notifications. Inspection of `Loop::deliver` and `Loop::store` confirms this callback follows guard application, current-resolution publication, and generation increment. This removes the second race in which the test could observe the changed guard before the handle state was published. Receiver lifetime outlasts the watcher handle.

All original assertions remain: the guard initially allows and later denies, generation advances, error count stays zero, and the current policy is `blocking`. Failure output additionally includes `last_error`. The separate malformed-policy and guard-refusal tests remain unchanged; the fix does not suppress legitimate errors from non-atomic writes in production.

The reviewer independently ran all-feature provider tests: 11 passed, including the happy-path test and both refusal-retains-policy cases. `git diff --check` passed. Both modified regions are test code; the existing tempfile development dependency is reused.

## Limits considered before verdict

- These changes do not establish that arbitrary non-atomic policy writers produce no refusal events. Such events are legitimate, and production refusal handling is unchanged.
- Local Node 20 execution and focused provider tests do not replace the pending instrumented Rust run, full coordinator gates, or fresh exact-commit hosted CI. Previous failed runs on `295022c` remain failed evidence, not qualification of the next commit.
- No broader runtime re-review, merge, tag, or publication approval is included.

## Verdict

Pass for committing these fixture repairs and rerunning exact-commit qualification, subject to the coordinator's remaining gates. No Critical, Important, or Minor finding blocks this narrow delta. The fixtures now isolate the behaviors their unchanged assertions are intended to check.

## Coordinator qualification record

The direct run on `295022c` completed with 22 of 24 jobs passing: TypeScript and Coverage failed on the same TypeScript fixture. The PR run additionally exposed the Rust watcher fixture race under coverage. Those failures remain recorded; they are not treated as successful qualification.

Before the fixture commit, Node 20.20.2 and Node 24.16.0 each passed the TypeScript build, lint, all 2,328 tests, and coverage. Rust passed all 294 core tests and clippy. The revised watcher passed 50 consecutive executions, and all 10 default-feature provider tests passed under LLVM coverage instrumentation. Clean package verification and fresh exact-commit CI remain separate post-commit gates.
