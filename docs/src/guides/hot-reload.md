# Change policy safely at runtime

Hot reload is policy adoption under a running guard, not a guarantee of
nonblocking execution. Treat policy, provenance, compiled state and recorded
policy events as one ordered transition.

## Ordinary guard ordering

1. A check captures the policy in force and evaluates the action.
2. If needed, the confirmation handler completes under that check's ordering gate.
3. The guard records the receipt under the same policy.
4. A waiting reload adopts the next validated policy and records its policy event.
5. Subsequent checks use the new policy. Observers run outside the recording gate.

A slow confirmation or sink can delay reload. Bound callback work and avoid
network round trips inside synchronous sinks. A swap cannot revoke an effect
that an earlier successful check already dispatched.

## Callback contract

Confirmation handlers and custom receipt sinks must not call, or wait for
another thread to call, the same guard. Threaded SDKs can deadlock on that
dependency. TypeScript rejects synchronous re-entry with an explicit error.
Observer callbacks are delivered after recording finishes and may re-enter.
Do not move approval or authoritative recording into an observer: observers
cannot alter the decision they observe.

## Initial load, refusal and last-good state

| Event | Ordinary guard behavior | Application responsibility |
|---|---|---|
| Initial file/parse/configuration failure | Construction may fail | Stop startup; never fall back to an unguarded handler |
| Required signature cannot verify | Refused guard denies every action where the SDK supports refused construction | Surface refusal and repair trust/policy inputs |
| Replacement fails read, resolution, verification or compilation | Keep the last good policy and report failure | Alert on stale policy and retry deliberately |
| Replacement validates and is adopted | Record policy transition and use the new generation | Confirm the intended canonical hash is active |
| Receipt sink fails | Report `sink.error`; decision is not reversed | Respond to evidence loss according to operational policy |

The **experimental invocation coordinator has a different contract**: a rejected
installation leaves it refusing calls, and pending confirmations are bound to
the policy generation. Read [its lifecycle](../reference/trusted-invocation.md)
before adopting it; do not infer ordinary-guard behavior.

## Watchers, pollers and shutdown

Use a file watcher for local policy changes or a poller for a provider. Preserve
the same signature, host allowlist and digest-pin requirements on each load.
A driver commits its current snapshot only after the subscriber accepts it;
failed candidates remain eligible for retry.

The four [SDK guides](../reference/sdk-conformance.md#language-guides) identify
who starts and stops background work. TypeScript `fromProvider` starts watching;
its owner must stop the provider. Python/Go callers explicitly own watcher or
poller lifetimes. Rust handles stop on their documented lifecycle. Stop reload
loops before releasing dependent resources at shutdown.

For remote policy, use the bounded HTTPS loader with an explicit host allowlist.
Disallowed/reserved DNS addresses, redirects, size limits and timeouts are
refusals. Never “fix” one by disabling signature checks or accepting arbitrary
model-selected URLs.

## Panic and recovery

Configure a sentinel path the host controls. Sentinel absence must be provable;
an I/O error can arm panic. Panic is latched: deleting the file does not by
itself clear a process's in-memory panic state. The sentinel command controls
the file; reset the SDK latch through the application's authorized recovery path.

After an incident, inspect the active policy hash, repair permissions/trust,
clear the sentinel when appropriate, deliberately reset the latch, and test a
known-denied action before reopening traffic. Panic and refused-policy states
always enforce, even in monitor mode.

## Rollout checklist

Test a candidate offline; verify origin and monotonically increasing policy
version where used; stage a narrowly scoped monitor phase; review `would_block`
events; adopt enforcement; observe reload and sink errors. Keep exceptions
scoped, owner-approved and expiring. Retain evidence of the actual adopted hash,
not just the deployment configuration you intended to load.
