# Staged conformance vectors

Vectors under `fixtures/staged/<spec-version>/` encode requirements that the
specification has ratified but the reference implementation has not yet
shipped. No fixture runner walks this directory. When an SDK implements the
behavior, the vector is promoted into `fixtures/` (same layout) and becomes
normative for conformance.

## 0.2.0

| File | Decision | Spec section | Blocked on |
|------|----------|--------------|------------|
| `posture/evaluation/transition-priority.test.yaml` | D18 (pending) | posture 5.3 | Ratifying whether a named `from` outranks `"*"` for the same trigger. The reference implementation selects the first matching transition in document order. |

Every other 0.2.0 vector was promoted in Wave 2 (P1-03/P1-08) when the Rust
reference evaluator implemented decisions D1--D17.
