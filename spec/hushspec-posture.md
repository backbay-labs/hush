# HushSpec Posture Extension Specification

**Version:** 1.0.0-rc.1
**Status:** Release Candidate
**Date:** 2026-09-15
**Companion to:** HushSpec Core v0.2.0
**Supersedes:** 0.1.0 (2026-03-15). See Appendix C for the list of changes.

---

## 1. Overview

The Posture extension provides a declarative state machine for capability and budget management. An agent starts in an initial state and transitions between states based on triggers. Each state declares which capabilities are available and optional budget limits that constrain the number of operations the agent may perform.

Posture is declared under `extensions.posture` in a HushSpec document. When a conformant engine supports the posture extension, posture state MUST be evaluated alongside core rules. The active state's capabilities narrow the set of permitted actions, and budget limits impose hard ceilings on cumulative operation counts within a session.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

---

## 2. Schema

The posture extension is declared under `extensions.posture`:

```yaml
extensions:
  posture:
    initial: <state_name>       # REQUIRED. Must reference a key in states.
    states:
      <state_name>:
        description: <string>   # OPTIONAL. Human-readable description.
        capabilities:           # OPTIONAL. Capabilities available in this state.
          - <capability>
          - ...
        budgets:                # OPTIONAL. Budget limits for this state.
          <budget_key>: <integer>
    transitions:
      - from: <state_name|"*">  # REQUIRED. Source state ("*" matches any).
        to: <state_name>        # REQUIRED. Target state (must not be "*").
        on: <trigger>           # REQUIRED. What causes the transition.
        after: <duration>       # REQUIRED when on is "timeout".
```

### 2.1 `initial`

The `initial` field is REQUIRED and MUST reference a state name that exists as a key in the `states` object. This is the state the agent enters at session start.

### 2.2 `states`

The `states` field is REQUIRED and MUST contain at least one state. Each key is a state name (a string identifier), and each value is a state object with the following fields:

| Field          | Type              | Required | Description                                      |
|----------------|-------------------|----------|--------------------------------------------------|
| `description`  | string            | OPTIONAL | Human-readable description of this state.        |
| `capabilities` | array of string   | OPTIONAL | Capability identifiers available in this state.  |
| `budgets`      | object            | OPTIONAL | Budget limits keyed by budget key.               |

### 2.3 `transitions`

The `transitions` field is REQUIRED and MUST be an array of transition objects. Each transition declares how the state machine moves from one state to another.

| Field   | Type   | Required    | Description                                             |
|---------|--------|-------------|---------------------------------------------------------|
| `from`  | string | REQUIRED    | Source state name, or `"*"` to match any state.         |
| `to`    | string | REQUIRED    | Target state name. MUST NOT be `"*"`.                   |
| `on`    | string | REQUIRED    | Trigger that causes this transition.                    |
| `after` | string | CONDITIONAL | Duration string. REQUIRED when `on` is `"timeout"`.    |

---

## 3. Capabilities

Capabilities declare what categories of action an agent may perform in a given state. A rule block's `when.capability` condition (core Section 3.13) tests whether the effective state grants a capability, so a block can be gated on posture without being a capability guard itself. When the posture extension is active, an action that requires a capability (Section 3.3) is permitted by the posture guard only if the current state's `capabilities` array lists that capability. If `capabilities` is absent or empty, the state permits **no** capability-requiring action: every such action MUST be denied with `matched_rule` `extensions.posture.states.<state>.capabilities`. An empty capability list is the idiom for a locked-down state (see Appendix B); it is never "no restriction".

An action whose `posture.current` names a state absent from `states` MUST be denied with `matched_rule` `extensions.posture.states.<state>` (fail-closed).

The posture guard runs before core rule blocks (core Section 6.1); a deny from it is final.

Test vectors: `fixtures/posture/evaluation/posture-transitions.test.yaml`, `fixtures/posture/evaluation/empty-capabilities.test.yaml`, `fixtures/posture/evaluation/unknown-state-fail-closed.test.yaml`.

### 3.1 Standard Capabilities

The following capability identifiers are defined by this specification:

| Capability     | Description                                                |
|----------------|------------------------------------------------------------|
| `file_access`  | Read and navigate filesystem paths.                        |
| `file_write`   | Write, create, or modify files.                            |
| `egress`       | Make outbound network requests.                            |
| `shell`        | Execute shell commands.                                    |
| `tool_call`    | Invoke tools or MCP endpoints.                             |
| `patch`        | Apply patches or diffs to files.                           |
| `custom`       | Engine-defined custom capability.                          |

### 3.2 Forward Compatibility

Engines MAY support additional capability identifiers beyond the standard set. Conformant validators SHOULD produce warnings (not errors) for unrecognized capabilities. This ensures that documents authored for engines with extended capability sets remain valid under stricter validators.

### 3.3 Required Capability by Action Type

The posture guard maps each core action type (core Section 5) to the capability it requires:

| Action type      | Required capability |
|------------------|---------------------|
| `file_read`      | `file_access`       |
| `file_write`     | `file_write`        |
| `patch_apply`    | `patch`             |
| `shell_command`  | `shell`             |
| `tool_call`      | `tool_call`         |
| `egress`         | `egress`            |
| `custom`         | `custom`            |
| `computer_use`, `input_inject`, `browser_action`, `code_exec` | none (not gated by posture) |

Action types not in this table are unknown and are denied by the core evaluator before the posture guard runs (core Section 5).

---

## 4. Budget Keys

Budget limits impose hard ceilings on cumulative operation counts within a session or posture state. Budget values MUST be non-negative integers.

### 4.1 Standard Budget Keys

| Budget Key       | Description                                          |
|------------------|------------------------------------------------------|
| `file_writes`    | Maximum number of file write operations.             |
| `egress_calls`   | Maximum number of outbound network requests.         |
| `shell_commands` | Maximum number of shell command executions.          |
| `tool_calls`     | Maximum number of tool/MCP invocations.              |
| `patches`        | Maximum number of patch applications.                |
| `custom_calls`   | Maximum number of engine-defined custom operations.  |

### 4.2 Budget Enforcement

When a budget key reaches its limit, the corresponding action type MUST be denied. Engines MAY trigger a `budget_exhausted` transition (see Section 5) when any budget is fully consumed.

Budget counters are scoped to the session. Engines MAY support alternative scoping (per-state, per-window) as engine-specific extensions, but MUST document this behavior.

### 4.3 Budget Value Constraints

Budget values MUST be non-negative integers. A value of `0` means the operation is never permitted in this state. Validators MUST reject documents containing negative budget values.

---

## 5. Transition Triggers

Transitions define how the state machine moves between states. Each transition fires when its trigger condition is met.

### 5.1 Standard Triggers

| Trigger              | Description                                                              |
|----------------------|--------------------------------------------------------------------------|
| `user_approval`      | The user or operator explicitly approves a state change.                 |
| `user_denial`        | The user or operator explicitly denies a pending action or confirmation. |
| `critical_violation` | A core rule evaluation produces a deny for a critical-severity finding.  |
| `any_violation`      | Any core rule evaluation produces a deny.                                |
| `timeout`            | A duration has elapsed since entering the current state.                 |
| `budget_exhausted`   | Any budget in the current state has reached its limit.                   |
| `pattern_match`      | A content pattern match occurs (engine-specific semantics).              |

### 5.2 Trigger Semantics

- **`timeout`** transitions MUST include an `after` field specifying the duration. The `after` value is a string in the format `<number><unit>` where unit is one of: `s` (seconds), `m` (minutes), `h` (hours), `d` (days). Examples: `"30s"`, `"5m"`, `"1h"`, `"7d"`. Engines MUST support at least `s`, `m`, and `h` units.

- **`from: "*"`** matches any source state. This allows defining transitions that apply globally (e.g., a critical violation from any state transitions to a locked-down state).

- **`to` MUST NOT be `"*"`.** Wildcard targets are not permitted because the target state must be deterministic.

### 5.3 Transition Priority

When multiple transitions match the same trigger from the same source state, the engine MUST select the most specific `from` match. A named state takes priority over `"*"`. If two transitions have equal specificity, the first transition in document order wins.

Test vector: `fixtures/posture/evaluation/transition-priority.test.yaml`.

---

## 6. Validation Requirements

Conformant validators MUST enforce the following:

1. **Initial state reference.** The `initial` field MUST reference a key that exists in `states`. Documents where `initial` references a nonexistent state MUST be rejected.

2. **Transition state references.** All `from` values MUST either be `"*"` or reference a key in `states`. All `to` values MUST reference a key in `states` and MUST NOT be `"*"`. Documents with dangling state references MUST be rejected.

3. **Timeout after field.** Transitions with `on: "timeout"` MUST include an `after` field. Documents with timeout transitions missing `after` MUST be rejected.

4. **Duration format.** The `after` field MUST match the pattern `^\d+[smhd]$`. Invalid duration strings MUST cause document rejection.

5. **Budget values.** All budget values MUST be non-negative integers. Negative values MUST cause document rejection.

6. **Unknown capabilities.** Unrecognized capability identifiers SHOULD produce warnings but MUST NOT cause document rejection. This permits forward compatibility with extended capability sets.

7. **Unknown budget keys.** Unrecognized budget keys SHOULD produce warnings but MUST NOT cause document rejection.

8. **Unknown fields.** Unknown fields within posture objects (state objects, transition objects) MUST cause document rejection, consistent with core HushSpec strictness.

---

## 7. Merge Semantics

When a child document extends a base document that contains posture configuration, the following merge rules apply under `deep_merge` strategy:

### 7.1 States

Child states override base states by name. If a child defines a state with the same name as a base state, the child's state object entirely replaces the base's state object. States present in the base but absent in the child are preserved.

### 7.2 Transitions

Child transitions fully replace base transitions. If the child defines a `transitions` array, the base's `transitions` array is discarded entirely. If the child does not define `transitions`, the base's transitions are preserved.

### 7.3 Initial

If the child defines `initial`, it overrides the base's `initial`. If the child does not define `initial`, the base's value is preserved.

### 7.4 Replace and Merge Strategies

Under `replace` strategy, the child's posture object entirely replaces the base's. Under `merge` strategy, the child's posture object entirely replaces the base's (since posture is a single block under extensions).

---

## Security Considerations

The security considerations for the whole specification family are collected in `hushspec-security.md`; the ones that bear on this extension are the panic sentinel and monitor mode (Security Sections 10 and 11) for posture, and remote resolution and canonicalization (Security Sections 4 and 12) for origin overlays.

---

## Appendix A. Duration ABNF

```abnf
duration = 1*DIGIT unit
unit     = "s" / "m" / "h" / "d"
```

## Appendix B. Example

```yaml
hushspec: "0.1.0"
name: "posture-example"

extensions:
  posture:
    initial: "standard"
    states:
      standard:
        description: "Normal operating mode"
        capabilities:
          - file_access
          - file_write
          - egress
          - tool_call
        budgets:
          file_writes: 100
          egress_calls: 50
          tool_calls: 200
      restricted:
        description: "Limited mode after violation"
        capabilities:
          - file_access
          - tool_call
        budgets:
          tool_calls: 10
      locked:
        description: "No operations permitted"
        capabilities: []
    transitions:
      - from: "standard"
        to: "restricted"
        on: any_violation
      - from: "*"
        to: "locked"
        on: critical_violation
      - from: "restricted"
        to: "standard"
        on: user_approval
      - from: "standard"
        to: "restricted"
        on: timeout
        after: "1h"
      - from: "standard"
        to: "restricted"
        on: budget_exhausted
```

## Appendix C. Changes from 0.1.0

| Section | Change                                                                                                     |
|---------|------------------------------------------------------------------------------------------------------------|
| 3       | An absent or empty `capabilities` list denies every capability-requiring action. Version 0.1.0 said "no capability restriction is applied", which contradicted Appendix B's `locked` state and the implementations; the fail-closed reading is now normative. |
| 3       | Unknown posture state and guard ordering made explicit.                                                     |
| 3.3     | Required-capability table added; `custom` actions require the `custom` capability.                           |
| 5.3     | For the same trigger, a transition whose `from` names the current state outranks one whose `from` is `"*"`; among equals, document order wins. Implementations previously took the first match in document order. Test vector: `fixtures/posture/evaluation/transition-priority.test.yaml`. |
