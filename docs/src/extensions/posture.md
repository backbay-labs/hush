# Posture Extension

The full normative specification is at [`spec/hushspec-posture.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-posture.md).

## Overview

The Posture extension adds a declarative state machine for capability and budget management. An agent starts in an `initial` state and transitions between states based on triggers (violations, timeouts, approvals, budget exhaustion). Each state declares available capabilities and optional budget limits.

Posture is declared under `extensions.posture` in a HushSpec document.

## Key Concepts

- **States** define which capabilities are available and impose budget ceilings on operation counts.
- **Transitions** define how the agent moves between states, triggered by events like `critical_violation`, `timeout`, or `user_approval`.
- **Budgets** are hard limits on cumulative operations (e.g., max 100 file writes per session). When exhausted, the corresponding action type is denied.
- **Capabilities** narrow the set of permitted action types. Absent or empty capabilities deny every capability-requiring action; they never mean unrestricted access.

## Example

A 3-state posture configuration: normal operation, restricted mode after a violation, and full lockdown on critical violations.

```yaml
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

## Standard Capabilities

`file_access`, `file_write`, `egress`, `shell`, `tool_call`, `patch`, `custom`

## Standard Triggers

`user_approval`, `user_denial`, `critical_violation`, `any_violation`, `timeout`, `budget_exhausted`, `pattern_match`

## Schema and Field Reference

`initial` names a state. `states` maps names to objects containing `description`,
`capabilities`, and `budgets`. `transitions` contain `from`, `to`, and `on`, plus
`after` for a timeout. The complete field types and validation requirements are
in [posture sections 2 and 6](../../../spec/hushspec-posture.md#2-schema).
A timeout without `after`, a missing initial state, or an unknown runtime state
is not a fallback to unrestricted operation.

## Capability Narrowing

The action-to-capability table is [posture section 3.3](../../../spec/hushspec-posture.md#33-required-capability-by-action-type).
An empty list locks down capability-requiring actions; an action type outside
that table is not automatically covered by this guard. Keep its core rule enabled.
The runtime supplies the current state and event context. A model must not be
able to grant itself `user_approval` or rewrite its counters.

## Budget Enforcement

Standard keys are `file_writes`, `egress_calls`, `shell_commands`, `tool_calls`,
`patches`, and `custom_calls`. Values are non-negative integers. A zero budget
permits no corresponding operations; reaching a limit denies the next action.
Counters are session-scoped unless an engine documents another scope. The
evaluator consumes counters, while the host maintains them, including concurrent
reservation and failure accounting. See [posture section 4](../../../spec/hushspec-posture.md#4-budget-keys).

## Transition Priority

For the same trigger, a transition naming the current state outranks `from: "*"`.
Among equal-specificity matches, the first in document order wins. This is not
globally first-match-wins. See [posture section 5.3](../../../spec/hushspec-posture.md#53-transition-priority).

## Design Patterns

An approval gate starts with read-only capabilities and enters a write-capable
state only after host-confirmed approval. A timeout demotion returns elevated
sessions to restricted permissions. A violation ratchet moves toward a smaller
capability set after violations. The three-state example above combines these
ideas; a two-state gate can omit `locked`, while a budget-driven transition uses
`budget_exhausted`. Test each state and each simultaneous transition candidate.

## Merge Rules

Under `deep_merge`, child states replace base states by name, child transitions
replace the entire transition list, and an omitted `initial` inherits the base.
`merge` replaces the supplied extension block; `replace` uses only the child.
See [posture section 7](../../../spec/hushspec-posture.md#7-merge-semantics).
