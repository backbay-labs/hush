# RFC 07: Conditional Rules and Vertical Policy Library

**Status:** Historical design record (Draft)
**Authors:** HushSpec Core Team
**Date:** 2026-03-15
**HushSpec Version:** 0.1.0 (proposed additions targeting 0.2.0)

---

> **Delivery status:** See [the delivery ledger](STATUS.md#numbered-plan-reconciliation). Conditions and eight control-tagged library policies are implemented on the open stack. The larger vertical catalog and policy-registry ambitions remain explicit deferrals; current candidate qualification is pending.

## 1. Executive Summary

HushSpec v0.1.0 provides a solid foundation for declaring static security rules at the AI agent tool boundary. Its ten rule blocks cover filesystem access, network egress, secret detection, shell commands, tool access, computer use, and input injection. The posture extension adds stateful capability management, and the origins extension enables origin-aware policy projection.

However, real-world deployments expose three critical gaps:

1. **Static rules cannot adapt to runtime context.** A healthcare organization may want to allow broader tool access during business hours but restrict it overnight. A financial institution may need different egress rules in production versus staging. Today, these organizations must maintain separate HushSpec documents and swap them externally -- the spec itself has no notion of conditional evaluation.

2. **No general condition system exists.** The posture extension provides state-machine transitions triggered by discrete events (`user_approval`, `budget_exhausted`, `timeout`), and the origins extension matches on request source metadata. Neither supports general-purpose conditions such as time windows, user attributes, environment variables, or rate limits. Organizations are forced to encode these concerns in the enforcement engine, breaking HushSpec's portability guarantee.

3. **No shared policy library exists.** Every organization deploying HushSpec must author policies from scratch. Compliance-driven verticals (healthcare, finance, government) face the same regulatory requirements but have no way to start from vetted, community-reviewed policy templates. This slows adoption and increases the risk of misconfiguration.

This RFC proposes two complementary additions:

- **A condition system** that allows individual rule blocks to declare when they are active, based on deterministic, auditable predicates evaluated against a well-defined runtime context object.
- **A vertical policy library** containing curated, compliance-mapped HushSpec documents for healthcare (HIPAA), finance (SOC2, PCI-DSS), government (FedRAMP), education (FERPA), DevOps, and general-purpose deployments.

Together, these additions transform HushSpec from a static declaration format into an environment-aware security language with a practical on-ramp for regulated industries.

---

## 2. Current Conditional Capabilities

### 2.1 Posture Extension

The posture extension (`extensions.posture`) defines a finite state machine for capability management:

- **States** declare which capabilities (`file_access`, `file_write`, `egress`, `shell`, `tool_call`, `patch`) are available and impose per-state budget limits (`file_writes: 50`, `egress_calls: 20`).
- **Transitions** move between states in response to discrete events: `user_approval`, `user_denial`, `critical_violation`, `any_violation`, `timeout`, `budget_exhausted`, and `pattern_match`.

This provides a form of conditional behavior -- the active rule set changes based on the current posture state. For example, a `restricted` state can remove shell access while a `standard` state permits it. Transitions can degrade capabilities automatically when budgets are exhausted or violations occur.

**Strengths:**
- Well-defined state semantics with clear transitions
- Budget-based degradation is a powerful safety mechanism
- The `timeout` trigger with duration strings enables time-bounded elevated access

**Gaps:**
- Posture is purely event-driven; there is no way to condition a transition on external context (time of day, user role, environment)
- States are agent-session-scoped; there is no facility for organization-wide or deployment-wide conditional behavior
- Budgets are numeric counters, not rate limits (no "10 per minute" -- only "10 total")

### 2.2 Origins Extension

The origins extension (`extensions.origins`) provides origin-aware policy projection:

- **Profiles** bind match criteria (provider, tenant, space, visibility, tags, actor role) to policy overrides (tool access, egress, data handling, budgets, bridge policies).
- **Matching** uses specificity-based precedence (exact `space_id` beats broad `visibility` match).
- **Composition** is narrowing: origin allowlists intersect with base allowlists, origin blocklists union with base blocklists. The stricter of base or origin always wins.

This is a form of conditional rules -- the effective policy depends on where a request originates. An agent operating in an external-shared Slack channel gets different rules than one in a private incident-response channel.

**Strengths:**
- Rich match criteria covering common enterprise communication platforms
- Narrowing composition enforces the principle of least privilege
- Cross-origin bridge policies address data flow between contexts

**Gaps:**
- Match criteria are limited to origin metadata; no support for user attributes, deployment environment, or temporal conditions
- No general condition combinators (AND/OR/NOT across arbitrary predicates)
- Cannot express "this rule applies only during business hours" or "this rule applies only for premium-tier users"

### 2.3 Gap Analysis

| Capability | Posture | Origins | Needed |
|---|---|---|---|
| Time-based activation | `timeout` trigger only (duration after state entry) | None | Time windows with timezone support |
| User attributes | None | `actor_role` field in match criteria | General user context (role, tier, groups, department) |
| Environment awareness | None | None | Environment labels (production, staging, dev) |
| Rate limiting | Budgets (total count per session) | Per-origin budgets | Sliding-window rate limits |
| Compound conditions | None | AND semantics on tags | General AND/OR/NOT combinators |
| Capability-based gating | State capabilities (present/absent) | None | Condition on agent capabilities or model type |

---

## 3. Conditional Rules Design

### 3.1 Design Principles

The condition system is governed by five principles drawn from HushSpec's core philosophy:

1. **Fail-closed.** If a condition cannot be evaluated (missing context field, unknown condition type, evaluation error), the rule block is treated as if it produces a `deny` decision. Specifically: when a `when` condition fails to evaluate, the rule block behaves as though `enabled: false` were set, except that the engine MUST also emit a diagnostic. Since a deactivated rule block does not contribute decisions, the remaining active rule blocks determine the outcome. If no other rule block covers the action type, the engine's default (which MUST be deny for Level 3 conformance) applies.

2. **Deterministic.** Given the same context object and the same condition, the result is always the same. No randomness, no external I/O during evaluation.

3. **Not Turing-complete.** Conditions are a fixed set of predicate types composed with AND/OR/NOT. There are no loops, no variables, no recursion, no general arithmetic, no string manipulation, and no user-defined functions. This is intentional: policies must be auditable by humans and analyzable by tools. The condition language is equivalent in power to a propositional logic over a finite set of ground predicates -- it can express any boolean combination of fixed checks, but it cannot compute new values.

4. **Portable.** Conditions evaluate against a well-defined context object. The context schema is part of the specification; engines populate it from their runtime environment.

5. **Backward-compatible.** The `when` field is optional. Documents without `when` fields are valid and behave identically to v0.1.0. Engines that do not support conditions MUST reject documents containing `when` fields with a clear error message indicating that conditions require HushSpec 0.2.0 support. This preserves fail-closed semantics. Engines MUST NOT silently ignore `when` fields, because doing so could over-permit (a conditional restriction would be evaluated unconditionally as always-active, or worse, always-inactive).

### 3.2 The `when` Field

Each rule block gains an optional `when` field. When present, the rule block is active only if the condition evaluates to `true`. When absent, the rule block is unconditionally active (preserving v0.1.0 behavior).

```yaml
rules:
  egress:
    enabled: true
    allow: ["api.openai.com"]
    default: block
    when:
      context:
        environment: production
```

The `when` field appears at the same level as `enabled`. Evaluation order:

1. If `enabled` is `false`, the rule block is inert regardless of `when`.
2. If `when` is present and evaluates to `false`, the rule block is inert.
3. Otherwise, the rule block is active and its normal semantics apply.

This means `enabled: false` is an unconditional override (useful for emergency disablement), while `when` provides conditional activation.

### 3.3 Condition Types

#### 3.3.1 Time Window Conditions

Activate a rule block only during specific time periods.

```yaml
rules:
  tool_access:
    allow: [deploy, database_write]
    default: block
    when:
      time_window:
        start: "09:00"
        end: "17:00"
        timezone: "America/New_York"
        days: [mon, tue, wed, thu, fri]
```

**Schema:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `start` | string | REQUIRED | -- | Start time in `HH:MM` (24-hour) format |
| `end` | string | REQUIRED | -- | End time in `HH:MM` (24-hour) format |
| `timezone` | string | OPTIONAL | `"UTC"` | IANA timezone identifier |
| `days` | array of string | OPTIONAL | all days | Day abbreviations: `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun` |

**Semantics:**
- If `start` < `end`, the window is the period from `start` to `end` on the specified days.
- If `start` > `end`, the window wraps across midnight (e.g., `start: "22:00"`, `end: "06:00"` covers 10 PM to 6 AM).
- If `start` == `end`, the window is the entire day (24 hours) on the specified days.
- An invalid timezone identifier MUST cause document rejection (fail-closed).
- The current time is obtained from the engine's runtime environment. Engines MUST document their time source and SHOULD support clock injection for testing.

#### 3.3.2 Context Conditions

Activate a rule block based on runtime context values.

```yaml
rules:
  egress:
    allow: ["*.internal.corp"]
    default: block
    when:
      context:
        environment: production
        user.tier: premium
```

**Schema:**

The `context` condition is an object whose keys are dot-delimited paths into the runtime context object (Section 3.4) and whose values are the expected values. All key-value pairs must match (AND semantics).

| Value Type | Matching Rule |
|---|---|
| string | Exact string equality |
| boolean | Exact boolean equality |
| integer | Exact numeric equality |
| array of string | Context field value must be one of the listed values (OR within a single key) |

**Examples:**

```yaml
# Match exactly one value
when:
  context:
    environment: production

# Match any of several values (OR within a key)
when:
  context:
    environment: [production, staging]

# Match multiple fields (AND across keys)
when:
  context:
    environment: production
    user.role: admin

# Match nested context using dot notation
when:
  context:
    agent.type: coding-assistant
    user.groups: ml-team   # true if "ml-team" is in user.groups array
```

**Missing context fields:** If a context condition references a field that is not present in the runtime context object, the condition evaluates to `false` (fail-closed). The engine SHOULD log a warning indicating which context field was missing.

#### 3.3.3 Capability Conditions

Activate a rule block based on the declared capabilities of the agent.

```yaml
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: database_connection_string
        pattern: "(?i)(postgres|mysql|mongodb)://[^\\s]+"
        severity: critical
    when:
      capability:
        has: [database_access]
```

**Schema:**

| Field | Type | Required | Description |
|---|---|---|---|
| `has` | array of string | OPTIONAL | Capabilities that MUST be present (AND) |
| `lacks` | array of string | OPTIONAL | Capabilities that MUST be absent (AND) |

**Semantics:**
- The agent's declared capabilities are provided in the context object under `agent.capabilities`.
- If `has` is specified, every listed capability must be present in `agent.capabilities`.
- If `lacks` is specified, none of the listed capabilities may be present in `agent.capabilities`.
- If both `has` and `lacks` are specified, both constraints must be satisfied.
- If `agent.capabilities` is not present in the context, the condition evaluates to `false`.

#### 3.3.4 Rate Conditions

Activate (or deactivate) a rule block based on action frequency. Unlike posture budgets (which are total counts per session), rate conditions express sliding-window limits.

```yaml
rules:
  tool_access:
    allow: []
    block: [deploy]
    default: allow
    when:
      rate:
        action_type: tool_call
        count: 100
        window: "1h"
        behavior: activate_above
```

**Schema:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `action_type` | string | REQUIRED | -- | Action type to count (from Section 5 of core spec) |
| `count` | integer | REQUIRED | -- | Threshold count |
| `window` | string | REQUIRED | -- | Sliding window duration (same format as posture `after`: `<number><unit>`, unit in `s`, `m`, `h`, `d`) |
| `behavior` | string | OPTIONAL | `"activate_above"` | One of `"activate_above"` or `"activate_below"` |

**Semantics:**
- `activate_above`: The rule block is active when the number of actions of the specified type within the sliding window exceeds `count`. This is the common case -- "after 100 tool calls in an hour, activate this restrictive rule."
- `activate_below`: The rule block is active when the action count is at or below `count`. This is useful for "allow expensive operations only when usage is low."
- The engine is responsible for maintaining action counters. Counter scope (per-session, per-user, per-agent) is engine-specific but MUST be documented.
- If the engine does not support rate tracking, the condition evaluates to `false` (fail-closed), and the engine MUST log a warning.

#### 3.3.5 Compound Conditions

Combine multiple conditions with boolean logic.

```yaml
rules:
  shell_commands:
    forbidden_patterns: []
    when:
      all_of:
        - time_window:
            start: "09:00"
            end: "17:00"
            timezone: "America/New_York"
            days: [mon, tue, wed, thu, fri]
        - context:
            environment: production
            user.role: [admin, sre]
```

**Combinators:**

| Field | Type | Description |
|---|---|---|
| `all_of` | array of Condition | All conditions must be true (AND) |
| `any_of` | array of Condition | At least one condition must be true (OR) |
| `not` | Condition | The condition must be false (NOT) |

**Nesting:** Combinators may be nested to any depth. However, implementations MAY impose a maximum nesting depth (RECOMMENDED: 8 levels) to prevent pathological cases. Documents exceeding the depth limit MUST be rejected.

**Examples:**

```yaml
# Business hours AND production AND (admin OR sre)
when:
  all_of:
    - time_window:
        start: "09:00"
        end: "17:00"
        timezone: "UTC"
    - context:
        environment: production
    - any_of:
        - context:
            user.role: admin
        - context:
            user.role: sre

# NOT during maintenance window
when:
  not:
    time_window:
      start: "02:00"
      end: "04:00"
      timezone: "America/Los_Angeles"
      days: [sun]

# Off-hours restriction (activate rule when NOT business hours)
when:
  not:
    time_window:
      start: "09:00"
      end: "17:00"
      timezone: "America/New_York"
      days: [mon, tue, wed, thu, fri]
```

### 3.4 Runtime Context Object

The context object is a structured bag of key-value pairs populated by the engine at evaluation time. Conditions reference context fields using dot-delimited paths.

```yaml
# Canonical context schema (informative)
context:
  user:
    id: "user-123"
    role: "developer"
    tier: "premium"
    groups: ["engineering", "ml-team"]
    department: "engineering"
    email_domain: "corp.example.com"
  environment: "production"
  deployment:
    region: "us-east-1"
    cluster: "prod-01"
    cloud_provider: "aws"
  agent:
    id: "agent-456"
    type: "coding-assistant"
    model: "claude-sonnet-4-6"
    capabilities: ["file_access", "file_write", "egress", "tool_call"]
    version: "2.1.0"
  session:
    id: "session-789"
    started_at: "2026-01-15T10:00:00Z"
    action_count: 42
    duration_seconds: 1800
  request:
    id: "req-012"
    timestamp: "2026-01-15T10:30:00Z"
  custom: {}
```

**Standard context fields:**

| Path | Type | Description |
|---|---|---|
| `user.id` | string | Unique user identifier |
| `user.role` | string | User's role (e.g., `admin`, `developer`, `viewer`) |
| `user.tier` | string | Subscription or access tier |
| `user.groups` | array of string | Groups the user belongs to |
| `user.department` | string | Organizational department |
| `user.email_domain` | string | Domain portion of user's email |
| `environment` | string | Deployment environment (`production`, `staging`, `development`, `test`) |
| `deployment.region` | string | Cloud region or datacenter identifier |
| `deployment.cluster` | string | Cluster or deployment group identifier |
| `deployment.cloud_provider` | string | Cloud provider identifier |
| `agent.id` | string | Unique agent instance identifier |
| `agent.type` | string | Agent type (e.g., `coding-assistant`, `data-analyst`) |
| `agent.model` | string | Model identifier |
| `agent.capabilities` | array of string | Declared agent capabilities |
| `agent.version` | string | Agent version |
| `session.id` | string | Session identifier |
| `session.started_at` | string | ISO 8601 timestamp of session start |
| `session.action_count` | integer | Total actions in this session |
| `session.duration_seconds` | integer | Session duration in seconds |
| `request.id` | string | Current request identifier |
| `request.timestamp` | string | ISO 8601 timestamp of current request |
| `custom` | object | Engine-specific custom fields |

**Extensibility:** The `custom` namespace is reserved for engine-specific context fields. Condition expressions MAY reference `custom.*` paths. Standard fields (everything outside `custom`) are part of the specification and engines SHOULD populate them when the information is available.

**Array membership:** When a context condition references a field whose value is an array (e.g., `user.groups`) and the condition value is a scalar string, the condition is true if the scalar is a member of the array. This enables patterns like:

```yaml
when:
  context:
    user.groups: ml-team  # true if "ml-team" is in the user.groups array
```

### 3.5 Condition Evaluation Semantics

#### 3.5.1 Evaluation Order

Conditions are evaluated **before** rule-block-specific logic. This avoids unnecessary work (e.g., regex compilation for secret patterns) when the condition will deactivate the block.

The full evaluation pipeline for a single action against a single rule block:

1. Check `enabled`. If `false`, the block is inert. Stop.
2. Evaluate `when`. If the condition is `false`, the block is inert. Stop.
3. Apply rule-block-specific semantics (pattern matching, allowlist checks, etc.).
4. Produce a decision (`allow`, `warn`, or `deny`).

#### 3.5.2 Interaction with Decision Precedence

Conditional rules do not change decision precedence (Section 6.1 of the core spec). When a condition deactivates a rule block, that block simply does not participate in the decision. It is as if the block were absent from the document.

Example: A document has two `tool_access` configurations (one conditional, one not). This is NOT how HushSpec works -- each rule block appears at most once. Instead, conditional rules within a single block control whether that block contributes to the decision.

If an organization needs different tool-access rules for different contexts, they should use either:
- The `extends` mechanism with separate documents, or
- The origins extension for origin-based variation, or
- Multiple documents with conditions on different rule blocks that collectively cover the policy.

#### 3.5.3 Interaction with Posture and Origins

The `when` field is available on core rule blocks only (within `rules.*`). Extension blocks (`extensions.posture`, `extensions.origins`, `extensions.detection`) do not support `when` in this proposal. The rationale is that posture and origins already provide their own conditional mechanisms; adding `when` to them would create confusing interactions. A future RFC may revisit this constraint.

The condition system is orthogonal to posture and origins:

- **Posture** manages state transitions driven by events within the agent session. Conditions gate static rule blocks based on external context. They can coexist: a rule block might be conditional on business hours (via `when`) while the posture extension manages degradation within those hours (via budget exhaustion). Importantly, posture capability checks are evaluated independently of `when` conditions. If a `when` condition deactivates a rule block, posture still enforces its own capability restrictions. For example, if `rules.tool_access` is deactivated by a `when` condition, but the current posture state lacks the `tool_call` capability, the action is still denied by posture -- posture operates at a layer below rule blocks.

- **Origins** project policy based on request source. Conditions gate rule blocks based on runtime context. They can coexist: an origin profile might restrict tool access for external channels, while a `when` condition further restricts tool access outside business hours. Origin narrowing is applied after `when` evaluation: first the rule block is activated/deactivated by `when`, then origin overrides are composed on top of the active rule block.

There is intentional overlap between `context.user.role` in conditions and `actor_role` in origins match criteria. The guidance is:
- Use **origins** when the policy variation is tied to the communication platform and channel context (Slack channel visibility, GitHub PR context).
- Use **conditions** when the policy variation is tied to deployment environment, time, user attributes, or agent properties that are independent of the communication platform.

#### 3.5.4 Error Handling

| Scenario | Behavior |
|---|---|
| Unknown condition type | Document rejection (fail-closed) |
| Missing context field referenced by `context` condition | Condition evaluates to `false`; engine SHOULD log warning |
| Invalid timezone in `time_window` | Document rejection (fail-closed) |
| Invalid `start`/`end` time format | Document rejection (fail-closed) |
| Invalid day abbreviation in `days` | Document rejection (fail-closed) |
| `rate` condition when engine lacks rate tracking | Condition evaluates to `false`; engine MUST log warning |
| Nesting depth exceeded | Document rejection (fail-closed) |
| Type mismatch (condition expects string, context has integer) | Condition evaluates to `false`; engine SHOULD log warning |
| Engine does not support conditions but document contains `when` | Document rejection with clear error message |

---

## 4. Design Considerations

### 4.1 Simplicity and Auditability

The condition system is deliberately limited. There are exactly five condition types (`time_window`, `context`, `capability`, `rate`, and compound combinators). This is not accidental -- every condition type added increases the cognitive burden on policy authors and auditors. A security auditor reviewing a HushSpec document should be able to understand every condition's effect without consulting external documentation or running code.

**Anti-goals:**
- No expression language (no `user.age > 18`)
- No string interpolation or templating
- No reference to external data sources at evaluation time
- No conditional mutation of rule parameters (a condition activates or deactivates a block; it does not change the block's values)

### 4.2 Turing-Completeness Avoidance

The condition system is intentionally not Turing-complete:
- No loops or recursion
- No mutable state (conditions are pure predicates)
- No general arithmetic (rate conditions have a fixed threshold comparison, not arbitrary expressions)
- No string operations (no regex, no substring, no concatenation)
- Finite nesting depth for compound conditions
- No self-reference (a condition cannot reference the result of another condition)
- No data flow between conditions (each condition evaluates independently against the context)

This guarantees that condition evaluation always terminates and has bounded resource consumption. Specifically, evaluation of a condition tree of depth D with N leaf conditions requires O(N) predicate evaluations and O(D) stack depth, both bounded by document validation.

### 4.3 Determinism

Given the same context object and the same wall-clock time, condition evaluation MUST produce the same result. Conditions do not have side effects. The `rate` condition depends on historical action counts, which is state external to the condition itself -- the engine maintains this state and injects it into the evaluation. The condition itself is a pure function of its inputs.

### 4.4 Performance

Conditions are evaluated before rule-block logic, so they serve as early-exit short circuits:
- A `context` condition is a map lookup and comparison -- O(k) where k is the number of context keys in the condition.
- A `time_window` condition is a single timestamp comparison -- O(1).
- A `capability` condition is an array membership check -- O(c * h) where c is the number of agent capabilities and h is the number of `has`/`lacks` entries.
- A `rate` condition requires a counter lookup -- O(1) with appropriate data structures.
- Compound conditions are bounded by the nesting depth limit.

Rule-block logic (regex compilation, glob matching) is avoided entirely when the condition short-circuits.

---

## 5. Schema Changes

### 5.1 Condition Schema (JSON Schema)

The following additions to the core schema introduce the condition system.

```json
{
  "$defs": {
    "Condition": {
      "oneOf": [
        { "$ref": "#/$defs/TimeWindowCondition" },
        { "$ref": "#/$defs/ContextCondition" },
        { "$ref": "#/$defs/CapabilityCondition" },
        { "$ref": "#/$defs/RateCondition" },
        { "$ref": "#/$defs/AllOfCondition" },
        { "$ref": "#/$defs/AnyOfCondition" },
        { "$ref": "#/$defs/NotCondition" }
      ]
    },
    "TimeWindowCondition": {
      "type": "object",
      "required": ["time_window"],
      "additionalProperties": false,
      "properties": {
        "time_window": {
          "type": "object",
          "required": ["start", "end"],
          "additionalProperties": false,
          "properties": {
            "start": {
              "type": "string",
              "pattern": "^([01]\\d|2[0-3]):[0-5]\\d$",
              "description": "Start time in HH:MM 24-hour format."
            },
            "end": {
              "type": "string",
              "pattern": "^([01]\\d|2[0-3]):[0-5]\\d$",
              "description": "End time in HH:MM 24-hour format."
            },
            "timezone": {
              "type": "string",
              "default": "UTC",
              "description": "IANA timezone identifier (e.g., America/New_York)."
            },
            "days": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
              },
              "description": "Days of the week. Defaults to all days."
            }
          }
        }
      }
    },
    "ContextCondition": {
      "type": "object",
      "required": ["context"],
      "additionalProperties": false,
      "properties": {
        "context": {
          "type": "object",
          "description": "Map of dot-delimited context paths to expected values. All must match (AND).",
          "additionalProperties": {
            "oneOf": [
              { "type": "string" },
              { "type": "boolean" },
              { "type": "integer" },
              {
                "type": "array",
                "items": { "type": "string" }
              }
            ]
          }
        }
      }
    },
    "CapabilityCondition": {
      "type": "object",
      "required": ["capability"],
      "additionalProperties": false,
      "properties": {
        "capability": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "has": {
              "type": "array",
              "items": { "type": "string" },
              "description": "Capabilities that must be present."
            },
            "lacks": {
              "type": "array",
              "items": { "type": "string" },
              "description": "Capabilities that must be absent."
            }
          }
        }
      }
    },
    "RateCondition": {
      "type": "object",
      "required": ["rate"],
      "additionalProperties": false,
      "properties": {
        "rate": {
          "type": "object",
          "required": ["action_type", "count", "window"],
          "additionalProperties": false,
          "properties": {
            "action_type": {
              "type": "string",
              "enum": [
                "file_read", "file_write", "egress",
                "shell_command", "tool_call", "patch_apply",
                "computer_use", "input_inject"
              ],
              "description": "Action type to count."
            },
            "count": {
              "type": "integer",
              "minimum": 0,
              "description": "Threshold count."
            },
            "window": {
              "type": "string",
              "pattern": "^\\d+[smhd]$",
              "description": "Sliding window duration."
            },
            "behavior": {
              "type": "string",
              "enum": ["activate_above", "activate_below"],
              "default": "activate_above",
              "description": "Whether the rule activates above or below the threshold."
            }
          }
        }
      }
    },
    "AllOfCondition": {
      "type": "object",
      "required": ["all_of"],
      "additionalProperties": false,
      "properties": {
        "all_of": {
          "type": "array",
          "items": { "$ref": "#/$defs/Condition" },
          "minItems": 1,
          "description": "All conditions must be true."
        }
      }
    },
    "AnyOfCondition": {
      "type": "object",
      "required": ["any_of"],
      "additionalProperties": false,
      "properties": {
        "any_of": {
          "type": "array",
          "items": { "$ref": "#/$defs/Condition" },
          "minItems": 1,
          "description": "At least one condition must be true."
        }
      }
    },
    "NotCondition": {
      "type": "object",
      "required": ["not"],
      "additionalProperties": false,
      "properties": {
        "not": {
          "$ref": "#/$defs/Condition",
          "description": "The condition must be false."
        }
      }
    }
  }
}
```

### 5.2 Rule Block Schema Changes

Each rule block definition (e.g., `ForbiddenPaths`, `Egress`, `ToolAccess`) gains an optional `when` property:

```json
{
  "when": {
    "$ref": "#/$defs/Condition",
    "description": "Condition that must be true for this rule block to be active."
  }
}
```

This is added to: `ForbiddenPaths`, `PathAllowlist`, `Egress`, `SecretPatterns`, `PatchIntegrity`, `ShellCommands`, `ToolAccess`, `ComputerUse`, `RemoteDesktopChannels`, `InputInjection`.

### 5.3 Backward Compatibility

- `when` is optional on all rule blocks. Documents without `when` are fully backward-compatible.
- Engines that do not implement conditions MUST reject documents containing `when` fields with a clear error message indicating conditions are not supported. This preserves fail-closed semantics and prevents silent misconfiguration.
- The recommended approach for engines that do not implement conditions is rejection, which preserves fail-closed semantics.

### 5.4 Versioning Strategy

The condition system is introduced in HushSpec 0.2.0. Documents using conditions MUST declare `hushspec: "0.2.0"`. This allows engines to detect and reject unsupported features cleanly.

Since HushSpec is in the v0.x series, this is a permitted minor-version change. Engines supporting 0.2.0 MUST also accept 0.1.0 documents (which will never contain `when` fields).

**Conformance test requirement:** The conformance test suite MUST include a test vector where a 0.1.0-only engine receives a 0.2.0 document containing `when` fields. The expected behavior is document rejection with a version-mismatch error.

---

## 6. Vertical Policy Library

### 6.1 Library Structure

The policy library lives in a top-level `library/` directory alongside `rulesets/`. While `rulesets/` contains generic security profiles (default, strict, permissive), `library/` contains compliance-mapped, vertical-specific policies.

```
library/
  healthcare/
    hipaa-base.yaml               # HIPAA-compliant base policy
    hipaa-coding-agent.yaml       # Coding assistants in healthcare orgs
    hipaa-data-analysis.yaml      # Data analysis agents handling PHI
    README.md
  finance/
    soc2-base.yaml                # SOC2 compliance base
    pci-dss.yaml                  # PCI-DSS for payment data contexts
    trading-agent.yaml            # Quantitative trading agents
    README.md
  government/
    fedramp-base.yaml             # FedRAMP-aligned base
    itar-restricted.yaml          # ITAR-controlled environments
    README.md
  education/
    ferpa-student-agent.yaml      # Student-facing agents (FERPA)
    grading-agent.yaml            # Automated grading systems
    README.md
  devops/
    cicd-hardened.yaml            # Hardened CI/CD pipeline security
    incident-response.yaml        # Incident response agents
    README.md
  general/
    minimal.yaml                  # Minimal viable security
    recommended.yaml              # Recommended production baseline
    maximum.yaml                  # Maximum security posture
    air-gapped.yaml               # No network access, no shell
    README.md
```

Each vertical directory contains:
- One or more `.yaml` HushSpec policy files
- A `README.md` documenting the threat model, compliance mapping, and usage guidance

### 6.2 Policy Authoring Conventions

Every library policy MUST:

1. Include a `name` field matching the filename (without extension).
2. Include a `description` field summarizing the policy's purpose and target vertical.
3. Document each rule block with inline YAML comments mapping rules to specific compliance controls.
4. Use `extends` when appropriate to layer on top of a base policy.
5. Pass `cargo test --workspace` and all conformance test vectors.
6. Include a companion test fixture file in `fixtures/library/<vertical>/` that exercises key scenarios.

### 6.3 HIPAA Policy (Healthcare)

#### 6.3.1 Threat Model

**What we are protecting:** Protected Health Information (PHI) as defined by the HIPAA Privacy Rule (45 CFR 164.514). This includes patient names, medical record numbers, social security numbers, dates of treatment, diagnoses, prescription information, and any data that could identify an individual patient.

**Threat actors:**
- AI agent inadvertently leaking PHI to unauthorized external services via egress
- AI agent writing PHI to log files, temporary files, or unprotected locations
- AI agent executing shell commands that could exfiltrate data
- Prompt injection attacks causing the agent to reveal PHI
- Accidental inclusion of PHI in code patches or commits
- Insiders using AI agents to bypass access controls on patient data

**Compliance controls addressed:**
- 45 CFR 164.312(a)(1) -- Access Control: Technical policies to allow access only to authorized persons
- 45 CFR 164.312(a)(2)(i) -- Unique User Identification: Assign unique identifier for tracking
- 45 CFR 164.312(b) -- Audit Controls: Hardware/software/procedural mechanisms to record and examine access
- 45 CFR 164.312(c)(1) -- Integrity Controls: Protect ePHI from improper alteration or destruction
- 45 CFR 164.312(d) -- Person or Entity Authentication: Verify identity before granting access
- 45 CFR 164.312(e)(1) -- Transmission Security: Guard against unauthorized access during transmission
- 45 CFR 164.502 -- Uses and Disclosures of PHI: General rules for permissible uses
- 45 CFR 164.514(a)-(c) -- De-identification Standard: Requirements for removing identifiers
- 45 CFR 164.404-164.410 -- Breach Notification: Requirements for notifying affected parties

#### 6.3.2 HIPAA Base Policy

```yaml
# HushSpec HIPAA Base Policy
# Compliance: HIPAA Security Rule (45 CFR 164.312), Privacy Rule (45 CFR 164.502)
#
# DISCLAIMER: This policy is a starting point for HIPAA compliance. It does
# NOT constitute legal or compliance advice. Organizations MUST review and
# customize this policy for their environment and have it validated by a
# qualified HIPAA Privacy Officer or compliance professional.
hushspec: "0.2.0"
name: hipaa-base
description: >
  Base security policy for AI agents operating in HIPAA-regulated environments.
  Enforces PHI protection, restricts egress to approved health data endpoints,
  blocks access to patient data directories, and detects PHI patterns in content.

rules:
  # --- 45 CFR 164.312(a)(1): Access Control ---
  # Restrict filesystem access to prevent unauthorized PHI disclosure.
  # Maps to: HIPAA Security Rule - Technical Safeguards - Access Control
  forbidden_paths:
    enabled: true
    patterns:
      # Patient data directories
      - "**/patient-data/**"
      - "**/patient_data/**"
      - "**/phi/**"
      - "**/protected-health/**"
      - "**/medical-records/**"
      - "**/medical_records/**"
      - "**/health-records/**"
      - "**/health_records/**"
      - "**/ehr/**"
      - "**/emr/**"
      # HIPAA audit logs (read-only via approved tools)
      # Maps to: 45 CFR 164.312(b) - Audit Controls
      - "**/hipaa-audit/**"
      - "**/audit-logs/**"
      # Credential stores (standard)
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "**/.npmrc"
      - "**/.password-store/**"
      - "**/.1password/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "/etc/sudoers"
      # Database connection files
      - "**/database.yml"
      - "**/database.yaml"
      - "**/db.conf"
      - "**/pg_hba.conf"
      # Backup files that may contain PHI
      - "**/*.bak"
      - "**/*.backup"
      - "**/*.dump"
      - "**/*.sql.gz"
    exceptions:
      - "**/.env.example"
      - "**/.env.template"
      - "**/test/fixtures/**"

  # --- 45 CFR 164.312(a)(1): Access Control (allowlist mode) ---
  # When enabled, only allow access to approved directories.
  path_allowlist:
    enabled: true
    read:
      - "**/src/**"
      - "**/lib/**"
      - "**/config/**"
      - "**/docs/**"
      - "**/tests/**"
      - "**/package.json"
      - "**/Cargo.toml"
      - "**/pyproject.toml"
      - "**/go.mod"
      - "**/README*"
      - "**/LICENSE*"
    write:
      - "**/src/**"
      - "**/lib/**"
      - "**/tests/**"
    patch:
      - "**/src/**"
      - "**/lib/**"
      - "**/tests/**"

  # --- 45 CFR 164.312(e)(1): Transmission Security ---
  # Restrict egress to approved health data endpoints only.
  # AI services that may train on data are explicitly blocked.
  egress:
    enabled: true
    allow:
      # Approved EHR/EMR API endpoints (customize per organization)
      - "api.epic.com"
      - "api.cerner.com"
      - "fhir.epic.com"
      - "*.smarthealth.cards"
      # HL7 FHIR endpoints
      - "*.fhir.org"
      # Package registries (for dependency management)
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
    block:
      # Explicitly block common data-sharing platforms
      # Maps to: 45 CFR 164.502 - Minimum Necessary Standard
      - "*.pastebin.com"
      - "paste.ee"
      - "hastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
      - "*.wetransfer.com"
      - "*.dropbox.com"
      - "*.drive.google.com"
      - "*.onedrive.live.com"
      # Block social media
      - "*.twitter.com"
      - "*.x.com"
      - "*.facebook.com"
      - "*.reddit.com"
      - "*.slack.com"
      # Block AI services that may train on data
      # Maps to: 45 CFR 164.502(a) - unauthorized disclosure
      - "*.openai.com"
      - "*.anthropic.com"
      - "*.cohere.ai"
      - "*.huggingface.co"
    default: block

  # --- 45 CFR 164.312(c)(1): Integrity + 45 CFR 164.514: De-identification ---
  # Detect PHI and secrets in content before writes or transmissions.
  secret_patterns:
    enabled: true
    patterns:
      # PHI Patterns -- 45 CFR 164.514(b)(2): 18 HIPAA identifiers
      - name: ssn
        pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        severity: critical
        description: "Social Security Number -- HIPAA identifier #1 (45 CFR 164.514(b)(2)(i))"
      - name: medical_record_number
        pattern: "(?i)\\b(mrn|medical[\\s_-]?record[\\s_-]?(number|num|no|#))\\s*:?\\s*[A-Z0-9]{6,15}\\b"
        severity: critical
        description: "Medical Record Number -- HIPAA identifier #4 (45 CFR 164.514(b)(2)(iv))"
      - name: health_plan_id
        pattern: "(?i)\\b(health[\\s_-]?plan[\\s_-]?(id|number|num|no|#))\\s*:?\\s*[A-Z0-9]{8,20}\\b"
        severity: critical
        description: "Health Plan Beneficiary Number -- HIPAA identifier #5 (45 CFR 164.514(b)(2)(v))"
      - name: dea_number
        pattern: "\\b[A-Z][A-Z9][0-9]{7}\\b"
        severity: error
        description: "DEA Registration Number (prescriber identifier)"
      - name: npi_number
        pattern: "\\b\\d{10}\\b"
        severity: warn
        description: "National Provider Identifier (10-digit, may false-positive)"
      - name: icd10_code_in_context
        pattern: "(?i)(diagnosis|dx|icd)[\\s_-]*(10)?[\\s_-]*:?\\s*[A-Z]\\d{2}(\\.\\d{1,4})?"
        severity: error
        description: "ICD-10 diagnosis code in clinical context"
      - name: patient_name_pattern
        pattern: "(?i)(patient[\\s_-]?(name|nm))\\s*:?\\s*[A-Z][a-z]+\\s+[A-Z][a-z]+"
        severity: critical
        description: "Patient name -- HIPAA identifier #1 (45 CFR 164.514(b)(2)(i))"
      - name: date_of_birth
        pattern: "(?i)(dob|date[\\s_-]?of[\\s_-]?birth)\\s*:?\\s*\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4}"
        severity: critical
        description: "Date of birth -- HIPAA identifier #3 (45 CFR 164.514(b)(2)(iii))"
      - name: phone_number_us
        pattern: "(?i)(phone|tel|mobile|cell)\\s*:?\\s*\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}"
        severity: error
        description: "US phone number -- HIPAA identifier #8 (45 CFR 164.514(b)(2)(viii))"
      # Standard secret patterns
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
      - name: generic_api_key
        pattern: "(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*[A-Za-z0-9]{32,}"
        severity: error
      - name: connection_string
        pattern: "(?i)(postgres|mysql|mongodb|sqlserver)://[^\\s\"']{10,}"
        severity: critical
        description: "Database connection string (may contain credentials)"
    skip_paths:
      - "**/test/**"
      - "**/tests/**"
      - "**/fixtures/**"

  # --- 45 CFR 164.312(c)(1): Integrity Controls ---
  # Strict patch limits to prevent large-scale data exfiltration via patches.
  patch_integrity:
    enabled: true
    max_additions: 500
    max_deletions: 200
    require_balance: true
    max_imbalance_ratio: 5.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls|hipaa|audit)"
      - "(?i)skip[\\s_\\-]?(verify|validation|check|audit)"
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+777"
      - "(?i)(patient|phi|ssn|mrn|dob)"
      - "(?i)SELECT\\s+\\*\\s+FROM.*(patient|health|medical|diagnosis)"

  # --- Shell command restrictions ---
  # Block commands that could exfiltrate PHI.
  # Maps to: 45 CFR 164.312(a)(1) - Access Control
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "wget.*\\|.*bash"
      - "(?i)curl.*(patient|phi|medical|health)"
      - "(?i)scp\\s"
      - "(?i)rsync.*--rsh"
      - "(?i)nc\\s+-"
      - "(?i)ncat\\s"
      - "(?i)base64.*\\|.*curl"
      - "(?i)(mysql|psql|mongosh?)\\s+.*-p"
      - "(?i)pg_dump"
      - "(?i)mysqldump"
      - "(?i)mongodump"

  # --- 45 CFR 164.312(a)(1): Access Control ---
  # Strict tool access controls.
  tool_access:
    enabled: true
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
    block:
      - shell_exec
      - run_command
      - deploy
      - deploy_production
      - raw_file_write
      - raw_file_delete
      - database_query
      - database_write
    require_confirmation:
      - file_write
      - file_delete
      - git_push
      - git_commit
    default: block
    max_args_size: 524288

extensions:
  # --- 45 CFR 164.312(b): Audit Controls (via posture degradation) ---
  posture:
    initial: standard
    states:
      standard:
        description: "Normal HIPAA-compliant operation"
        capabilities:
          - file_access
          - file_write
          - egress
          - tool_call
        budgets:
          file_writes: 50
          egress_calls: 10
          tool_calls: 100
      restricted:
        description: "Restricted after violation -- read-only access"
        capabilities:
          - file_access
          - tool_call
        budgets:
          tool_calls: 10
      locked:
        description: "Locked after critical violation -- no capabilities"
        capabilities: []
    transitions:
      - from: standard
        to: restricted
        on: any_violation
      - from: restricted
        to: locked
        on: critical_violation
      - from: restricted
        to: standard
        on: user_approval
      - from: locked
        to: restricted
        on: user_approval

  # --- Detection: aggressive threat detection ---
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
      max_scan_bytes: 200000
    jailbreak:
      enabled: true
      block_threshold: 70
      warn_threshold: 40
      max_input_bytes: 200000
```

#### 6.3.3 HIPAA Coding Agent Policy (extends base)

```yaml
# HushSpec HIPAA Coding Agent Policy
# For AI coding assistants in healthcare engineering teams.
# Extends hipaa-base with development-specific relaxations.
#
# DISCLAIMER: This policy is a starting point. Organizations MUST customize
# and have it reviewed by qualified HIPAA compliance personnel.
hushspec: "0.2.0"
name: hipaa-coding-agent
description: >
  Policy for AI coding assistants used by engineering teams in
  HIPAA-regulated organizations. Allows broader tool access for
  development tasks while maintaining PHI protections.
extends: hipaa-base
merge_strategy: deep_merge

rules:
  # Relax tool access for development tasks
  # 45 CFR 164.312(a)(1): development access is broader but still controlled
  tool_access:
    enabled: true
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
      - build
      - lint
      - format
    block:
      - shell_exec
      - deploy_production
      - database_query
      - database_write
    require_confirmation:
      - git_push
      - deploy
    default: block
    max_args_size: 1048576

  # Slightly larger patch limits for dev work
  patch_integrity:
    enabled: true
    max_additions: 1000
    max_deletions: 500
    require_balance: false
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls|hipaa|audit)"
      - "(?i)skip[\\s_\\-]?(verify|validation|check|audit)"
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+777"
      - "(?i)SELECT\\s+\\*\\s+FROM.*(patient|health|medical|diagnosis)"

  # Broader egress for development (package registries, code hosting)
  # 45 CFR 164.312(e)(1): AI services still blocked to prevent PHI leakage
  egress:
    enabled: true
    allow:
      - "api.epic.com"
      - "api.cerner.com"
      - "fhir.epic.com"
      - "*.fhir.org"
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
    block:
      - "*.pastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
      - "*.openai.com"
      - "*.anthropic.com"
    default: block
```

### 6.4 SOC2 Policy (Finance/SaaS)

#### 6.4.1 Threat Model

**What we are protecting:** Customer data, internal systems, and audit trails in accordance with the AICPA Trust Services Criteria for SOC2 Type II.

**Threat actors:**
- AI agent writing to production infrastructure without authorization
- AI agent accessing customer databases or PII
- Uncontrolled deployments bypassing change management
- Data exfiltration through unrestricted egress
- Privilege escalation through unrestricted tool access
- AI agent modifying audit logs or compliance artifacts

**SOC2 Trust Services Criteria addressed:**
- CC6.1 -- Logical and Physical Access Controls: Entity implements logical access security software, infrastructure, and architectures over protected information assets
- CC6.2 -- Access to Protected Information Assets: Prior to issuing system credentials and granting system access, the entity registers and authorizes new users
- CC6.3 -- Access to Protected Information -- Restricted: The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles
- CC6.6 -- System Operations -- External Threats: The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software
- CC6.7 -- System Operations -- Transmission Security: The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes
- CC6.8 -- System Operations -- Unauthorized Changes: The entity implements controls to prevent or detect and act upon unauthorized changes
- CC7.1 -- System Operations -- Detection of Changes: To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations
- CC7.2 -- System Operations -- Monitoring: The entity monitors system components for anomalies
- CC8.1 -- Change Management: The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures

#### 6.4.2 SOC2-Compliant Policy

```yaml
# HushSpec SOC2-Compliant Policy
# Compliance: AICPA Trust Services Criteria (SOC2 Type II)
#
# DISCLAIMER: This policy is a starting point for SOC2 alignment. It does
# NOT constitute compliance certification. Organizations MUST customize for
# their specific control environment and engage their auditor.
hushspec: "0.2.0"
name: soc2-base
description: >
  Security policy aligned with SOC2 Trust Services Criteria.
  Enforces access controls, change management, transmission security,
  and monitoring requirements for AI agents in SOC2-audited environments.

rules:
  # --- CC6.1, CC6.2: Logical Access Controls ---
  # Prevent access to infrastructure, credential, and customer data paths.
  forbidden_paths:
    enabled: true
    patterns:
      # Infrastructure credentials
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.gcp/**"
      - "**/.azure/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "**/.npmrc"
      - "**/.password-store/**"
      - "**/.1password/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "/etc/sudoers"
      # Infrastructure configuration -- CC6.8
      - "**/terraform.tfstate*"
      - "**/.terraform/**"
      - "**/pulumi.*.yaml"
      - "**/ansible/vault/**"
      # Customer data directories -- CC6.2
      - "**/customer-data/**"
      - "**/customer_data/**"
      - "**/user-data/**"
      - "**/user_data/**"
      - "**/pii/**"
      - "**/exports/**"
      # Production configuration -- CC6.3
      - "**/production.yml"
      - "**/production.yaml"
      - "**/prod.env"
      - "**/prod.config.*"
      # Audit logs -- CC7.2
      - "**/audit-logs/**"
      - "**/compliance-reports/**"
      # Database files -- CC6.2
      - "**/*.sqlite"
      - "**/*.db"
      - "**/*.mdb"
    exceptions:
      - "**/.env.example"
      - "**/.env.template"
      - "**/test/**"
      - "**/tests/**"

  # --- CC6.7: Transmission Security ---
  # Restrict egress to approved endpoints.
  egress:
    enabled: true
    allow:
      # Code hosting (for PRs and code review)
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
      # Package registries
      - "registry.npmjs.org"
      - "*.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
      # Approved monitoring / observability -- CC7.2
      - "*.datadoghq.com"
      - "*.pagerduty.com"
      - "*.opsgenie.com"
    block:
      # Block data sharing platforms -- CC6.7
      - "*.pastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
      - "*.wetransfer.com"
      # Block consumer cloud storage -- CC6.7
      - "*.dropbox.com"
      - "drive.google.com"
      - "*.onedrive.live.com"
      # Block social media -- CC6.7
      - "*.twitter.com"
      - "*.x.com"
      - "*.facebook.com"
      - "*.reddit.com"
    default: block

  # --- CC6.2, CC7.1: Secret Detection ---
  # Detect credentials and PII in content.
  secret_patterns:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
        description: "AWS access key -- CC6.1 access control violation"
      - name: aws_secret_key
        pattern: "(?i)aws_secret_access_key\\s*[:=]\\s*[A-Za-z0-9/+=]{40}"
        severity: critical
        description: "AWS secret key -- CC6.1 access control violation"
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
        description: "GitHub token -- CC6.1 credential exposure"
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
        description: "Private key material -- CC6.1 cryptographic key exposure"
      - name: generic_api_key
        pattern: "(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*[A-Za-z0-9]{32,}"
        severity: error
        description: "API key pattern -- CC6.1 credential exposure"
      - name: connection_string
        pattern: "(?i)(postgres|mysql|mongodb|redis|amqp)://[^\\s\"']{10,}"
        severity: critical
        description: "Database connection string -- CC6.1/CC6.2 data access"
      - name: jwt_token
        pattern: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+"
        severity: error
        description: "JWT token -- CC6.1 session credential"
      - name: slack_token
        pattern: "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"
        severity: critical
        description: "Slack token -- CC6.1 credential exposure"
      - name: email_address
        pattern: "(?i)(customer|user|client)[_\\-]?email\\s*[:=]\\s*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
        severity: error
        description: "Customer email in code -- CC6.2 PII exposure"
      - name: ssn
        pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        severity: critical
        description: "Social Security Number -- CC6.2 PII exposure"
    skip_paths:
      - "**/test/**"
      - "**/tests/**"
      - "**/fixtures/**"
      - "**/*.test.*"

  # --- CC8.1: Change Management ---
  # Strict patch controls to support change management.
  patch_integrity:
    enabled: true
    max_additions: 500
    max_deletions: 200
    require_balance: true
    max_imbalance_ratio: 5.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls|audit|logging|monitoring)"
      - "(?i)skip[\\s_\\-]?(verify|validation|check|audit|test)"
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+(777|666|o\\+w)"
      - "(?i)eval\\s*\\("
      - "(?i)exec\\s*\\("
      - "(?i)--no-verify"
      - "(?i)force[_\\-]?push"
      - "(?i)DROP\\s+(TABLE|DATABASE|INDEX)"

  # --- CC6.6: External Threat Prevention ---
  # Block dangerous shell commands.
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "curl.*\\|.*bash"
      - "wget.*\\|.*sh"
      - "wget.*\\|.*bash"
      - "(?i)nc\\s+-"
      - "(?i)ncat\\s"
      - "(?i)scp\\s"
      - "(?i)rsync.*--rsh"
      - "(?i)ssh\\s+-R"
      - "(?i)kubectl.*exec"
      - "(?i)docker.*exec"
      - "(?i)terraform\\s+(destroy|apply)"
      - "(?i)aws\\s+s3.*rm"
      - "(?i)gcloud.*delete"

  # --- CC6.1, CC6.3: Tool Access Controls ---
  # Strict allowlist for tools.
  tool_access:
    enabled: true
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
      - build
      - lint
    block:
      - shell_exec
      - run_command
      - deploy_production
      - database_query
      - database_write
      - raw_file_write
      - raw_file_delete
    require_confirmation:
      - file_write
      - file_delete
      - git_push
      - git_commit
      - deploy
    default: block
    max_args_size: 524288

extensions:
  # --- CC7.2: Monitoring (via posture degradation) ---
  posture:
    initial: standard
    states:
      standard:
        description: "Normal SOC2-compliant operation"
        capabilities:
          - file_access
          - file_write
          - egress
          - tool_call
        budgets:
          file_writes: 100
          egress_calls: 25
          tool_calls: 200
      review_required:
        description: "Elevated scrutiny -- confirmation required for all writes"
        capabilities:
          - file_access
          - file_write
          - egress
          - tool_call
        budgets:
          file_writes: 20
          egress_calls: 5
          tool_calls: 50
      locked:
        description: "Locked -- no capabilities until human review"
        capabilities: []
    transitions:
      - from: standard
        to: review_required
        on: any_violation
      - from: review_required
        to: locked
        on: critical_violation
      - from: review_required
        to: standard
        on: user_approval
      - from: locked
        to: review_required
        on: user_approval

  # --- CC6.6: Threat Detection ---
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 75
      warn_threshold: 45
```

### 6.5 PCI-DSS Policy (Finance/Payments)

#### 6.5.1 Threat Model

**What we are protecting:** Cardholder data (CHD) and sensitive authentication data (SAD) as defined by PCI-DSS v4.0. This includes primary account numbers (PANs), cardholder names, expiration dates, service codes, and card verification values (CVV/CVC).

**Threat actors:**
- AI agent processing or storing PAN data in plaintext (violates Req 3.4)
- AI agent logging or writing CVV/CVC values post-authorization (violates Req 3.2)
- AI agent transmitting CHD over unrestricted egress channels (violates Req 4.1)
- AI agent accessing payment processing infrastructure without authorization (violates Req 7.1)
- Prompt injection causing the agent to exfiltrate card data
- AI agent executing database queries that return cardholder data

**PCI-DSS v4.0 Requirements addressed:**
- Req 1.3 -- Network access to and from the cardholder data environment is restricted
- Req 2.2 -- System components are configured and managed securely
- Req 3.2 -- Storage of sensitive authentication data after authorization is prohibited
- Req 3.4 -- PAN is secured wherever it is stored
- Req 3.5 -- PAN is secured wherever it is transmitted
- Req 4.1 -- Strong cryptography is used during transmission of CHD over open, public networks
- Req 6.3 -- Security vulnerabilities are identified and addressed
- Req 7.1 -- Access to system components and CHD is limited to those whose job requires it
- Req 10.2 -- Audit logs record all actions affecting CHD

#### 6.5.2 PCI-DSS Policy

```yaml
# HushSpec PCI-DSS Policy
# Compliance: PCI-DSS v4.0 for cardholder data environments
#
# DISCLAIMER: This policy is a starting point for PCI-DSS alignment. It
# does NOT constitute PCI-DSS certification. Organizations MUST have this
# policy reviewed by a Qualified Security Assessor (QSA) as part of their
# overall assessment.
hushspec: "0.2.0"
name: pci-dss
description: >
  Policy for AI agents operating in or near cardholder data environments.
  Detects PANs, restricts egress, and blocks access to payment data stores.

rules:
  # --- Req 7.1: Restrict access to CHD by business need-to-know ---
  forbidden_paths:
    enabled: true
    patterns:
      # Cardholder data stores -- Req 3.4
      - "**/cardholder/**"
      - "**/card_data/**"
      - "**/payment-data/**"
      - "**/payment_data/**"
      - "**/pan/**"
      - "**/cvv/**"
      - "**/transactions/**"
      # Key management -- Req 3.5
      - "**/key-store/**"
      - "**/keystore/**"
      - "**/hsm/**"
      - "**/encryption-keys/**"
      # Standard credential stores
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "/etc/shadow"
      - "/etc/passwd"
    exceptions:
      - "**/.env.example"
      - "**/test/**"

  # --- Req 1.3, Req 4.1: Restrict network egress from CDE ---
  egress:
    enabled: true
    allow:
      # Payment processor APIs (customize per organization)
      - "api.stripe.com"
      - "api.braintreegateway.com"
      - "*.paypal.com"
      # Package registries
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
    block:
      - "*.pastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
    default: block

  # --- Req 3.2, 3.4: Detect and prevent CHD storage ---
  secret_patterns:
    enabled: true
    patterns:
      # PCI-DSS Requirement 3.4: PAN must not appear in plaintext
      - name: credit_card_visa
        pattern: "\\b4[0-9]{12}(?:[0-9]{3})?\\b"
        severity: critical
        description: "Visa card number -- PCI-DSS Req 3.4 (PAN protection)"
      - name: credit_card_mastercard
        pattern: "\\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\\b"
        severity: critical
        description: "Mastercard number -- PCI-DSS Req 3.4 (PAN protection)"
      - name: credit_card_amex
        pattern: "\\b3[47][0-9]{13}\\b"
        severity: critical
        description: "American Express card number -- PCI-DSS Req 3.4"
      - name: credit_card_discover
        pattern: "\\b6(?:011|5[0-9]{2})[0-9]{12}\\b"
        severity: critical
        description: "Discover card number -- PCI-DSS Req 3.4"
      # PCI-DSS Requirement 3.2: SAD must never be stored post-auth
      - name: cvv_pattern
        pattern: "(?i)(cvv|cvc|cvv2|cvc2|cid)\\s*[:=]\\s*\\d{3,4}"
        severity: critical
        description: "Card verification value -- PCI-DSS Req 3.2 (SAD prohibition)"
      - name: card_expiry
        pattern: "(?i)(exp(iry|iration)?[_\\-\\s]?date)\\s*[:=]\\s*\\d{2}[/-]\\d{2,4}"
        severity: error
        description: "Card expiration date -- PCI-DSS Req 3.2"
      - name: track_data
        pattern: "(?i)(track[_\\-\\s]?(1|2|data))\\s*[:=]"
        severity: critical
        description: "Track data reference -- PCI-DSS Req 3.2 (SAD prohibition)"
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
    skip_paths:
      - "**/test/**"
      - "**/tests/**"

  # --- Req 6.3: Prevent security vulnerabilities ---
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "(?i)curl.*(card|pan|cvv|payment|transaction)"
      - "(?i)pg_dump.*(card|payment|transaction)"
      - "(?i)mysqldump.*(card|payment|transaction)"

  # --- Req 7.1: Least privilege tool access ---
  # --- Req 10.2: All access must be auditable ---
  tool_access:
    enabled: true
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
    block:
      - shell_exec
      - run_command
      - deploy_production
      - database_query
      - database_write
    require_confirmation:
      - file_write
      - git_push
    default: block
    max_args_size: 524288
```

### 6.6 FedRAMP Policy (Government)

#### 6.6.1 Threat Model

**What we are protecting:** Federal information and information systems at the Moderate impact level, as categorized under FIPS 199. This includes Controlled Unclassified Information (CUI), system security plans, and any data processed by systems operating under a FedRAMP Authority to Operate (ATO).

**Threat actors:**
- AI agent accessing CUI or FOUO documents without authorization
- AI agent egressing to non-FedRAMP-authorized cloud services
- AI agent modifying infrastructure-as-code that governs federal systems
- AI agent interacting with cloud provider CLIs in unauthorized ways
- Nation-state adversaries using prompt injection to extract federal data

**NIST SP 800-53 Rev. 5 control families addressed:**
- AC-3 -- Access Enforcement: The system enforces approved authorizations
- AC-6 -- Least Privilege: The system enforces the most restrictive set of privileges
- AU-2 -- Audit Events: The system is capable of auditing defined events
- CM-3 -- Configuration Change Control: The organization authorizes, documents, and controls changes
- CM-7 -- Least Functionality: The system provides only essential capabilities
- SC-7 -- Boundary Protection: The system monitors and controls communications at external managed interfaces
- SC-8 -- Transmission Confidentiality and Integrity: The system protects information during transmission

#### 6.6.2 FedRAMP-Aligned Policy

```yaml
# HushSpec FedRAMP-Aligned Policy
# Compliance: FedRAMP Moderate baseline (NIST SP 800-53 Rev. 5)
#
# DISCLAIMER: This policy is a starting point for FedRAMP alignment. It
# does NOT constitute an ATO. Organizations MUST work with their 3PAO and
# authorizing official to validate compliance.
hushspec: "0.2.0"
name: fedramp-base
description: >
  Policy aligned with FedRAMP Moderate baseline controls for AI agents
  operating in federal information systems. Implements AC, AU, CM, SC
  control families.

rules:
  # --- AC-3: Access Enforcement, AC-6: Least Privilege ---
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.gcp/**"
      - "**/.azure/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "/etc/sudoers"
      # Federal data classifications -- AC-3
      - "**/cui/**"
      - "**/controlled-unclassified/**"
      - "**/fouo/**"
      - "**/classified/**"
      - "**/sensitive/**"
      # FedRAMP artifacts -- CM-3
      - "**/ssp/**"
      - "**/system-security-plan/**"
      - "**/poam/**"
      - "**/plan-of-action/**"
      # Infrastructure -- CM-7
      - "**/terraform.tfstate*"
      - "**/.terraform/**"
    exceptions:
      - "**/.env.example"

  # --- SC-7: Boundary Protection, SC-8: Transmission Confidentiality ---
  egress:
    enabled: true
    allow:
      # .gov and .mil endpoints only by default
      - "*.gov"
      - "*.mil"
      # FedRAMP-authorized services (customize per ATO)
      - "*.amazonaws.com"
      - "*.azure.com"
      - "*.cloud.google.com"
      # Package registries
      - "registry.npmjs.org"
      - "pypi.org"
    block:
      - "*.pastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
    default: block

  # --- AU-2: Audit Events (secrets as audit-triggering content) ---
  secret_patterns:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
      - name: ssn
        pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        severity: critical
        description: "SSN -- PII in federal context (AU-2 audit event)"
      - name: generic_api_key
        pattern: "(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*[A-Za-z0-9]{32,}"
        severity: error

  # --- CM-3: Configuration Change Control ---
  patch_integrity:
    enabled: true
    max_additions: 300
    max_deletions: 100
    require_balance: true
    max_imbalance_ratio: 3.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls|fips|audit|logging)"
      - "(?i)skip[\\s_\\-]?(verify|validation|check|audit)"
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+(777|666)"
      - "(?i)--no-verify"

  # --- CM-7: Least Functionality ---
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "wget.*\\|.*bash"
      - "(?i)nc\\s+-"
      - "(?i)ssh\\s+-R"
      - "(?i)kubectl"
      - "(?i)docker"
      - "(?i)terraform"
      - "(?i)aws\\s+"
      - "(?i)gcloud\\s+"
      - "(?i)az\\s+"

  # --- AC-3: Access Enforcement ---
  tool_access:
    enabled: true
    allow:
      - read_file
      - list_directory
      - search
      - grep
    block:
      - shell_exec
      - run_command
      - deploy
      - deploy_production
      - database_query
      - database_write
    require_confirmation:
      - file_write
      - file_delete
      - git_push
      - git_commit
      - run_tests
      - build
    default: block
    max_args_size: 262144

extensions:
  posture:
    initial: standard
    states:
      standard:
        description: "Normal FedRAMP-compliant operation"
        capabilities:
          - file_access
          - file_write
          - tool_call
        budgets:
          file_writes: 30
          tool_calls: 75
      locked:
        description: "Locked -- pending security review"
        capabilities: []
    transitions:
      - from: standard
        to: locked
        on: any_violation
      - from: locked
        to: standard
        on: user_approval
```

### 6.7 FERPA Education Policy

#### 6.7.1 Threat Model

**What we are protecting:** Student education records and personally identifiable information (PII) from education records, as protected under the Family Educational Rights and Privacy Act (FERPA, 20 U.S.C. 1232g; 34 CFR Part 99).

**Threat actors:**
- AI agent accessing or disclosing student grades, disciplinary records, or financial aid data
- AI agent transmitting student PII to unauthorized third-party services
- AI agent assisting students in academic dishonesty (accessing grading rubrics or answer keys)
- Prompt injection causing disclosure of other students' records

**FERPA provisions addressed:**
- 34 CFR 99.3 -- Definition of education records (what is protected)
- 34 CFR 99.30 -- Conditions for prior consent (disclosure requires consent)
- 34 CFR 99.31 -- Exceptions to consent requirement (directory information, legitimate educational interest)
- 34 CFR 99.33 -- Limitations on redisclosure
- 34 CFR 99.35 -- Conditions for disclosure to certain federal/state authorities

#### 6.7.2 Student-Facing Agent Policy

```yaml
# HushSpec FERPA Student Agent Policy
# Compliance: FERPA (20 U.S.C. 1232g; 34 CFR Part 99)
#
# DISCLAIMER: This policy is a starting point for FERPA alignment. It
# does NOT constitute legal advice. Institutions MUST validate with their
# FERPA compliance officer or legal counsel.
hushspec: "0.2.0"
name: ferpa-student-agent
description: >
  Policy for AI agents operating in student-facing educational contexts.
  Prevents access to grading systems, student records, and answer keys.
  Restricts egress to approved educational platforms only.

rules:
  # --- 34 CFR 99.3: Protect education records ---
  forbidden_paths:
    enabled: true
    patterns:
      # Student records -- 34 CFR 99.3
      - "**/student-records/**"
      - "**/student_records/**"
      - "**/grades/**"
      - "**/gradebook/**"
      - "**/grade_data/**"
      - "**/transcripts/**"
      - "**/disciplinary/**"
      - "**/financial-aid/**"
      - "**/financial_aid/**"
      - "**/enrollment/**"
      # Assessment materials (prevent cheating)
      - "**/answer-keys/**"
      - "**/answer_keys/**"
      - "**/exam-solutions/**"
      - "**/rubrics/**"
      - "**/grading-criteria/**"
      # Faculty-only materials
      - "**/faculty/**"
      - "**/admin/**"
      - "**/staff/**"
      # Standard credential stores
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "/etc/shadow"
      - "/etc/passwd"
    exceptions:
      - "**/.env.example"
      - "**/tests/**"

  # --- 34 CFR 99.33: Restrict redisclosure ---
  egress:
    enabled: true
    allow:
      # Approved LMS platforms (customize per institution)
      - "*.instructure.com"
      - "*.blackboard.com"
      - "*.brightspace.com"
      - "*.moodle.org"
      # Academic resources
      - "*.wikipedia.org"
      - "*.arxiv.org"
      - "*.doi.org"
      - "*.jstor.org"
      # Package registries (for CS courses)
      - "registry.npmjs.org"
      - "pypi.org"
      - "crates.io"
    block:
      # Block data sharing platforms
      - "*.pastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
      # Block social media
      - "*.twitter.com"
      - "*.x.com"
      - "*.facebook.com"
      - "*.reddit.com"
      - "*.discord.com"
      # Block AI services (prevent outsourcing academic work)
      - "*.openai.com"
      - "*.anthropic.com"
    default: block

  # --- Detect student PII in content ---
  secret_patterns:
    enabled: true
    patterns:
      - name: student_id
        pattern: "(?i)(student[\\s_-]?(id|number|num|no|#))\\s*:?\\s*[A-Z0-9]{6,12}"
        severity: critical
        description: "Student ID number -- FERPA education record"
      - name: ssn
        pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        severity: critical
        description: "Social Security Number -- FERPA PII"
      - name: student_grade
        pattern: "(?i)(grade|score|gpa|mark)\\s*:?\\s*[A-F][+-]?\\b"
        severity: error
        description: "Student grade in structured context"
      - name: date_of_birth
        pattern: "(?i)(dob|date[\\s_-]?of[\\s_-]?birth)\\s*:?\\s*\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4}"
        severity: error
        description: "Date of birth -- FERPA PII"
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
    skip_paths:
      - "**/test/**"
      - "**/tests/**"

  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "wget.*\\|.*bash"
      - "(?i)scp\\s"

  tool_access:
    enabled: true
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
    block:
      - shell_exec
      - run_command
      - deploy
      - deploy_production
      - database_query
      - database_write
    require_confirmation:
      - file_write
      - git_push
    default: block
    max_args_size: 524288
```

### 6.8 DevOps Policies

#### 6.8.1 Hardened CI/CD Pipeline Policy

**Threat model:** AI agents operating within CI/CD pipelines have access to build infrastructure, deployment credentials, and artifact registries. The primary threats are: supply-chain attacks via malicious dependencies or build modifications, secret leakage through build logs, unauthorized deployments to production, and lateral movement through infrastructure credentials stored in CI environments.

```yaml
# HushSpec Hardened CI/CD Policy
# For AI agents operating within build pipelines.
#
# Threat model: supply-chain attacks, secret leakage through build
# logs, unauthorized deployments, lateral movement via CI credentials.
hushspec: "0.2.0"
name: cicd-hardened
description: >
  Hardened security policy for AI agents in CI/CD pipelines. Restricts
  deployment access, blocks infrastructure credential exposure, and
  enforces strict egress to package registries and build services only.

rules:
  forbidden_paths:
    enabled: true
    patterns:
      # CI/CD secrets
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.gcp/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.github/secrets/**"
      - "**/.gitlab-ci-secrets/**"
      - "**/.circleci/secrets/**"
      # Infrastructure state
      - "**/terraform.tfstate*"
      - "**/.terraform/**"
      - "**/pulumi.*.yaml"
      # Deployment credentials
      - "**/deploy-keys/**"
      - "**/service-accounts/**"
      - "**/kubeconfig*"
    exceptions:
      - "**/.github/workflows/**"
      - "**/.gitlab-ci.yml"
      - "**/.circleci/config.yml"
      - "**/.env.example"

  egress:
    enabled: true
    allow:
      # Package registries
      - "*.npmjs.org"
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
      - "rubygems.org"
      - "packagist.org"
      - "plugins.gradle.org"
      # Container registries
      - "*.docker.io"
      - "*.docker.com"
      - "*.gcr.io"
      - "*.ecr.aws"
      - "ghcr.io"
      # Build tools
      - "repo1.maven.org"
      - "services.gradle.org"
      # Source control
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
    block:
      - "*.pastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
    default: block

  secret_patterns:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
        description: "AWS access key in CI context"
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
        description: "GitHub token -- potential CI credential leak"
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
      - name: npm_token
        pattern: "npm_[A-Za-z0-9]{36}"
        severity: critical
        description: "NPM publish token -- supply chain risk"
      - name: docker_password
        pattern: "(?i)docker[_\\-]?password\\s*[:=]\\s*[^\\s]{8,}"
        severity: critical
        description: "Docker registry credential"
    skip_paths:
      - "**/test/**"
      - "**/tests/**"

  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "wget.*\\|.*bash"
      - "(?i)chmod\\s+777"
      - "(?i)ssh\\s+-R"

  tool_access:
    enabled: true
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
      - build
    block:
      - shell_exec
      - deploy_production
      - database_query
      - database_write
    require_confirmation:
      - deploy
      - git_push
    default: block

  patch_integrity:
    enabled: true
    max_additions: 1000
    max_deletions: 500
    require_balance: false
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls)"
      - "(?i)skip[\\s_\\-]?(verify|validation|check|test)"
      - "(?i)--no-verify"
      - "(?i)force[_\\-]?push"
```

#### 6.8.2 Incident Response Agent Policy

**Threat model:** Incident response agents operate under time pressure with elevated access. The primary threats are: an attacker triggering a false incident to gain elevated agent access, the agent making destructive changes under stress, credential exposure during log investigation, and the agent exceeding its intended scope of investigation.

```yaml
# HushSpec Incident Response Agent Policy
# For agents assisting during security incidents with time-limited elevation.
#
# Threat model: false-flag incidents for privilege escalation, destructive
# changes under time pressure, credential exposure during investigation,
# scope creep beyond incident boundaries.
hushspec: "0.2.0"
name: incident-response
description: >
  Policy for AI agents assisting during security incidents. Provides
  elevated access with strict audit controls and automatic degradation.
  Uses conditional rules for time-bounded access.

rules:
  # During incidents, allow read access to broader paths for investigation.
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/id_*"
      - "**/.gnupg/private-keys*"
      - "**/password-store/**"
      - "**/.1password/**"
    exceptions: []

  # Allow observability and alerting endpoints during incident.
  egress:
    enabled: true
    allow:
      - "*.datadoghq.com"
      - "*.pagerduty.com"
      - "*.opsgenie.com"
      - "*.splunk.com"
      - "*.elastic.co"
      - "*.sumologic.com"
      - "*.grafana.com"
      - "api.github.com"
      - "github.com"
      - "*.statuspage.io"
      - "*.atlassian.net"
    block:
      - "*.pastebin.com"
      - "*.transfer.sh"
    default: block

  # Allow broader shell access for diagnostics.
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "(?i)chmod\\s+777"
      # Block destructive database operations
      - "(?i)DROP\\s+(TABLE|DATABASE)"
      - "(?i)TRUNCATE\\s+TABLE"
      - "(?i)DELETE\\s+FROM(?!.*WHERE)"

  # Broader tool access but with confirmation gates.
  tool_access:
    enabled: true
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
      - run_command
      - database_query
    block:
      - deploy_production
      - database_write
      - raw_file_delete
    require_confirmation:
      - shell_exec
      - deploy
      - git_push
    default: block

  secret_patterns:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical

extensions:
  # Time-limited escalation with automatic lockdown.
  posture:
    initial: triage
    states:
      triage:
        description: "Initial triage -- broad read, limited write"
        capabilities:
          - file_access
          - egress
          - tool_call
        budgets:
          egress_calls: 100
          tool_calls: 500
      investigation:
        description: "Active investigation -- shell and database access"
        capabilities:
          - file_access
          - file_write
          - egress
          - shell
          - tool_call
        budgets:
          file_writes: 50
          egress_calls: 200
          shell_commands: 100
          tool_calls: 1000
      containment:
        description: "Containment -- write access for fixes"
        capabilities:
          - file_access
          - file_write
          - egress
          - tool_call
          - patch
        budgets:
          file_writes: 100
          egress_calls: 50
          tool_calls: 500
      post_incident:
        description: "Post-incident -- read-only for review"
        capabilities:
          - file_access
          - tool_call
        budgets:
          tool_calls: 100
    transitions:
      - from: triage
        to: investigation
        on: user_approval
      - from: investigation
        to: containment
        on: user_approval
      - from: containment
        to: post_incident
        on: user_approval
      # Auto-degrade after time limits
      - from: investigation
        to: post_incident
        on: timeout
        after: "4h"
      - from: containment
        to: post_incident
        on: timeout
        after: "2h"
      # Lock on critical violation at any stage
      - from: "*"
        to: post_incident
        on: critical_violation
```

### 6.9 General Purpose Policies

#### 6.9.1 Air-Gapped Policy

```yaml
# library/general/air-gapped.yaml
# For agents that must not access the network or execute shell commands.
hushspec: "0.1.0"
name: air-gapped
description: >
  Maximum isolation policy. No network access, no shell execution,
  no computer use. Suitable for offline code review or analysis tasks.

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "**/.npmrc"
      - "**/.password-store/**"
      - "**/.1password/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "/etc/sudoers"

  egress:
    enabled: true
    allow: []
    block: []
    default: block

  secret_patterns:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
      - name: generic_api_key
        pattern: "(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*[A-Za-z0-9]{32,}"
        severity: error

  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"

  tool_access:
    enabled: true
    allow:
      - read_file
      - list_directory
      - search
      - grep
    block: []
    require_confirmation: []
    default: block

  computer_use:
    enabled: false

  input_injection:
    enabled: false
```

#### 6.9.2 Recommended Baseline Policy

```yaml
# library/general/recommended.yaml
# Recommended baseline for production AI agent deployments.
hushspec: "0.1.0"
name: recommended
description: >
  Recommended baseline security policy for production AI agent deployments.
  Balances security with usability. Suitable as a starting point for
  most organizations.
extends: default
merge_strategy: deep_merge

rules:
  egress:
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
      - "registry.npmjs.org"
      - "*.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
    block:
      - "*.pastebin.com"
      - "*.transfer.sh"
      - "*.file.io"
    default: block

  tool_access:
    allow:
      - read_file
      - write_file
      - list_directory
      - search
      - grep
      - run_tests
      - build
      - lint
      - format
    block:
      - shell_exec
      - deploy_production
    require_confirmation:
      - git_push
      - deploy
      - run_command
    default: block
    max_args_size: 1048576

  patch_integrity:
    max_additions: 1000
    max_deletions: 500
    require_balance: false
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls)"
      - "(?i)skip[\\s_\\-]?(verify|validation|check)"
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+777"

extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 80
      warn_threshold: 50
```

### 6.10 Conditional Rules in Vertical Policies

The following example demonstrates how conditional rules enhance the SOC2 policy for real-world deployment:

```yaml
# SOC2 policy with conditional rules for environment-aware enforcement.
# This extends soc2-base and adds time/context conditions.
hushspec: "0.2.0"
name: soc2-conditional
description: >
  SOC2 policy with environment-aware conditional rules. Tightens
  restrictions in production, relaxes slightly in development, and
  applies maintenance-window exceptions.
extends: soc2-base
merge_strategy: deep_merge

rules:
  # Production: block all shell access -- CC6.6
  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"
    when:
      context:
        environment: production

  # Development: allow broader egress for package installation -- CC6.7
  egress:
    enabled: true
    allow:
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
      - "registry.npmjs.org"
      - "*.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
      - "*.openai.com"
      - "*.anthropic.com"
    default: block
    when:
      context:
        environment: [development, staging]

  # During maintenance windows: relax patch limits for bulk operations -- CC8.1
  patch_integrity:
    enabled: true
    max_additions: 2000
    max_deletions: 1000
    require_balance: false
    max_imbalance_ratio: 20.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls)"
      - "(?i)rm\\s+-rf\\s+/"
    when:
      all_of:
        - time_window:
            start: "02:00"
            end: "06:00"
            timezone: "America/New_York"
            days: [sun]
        - context:
            user.role: [admin, sre]

  # Rate-limit tool access: after 500 calls/hour, require confirmation -- CC7.2
  tool_access:
    enabled: true
    allow: []
    block: []
    require_confirmation:
      - read_file
      - write_file
      - search
      - grep
    default: block
    when:
      rate:
        action_type: tool_call
        count: 500
        window: "1h"
        behavior: activate_above
```

---

## 7. Community Contribution Model

### 7.1 Policy Lifecycle

Every policy in the library follows a defined lifecycle:

| Stage | Description |
|---|---|
| **Draft** | Initial submission. Undergoing review. Not recommended for production. |
| **Review** | Community review period (minimum 30 days). Compliance mapping under audit. |
| **Accepted** | Reviewed and merged. Suitable for production with customization. |
| **Stable** | Has been in production use for 6+ months with no significant issues. |
| **Deprecated** | Superseded by a newer version or no longer maintained. |

### 7.2 Contribution Requirements

Contributors submitting a vertical policy MUST provide:

1. **Policy YAML file(s)** conforming to the HushSpec schema and passing all validation.
2. **README.md** for the vertical directory containing:
   - Threat model (what assets are protected, what threat actors are considered)
   - Compliance mapping table (regulation section to HushSpec rule)
   - Known limitations and false-positive risks
   - Customization guidance (which fields organizations should change)
3. **Test fixtures** in `fixtures/library/<vertical>/` with at minimum:
   - 5 scenarios testing expected `allow` decisions
   - 5 scenarios testing expected `deny` decisions
   - 2 scenarios testing edge cases (pattern near-misses, boundary values)
4. **Changelog entry** in the vertical's README for each modification.

### 7.3 Compliance Certification Disclaimer

The HushSpec project does NOT certify that policies meet regulatory requirements. This is a critical distinction:

- Library policies are **aligned with** compliance frameworks, not **certified for** them.
- Each policy README and each policy YAML file includes a prominent disclaimer: *"This policy is a starting point for compliance. It does not constitute legal or compliance advice. Organizations are responsible for validating that their configuration meets their specific regulatory obligations."*
- Compliance mapping tables cite specific regulation sections and describe how the HushSpec rule addresses the control objective, but this mapping is informational.
- Organizations SHOULD have their customized policies reviewed by qualified compliance personnel:
  - **HIPAA:** A HIPAA Privacy Officer or qualified compliance consultant
  - **PCI-DSS:** A Qualified Security Assessor (QSA) or Internal Security Assessor (ISA)
  - **FedRAMP:** A Third Party Assessment Organization (3PAO) and the authorizing official
  - **FERPA:** The institution's FERPA compliance officer or legal counsel
  - **SOC2:** The organization's external auditor (CPA firm)

### 7.4 Review Process

1. **Submission:** Contributor opens a pull request with the policy, README, and test fixtures.
2. **Automated checks:** CI validates the policy against the HushSpec schema, runs test fixtures, and checks that the README contains required sections.
3. **Peer review:** At least two maintainers review for:
   - Schema conformance and validation pass
   - Reasonable threat model
   - Compliance mapping accuracy (spot-check, not exhaustive audit)
   - Test fixture coverage
   - Documentation quality
4. **Community feedback period:** The PR remains open for at least 14 days after initial review approval to allow community feedback.
5. **Merge:** A maintainer merges the PR. The policy enters `Draft` stage.
6. **Promotion to Accepted:** After the 30-day review period with no blocking issues, a maintainer promotes the policy to `Accepted`.

### 7.5 Versioning and Maintenance

- Library policies are versioned via the HushSpec document's `hushspec` field and Git history.
- When the core HushSpec schema changes (e.g., new rule blocks in 0.2.0, 0.3.0), library policies MUST be updated within 90 days or be marked `Deprecated`.
- Breaking changes to a policy (removing patterns, relaxing restrictions) require a new file with a versioned name (e.g., `hipaa-base-v2.yaml`) and deprecation of the old file.
- Non-breaking changes (adding patterns, tightening restrictions) are applied in-place.

### 7.6 Deprecation

Deprecated policies:
- Remain in the repository for 6 months after deprecation.
- Include a deprecation notice in YAML comments and the vertical README.
- Are excluded from CI test suites after removal.
- Are moved to an `archive/` subdirectory after the 6-month grace period, then removed in the next minor release.

---

## 8. Implementation Roadmap

### Phase 1: Condition System Design (Weeks 1-3)

- Finalize condition JSON Schema (`Condition`, `TimeWindowCondition`, `ContextCondition`, `CapabilityCondition`, `RateCondition`, `AllOfCondition`, `AnyOfCondition`, `NotCondition`)
- Add `when` field to all rule block schemas
- Write conformance test vectors for condition evaluation, including:
  - Positive and negative time-window tests
  - Context matching with missing fields (must fail closed)
  - Compound condition nesting at depth limits
  - Version-mismatch rejection (0.1.0 engine receives 0.2.0 document)
- Update spec prose (Section 3 addendum for `when` field on each rule block)

**Deliverables:** Updated `schemas/hushspec-core.v0.schema.json`, new `schemas/hushspec-conditions.v0.schema.json`, test fixtures in `fixtures/core/conditions/`

### Phase 2: Time-Based and Context-Based Conditions (Weeks 4-6)

- Implement `TimeWindowCondition` evaluation in Rust SDK
- Implement `ContextCondition` evaluation in Rust SDK
- Implement `CapabilityCondition` evaluation in Rust SDK
- Define runtime context object types (`EvaluationContext` struct)
- Add `when` field to all Rust rule block types
- Write unit tests and property tests for condition evaluation

**Deliverables:** Updated `crates/hushspec/`, passing `cargo test --workspace`

### Phase 3: Compound and Rate Conditions (Weeks 7-9)

- Implement `AllOfCondition`, `AnyOfCondition`, `NotCondition` in Rust
- Implement `RateCondition` with engine-provided counter interface
- Implement nesting depth limit enforcement
- Add condition-aware evaluation to the `evaluate` module
- End-to-end integration tests with full policy documents

**Deliverables:** Complete condition support in Rust SDK

### Phase 4: Port to TypeScript, Python, Go SDKs (Weeks 10-14)

- Port condition types and evaluation to TypeScript (`packages/hushspec/`)
- Port to Python (`packages/python/hushspec/`)
- Port to Go (`packages/go/hushspec/`)
- Run shared conformance test fixtures across all SDKs
- Update generated contract types for all languages

**Deliverables:** Condition support in all four SDKs, passing cross-language conformance tests

### Phase 5: Initial Policy Library (Weeks 15-19)

- Author HIPAA base, coding-agent, and data-analysis policies
- Author SOC2 base policy
- Author PCI-DSS policy
- Author FedRAMP base policy
- Author FERPA student-agent and grading-agent policies
- Author general-purpose policies (minimal, recommended, maximum, air-gapped)
- Write README and compliance mapping for each vertical
- Create test fixtures for each policy

**Deliverables:** `library/` directory with healthcare, finance, government, education, and general verticals

### Phase 6: Community Infrastructure (Weeks 20-23)

- Set up CI checks for library policy validation
- Create PR template for policy contributions
- Write contributor guide for policy authors
- Establish review process with CODEOWNERS
- Set up automated schema validation in CI for all `library/**/*.yaml`

**Deliverables:** Contribution infrastructure, documentation, CI pipeline

### Phase 7: Extended Verticals and Conditional Library Policies (Weeks 24-28)

- Author DevOps policies (cicd-hardened, incident-response)
- Add conditional variants of existing policies (SOC2 with time windows, HIPAA with environment conditions)
- Author trading-agent policy for finance vertical
- Author ITAR-restricted policy for government vertical

**Deliverables:** Complete library with all verticals, conditional policy examples

### Phase 8: Policy Registry (Weeks 29+)

- Design policy registry API (list, search, fetch policies by vertical/compliance/tag)
- Implement registry CLI (`hushspec policy list`, `hushspec policy fetch hipaa-base`)
- Consider integration with `extends` resolution (e.g., `extends: "registry:hipaa-base@0.2.0"`)
- Community dashboard for policy usage metrics and feedback

**Deliverables:** Policy registry service and CLI integration (scope TBD based on adoption)

---

## 9. Alternatives Considered

### 9.1 Open Policy Agent (OPA) / Rego

OPA is a general-purpose policy engine using the Rego language. It was considered as the basis for HushSpec's condition system.

**Why not:**
- Rego is a full programming language with imports, comprehensions, and partial evaluation. This violates our non-Turing-complete principle and makes policies difficult to audit without Rego expertise.
- OPA is designed for infrastructure policy (Kubernetes admission, API authorization). Its data model does not align with AI agent tool-boundary concerns.
- Rego policies are not portable YAML -- they require a Rego runtime, adding a dependency to every HushSpec engine.
- HushSpec's fail-closed philosophy requires that invalid or unparseable policies deny everything. OPA's default is more nuanced (undefined decisions, partial results), which creates semantic mismatches.

**What we took from OPA:** The concept of a structured input document (OPA's `input`) informed our runtime context object design. OPA's approach of separating policy from data is reflected in HushSpec's separation of rule declarations from engine implementation.

### 9.2 AWS Cedar

Cedar is Amazon's policy language used in Amazon Verified Permissions. It was considered for its clean syntax and formal verification properties.

**Why not:**
- Cedar is tightly coupled to the AWS entity-attribute model (principals, actions, resources, conditions). HushSpec's domain model (rule blocks, action types, tool boundaries) maps poorly to Cedar's structure.
- Cedar policies are written in a bespoke syntax, not YAML. Adopting Cedar would require either a YAML-to-Cedar transpiler (complexity) or abandoning YAML (breaking change).
- Cedar's formal verification is powerful but adds significant implementation complexity to every SDK. HushSpec targets minimal footprint across four languages.
- Cedar is Apache-licensed and open-source, but its ecosystem is AWS-centric. HushSpec is cloud-agnostic.

**What we took from Cedar:** Cedar's approach to deny-overrides-allow influenced HushSpec's decision precedence (Section 6.1). Cedar's condition expressions (`when { ... }`) inspired our `when` field name and positioning.

### 9.3 Casbin

Casbin is a multi-language authorization library supporting RBAC, ABAC, ACL, and custom models via a PERM (Policy, Effect, Request, Matchers) metamodel.

**Why not:**
- Casbin's matcher expressions are string-based DSL snippets (e.g., `r.sub == p.sub && r.obj == p.obj`). While more expressive than HushSpec conditions, they introduce a micro-language that is difficult to validate statically and audit without understanding Casbin's evaluation semantics.
- Casbin's model file + policy file split adds conceptual overhead. HushSpec aims for single-document policies that are self-contained and understandable in isolation.
- Casbin's ABAC support is powerful but general-purpose. HushSpec's condition types are intentionally domain-specific (time windows, agent capabilities, action rates) to provide better defaults and clearer semantics for the AI agent security domain.
- Casbin does not have a fail-closed default. Policies that do not match any rule produce engine-specific behavior, which conflicts with HushSpec's deny-by-default principle.

**What we took from Casbin:** Casbin's multi-language approach (Go, Java, Node.js, Python, Rust, etc.) validated HushSpec's strategy of providing SDKs in multiple languages with shared conformance tests. Casbin's ABAC model influenced the structure of our context object.

### 9.4 Raw Code Policies (JavaScript/Python/Lua)

Embedding policy logic as executable code was considered for maximum flexibility.

**Why not:**
- Executable policies are not auditable without reading and understanding the code. A YAML condition like `context: { environment: production }` is immediately comprehensible; a JavaScript function `(ctx) => ctx.environment === "production"` requires trusting the code is correct.
- Code policies are not portable. A JavaScript policy cannot run in a Rust or Go engine without embedding a JS runtime.
- Code policies can have side effects, access the network, modify state, or loop infinitely. None of these are acceptable for a security policy language.
- Code policies cannot be statically analyzed for coverage, conflicts, or completeness.

**What we took from code policies:** The recognition that some organizations genuinely need custom logic beyond what a fixed condition system provides. This is addressed by the `custom` namespace in the context object, which allows engines to inject arbitrary runtime data that conditions can match against using the standard `context` condition type.

### 9.5 Policy as Configuration Only (No Conditions)

The simplest alternative: keep HushSpec purely static and rely on external tooling (Terraform, Ansible, CI/CD pipelines) to swap policy documents based on context.

**Why not:**
- This approach works for environment-based variation (deploy different policies to production vs. staging) but fails for temporal variation (business hours), user-based variation (different rules for different roles), and rate-based variation (degrade after heavy usage).
- External policy swapping is not auditable within HushSpec itself -- an auditor examining a policy document has no way to know that a different document is used in production.
- It fragments the policy across multiple systems, making it harder to understand the complete security posture.

**What we took from this approach:** The recognition that many use cases are adequately served by static policies with external orchestration. Conditions are optional precisely because this simpler approach is often sufficient. The policy library includes static policies (using `hushspec: "0.1.0"`) alongside conditional ones (using `hushspec: "0.2.0"`).

---

## Appendix A: Full Condition Type Reference

| Condition Type | Activation Semantics | Fail-Closed Behavior |
|---|---|---|
| `time_window` | True when current wall-clock time falls within the specified window | Invalid timezone or time format: document rejection |
| `context` | True when all specified context paths match their expected values | Missing context field: evaluates to false |
| `capability` | True when agent capabilities satisfy `has`/`lacks` constraints | Missing `agent.capabilities`: evaluates to false |
| `rate` | True when action count is above/below threshold in sliding window | Engine lacks rate tracking: evaluates to false |
| `all_of` | True when all child conditions are true | Any child error: propagates per child type |
| `any_of` | True when at least one child condition is true | All children error: evaluates to false |
| `not` | True when child condition is false | Child error: propagates per child type |

## Appendix B: Context Object Schema (JSON Schema)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://hushspec.dev/schemas/hushspec-context.v0.schema.json",
  "title": "HushSpec Evaluation Context v0",
  "description": "Schema for the runtime context object passed to condition evaluation.",
  "type": "object",
  "properties": {
    "user": {
      "type": "object",
      "properties": {
        "id": { "type": "string" },
        "role": { "type": "string" },
        "tier": { "type": "string" },
        "groups": { "type": "array", "items": { "type": "string" } },
        "department": { "type": "string" },
        "email_domain": { "type": "string" }
      },
      "additionalProperties": false
    },
    "environment": { "type": "string" },
    "deployment": {
      "type": "object",
      "properties": {
        "region": { "type": "string" },
        "cluster": { "type": "string" },
        "cloud_provider": { "type": "string" }
      },
      "additionalProperties": false
    },
    "agent": {
      "type": "object",
      "properties": {
        "id": { "type": "string" },
        "type": { "type": "string" },
        "model": { "type": "string" },
        "capabilities": { "type": "array", "items": { "type": "string" } },
        "version": { "type": "string" }
      },
      "additionalProperties": false
    },
    "session": {
      "type": "object",
      "properties": {
        "id": { "type": "string" },
        "started_at": { "type": "string", "format": "date-time" },
        "action_count": { "type": "integer", "minimum": 0 },
        "duration_seconds": { "type": "integer", "minimum": 0 }
      },
      "additionalProperties": false
    },
    "request": {
      "type": "object",
      "properties": {
        "id": { "type": "string" },
        "timestamp": { "type": "string", "format": "date-time" }
      },
      "additionalProperties": false
    },
    "custom": {
      "type": "object",
      "additionalProperties": true,
      "description": "Engine-specific custom context fields. This is the extension point for engine-specific data."
    }
  },
  "additionalProperties": false
}
```

**Note on `additionalProperties`:** The top-level context object uses `additionalProperties: false` to ensure condition authors do not reference undefined standard paths. Engine-specific data MUST be placed under the `custom` namespace, which permits arbitrary subfields. This design ensures that condition paths like `custom.my_engine.feature_flag` work correctly while typos in standard paths (e.g., `usr.role` instead of `user.role`) are caught by schema validation.

## Appendix C: Example Conditional Document (Complete)

```yaml
hushspec: "0.2.0"
name: "conditional-production-policy"
description: >
  Production policy with business-hours deployment windows,
  environment-aware egress, and rate-based degradation.

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
    exceptions:
      - "**/.env.example"

  egress:
    enabled: true
    allow:
      - "api.github.com"
      - "registry.npmjs.org"
    default: block
    when:
      context:
        environment: production

  secret_patterns:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical

  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"
    when:
      not:
        all_of:
          - time_window:
              start: "09:00"
              end: "17:00"
              timezone: "America/New_York"
              days: [mon, tue, wed, thu, fri]
          - context:
              user.role: [admin, sre]

  tool_access:
    enabled: true
    allow:
      - read_file
      - list_directory
      - search
      - grep
    block:
      - deploy_production
    require_confirmation:
      - file_write
      - git_push
    default: block

  patch_integrity:
    enabled: true
    max_additions: 200
    max_deletions: 100
    require_balance: true
    max_imbalance_ratio: 3.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth)"
    when:
      rate:
        action_type: patch_apply
        count: 20
        window: "1h"
        behavior: activate_above

extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access, file_write, egress, tool_call]
        budgets:
          file_writes: 100
          tool_calls: 500
      degraded:
        capabilities: [file_access, tool_call]
        budgets:
          tool_calls: 50
    transitions:
      - from: standard
        to: degraded
        on: any_violation
      - from: degraded
        to: standard
        on: user_approval
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
```

## Appendix D: Compliance Mapping Summary

This appendix provides a cross-reference between compliance requirements and the library policies that address them.

| Compliance Framework | Requirement | Library Policy | HushSpec Rule Block |
|---|---|---|---|
| HIPAA | 45 CFR 164.312(a)(1) - Access Control | `hipaa-base` | `forbidden_paths`, `path_allowlist`, `tool_access` |
| HIPAA | 45 CFR 164.312(b) - Audit Controls | `hipaa-base` | `extensions.posture` (degradation logging) |
| HIPAA | 45 CFR 164.312(c)(1) - Integrity | `hipaa-base` | `patch_integrity`, `secret_patterns` |
| HIPAA | 45 CFR 164.312(e)(1) - Transmission Security | `hipaa-base` | `egress` |
| HIPAA | 45 CFR 164.514 - De-identification | `hipaa-base` | `secret_patterns` (PHI pattern detection) |
| SOC2 | CC6.1 - Logical Access Controls | `soc2-base` | `forbidden_paths`, `tool_access` |
| SOC2 | CC6.7 - Transmission Security | `soc2-base` | `egress` |
| SOC2 | CC7.2 - Monitoring | `soc2-base` | `extensions.posture`, `extensions.detection` |
| SOC2 | CC8.1 - Change Management | `soc2-base` | `patch_integrity` |
| PCI-DSS | Req 3.2 - SAD Prohibition | `pci-dss` | `secret_patterns` (CVV, track data) |
| PCI-DSS | Req 3.4 - PAN Protection | `pci-dss` | `secret_patterns` (card number patterns) |
| PCI-DSS | Req 4.1 - Transmission Security | `pci-dss` | `egress` |
| PCI-DSS | Req 7.1 - Least Privilege | `pci-dss` | `forbidden_paths`, `tool_access` |
| FedRAMP | AC-3 - Access Enforcement | `fedramp-base` | `forbidden_paths`, `tool_access` |
| FedRAMP | SC-7 - Boundary Protection | `fedramp-base` | `egress` |
| FedRAMP | CM-3 - Change Control | `fedramp-base` | `patch_integrity` |
| FedRAMP | CM-7 - Least Functionality | `fedramp-base` | `shell_commands`, `tool_access` |
| FERPA | 34 CFR 99.3 - Education Records | `ferpa-student-agent` | `forbidden_paths` |
| FERPA | 34 CFR 99.33 - Redisclosure | `ferpa-student-agent` | `egress` |
