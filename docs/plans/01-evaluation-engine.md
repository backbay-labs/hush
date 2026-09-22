# RFC 01: SDK-Level Evaluation Engine

**Status:** Historical design record (Draft)
**Date:** 2026-03-15
**Authors:** HushSpec Core Team

---

> **Delivery status:** See [the delivery ledger](STATUS.md#numbered-plan-reconciliation). The original RFC scope is retained below for traceability. Four evaluator implementations exist on the open RFC 09 stack; raw-YAML and invalid-runtime-time repairs have a local verification record, not hosted, merge, or release qualification.

## Critique Log

> This section records issues found during review so readers understand what was fixed and why. It should be preserved in the Draft document and removed before the RFC is marked Accepted.

1. **Spec vs. reference divergence on tool_access matching.** The RFC (Section 4.7) stated "Tool names use exact string matching, NOT glob or regex" per spec Section 3.7, but the Rust reference implementation uses `find_first_match` -> `glob_matches` for tool name matching. The RFC must document actual reference behavior and flag the spec divergence.

2. **Phantom "allowlist mode" step in tool_access algorithm.** The RFC described a Step 6: "If `allow` is non-empty and `action.target` is NOT found in it, return deny (allowlist mode)." This step does not exist in the Rust reference. The reference falls through to `default` after the allow check. The RFC's algorithm did not match the code.

3. **Egress glob semantics vs. path glob semantics.** The spec says `*` in egress patterns "matches within a single domain label" (i.e., does not cross `.`), but the reference `glob_matches` function uses `[^/]*` (does not cross `/`). For domain names (which contain no `/`), `*` effectively matches across domain labels. The RFC noted glob implementation details but did not call out this behavioral divergence.

4. **Missing `input_inject` and `remote_desktop_channels` from the action type enum in the test schema.** The test fixture schema (`schemas/hushspec-evaluator-test.v0.schema.json`) constrains action types to 7 values and omits `input_inject`. The RFC mentioned this gap but did not make it an explicit Phase 1 deliverable.

5. **No integration examples.** The original API examples (Section 7) showed isolated `evaluate()` calls. There were no realistic runtime integration patterns showing how evaluate() fits into a middleware pipeline, tool-calling loop, or MCP proxy -- which was called out as Gap #4 in the adoption analysis.

6. **No coverage of evaluate() interaction with extends/resolve().** The RFC mentioned that evaluate() takes a "resolved" spec but never explained what happens if you pass an unresolved spec, how resolve() feeds into evaluate(), or what the end-to-end pipeline looks like. This was Gap #3.

7. **Missing error handling section.** The RFC did not discuss what happens during evaluation when regex compilation fails, when required fields are missing, or when the spec is malformed. The Rust reference uses `unwrap_or(false)` for bad regexes (non-matching), but this was not documented.

8. **Missing performance discussion.** The RFC had no section on evaluation performance characteristics or guidance for hot-path optimization.

9. **computer_use action type missing from the posture capability map.** The Rust reference `required_capability()` function returns `None` for `computer_use`, meaning posture capability guards do not apply to it. The RFC's capability mapping table in Section 5.4.2 did not list `computer_use` and did not explain why it is excluded.

10. **Incomplete fixture reference.** The fixture reference table in Section 8.1 was accurate but did not cross-reference extension fixtures (posture, origins) with their specific test scenarios.

11. **`path_allowlist` default `enabled` value.** The spec says `path_allowlist.enabled` defaults to `false` (unlike most other rules which default to `true`). The RFC mentioned this but did not emphasize it strongly enough -- implementors could easily miss this and default to `true`.

12. **`secret_patterns` severity-to-decision mapping.** The RFC correctly noted that all severities produce `deny` in the current reference, but the spec (Section 3.4) says "The engine determines how severities map to decisions" including `warn` -> `warn`. This is a design decision the RFC should make explicit.

All issues above have been addressed in the revised text below.

---

## 1. Executive Summary

### What we are building

A conformant `evaluate()` function for all four HushSpec SDKs (Rust, TypeScript, Python, Go) that accepts an action description and a resolved HushSpec document and returns a structured decision: `allow`, `warn`, or `deny`, along with the matched rule path and a human-readable reason.

### Why

HushSpec defines four conformance levels (Section 8 of the core spec):

| Level | Capability | Status in Rust | Status in TS | Status in Python | Status in Go |
|-------|-----------|----------------|-------------|-----------------|-------------|
| 0 | Parser | Done | Done | Done | Done |
| 1 | Validator | Done | Done | Done | Done |
| 2 | Merger | Done | Done | Done | Done |
| 3 | Evaluator | **Done** | **Missing** | **Missing** | **Missing** |

The Rust SDK already ships a complete reference evaluator (`crates/hushspec/src/evaluate.rs`, ~1033 lines). The TypeScript, Python, and Go SDKs stop at Level 2. Downstream consumers in those ecosystems cannot use HushSpec to make runtime security decisions without re-implementing evaluation logic from scratch, which defeats the portability guarantee.

### Current state

Each SDK can:

- **Parse** YAML into typed structures (`parse()` / `Parse()`)
- **Validate** structural correctness (`validate()` / `Validate()`)
- **Merge** parent and child specs via `extends` (`merge()` / `Merge()`)
- **Resolve** full inheritance chains (`resolve()` / `Resolve()`)

None of the non-Rust SDKs can answer the question: "Given this resolved policy and this proposed action, what is the decision?"

### Target state

All four SDKs export an `evaluate()` function with identical semantics. Conformance is verified by a shared corpus of YAML evaluation fixtures (`fixtures/core/evaluation/*.test.yaml`, `fixtures/posture/evaluation/*.test.yaml`, `fixtures/origins/evaluation/*.test.yaml`). Any conformant evaluator must produce the same decision, matched rule, and (where specified) the same reason string for every fixture case.

### Gaps addressed

This RFC directly addresses three gaps from the adoption analysis:

- **Gap #1 (No evaluation engine):** Provides `evaluate(spec, action) -> Decision` in all four SDKs.
- **Gap #3 (No extends resolution interaction):** Specifies how `resolve()` feeds into `evaluate()` and what happens with unresolved specs (Section 5.7).
- **Gap #4 (No runtime integration examples):** Includes realistic integration patterns for middleware, tool-calling loops, and MCP proxies (Section 7.7--7.10).

---

## 2. Current State Analysis

### 2.1 Rust SDK (Level 3 -- Complete)

The Rust crate `hushspec` (at `crates/hushspec/`) already exports a full evaluation engine.

**Public API surface:**

```rust
// crates/hushspec/src/lib.rs
pub use evaluate::{
    Decision, EvaluationAction, EvaluationResult, OriginContext, PostureContext, PostureResult,
    evaluate,
};
```

**Key types:**

```rust
pub enum Decision { Allow, Warn, Deny }

pub struct EvaluationAction {
    pub action_type: String,     // "file_read", "egress", "tool_call", etc.
    pub target: Option<String>,  // path, domain, tool name, command string
    pub content: Option<String>, // file content (for secret scan), patch content
    pub origin: Option<OriginContext>,
    pub posture: Option<PostureContext>,
    pub args_size: Option<usize>,
}

pub struct EvaluationResult {
    pub decision: Decision,
    pub matched_rule: Option<String>,  // e.g. "rules.egress.block"
    pub reason: Option<String>,
    pub origin_profile: Option<String>,
    pub posture: Option<PostureResult>,
}
```

**Function signature:**

```rust
pub fn evaluate(spec: &HushSpec, action: &EvaluationAction) -> EvaluationResult;
```

The Rust implementation handles all 7 core action types (`file_read`, `file_write`, `egress`, `shell_command`, `tool_call`, `patch_apply`, `computer_use`), plus origin profile selection, posture state resolution, and posture capability guards. It serves as the reference against which all other SDKs must be tested.

### 2.2 TypeScript SDK (Level 2)

Located at `packages/hushspec/`. Exports parse, validate, merge, and resolve. No evaluation types or functions exist.

**Current public API (`packages/hushspec/src/index.ts`):**

```typescript
export { parse, parseOrThrow } from './parse.js';
export { validate } from './validate.js';
export { merge } from './merge.js';
export { resolve, resolveFromFile } from './resolve.js';
```

The shared fixture test (`packages/hushspec/tests/shared-fixtures.test.ts`) loads evaluation fixtures but only validates their structure -- it does not run them through an evaluator:

```typescript
// Current: validates fixture shape only
for (const testCase of raw.cases) {
  expect(['allow', 'warn', 'deny']).toContain(testCase.expect.decision);
}
```

### 2.3 Python SDK (Level 2)

Located at `packages/python/hushspec/`. Same situation as TypeScript.

**Current public API (`packages/python/hushspec/__init__.py`):**

```python
from hushspec.parse import parse, parse_or_raise
from hushspec.validate import validate, ValidationResult, ValidationError
from hushspec.merge import merge
from hushspec.resolve import resolve, resolve_file, resolve_or_raise, LoadedSpec
```

The shared fixture test (`packages/python/tests/test_shared_fixtures.py`) validates evaluation fixture structure but does not execute evaluation.

### 2.4 Go SDK (Level 2)

Located at `packages/go/hushspec/`. Exports `Parse`, `Validate`, `Merge`, `Resolve`, `ResolveFile`. No evaluation capability.

**Current public API:**

```go
func Parse(yamlStr string) (*HushSpec, error)
func Validate(spec *HushSpec) *ValidationResult
func Merge(base, child *HushSpec) *HushSpec
func Resolve(spec *HushSpec, source string, loader ResolveLoader) (*HushSpec, error)
func ResolveFile(path string) (*HushSpec, error)
```

The shared fixture test (`packages/go/hushspec/fixtures_test.go`) validates evaluation fixture structure but does not execute evaluation.

### 2.5 The gap

The non-Rust SDKs cannot:

1. Accept an `EvaluationAction` describing a proposed agent operation
2. Route that action to the correct rule blocks based on action type
3. Evaluate glob patterns, regex patterns, or list membership
4. Aggregate decisions across multiple applicable rule blocks
5. Return a structured `EvaluationResult` with the winning decision and its provenance

The Rust implementation at `crates/hushspec/src/evaluate.rs` is the canonical reference for all of the above.

---

## 3. Core Design: The Evaluate Function

### 3.1 Function signature in each language

**Rust** (already implemented):

```rust
pub fn evaluate(spec: &HushSpec, action: &EvaluationAction) -> EvaluationResult;
```

**TypeScript** (proposed):

```typescript
export function evaluate(spec: HushSpec, action: EvaluationAction): EvaluationResult;
```

**Python** (proposed):

```python
def evaluate(spec: HushSpec, action: EvaluationAction) -> EvaluationResult:
```

**Go** (proposed):

```go
func Evaluate(spec *HushSpec, action *EvaluationAction) *EvaluationResult
```

### 3.2 Input type: EvaluationAction

The `EvaluationAction` type represents a proposed agent operation to be evaluated against a resolved policy. Its shape is defined by the evaluator test fixture schema (`schemas/hushspec-evaluator-test.v0.schema.json`).

**Canonical fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | REQUIRED | One of the action types from spec Section 5 |
| `target` | string | OPTIONAL | Path, domain, tool name, CUA action ID, or shell command |
| `content` | string | OPTIONAL | File content body or patch diff content |
| `args_size` | integer | OPTIONAL | Serialized argument payload size in bytes (for `tool_call`) |
| `origin` | OriginContext | OPTIONAL | Origin metadata for origin-aware evaluation |
| `posture` | PostureContext | OPTIONAL | Current posture state and signal |

**OriginContext fields** (all optional):

`provider`, `tenant_id`, `space_id`, `space_type`, `visibility`, `external_participants` (bool), `tags` (string array), `sensitivity`, `actor_role`

**PostureContext fields** (all optional):

`current` (current posture state name), `signal` (transition signal name)

**TypeScript definition:**

```typescript
export interface EvaluationAction {
  type: string;
  target?: string;
  content?: string;
  args_size?: number;
  origin?: OriginContext;
  posture?: PostureContext;
}

export interface OriginContext {
  provider?: string;
  tenant_id?: string;
  space_id?: string;
  space_type?: string;
  visibility?: string;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  actor_role?: string;
}

export interface PostureContext {
  current?: string;
  signal?: string;
}
```

**Python definition:**

```python
@dataclass
class EvaluationAction:
    type: str
    target: str | None = None
    content: str | None = None
    args_size: int | None = None
    origin: OriginContext | None = None
    posture: PostureContext | None = None

@dataclass
class OriginContext:
    provider: str | None = None
    tenant_id: str | None = None
    space_id: str | None = None
    space_type: str | None = None
    visibility: str | None = None
    external_participants: bool | None = None
    tags: list[str] = field(default_factory=list)
    sensitivity: str | None = None
    actor_role: str | None = None

@dataclass
class PostureContext:
    current: str | None = None
    signal: str | None = None
```

**Go definition:**

```go
type EvaluationAction struct {
    Type     string         `yaml:"type" json:"type"`
    Target   string         `yaml:"target,omitempty" json:"target,omitempty"`
    Content  string         `yaml:"content,omitempty" json:"content,omitempty"`
    ArgsSize *int           `yaml:"args_size,omitempty" json:"args_size,omitempty"`
    Origin   *OriginContext `yaml:"origin,omitempty" json:"origin,omitempty"`
    Posture  *PostureContext `yaml:"posture,omitempty" json:"posture,omitempty"`
}

type OriginContext struct {
    Provider             string   `yaml:"provider,omitempty" json:"provider,omitempty"`
    TenantID             string   `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
    SpaceID              string   `yaml:"space_id,omitempty" json:"space_id,omitempty"`
    SpaceType            string   `yaml:"space_type,omitempty" json:"space_type,omitempty"`
    Visibility           string   `yaml:"visibility,omitempty" json:"visibility,omitempty"`
    ExternalParticipants *bool    `yaml:"external_participants,omitempty" json:"external_participants,omitempty"`
    Tags                 []string `yaml:"tags,omitempty" json:"tags,omitempty"`
    Sensitivity          string   `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
    ActorRole            string   `yaml:"actor_role,omitempty" json:"actor_role,omitempty"`
}

type PostureContext struct {
    Current string `yaml:"current,omitempty" json:"current,omitempty"`
    Signal  string `yaml:"signal,omitempty" json:"signal,omitempty"`
}
```

### 3.3 Output type: EvaluationResult

**Canonical fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `decision` | Decision | REQUIRED | `allow`, `warn`, or `deny` |
| `matched_rule` | string | OPTIONAL | Dot-path to the rule that produced the decision (e.g., `rules.egress.block`) |
| `reason` | string | OPTIONAL | Human-readable explanation |
| `origin_profile` | string | OPTIONAL | ID of the matched origin profile, if any |
| `posture` | PostureResult | OPTIONAL | Resolved posture state transition |

**PostureResult fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `current` | string | REQUIRED | Posture state at evaluation time |
| `next` | string | REQUIRED | Posture state after signal processing |

**Decision enum values:** `allow`, `warn`, `deny`

### 3.4 Decision precedence logic

Per spec Section 6.1, when multiple rule blocks apply to a single action:

1. **`deny` takes absolute precedence.** If any applicable rule block denies, the action is denied.
2. **`warn` is next.** If no rule block denies but at least one warns, the decision is `warn`.
3. **`allow` applies only when all applicable rule blocks allow.**

In the current Rust reference implementation, decision precedence is handled by short-circuit evaluation within each action type handler, not by a generic aggregation function. This is because each action type has a fixed, known set of applicable rule blocks, and those blocks are evaluated in priority order. The first `deny` or `warn` result terminates evaluation.

For example, `file_write` checks `forbidden_paths` then `path_allowlist` then `secret_patterns`, returning early on the first non-allow result. This is semantically equivalent to aggregating all decisions and picking the highest-precedence one.

### 3.5 Action type to rule block routing

Per spec Section 5, each action type is evaluated against specific rule blocks:

| Action Type | Rule Blocks (evaluated in order) |
|-------------|----------------------------------|
| `file_read` | `forbidden_paths`, `path_allowlist` |
| `file_write` | `forbidden_paths`, `path_allowlist`, `secret_patterns` |
| `patch_apply` | `forbidden_paths`, `path_allowlist`, `patch_integrity` |
| `egress` | `egress` |
| `shell_command` | `shell_commands` |
| `tool_call` | `tool_access` |
| `computer_use` | `computer_use` |
| `input_inject` | `input_injection` (not yet implemented in reference) |
| `custom` | Engine-specific (not in scope) |

When a rule block is absent from the document, it has no effect on the decision (implicit allow). When a rule block is present but `enabled: false`, it is inert and MUST NOT influence decisions.

---

## 4. Rule-by-Rule Evaluation Logic

This section documents the precise evaluation algorithm for each of the 10 core rule blocks. All implementations MUST match the Rust reference behavior to pass the conformance fixtures. Where the reference diverges from the spec text, the reference behavior is authoritative for conformance testing, and the divergence is noted.

### 4.1 `rules.forbidden_paths`

**Applicable action types:** `file_read`, `file_write`, `patch_apply`

**Input:** `action.target` (file path)

**Algorithm:**

1. If rule is absent or `enabled: false`, return no decision (continue to next rule).
2. If `action.target` matches any pattern in `exceptions` (glob match), return **allow** with `matched_rule: "rules.forbidden_paths.exceptions"`.
3. If `action.target` matches any pattern in `patterns` (glob match), return **deny** with `matched_rule: "rules.forbidden_paths.patterns"`.
4. Otherwise, return no decision (continue to next rule).

**Important:** Exceptions are checked BEFORE patterns. This means an exception can override a pattern match. The check order is: exceptions first, patterns second.

**Default `enabled` value:** `true`

**Glob matching rules:**
- `*` matches any sequence of characters within a single path segment (does not cross `/`)
- `**` matches any sequence of characters including path separators (crosses `/`)
- `?` matches any single character
- Matching is anchored (full string match, not substring)

**Fixture coverage** (`fixtures/core/evaluation/forbidden-paths.test.yaml` -- 5 cases):

| Case | Target | Expected | Matched Rule |
|------|--------|----------|--------------|
| SSH key deny | `/home/user/.ssh/id_rsa` | deny | `rules.forbidden_paths.patterns` |
| AWS creds deny | `/home/user/.aws/credentials` | deny | `rules.forbidden_paths.patterns` |
| /etc/passwd deny | `/etc/passwd` | deny | `rules.forbidden_paths.patterns` |
| SSH config exception | `/home/user/.ssh/config` | allow | `rules.forbidden_paths.exceptions` |
| Normal file allow | `/home/user/src/main.rs` | allow | (none) |

**Edge cases:**
- Empty `patterns` array: no paths are forbidden regardless of `enabled` state
- Target is empty string: unlikely to match any real pattern, passes through
- When `forbidden_paths` returns allow (via exception), `path_allowlist` is NOT consulted (short-circuit)

### 4.2 `rules.path_allowlist`

**Applicable action types:** `file_read`, `file_write`, `patch_apply`

**Input:** `action.target` (file path), operation type derived from action type

**Algorithm:**

1. If rule is absent or `enabled: false`, return no decision.
2. Determine the relevant pattern array based on operation:
   - `file_read` -> use `read` array
   - `file_write` -> use `write` array
   - `patch_apply` -> use `patch` array; if `patch` is empty, fall back to `write` array
3. If `action.target` matches any pattern in the relevant array (glob match), return **allow** with `matched_rule: "rules.path_allowlist"`.
4. Otherwise, return **deny** with `matched_rule: "rules.path_allowlist"`.

**Important: Default `enabled` value is `false`.** Unlike most other rule blocks which default to `true`, `path_allowlist` defaults to `false`. Implementors MUST respect this -- a document that defines `path_allowlist` without explicitly setting `enabled: true` will have an inert allowlist that does not restrict access.

**Important:** When `path_allowlist` is enabled, it acts as a strict allowlist -- anything not explicitly listed is denied. This is the inverse of `forbidden_paths`.

**Interaction with `forbidden_paths`:** Both rules can apply to the same action. `forbidden_paths` is evaluated first. If it produces a deny, that deny is returned immediately and `path_allowlist` is never consulted. If `forbidden_paths` produces an allow (via exception), that allow is returned and `path_allowlist` is not consulted. Only when `forbidden_paths` produces no decision does `path_allowlist` get evaluated.

**Fixture coverage:** No dedicated fixture file exists in the current suite. See Section 8.5 for the `path-allowlist.test.yaml` fixture to be added.

### 4.3 `rules.egress`

**Applicable action types:** `egress`

**Input:** `action.target` (domain name)

**Algorithm:**

1. If rule is absent or `enabled: false`, return **allow** (no restriction).
2. If `action.target` matches any pattern in `block` (glob match), return **deny** with `matched_rule: "rules.egress.block"`.
3. If `action.target` matches any pattern in `allow` (glob match), return **allow** with `matched_rule: "rules.egress.allow"`.
4. If `default` is `"allow"`, return **allow** with `matched_rule: "rules.egress.default"`.
5. If `default` is `"block"` (the default value), return **deny** with `matched_rule: "rules.egress.default"`.

**Important:** Block takes precedence over allow. A domain that matches both a `block` pattern and an `allow` pattern is denied.

**Known spec/reference divergence on domain glob matching:** The spec (Section 3.3) says `*` should match "within a single domain label" (not crossing `.`), and `**` should match "across labels." However, the reference implementation uses the same `glob_matches` function as path matching, where `*` translates to `[^/]*` (does not cross `/`). Since domain names never contain `/`, a `*` in domain patterns effectively matches across `.` boundaries. For example, `*.evil.com` would match both `a.evil.com` AND `a.b.evil.com` in the reference, whereas the spec intent is that only `a.evil.com` should match. All SDK implementations MUST match the reference behavior (use `[^/]*` for `*`) so that conformance fixtures pass. A future spec revision may introduce a domain-specific matching mode.

**Fixture coverage** (`fixtures/core/evaluation/egress.test.yaml` -- 5 cases):

| Case | Target | Expected | Matched Rule |
|------|--------|----------|--------------|
| Exact allow | `api.openai.com` | allow | `rules.egress.allow` |
| Wildcard allow | `api.anthropic.com` | allow | `rules.egress.allow` |
| Default block | `unknown-api.com` | deny | `rules.egress.default` |
| Explicit block | `phishing.evil.com` | deny | `rules.egress.block` |
| Block over allow | `api.evil.com` | deny | `rules.egress.block` |

### 4.4 `rules.secret_patterns`

**Applicable action types:** `file_write`

**Input:** `action.target` (file path), `action.content` (file content body)

**Algorithm:**

1. If rule is absent or `enabled: false`, return **allow** (no restriction).
2. If `action.target` matches any entry in `skip_paths` (glob match), return **allow** with `matched_rule: "rules.secret_patterns.skip_paths"`.
3. For each entry in `patterns` (in order):
   a. Compile `pattern.pattern` as a regex.
   b. If the regex matches anywhere in `action.content`, return **deny** with `matched_rule: "rules.secret_patterns.patterns.<name>"` where `<name>` is the pattern's `name` field.
4. If no pattern matched, return **allow**.

**Severity-to-decision mapping:** The `severity` field on each pattern (`critical`, `error`, `warn`) is informational in the current reference evaluator. All severity levels produce a **deny** decision. The spec (Section 3.4) says "The engine determines how severities map to decisions," leaving room for `warn`-severity patterns to produce a `warn` decision. For cross-SDK conformance, all SDKs MUST match the reference behavior: all severities produce `deny`. A future RFC may introduce severity-aware decision mapping.

**Regex matching:** The `pattern` field is a full regular expression, not a glob. Matching is a substring search (not anchored). The regex flavor should be as compatible as possible across languages (PCRE2-compatible per spec Section 3.4).

**Error handling:** If a `pattern.pattern` fails to compile as a regex, the reference treats it as non-matching (`unwrap_or(false)`). All SDKs MUST match this behavior -- a bad regex silently fails to match rather than causing an error or a deny. (Note: invalid regexes should have been caught at validation/parse time; encountering one at evaluation time indicates a parser bug.)

**Fixture coverage** (`fixtures/core/evaluation/secret-patterns.test.yaml` -- 4 cases):

| Case | Target | Content | Expected | Matched Rule |
|------|--------|---------|----------|--------------|
| AWS key deny | `/src/config.js` | contains `AKIA...` | deny | `rules.secret_patterns.patterns.aws_access_key` |
| GitHub token deny | `/src/auth.js` | contains `ghp_...` | deny | `rules.secret_patterns.patterns.github_token` |
| Clean content | `/src/main.js` | no secrets | allow | (none) |
| Skip path | `/test/fixtures/sample.js` | contains `AKIA...` | allow | `rules.secret_patterns.skip_paths` |

### 4.5 `rules.patch_integrity`

**Applicable action types:** `patch_apply`

**Input:** `action.content` (patch/diff content in unified diff format)

**Algorithm:**

1. If rule is absent or `enabled: false`, return **allow**.
2. For each entry in `forbidden_patterns` (in order, indexed from 0):
   a. If the regex matches anywhere in `action.content`, return **deny** with `matched_rule: "rules.patch_integrity.forbidden_patterns[<index>]"`.
3. Count patch statistics by scanning lines of `action.content`:
   - Lines starting with `+++` or `---` are skipped (diff headers)
   - Lines starting with `+` (but not `+++`) are additions
   - Lines starting with `-` (but not `---`) are deletions
4. If additions exceed `max_additions` (default 1000), return **deny** with `matched_rule: "rules.patch_integrity.max_additions"`.
5. If deletions exceed `max_deletions` (default 500), return **deny** with `matched_rule: "rules.patch_integrity.max_deletions"`.
6. If `require_balance` is `true`:
   a. Compute the imbalance ratio:
      - If both additions and deletions are 0, ratio is 0.0
      - If one is 0 and the other is nonzero, ratio equals the nonzero count as a float (e.g., 50 additions and 0 deletions yields ratio 50.0). This always exceeds any reasonable `max_imbalance_ratio`, resulting in deny.
      - Otherwise, ratio = max(additions, deletions) / min(additions, deletions)
   b. If ratio exceeds `max_imbalance_ratio` (default 10.0), return **deny** with `matched_rule: "rules.patch_integrity.max_imbalance_ratio"`.
7. Return **allow**.

**Regex error handling:** Same as `secret_patterns` -- a bad regex silently fails to match.

**Fixture coverage** (`fixtures/core/evaluation/patch-integrity.test.yaml` -- 2 cases):

| Case | Content | Expected | Matched Rule |
|------|---------|----------|--------------|
| Forbidden pattern | `disable security` in diff | deny | `rules.patch_integrity.forbidden_patterns[0]` |
| Clean patch | 2 additions | allow | (none) |

**Fixture gaps:** The current fixture file has only 2 cases. Missing: `max_additions` exceeded, `max_deletions` exceeded, imbalance ratio violations for `(0, N)` and `(N, 0)`, and balanced patches within ratio. See Section 8.5.

### 4.6 `rules.shell_commands`

**Applicable action types:** `shell_command`

**Input:** `action.target` (complete shell command string)

**Algorithm:**

1. If rule is absent or `enabled: false`, return **allow**.
2. For each entry in `forbidden_patterns` (in order, indexed from 0):
   a. If the regex matches anywhere in `action.target`, return **deny** with `matched_rule: "rules.shell_commands.forbidden_patterns[<index>]"`.
3. Return **allow**.

**Fixture coverage** (`fixtures/core/evaluation/shell-commands.test.yaml` -- 5 cases):

| Case | Target | Expected | Matched Rule |
|------|--------|----------|--------------|
| rm -rf / | `rm -rf /` | deny | `rules.shell_commands.forbidden_patterns[0]` |
| curl pipe bash | `curl ... \| bash` | deny | `rules.shell_commands.forbidden_patterns[1]` |
| chmod 777 | `chmod 777 /etc/passwd` | deny | `rules.shell_commands.forbidden_patterns[3]` |
| safe command | `ls -la /home/user` | allow | (none) |
| safe rm | `rm temp.txt` | allow | (none) |

### 4.7 `rules.tool_access`

**Applicable action types:** `tool_call`

**Input:** `action.target` (tool name), `action.args_size` (optional argument payload size)

**Algorithm:**

1. If rule is absent or `enabled: false`, return **allow**.
2. If `max_args_size` is specified and `action.args_size` exceeds it, return **deny** with `matched_rule: "rules.tool_access.max_args_size"`.
3. If `action.target` matches any entry in `block`, return **deny** with `matched_rule: "rules.tool_access.block"`.
4. If `action.target` matches any entry in `require_confirmation`, return **warn** with `matched_rule: "rules.tool_access.require_confirmation"`.
5. If `action.target` matches any entry in `allow`, return **allow** with `matched_rule: "rules.tool_access.allow"`.
6. Apply `default`:
   - `"allow"` (the default) -> return **allow** with `matched_rule: "rules.tool_access.default"`
   - `"block"` -> return **deny** with `matched_rule: "rules.tool_access.default"`

**Known spec/reference divergence on matching method:** The spec (Section 3.7) states: "Tool names are matched as exact strings. Glob or regex matching is NOT supported for tool names." However, the Rust reference implementation uses the same `find_first_match` -> `glob_matches` function for tool name matching as it does for paths and domains. In practice, tool names rarely contain `*`, `**`, or `?` characters, so the divergence is harmless for real-world usage. All SDKs MUST match the reference behavior: use glob matching for tool names. If the spec is amended to require exact matching, all SDKs will be updated together.

**Known spec/reference divergence on allowlist mode:** The spec (Section 3.7, Step 4) says: "If `allow` is non-empty and the tool name does NOT match, the decision is **deny** (allowlist mode)." The Rust reference does NOT implement this step. After checking `block`, `require_confirmation`, and `allow`, the reference falls through directly to the `default` value. When `default: "block"`, the behavior is equivalent to the spec's allowlist mode. When `default: "allow"`, an unlisted tool is allowed even if the `allow` list is non-empty -- which contradicts the spec's intent. All SDKs MUST match the reference behavior: no explicit allowlist mode check; fall through to `default`. A spec errata or future revision should reconcile this.

**Precedence within tool_access:** block > max_args_size > require_confirmation > allow > default. A tool in both `block` and `allow` is denied. A tool in both `require_confirmation` and `allow` gets `warn`.

(Note: `max_args_size` is checked first in the code, before `block`. But since a size violation always produces deny and block also produces deny, the precedence between them only affects the `matched_rule` path, not the decision.)

**Fixture coverage** (`fixtures/core/evaluation/tool-access.test.yaml` -- 5 cases):

| Case | Target | Expected | Matched Rule |
|------|--------|----------|--------------|
| Allow listed | `read_file` | allow | `rules.tool_access.allow` |
| Deny blocked | `shell_exec` | deny | `rules.tool_access.block` |
| Default block | `deploy_production` | deny | `rules.tool_access.default` |
| Require confirmation | `file_write` | warn | `rules.tool_access.require_confirmation` |
| Block precedence | `run_command` | deny | `rules.tool_access.block` |

**Decision precedence fixture** (`fixtures/core/evaluation/decision-precedence.test.yaml` -- 3 cases):

| Case | Action Type | Target | Expected | Matched Rule |
|------|-------------|--------|----------|--------------|
| Block beats allow (egress) | egress | `api.example.com` | deny | `rules.egress.block` |
| Warn beats allow (tool) | tool_call | `file_write` | warn | `rules.tool_access.require_confirmation` |
| Plain allow | tool_call | `github_search` | allow | `rules.tool_access.allow` |

### 4.8 `rules.computer_use`

**Applicable action types:** `computer_use`

**Input:** `action.target` (CUA action identifier)

**Algorithm:**

1. If rule is absent or `enabled: false` (default is `false`), return **allow**.
2. If `action.target` is found in `allowed_actions` (exact string match via `iter().any()`), return **allow** with `matched_rule: "rules.computer_use.allowed_actions"`.
3. Based on `mode`:
   - `"observe"`: return **allow** with `matched_rule: "rules.computer_use.mode"` (log but do not block)
   - `"guardrail"` (default): return **warn** with `matched_rule: "rules.computer_use.mode"`
   - `"fail_closed"`: return **deny** with `matched_rule: "rules.computer_use.mode"`

**Fixture coverage** (`fixtures/core/evaluation/computer-use.test.yaml` -- 3 cases):

| Case | Target | Expected | Matched Rule |
|------|--------|----------|--------------|
| Allowed action | `remote.session.connect` | allow | `rules.computer_use.allowed_actions` |
| Unlisted (guardrail) | `remote.file_transfer` | warn | `rules.computer_use.mode` |
| Allowed (input.inject) | `input.inject` | allow | `rules.computer_use.allowed_actions` |

**Fixture gaps:** The current fixture only tests `guardrail` mode. Missing: `observe` mode (allow with audit), `fail_closed` mode (deny). See Section 8.5.

### 4.9 `rules.remote_desktop_channels`

**Applicable action types:** Not directly mapped to any standard action type in the current evaluator. This rule block provides boolean channel controls queried by engines directly.

**Semantics:** Each boolean field controls whether a specific side channel is permitted. When `enabled: true`, `clipboard: false` means clipboard sharing is blocked, `file_transfer: true` means file transfer is allowed, and so on.

**Evaluation approach:** The reference evaluator does not currently route any standard action type to this rule. Engines that support remote desktop sessions query the channel booleans directly. SDK implementations SHOULD expose these fields on the parsed `Rules` type but MAY defer routing until a dedicated action type (e.g., `channel_access`) is defined in a future spec version.

### 4.10 `rules.input_injection`

**Applicable action types:** `input_inject`

**Input:** `action.target` (input type identifier, e.g., `"keyboard"`, `"mouse"`, `"touch"`)

**Algorithm:**

1. If rule is absent or `enabled: false` (default is `false`), return **allow**.
2. If `allowed_types` is empty, return **deny** (fail-closed).
3. If `action.target` is found in `allowed_types` (exact string match), return **allow**.
4. Otherwise, return **deny**.

**Note:** The reference Rust evaluator does not yet implement `input_inject` as a routed action type. The `match` statement in `evaluate()` does not have an `"input_inject"` arm, so it falls through to the unknown action type handler (which returns allow). This is a gap to be closed in Phase 1. See Section 6.

**Note:** The test fixture schema (`schemas/hushspec-evaluator-test.v0.schema.json`) does not include `"input_inject"` in the action type enum. This must be updated alongside the evaluator code.

---

## 5. Cross-Cutting Concerns

### 5.1 Unknown action types

The current Rust reference evaluator returns **allow** for unrecognized action types with reason `"no reference evaluator rule for this action type"`. This is a pragmatic choice: unknown action types pass through without triggering any rule block.

However, the spec's fail-closed principle (Section 1.2) suggests that unknown action types should arguably be denied. The evaluator test fixture schema (`schemas/hushspec-evaluator-test.v0.schema.json`) constrains the `type` field to a fixed enum of 7 values, so this ambiguity does not affect conformance testing.

**Implementation guidance:** All SDKs MUST match the Rust reference behavior (allow for unknown action types with a descriptive reason) to ensure cross-SDK conformance. If the spec is amended to require fail-closed for unknown action types, all SDKs will be updated together.

### 5.2 Multiple rules matching a single action

For action types that consult multiple rule blocks (e.g., `file_write` checks `forbidden_paths`, `path_allowlist`, and `secret_patterns`), the evaluation order matters:

1. **Path-level rules first:** `forbidden_paths`, then `path_allowlist`
2. **Content-level rules second:** `secret_patterns` (for `file_write`), `patch_integrity` (for `patch_apply`)

Short-circuit semantics: if any path-level rule produces a decision (allow via exception, or deny via pattern/allowlist), content-level rules are never consulted. This is an optimization but also has semantic implications -- a file write to a forbidden path is denied without scanning the content for secrets.

### 5.3 Missing or empty rules

If the `rules` field is absent or empty (`{}`), no rules are active. All actions are allowed. This is consistent with spec Section 3: "If `rules` is absent or empty, no rules are active."

If a specific rule block is absent (e.g., no `egress` rule), actions of the corresponding type pass through without restriction (implicit allow).

### 5.4 Extension evaluation

The evaluation engine supports three extension modules that layer on top of core rules:

#### 5.4.1 Origins extension (`extensions.origins`)

Origin-aware evaluation allows policies to vary based on the source context of a request. When an `action.origin` is provided:

1. **Profile selection:** Iterate `extensions.origins.profiles` and score each against the origin context. Each field that matches adds to the score (weighted: `space_id` = 8, `tenant_id` = 6, `provider`/`space_type`/`visibility`/`sensitivity`/`actor_role` = 4, `external_participants` = 2, each tag = 1). All specified fields in the profile's `match` block must match for a profile to be a candidate. The highest-scoring profile wins.

2. **Rule override:** A matched profile may override `tool_access` or `egress` rules. When a profile provides these, the profile's rule replaces the top-level rule for that evaluation. The `matched_rule` path reflects this (e.g., `extensions.origins.profiles.<id>.tool_access.block`). The prefix format is `extensions.origins.profiles.<profile_id>.<rule_name>`.

3. **Posture override:** A matched profile may specify a `posture` field that overrides the initial posture state.

**Fixture coverage** (`fixtures/origins/evaluation/origin-matching.test.yaml` -- 2 cases):

| Case | Origin | Expected | Origin Profile | Posture |
|------|--------|----------|----------------|---------|
| Exact channel wins | provider=slack, space_id=C123, visibility=internal | allow | `exact-channel` | standard->standard |
| External shared | provider=slack, visibility=external_shared, ext_participants=true | deny (posture cap) | `external-shared` | restricted->restricted |

The first case demonstrates that a more-specific profile (matching `space_id`) wins over a broader match. The second case shows how a matched profile's posture override (`restricted`) can deny an action via capability guard before core rules are even consulted.

#### 5.4.2 Posture extension (`extensions.posture`)

Posture provides stateful capability management. When `extensions.posture` is defined:

1. **State resolution:** Determine the current posture state from (in priority order):
   a. Matched origin profile's `posture` field
   b. `action.posture.current`
   c. `extensions.posture.initial`

2. **Signal processing:** If `action.posture.signal` is provided (and is not `"none"`), search `transitions` for a matching transition (`from` matches current state or is `"*"`, and trigger name matches the signal). If found, the `next` state is the transition's `to`. Otherwise, `next` equals `current`.

   **Transition trigger names:** The following signal names are recognized:
   - `user_approval`
   - `user_denial`
   - `critical_violation`
   - `any_violation`
   - `timeout`
   - `budget_exhausted`
   - `pattern_match`

3. **Capability guard:** Before evaluating core rules, check if the current posture state has the required capability for the action type. The capability mapping is:

   | Action Type | Required Capability |
   |-------------|-------------------|
   | `file_read` | `file_access` |
   | `file_write` | `file_write` |
   | `patch_apply` | `patch` |
   | `shell_command` | `shell` |
   | `tool_call` | `tool_call` |
   | `egress` | `egress` |
   | `computer_use` | (none -- no capability required) |
   | `input_inject` | (none -- not mapped in reference) |
   | unknown | (none -- no capability required) |

   If the required capability is missing from the state's `capabilities` list, return **deny** immediately with `matched_rule: "extensions.posture.states.<state>.capabilities"` and reason `"posture '<state>' does not allow capability '<capability>'"`. Core rule evaluation is skipped entirely.

4. **Result attachment:** Every evaluation result includes the `posture` field with `current` and `next` states, even when the decision comes from core rules.

**Fixture coverage** (`fixtures/posture/evaluation/posture-transitions.test.yaml` -- 3 cases):

| Case | Current | Signal | Expected | Posture |
|------|---------|--------|----------|---------|
| Standard allows tool use | standard | none | allow | standard->standard |
| Restricted warns on confirmation tool | restricted | any_violation | warn | restricted->restricted |
| Locked denies further tool access | locked | critical_violation | deny (capability) | locked->locked |

The third case is critical: the `locked` state has `capabilities: []`, so the capability guard fires before tool_access rules are consulted. The `matched_rule` is `extensions.posture.states.locked.capabilities`, not a `rules.*` path.

#### 5.4.3 Detection extension (`extensions.detection`)

Detection extension configuration (prompt injection thresholds, jailbreak scoring, threat intel matching) is consumed directly by engines at runtime. It does not participate in the `evaluate()` function's decision logic. SDKs MUST parse and expose detection configuration but MAY defer detection-based evaluation to engine-specific code.

No evaluation fixtures exist for the detection extension, and no fixtures are planned for this RFC.

### 5.5 Glob matching implementation

All SDKs must implement the same glob-to-regex translation for `forbidden_paths`, `path_allowlist`, `egress`, `secret_patterns.skip_paths`, and `tool_access` (block, allow, require_confirmation):

```
*   -> [^/]*     (any chars except path separator, within one segment)
**  -> .*        (any chars including path separator, across segments)
?   -> .         (any single char)
.   -> \.        (escaped literal)
+(){}[]^$|\  -> escaped
all other chars -> literal
```

The translated pattern is anchored with `^` and `$` for full-string matching.

**Reference implementation** (from `crates/hushspec/src/evaluate.rs`, `glob_matches` function):

```rust
fn glob_matches(pattern: &str, target: &str) -> bool {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }
    regex.push('$');
    Regex::new(&regex)
        .map(|compiled| compiled.is_match(target))
        .unwrap_or(false)
}
```

Each non-Rust SDK must port this function exactly. Regex flavor differences between languages (Rust `regex`, JS `RegExp`, Python `re`, Go `regexp`) may require minor adjustments, but the glob-to-regex translation itself must produce identical match behavior.

**Go-specific note:** Go's `regexp` package uses RE2 syntax, which does not support lookahead/lookbehind. The glob translation above uses only basic constructs (`.*`, `[^/]*`, `.`) and is fully compatible with RE2.

**Performance note:** The glob-to-regex translation compiles a new regex on every call. For hot-path evaluation, SDKs SHOULD cache compiled regexes keyed by the glob pattern string. The Rust reference does not cache, but production integrations handling thousands of evaluations per second should consider this optimization. See Section 5.9.

### 5.6 Regex matching behavior

Regex patterns (used in `secret_patterns`, `patch_integrity.forbidden_patterns`, `shell_commands.forbidden_patterns`) are distinct from glob patterns:

- Regex patterns are **not** translated. The `pattern` field value is used directly as a regex.
- Regex matching is a **substring search** (not anchored). The regex is applied via `is_match()` / `.test()` / `re.search()` / `regexp.MatchString()`, which finds matches anywhere in the target string.
- **Error handling:** If regex compilation fails at evaluation time, the pattern is treated as non-matching (the reference uses `unwrap_or(false)`). All SDKs MUST match this behavior.
- **Cross-language compatibility:** Regex patterns in fixtures should use syntax that is valid across Rust `regex`, JS `RegExp`, Python `re`, and Go `regexp` (RE2). In practice, this means avoiding PCRE-specific features like lookahead (`(?=...)`), lookbehind (`(?<=...)`), and backreferences (`\1`). Character classes, quantifiers, alternation, and non-capturing groups (`(?:...)`) are safe.

### 5.7 Interaction with extends and resolve()

The `evaluate()` function expects a **resolved** HushSpec document -- one where the `extends` chain has been fully resolved and merged. The typical usage pipeline is:

```
parse(yaml) -> validate(spec) -> resolve(spec, loader) -> evaluate(resolved_spec, action)
```

**What happens if you pass an unresolved spec to evaluate():**

The `evaluate()` function does not check for or process the `extends` field. If you pass a spec that still has `extends` set, the evaluator will evaluate only the rules defined in that document, ignoring any rules that would have been inherited from the base policy. This is not an error -- it silently produces an incomplete evaluation. SDKs MUST NOT add an `extends` check to `evaluate()` (to match reference behavior), but SDK documentation SHOULD warn users to resolve before evaluating.

**End-to-end pipeline example (TypeScript):**

```typescript
import { parse, validate, resolveFromFile, evaluate } from '@hushspec/core';
import type { EvaluationAction, EvaluationResult } from '@hushspec/core';

// 1. Parse the YAML
const { value: spec, error } = parse(yamlContent);
if (error) throw new Error(`Parse failed: ${error}`);

// 2. Validate
const validation = validate(spec);
if (!validation.valid) throw new Error(`Validation failed: ${validation.errors}`);

// 3. Resolve extends chain (loads base policies, merges)
const resolved = await resolveFromFile('/path/to/child-policy.yaml');

// 4. Evaluate
const result: EvaluationResult = evaluate(resolved, {
  type: 'file_read',
  target: '/home/user/.ssh/id_rsa',
});

console.log(result.decision); // 'deny'
```

**End-to-end pipeline example (Go):**

```go
// 1. Resolve from file (parses, validates, resolves extends)
resolved, err := hushspec.ResolveFile("/path/to/child-policy.yaml")
if err != nil {
    log.Fatalf("Failed to resolve: %v", err)
}

// 2. Evaluate
result := hushspec.Evaluate(resolved, &hushspec.EvaluationAction{
    Type:   "file_read",
    Target: "/home/user/.ssh/id_rsa",
})

fmt.Println(result.Decision) // "deny"
```

### 5.8 Error handling during evaluation

The `evaluate()` function is designed to be infallible -- it never returns an error, only a decision. This is intentional: at evaluation time, the document has already been parsed and validated. Any error during evaluation is treated as a non-match rather than a failure.

Specific error handling behaviors:

| Situation | Behavior | Reference code |
|-----------|----------|----------------|
| Regex compilation fails | Pattern treated as non-matching | `Regex::new(...).unwrap_or(false)` |
| `action.target` is `None` | Treated as empty string `""` | `action.target.as_deref().unwrap_or_default()` |
| `action.content` is `None` | Treated as empty string `""` | `action.content.as_deref().unwrap_or_default()` |
| `action.args_size` is `None` | Treated as 0 | `args_size.unwrap_or_default()` |
| Unknown posture state | No capability guard fires; core rules apply normally | `posture_extension.states.get(...)` returns `None` |

SDKs MUST match these behaviors exactly. The evaluate function must not panic, throw, or return an error type.

### 5.9 Performance considerations

Evaluation should be fast. In a typical agent runtime, `evaluate()` is called before every tool invocation, file access, and network request. Target latency for a single evaluation is under 1 millisecond.

**Hotspots:**

1. **Glob-to-regex compilation:** The reference compiles a new regex for every glob match. For policies with many patterns and high evaluation frequency, this is the dominant cost. SDKs SHOULD cache compiled regexes, keyed by the glob pattern string. A simple approach:

   ```typescript
   const regexCache = new Map<string, RegExp>();
   function globMatches(pattern: string, target: string): boolean {
     let re = regexCache.get(pattern);
     if (!re) {
       re = new RegExp(globToRegex(pattern));
       regexCache.set(pattern, re);
     }
     return re.test(target);
   }
   ```

2. **Secret pattern regex compilation:** The `patterns` array in `secret_patterns` should have its regexes compiled once at parse time or on first evaluation, not on every call.

3. **Origin profile scoring:** Profile selection iterates all profiles and scores each one. For documents with many profiles, this is O(N) per evaluation. This is acceptable for typical usage (< 20 profiles).

**Recommendation:** Phase 2-4 implementations should include regex caching from the start. The Rust reference can be optimized later without changing semantics.

---

## 6. Implementation Plan

### Phase 1: Rust Reference Hardening

**Status:** Largely complete. Remaining work:

1. **Add `input_inject` action type routing.** The reference evaluator currently does not handle `action_type: "input_inject"`. Add a case to the `match` statement in `evaluate()` that routes to `evaluate_input_injection()`.

2. **Update the test fixture schema.** Add `"input_inject"` to the action type enum in `schemas/hushspec-evaluator-test.v0.schema.json`.

3. **Add evaluation fixtures for `input_injection`.** Create `fixtures/core/evaluation/input-injection.test.yaml` with cases for: enabled with allowed_types, empty allowed_types (deny), unlisted type (deny), disabled (allow).

4. **Add missing evaluation fixtures.** See Section 8.5 for the full list of fixture files to create.

5. **Verify imbalance ratio edge case:** When `require_balance: true` and one of additions/deletions is 0, the current code computes ratio as the nonzero count. Add fixture cases that explicitly test `(0, N)` and `(N, 0)` imbalance.

**Files to modify:**
- `crates/hushspec/src/evaluate.rs` -- add `input_inject` case
- `schemas/hushspec-evaluator-test.v0.schema.json` -- add `input_inject` to enum
- `fixtures/core/evaluation/` -- new fixture files

**Estimated effort:** 1-2 days

### Phase 2: TypeScript Port

**New files:**
- `packages/hushspec/src/evaluate.ts` -- core evaluation logic
- `packages/hushspec/tests/evaluate.test.ts` -- fixture-driven conformance tests

**Modifications:**
- `packages/hushspec/src/index.ts` -- export `evaluate`, `EvaluationAction`, `EvaluationResult`, `Decision`, `OriginContext`, `PostureContext`, `PostureResult`
- `packages/hushspec/tests/shared-fixtures.test.ts` -- upgrade evaluation fixture tests from structural validation to full evaluation

**Implementation approach:**

1. Define `EvaluationAction`, `EvaluationResult`, `Decision`, `OriginContext`, `PostureContext`, `PostureResult` interfaces in `evaluate.ts`.

2. Implement `globMatches(pattern: string, target: string): boolean` as a direct port of the Rust `glob_matches` function. Use `RegExp` constructor with the same glob-to-regex translation. Add a `Map<string, RegExp>` cache for compiled patterns.

3. Implement per-rule evaluation functions:
   - `evaluateForbiddenPaths(rule, target, posture, originProfileId)`
   - `evaluatePathAllowlist(rule, target, operation, posture, originProfileId)`
   - `evaluateEgressRule(rule, prefix, target, posture, originProfileId)`
   - `evaluateSecretPatterns(rule, target, content, posture, originProfileId)`
   - `evaluatePatchIntegrity(rule, content, posture, originProfileId)`
   - `evaluateShellRule(rule, target, posture, originProfileId)`
   - `evaluateToolAccessRule(rule, prefix, target, argsSize, posture, originProfileId)`
   - `evaluateComputerUseRule(rule, target, posture, originProfileId)`

4. Implement origin profile selection: `selectOriginProfile(spec, origin)`

5. Implement posture resolution: `resolvePosture(spec, matchedProfile, postureContext)`

6. Implement the top-level `evaluate(spec, action)` function with the action-type dispatch.

7. Update `shared-fixtures.test.ts` to run full evaluation against all fixture cases.

**Estimated effort:** 3 days

### Phase 3: Python Port

**New files:**
- `packages/python/hushspec/evaluate.py` -- core evaluation logic
- `packages/python/tests/test_evaluate.py` -- fixture-driven conformance tests

**Modifications:**
- `packages/python/hushspec/__init__.py` -- export `evaluate`, `EvaluationAction`, `EvaluationResult`, `Decision`, `OriginContext`, `PostureContext`, `PostureResult`
- `packages/python/tests/test_shared_fixtures.py` -- upgrade evaluation fixture tests to full evaluation

**Implementation approach:**

1. Define dataclasses in `evaluate.py`:

```python
from enum import Enum
from dataclasses import dataclass, field
import re
from functools import lru_cache

class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"

@dataclass
class EvaluationAction:
    type: str
    target: str | None = None
    content: str | None = None
    args_size: int | None = None
    origin: OriginContext | None = None
    posture: PostureContext | None = None

@dataclass
class EvaluationResult:
    decision: Decision
    matched_rule: str | None = None
    reason: str | None = None
    origin_profile: str | None = None
    posture: PostureResult | None = None
```

2. Implement `glob_matches(pattern: str, target: str) -> bool` using Python's `re` module. Use `@lru_cache` on the glob-to-regex translation for pattern caching.

3. Port all per-rule evaluation functions from Rust.

4. Port origin and posture logic.

5. Implement `evaluate(spec: HushSpec, action: EvaluationAction) -> EvaluationResult`.

**Estimated effort:** 2 days

### Phase 4: Go Port

**New files:**
- `packages/go/hushspec/evaluate.go` -- core evaluation logic
- `packages/go/hushspec/evaluate_test.go` -- fixture-driven conformance tests

**Modifications:**
- `packages/go/hushspec/fixtures_test.go` -- upgrade evaluation fixture tests to full evaluation

**Implementation approach:**

1. Define types in `evaluate.go`:

```go
type Decision string

const (
    DecisionAllow Decision = "allow"
    DecisionWarn  Decision = "warn"
    DecisionDeny  Decision = "deny"
)

type EvaluationAction struct {
    Type     string         `yaml:"type" json:"type"`
    Target   string         `yaml:"target,omitempty" json:"target,omitempty"`
    Content  string         `yaml:"content,omitempty" json:"content,omitempty"`
    ArgsSize *int           `yaml:"args_size,omitempty" json:"args_size,omitempty"`
    Origin   *OriginContext `yaml:"origin,omitempty" json:"origin,omitempty"`
    Posture  *PostureContext `yaml:"posture,omitempty" json:"posture,omitempty"`
}

type EvaluationResult struct {
    Decision      Decision       `yaml:"decision" json:"decision"`
    MatchedRule   string         `yaml:"matched_rule,omitempty" json:"matched_rule,omitempty"`
    Reason        string         `yaml:"reason,omitempty" json:"reason,omitempty"`
    OriginProfile string         `yaml:"origin_profile,omitempty" json:"origin_profile,omitempty"`
    Posture       *PostureResult `yaml:"posture,omitempty" json:"posture,omitempty"`
}
```

2. Implement `globMatches(pattern, target string) bool` using Go's `regexp` package. Use a `sync.Map` or package-level cache for compiled patterns.

3. Port all per-rule evaluation functions.

4. Port origin and posture logic.

5. Implement `Evaluate(spec *HushSpec, action *EvaluationAction) *EvaluationResult`.

**Go-specific considerations:**
- Go's `regexp` uses RE2. Verify that all regex patterns in the test fixtures are RE2-compatible. PCRE features like `\s` are available in RE2 via Perl character classes, but backreferences (`\1`) and lookahead/behind are not. All current fixtures use RE2-compatible patterns.
- Go struct tags must serialize as `yaml:"type"` for the action type field (not `yaml:"action_type"`).
- Error handling: Go does not have exceptions. Invalid regexes in patterns should be handled gracefully by checking `regexp.Compile()` error and treating failures as non-matching, consistent with Rust's `unwrap_or(false)`.
- Optional fields: Use pointer types (`*int`, `*bool`) for truly optional fields. Use empty string as the zero value for optional strings (matching the YAML deserialization behavior).

**Estimated effort:** 2-3 days

### Phase 5: Conformance Verification

After all SDKs are implemented:

1. Run `cargo run -p hushspec-testkit -- --fixtures fixtures` and verify all evaluation fixtures pass.
2. Run `npm test` in `packages/hushspec/` and verify all evaluation fixtures pass.
3. Run `pytest packages/python/tests/` and verify all evaluation fixtures pass.
4. Run `cd packages/go && go test ./...` and verify all evaluation fixtures pass.
5. Add a CI step (`ci.yml`) that runs all four SDKs' evaluation conformance tests.
6. Cross-validate: for any fixture case, all four SDKs must produce identical `decision` and `matched_rule` values.

**Estimated effort:** 1 day

### Total estimated effort: 9-11 days

---

## 7. API Examples

### 7.1 File access check

**Rust:**

```rust
use hushspec::{evaluate, EvaluationAction, Decision};

let spec = hushspec::HushSpec::parse(yaml_content).unwrap();
let action = EvaluationAction {
    action_type: "file_read".to_string(),
    target: Some("/home/user/.ssh/id_rsa".to_string()),
    ..Default::default()
};
let result = evaluate(&spec, &action);
assert_eq!(result.decision, Decision::Deny);
assert_eq!(result.matched_rule.as_deref(), Some("rules.forbidden_paths.patterns"));
```

**TypeScript:**

```typescript
import { parse, evaluate } from '@hushspec/core';

const { value: spec } = parse(yamlContent);
const result = evaluate(spec, {
  type: 'file_read',
  target: '/home/user/.ssh/id_rsa',
});
// result.decision === 'deny'
// result.matched_rule === 'rules.forbidden_paths.patterns'
```

**Python:**

```python
from hushspec import parse, evaluate, EvaluationAction

ok, spec = parse(yaml_content)
result = evaluate(spec, EvaluationAction(
    type="file_read",
    target="/home/user/.ssh/id_rsa",
))
assert result.decision == Decision.DENY
assert result.matched_rule == "rules.forbidden_paths.patterns"
```

**Go:**

```go
spec, _ := hushspec.Parse(yamlContent)
result := hushspec.Evaluate(spec, &hushspec.EvaluationAction{
    Type:   "file_read",
    Target: "/home/user/.ssh/id_rsa",
})
// result.Decision == hushspec.DecisionDeny
// result.MatchedRule == "rules.forbidden_paths.patterns"
```

### 7.2 Egress check

**TypeScript:**

```typescript
const result = evaluate(spec, {
  type: 'egress',
  target: 'api.openai.com',
});
// result.decision === 'allow'
// result.matched_rule === 'rules.egress.allow'
```

### 7.3 Tool call check

**Python:**

```python
result = evaluate(spec, EvaluationAction(
    type="tool_call",
    target="deploy",
))
# If "deploy" is in require_confirmation:
# result.decision == Decision.WARN
# result.matched_rule == "rules.tool_access.require_confirmation"
```

### 7.4 Shell command check

**Go:**

```go
result := hushspec.Evaluate(spec, &hushspec.EvaluationAction{
    Type:   "shell_command",
    Target: "rm -rf /",
})
// result.Decision == hushspec.DecisionDeny
// result.MatchedRule == "rules.shell_commands.forbidden_patterns[0]"
```

### 7.5 File write with secret scanning

**TypeScript:**

```typescript
const result = evaluate(spec, {
  type: 'file_write',
  target: '/src/config.js',
  content: "const key = 'AKIA1234567890ABCDEF';",
});
// result.decision === 'deny'
// result.matched_rule === 'rules.secret_patterns.patterns.aws_access_key'
```

### 7.6 Patch apply with integrity check

**Python:**

```python
result = evaluate(spec, EvaluationAction(
    type="patch_apply",
    target="/src/config.rs",
    content="@@ -1 +1 @@\n-// security check\n+// disable security",
))
# result.decision == Decision.DENY
# result.matched_rule == "rules.patch_integrity.forbidden_patterns[0]"
```

### 7.7 Runtime integration: TypeScript tool-calling middleware

This example shows how `evaluate()` integrates into a realistic AI agent tool-calling loop:

```typescript
import { resolveFromFile, evaluate } from '@hushspec/core';
import type { EvaluationAction, EvaluationResult } from '@hushspec/core';

// Load and resolve policy once at startup
const policy = await resolveFromFile('./policies/agent.hush.yaml');

// Middleware that wraps every tool call
async function executeToolCall(
  toolName: string,
  args: Record<string, unknown>,
  confirmFn: (reason: string) => Promise<boolean>,
): Promise<unknown> {
  const action: EvaluationAction = {
    type: 'tool_call',
    target: toolName,
    args_size: JSON.stringify(args).length,
  };

  const result: EvaluationResult = evaluate(policy, action);

  switch (result.decision) {
    case 'deny':
      throw new ToolDeniedError(
        `Tool "${toolName}" denied: ${result.reason}`,
        result.matched_rule,
      );

    case 'warn': {
      const confirmed = await confirmFn(
        `Tool "${toolName}" requires confirmation: ${result.reason}`,
      );
      if (!confirmed) {
        throw new ToolDeniedError(
          `Tool "${toolName}" denied by user`,
          result.matched_rule,
        );
      }
      break; // Fall through to execution
    }

    case 'allow':
      break; // Proceed
  }

  // Also check file operations within tool args
  if (toolName === 'write_file' && typeof args.path === 'string') {
    const fileResult = evaluate(policy, {
      type: 'file_write',
      target: args.path,
      content: typeof args.content === 'string' ? args.content : undefined,
    });
    if (fileResult.decision === 'deny') {
      throw new ToolDeniedError(
        `File write to "${args.path}" denied: ${fileResult.reason}`,
        fileResult.matched_rule,
      );
    }
  }

  return await actualToolExecute(toolName, args);
}
```

### 7.8 Runtime integration: Python MCP proxy guard

This example shows a FastAPI middleware that guards MCP tool invocations:

```python
from fastapi import FastAPI, Request, HTTPException
from hushspec import resolve_file, evaluate, EvaluationAction, Decision

app = FastAPI()

# Load policy at startup
policy = resolve_file("./policies/mcp-proxy.hush.yaml")

@app.middleware("http")
async def hushspec_guard(request: Request, call_next):
    if request.url.path.startswith("/mcp/tools/"):
        tool_name = request.url.path.split("/")[-1]
        body = await request.json()

        result = evaluate(policy, EvaluationAction(
            type="tool_call",
            target=tool_name,
            args_size=len(request.body) if request.body else 0,
        ))

        if result.decision == Decision.DENY:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "policy_denied",
                    "matched_rule": result.matched_rule,
                    "reason": result.reason,
                },
            )

        if result.decision == Decision.WARN:
            # Log for audit; in interactive mode, prompt user
            logger.warning(
                "Tool %s requires confirmation: %s",
                tool_name,
                result.reason,
            )

    return await call_next(request)
```

### 7.9 Runtime integration: Go egress proxy

This example shows an HTTP transport wrapper that checks egress rules before making outbound requests:

```go
package main

import (
    "fmt"
    "net/http"
    "net/url"

    "github.com/backbay-labs/hush/packages/go/hushspec"
)

type HushSpecTransport struct {
    Policy *hushspec.HushSpec
    Inner  http.RoundTripper
}

func (t *HushSpecTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    result := hushspec.Evaluate(t.Policy, &hushspec.EvaluationAction{
        Type:   "egress",
        Target: req.URL.Hostname(),
    })

    switch result.Decision {
    case hushspec.DecisionDeny:
        return nil, fmt.Errorf(
            "egress to %s denied by policy (rule: %s, reason: %s)",
            req.URL.Hostname(), result.MatchedRule, result.Reason,
        )
    case hushspec.DecisionWarn:
        // Log warning but allow in non-interactive contexts
        fmt.Printf("WARNING: egress to %s flagged: %s\n",
            req.URL.Hostname(), result.Reason)
    }

    return t.Inner.RoundTrip(req)
}

func main() {
    policy, _ := hushspec.ResolveFile("./policies/agent.hush.yaml")

    client := &http.Client{
        Transport: &HushSpecTransport{
            Policy: policy,
            Inner:  http.DefaultTransport,
        },
    }

    // All HTTP requests through this client are policy-guarded
    resp, err := client.Get("https://api.openai.com/v1/chat/completions")
    // ...
}
```

### 7.10 Runtime integration: Rust pre-execution guard with posture

This example shows how posture-aware evaluation works in a Rust agent runtime:

```rust
use hushspec::{evaluate, EvaluationAction, Decision, PostureContext};

struct AgentRuntime {
    policy: hushspec::HushSpec,
    current_posture: String,
}

impl AgentRuntime {
    fn execute_action(&mut self, action_type: &str, target: &str) -> Result<(), String> {
        let action = EvaluationAction {
            action_type: action_type.to_string(),
            target: Some(target.to_string()),
            posture: Some(PostureContext {
                current: Some(self.current_posture.clone()),
                signal: None, // Signal would come from violation detection
            }),
            ..Default::default()
        };

        let result = evaluate(&self.policy, &action);

        // Update posture state for next evaluation
        if let Some(posture) = &result.posture {
            self.current_posture = posture.next.clone();
        }

        match result.decision {
            Decision::Allow => Ok(()),
            Decision::Warn => {
                eprintln!("Warning: {} requires confirmation: {:?}", target, result.reason);
                // In interactive mode, prompt user; in CI, deny
                Err(format!("Action requires confirmation: {:?}", result.reason))
            }
            Decision::Deny => Err(format!(
                "Action denied by policy rule {:?}: {:?}",
                result.matched_rule, result.reason
            )),
        }
    }
}
```

---

## 8. Test Strategy

### 8.1 Shared evaluation fixtures

All evaluation conformance tests are driven by YAML fixture files under `fixtures/`. Each fixture file follows the schema defined at `schemas/hushspec-evaluator-test.v0.schema.json`.

**Fixture structure:**

```yaml
hushspec_test: "0.1.0"
description: "Human-readable description of what this fixture tests"
policy:
  hushspec: "0.1.0"
  rules:
    # The policy under test
cases:
  - description: "test case description"
    action:
      type: <action_type>
      target: <target_string>
      content: <optional_content>
    expect:
      decision: <allow|warn|deny>
      matched_rule: <optional dot-path>
      reason: <optional reason string>
      origin_profile: <optional profile id>
      posture:
        current: <state>
        next: <state>
```

### 8.2 Complete fixture inventory

**Core evaluation fixtures** (`fixtures/core/evaluation/` -- 8 files, 32 cases):

| File | Cases | Tests |
|------|-------|-------|
| `forbidden-paths.test.yaml` | 5 | SSH key deny, AWS creds deny, /etc/passwd deny, SSH config exception, normal file allow |
| `egress.test.yaml` | 5 | Exact allow, wildcard allow, default block, explicit block, block-over-allow precedence |
| `tool-access.test.yaml` | 5 | Allow, block, default block, require_confirmation, block precedence |
| `shell-commands.test.yaml` | 5 | rm -rf deny, curl pipe deny, chmod 777 deny, safe command allow, safe rm allow |
| `secret-patterns.test.yaml` | 4 | AWS key deny, GitHub token deny, clean content allow, skip_paths allow |
| `patch-integrity.test.yaml` | 2 | Forbidden pattern deny, clean patch allow |
| `computer-use.test.yaml` | 3 | Allowed action, unlisted guardrail warn, allowed input.inject |
| `decision-precedence.test.yaml` | 3 | Block-over-allow in egress, warn-over-allow in tool_access, plain allow |

**Extension evaluation fixtures** (`fixtures/posture/evaluation/` -- 1 file, 3 cases):

| File | Cases | Tests |
|------|-------|-------|
| `posture-transitions.test.yaml` | 3 | Standard allows tool, restricted warns on confirmation, locked denies via capability |

**Extension evaluation fixtures** (`fixtures/origins/evaluation/` -- 1 file, 2 cases):

| File | Cases | Tests |
|------|-------|-------|
| `origin-matching.test.yaml` | 2 | Exact space_id wins over broader profile, external shared falls to restricted posture |

**Total existing fixtures:** 10 files, 37 cases.

### 8.3 Conformance matrix

Each SDK must pass every case in every fixture file. The test runner for each SDK:

1. Parses the fixture YAML
2. Extracts the embedded `policy` and parses it into an `HushSpec`
3. Validates the policy
4. For each `case`:
   a. Constructs an `EvaluationAction` from `case.action`
   b. Calls `evaluate(policy, action)`
   c. Asserts `result.decision == case.expect.decision`
   d. If `case.expect.matched_rule` is specified, asserts `result.matched_rule == case.expect.matched_rule`
   e. If `case.expect.reason` is specified, asserts `result.reason == case.expect.reason`
   f. If `case.expect.origin_profile` is specified, asserts `result.origin_profile == case.expect.origin_profile`
   g. If `case.expect.posture` is specified, asserts `result.posture == case.expect.posture`

**Assertions are one-directional for optional fields:** if the fixture does not specify `matched_rule`, any value in the result is acceptable. If the fixture does specify it, the result must match exactly. This allows fixtures to test decision correctness without over-constraining the reason text.

### 8.4 How each SDK runs fixtures

**Rust (testkit):** The `hushspec-testkit` crate (`crates/hushspec-testkit/src/runner.rs`) already implements full fixture evaluation. It discovers fixtures, deserializes them into `EvaluationFixture` structs, calls `evaluate()`, and compares results using `compare_expected()`. This is the reference conformance runner.

**TypeScript:** Update `packages/hushspec/tests/shared-fixtures.test.ts` to import `evaluate` and run each fixture case through the evaluator:

```typescript
for (const testCase of raw.cases) {
  const action = testCase.action as EvaluationAction;
  const result = evaluate(parsed.value, action);
  expect(result.decision).toBe(testCase.expect.decision);
  if (testCase.expect.matched_rule) {
    expect(result.matched_rule).toBe(testCase.expect.matched_rule);
  }
  if (testCase.expect.origin_profile) {
    expect(result.origin_profile).toBe(testCase.expect.origin_profile);
  }
  if (testCase.expect.posture) {
    expect(result.posture).toEqual(testCase.expect.posture);
  }
}
```

**Python:** Update `packages/python/tests/test_shared_fixtures.py` similarly:

```python
for case in fixture["cases"]:
    action = EvaluationAction(**case["action"])
    result = evaluate(policy, action)
    assert result.decision.value == case["expect"]["decision"]
    if "matched_rule" in case["expect"]:
        assert result.matched_rule == case["expect"]["matched_rule"]
    if "origin_profile" in case["expect"]:
        assert result.origin_profile == case["expect"]["origin_profile"]
    if "posture" in case["expect"]:
        assert result.posture.current == case["expect"]["posture"]["current"]
        assert result.posture.next == case["expect"]["posture"]["next"]
```

**Go:** Update `packages/go/hushspec/fixtures_test.go` to deserialize the `action` field into an `EvaluationAction`, call `Evaluate()`, and assert the result:

```go
for _, tc := range fixture.Cases {
    result := hushspec.Evaluate(policy, &tc.Action)
    if result.Decision != tc.Expect.Decision {
        t.Errorf("case %q: got decision %s, want %s",
            tc.Description, result.Decision, tc.Expect.Decision)
    }
    if tc.Expect.MatchedRule != "" && result.MatchedRule != tc.Expect.MatchedRule {
        t.Errorf("case %q: got matched_rule %s, want %s",
            tc.Description, result.MatchedRule, tc.Expect.MatchedRule)
    }
}
```

### 8.5 Property-based testing opportunities

Beyond fixture-driven conformance, each SDK should add property-based tests for:

1. **Glob matching round-trip:** For any pattern `p` and target `t`, `glob_matches(p, t)` must return the same result across all SDKs. Generate random patterns and targets and cross-check.

2. **Decision monotonicity:** Adding a `block` entry to a rule never changes a `deny` result to `allow`. Adding an `allow` entry never changes an `allow` result to `deny`.

3. **Disabled rules are inert:** For any rule block, setting `enabled: false` must result in the same decision as if the rule block were absent.

4. **Patch stats determinism:** For any unified diff content, the computed additions/deletions count must be deterministic and identical across SDKs.

The Rust crate already uses `proptest` for serialization round-trips. Adding evaluation property tests is straightforward.

### 8.6 New fixtures to add

As part of this work, the following fixture gaps should be filled:

| Fixture | Cases needed |
|---------|-------------|
| `path-allowlist.test.yaml` | Allowlist enabled with read/write/patch arrays; patch fallback to write; path not in allowlist -> deny; enabled: false -> allow |
| `input-injection.test.yaml` | Enabled with allowed_types; empty allowed_types -> deny; unlisted type -> deny; disabled -> allow |
| `tool-access-args-size.test.yaml` | max_args_size exceeded -> deny; within limit -> allow |
| `patch-integrity-balance.test.yaml` | require_balance with (0, N) -> deny, (N, 0) -> deny, balanced within ratio -> allow, imbalanced beyond ratio -> deny |
| `computer-use-modes.test.yaml` | All three modes: observe -> allow, guardrail -> warn, fail_closed -> deny for unlisted actions |
| `disabled-rules.test.yaml` | Each rule type with `enabled: false` -> allow; absent rule -> allow |
| `empty-rules.test.yaml` | No rules defined at all -> all action types allow |

---

## 9. Migration Guide

### 9.1 How existing users upgrade

**The `evaluate()` function is purely additive.** No existing API surface changes. Existing code that uses `parse()`, `validate()`, `merge()`, and `resolve()` continues to work without modification.

Users opt in to evaluation by importing the new `evaluate` function and the `EvaluationAction` / `EvaluationResult` types.

### 9.2 TypeScript

Before (Level 2):

```typescript
import { parse, validate } from '@hushspec/core';
const { value: spec } = parse(yaml);
const result = validate(spec);
```

After (Level 3):

```typescript
import { parse, validate, evaluate } from '@hushspec/core';
import type { EvaluationAction, EvaluationResult } from '@hushspec/core';

const { value: spec } = parse(yaml);
const decision = evaluate(spec, { type: 'file_read', target: '/etc/passwd' });
```

### 9.3 Python

Before:

```python
from hushspec import parse, validate
ok, spec = parse(yaml)
result = validate(spec)
```

After:

```python
from hushspec import parse, validate, evaluate, EvaluationAction
ok, spec = parse(yaml)
result = evaluate(spec, EvaluationAction(type="file_read", target="/etc/passwd"))
```

### 9.4 Go

Before:

```go
spec, err := hushspec.Parse(yaml)
result := hushspec.Validate(spec)
```

After:

```go
spec, err := hushspec.Parse(yaml)
result := hushspec.Evaluate(spec, &hushspec.EvaluationAction{
    Type:   "file_read",
    Target: "/etc/passwd",
})
```

### 9.5 Backward compatibility guarantees

- **No breaking changes** to any existing exported type or function.
- **New exports only:** `evaluate` (function), `EvaluationAction`, `EvaluationResult`, `Decision`, `OriginContext`, `PostureContext`, `PostureResult` (types).
- **SemVer:** This is a minor version bump for each SDK package. Existing `0.1.x` users can upgrade without code changes.
- **Fixture compatibility:** Existing validation and merge fixtures are unaffected. New evaluation fixtures are additive.

### 9.6 Dependency impact

| SDK | New dependencies |
|-----|-----------------|
| Rust | None (already uses `regex`) |
| TypeScript | None (`RegExp` is built-in) |
| Python | None (`re` is in the standard library) |
| Go | None (`regexp` is in the standard library) |

No new external dependencies are introduced by this work.

---

## Appendix A: Complete action-type dispatch table

This table summarizes the full dispatch logic in the `evaluate()` function, showing which internal functions are called for each action type:

| Action Type | Step 1 | Step 2 | Step 3 | Step 4 |
|-------------|--------|--------|--------|--------|
| `file_read` | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (cap: `file_access`) | `evaluatePathGuards` (forbidden_paths, path_allowlist) |
| `file_write` | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (cap: `file_write`) | `evaluatePathGuards` -> `evaluateSecretPatterns` |
| `patch_apply` | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (cap: `patch`) | `evaluatePathGuards` -> `evaluatePatchIntegrity` |
| `egress` | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (cap: `egress`) | `evaluateEgressRule` (may use profile override) |
| `shell_command` | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (cap: `shell`) | `evaluateShellRule` |
| `tool_call` | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (cap: `tool_call`) | `evaluateToolAccessRule` (may use profile override) |
| `computer_use` | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (no cap required) | `evaluateComputerUseRule` |
| `input_inject` | -- | -- | -- | `evaluateInputInjectionRule` (to be added) |
| unknown | `selectOriginProfile` | `resolvePosture` | `postureCapabilityGuard` (no cap required) | return allow with reason |

**Note on `computer_use` and posture:** The reference evaluator calls `selectOriginProfile` and `resolvePosture` for `computer_use` but the `required_capability()` function returns `None` for this action type, so the posture capability guard never fires. This means a `locked` posture with empty capabilities does NOT block `computer_use` actions. This is intentional -- computer use is controlled entirely by the `computer_use` rule block, not by posture capabilities.

## Appendix B: Matched rule path conventions

The `matched_rule` string in `EvaluationResult` follows a dot-path convention that reflects the location of the deciding rule within the HushSpec document:

| Pattern | Meaning | Example |
|---------|---------|---------|
| `rules.<rule>.<field>` | Core rule decision | `rules.egress.block` |
| `rules.<rule>.<field>[<index>]` | Indexed array element | `rules.shell_commands.forbidden_patterns[0]` |
| `rules.<rule>.patterns.<name>` | Named pattern | `rules.secret_patterns.patterns.aws_access_key` |
| `rules.<rule>` | Rule-level decision (allowlist) | `rules.path_allowlist` |
| `extensions.origins.profiles.<id>.<rule>.<field>` | Origin profile override | `extensions.origins.profiles.slack-dm.tool_access.block` |
| `extensions.posture.states.<state>.capabilities` | Posture capability denial | `extensions.posture.states.restricted.capabilities` |

## Appendix C: File inventory

Files to create:

| File | Language | Purpose |
|------|----------|---------|
| `packages/hushspec/src/evaluate.ts` | TypeScript | Core evaluation engine |
| `packages/hushspec/tests/evaluate.test.ts` | TypeScript | Unit tests for evaluation |
| `packages/python/hushspec/evaluate.py` | Python | Core evaluation engine |
| `packages/python/tests/test_evaluate.py` | Python | Unit tests for evaluation |
| `packages/go/hushspec/evaluate.go` | Go | Core evaluation engine |
| `packages/go/hushspec/evaluate_test.go` | Go | Unit tests for evaluation |
| `fixtures/core/evaluation/path-allowlist.test.yaml` | YAML | Path allowlist fixture |
| `fixtures/core/evaluation/input-injection.test.yaml` | YAML | Input injection fixture |
| `fixtures/core/evaluation/tool-access-args-size.test.yaml` | YAML | Args size limit fixture |
| `fixtures/core/evaluation/patch-integrity-balance.test.yaml` | YAML | Imbalance ratio fixture |
| `fixtures/core/evaluation/computer-use-modes.test.yaml` | YAML | All CUA modes fixture |
| `fixtures/core/evaluation/disabled-rules.test.yaml` | YAML | Disabled rule blocks fixture |
| `fixtures/core/evaluation/empty-rules.test.yaml` | YAML | Empty/absent rules fixture |

Files to modify:

| File | Change |
|------|--------|
| `packages/hushspec/src/index.ts` | Export evaluate + types |
| `packages/hushspec/tests/shared-fixtures.test.ts` | Run evaluation fixtures through evaluator |
| `packages/python/hushspec/__init__.py` | Export evaluate + types |
| `packages/python/tests/test_shared_fixtures.py` | Run evaluation fixtures through evaluator |
| `packages/go/hushspec/fixtures_test.go` | Run evaluation fixtures through evaluator |
| `crates/hushspec/src/evaluate.rs` | Add `input_inject` action type |
| `schemas/hushspec-evaluator-test.v0.schema.json` | Add `input_inject` to action type enum |
| `fixtures/core/evaluation/` | New fixture files (see above) |

## Appendix D: Known spec/reference divergences

This appendix catalogs places where the Rust reference implementation diverges from the spec text. All SDKs MUST match the reference behavior. These divergences should be reconciled in a future spec revision.

| Area | Spec says | Reference does | Impact |
|------|-----------|----------------|--------|
| Tool name matching | Exact string match (Section 3.7) | Glob match via `glob_matches()` | Low: tool names rarely contain glob characters |
| Tool access allowlist mode | Non-empty `allow` + unlisted tool = deny (Section 3.7, Step 4) | Falls through to `default` value | Medium: `default: "allow"` with a non-empty `allow` list permits unlisted tools |
| Egress domain `*` | Matches within single domain label (Section 3.3) | `[^/]*` -- matches across `.` since domains have no `/` | Medium: `*.evil.com` matches `a.b.evil.com` in reference but spec implies it should not |
| Unknown action types | Fail-closed principle implies deny (Section 1.2) | Returns allow | Low: fixture schema constrains to known types |
| Secret pattern severity | Engine determines severity-to-decision mapping (Section 3.4) | All severities produce deny | Low: conservative behavior |
