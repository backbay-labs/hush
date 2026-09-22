# RFC-08: Extends Resolution and Remote Policy Loading

**Status:** Historical design record (Draft)
**Authors:** Architecture Team
**Date:** 2026-03-15
**HushSpec Version:** 0.1.0

---

> **Delivery status:** See [the delivery ledger](STATUS.md#numbered-plan-reconciliation). File, builtin, and HTTPS resolution/loading artifacts are implemented on the open stack. Cloud/Vault/Git/registry providers, push reload, and shared caching remain deferred; the TypeScript watch-bootstrap lifecycle repair has a local verification record, with hosted qualification pending.

## 1. Executive Summary

Policy composition via the `extends` field is specified in the HushSpec Core
Specification (Section 2.3 and Section 4) but the current implementations in
all four SDKs only support filesystem-relative resolution. Production
deployments require remote policy loading from HTTPS endpoints, cloud storage,
secret managers, and git repositories, along with caching, integrity
verification, and hot reload.

This RFC covers the full policy lifecycle from authoring through runtime
loading:

- A formal resolution algorithm that supports six reference types (local file,
  built-in ruleset, HTTPS URL, package reference, git reference, and registry
  reference).
- A pluggable loader interface in each of the four SDKs (Rust, TypeScript,
  Python, Go).
- A multi-layer caching strategy with content-hash invalidation.
- Hot reload via file watching, polling, and push-based notification.
- Security hardening for remote policy fetching.

The design preserves the spec's engine-neutral principle: resolution mechanics
remain engine-specific while the merge semantics defined in the spec are
unchanged.

### Relationship to RFC-05

RFC-05 (Runtime Integration Patterns) defines a higher-level `PolicyProvider`
interface (`load() -> HushSpec`, `watch()`, `refresh()`) designed for
framework-specific adapters (LangChain, CrewAI, etc.). That interface
abstracts the entire policy lifecycle -- loading, caching, and hot reload --
behind a single facade for use by `HushGuard`.

This RFC operates at a lower level. The `PolicyLoader` trait defined here is
the mechanism that resolves a single `extends` reference to a loaded document.
`PolicyProvider` implementations from RFC-05 should **compose** the loaders,
caching, and watchers defined in this RFC:

```
RFC-05 PolicyProvider (high-level: load/watch/refresh)
  └── RFC-08 PolicyWatcher / PolicyPoller (hot reload)
        └── RFC-08 CachedLoader (caching layer)
              └── RFC-08 CompositeLoader (loader chain)
                    ├── BuiltinLoader
                    ├── FileLoader
                    ├── HTTPLoader
                    └── S3Loader / VaultLoader / GitLoader
```

Implementers should use the loaders from this RFC to build the providers
from RFC-05. The two RFCs do not compete; they address different layers.

---

## 2. Current State

### 2.1 What the Spec Says

The HushSpec Core Specification defines `extends` in three places.

**Section 2.3 -- Extends Field:**

> The `extends` field is a single string reference to a base policy document.
> Resolution of this reference (filesystem path, URL, registry identifier,
> built-in name) is engine-specific and outside the scope of this
> specification. Engines MUST document their resolution strategy. Circular
> inheritance MUST be detected and rejected.

**Section 4 -- Merge Semantics:**

Three merge strategies are specified: `deep_merge` (default), `merge`, and
`replace`. Merge order is pairwise from root to leaf. The `extends` field is
consumed during resolution and MUST NOT appear in the merged output.

**Schema (`schemas/hushspec-core.v0.schema.json`):**

The `extends` field is typed as a bare `string` with no format constraint:

```json
{
  "extends": {
    "type": "string",
    "description": "Reference to a base policy. Resolution is engine-specific."
  }
}
```

### 2.2 What Each SDK Currently Implements

All four SDKs implement the same pattern: a `resolve` function that walks the
`extends` chain recursively, a `LoadedSpec` struct pairing a canonical source
identifier with a parsed document, and a pluggable loader callback defaulting
to filesystem resolution.

| Feature | Rust | TypeScript | Python | Go |
|---|---|---|---|---|
| Filesystem resolution | Yes | Yes | Yes | Yes |
| Custom loader callback | Yes | Yes | Yes | Yes |
| Circular detection | Yes | Yes | Yes | Yes |
| Depth limit | No | No | No | No |
| HTTPS resolution | No | No | No | No |
| Built-in rulesets | No | No | No | No |
| Caching | No | No | No | No |
| Hot reload | No | No | No | No |

**Rust** (`crates/hushspec/src/resolve.rs`):

```rust
pub fn resolve_with_loader<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
```

The loader receives `(reference, from_source)` and returns a `LoadedSpec`.
Cycle detection uses a `Vec<String>` stack of canonical source identifiers.
The filesystem loader uses `fs::canonicalize` for path deduplication.

**TypeScript** (`packages/hushspec/src/resolve.ts`):

```typescript
export function resolve(
  spec: HushSpec,
  options: ResolveOptions = {},
): ResolveResult;

export interface ResolveOptions {
  source?: string;
  load?: (reference: string, from?: string) => LoadedSpec;
}
```

Returns a discriminated union `{ ok: true; value: HushSpec } | { ok: false;
error: string }`. Filesystem loader uses `realpathSync` for deduplication.

**Python** (`packages/python/hushspec/resolve.py`):

```python
def resolve(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: Resolver | None = None,
) -> tuple[bool, HushSpec | str]:
```

Same pattern using `pathlib.Path.resolve()` for canonicalization. A
convenience `resolve_or_raise` wrapper converts error tuples to exceptions.

**Go** (`packages/go/hushspec/resolve.go`):

```go
type ResolveLoader func(reference string, from string) (*LoadedSpec, error)

func Resolve(spec *HushSpec, source string, loader ResolveLoader) (*HushSpec, error)
```

Uses `filepath.EvalSymlinks` after `filepath.Abs` for canonical paths.

### 2.3 Merge Strategy Implementation

All SDKs implement the three strategies identically:

**`replace`:** Return the child document verbatim (with `extends` cleared).
The base document is loaded only for validation purposes.

**`merge`:** Shallow merge at the `rules` level. Each non-nil child rule block
replaces the base block entirely. Absent child rule blocks are inherited from
the base. Extensions use shallow block-level replacement (child posture
replaces base posture entirely, etc.). Scalar top-level fields (`name`,
`description`) follow child-wins-if-present semantics.

**`deep_merge` (default):** Rules behave identically to `merge` (rule-block
replacement). Extensions receive field-level deep merge:
- **Posture:** Child states are merged into base states by key; child
  `initial` and `transitions` replace base values.
- **Origins:** Profiles are merged by `id` (child profile replaces matching
  base profile; unmatched child profiles are appended). Child
  `default_behavior` replaces base value.
- **Detection:** Each sub-block (`prompt_injection`, `jailbreak`,
  `threat_intel`) is merged field-by-field with child values taking
  precedence.

**Why `merge` and `deep_merge` behave identically for rules:** In HushSpec
v0, rule blocks are atomic -- there is no field-level merge within a rule
block (e.g., you cannot merge just the `patterns` array of
`forbidden_paths`). The two strategies only diverge on extension blocks, where
`deep_merge` performs field-level merging within each extension (posture
states by key, origins profiles by ID, detection sub-blocks by field) while
`merge` replaces the entire extension block. A future HushSpec version may
introduce field-level rule merging, at which point `deep_merge` would become
meaningfully different from `merge` for rules as well.

### 2.4 Test Fixture Coverage

**Merge fixtures** (`fixtures/core/merge/`):

| File | Purpose |
|---|---|
| `base.yaml` | Base policy with egress (allow a.com, b.com, default block) and forbidden_paths |
| `child-deep-merge.yaml` | Overrides egress only (allow c.com, default allow), expects forbidden_paths inherited |
| `expected-deep-merge.yaml` | Verified merge output |
| `child-replace.yaml` | Complete replacement with tool_access only |
| `expected-replace.yaml` | Verified replace output |

**Resolve test coverage** (all SDKs):

1. Two-document extends chain from filesystem (base tool_access + child
   egress, verify both present after merge).
2. Circular extends detection (A extends B, B extends A).
3. Custom loader with `memory://` source identifiers.

**Gaps in coverage:**
- No tests for three-or-more-level chains.
- No tests for the `merge` strategy (only `deep_merge` and `replace`).
- No fixture for the `merge` strategy demonstrating that extensions are
  replaced wholesale (unlike `deep_merge`).
- No depth limit testing (no limit is currently enforced).
- No tests for missing parent (load error propagation).
- No extension merge tests within the resolve path.

---

## 3. Extends Resolution Algorithm

### 3.1 Reference Types

The `extends` field string is parsed into a typed reference using prefix
matching. The reference type determines which loader handles resolution.

| Prefix | Reference Type | Example |
|---|---|---|
| `./` or `../` or absolute path | Local file | `extends: ./base.yaml`, `extends: ../org/base.yaml` |
| `builtin:` | Built-in ruleset | `extends: builtin:default`, `extends: builtin:strict` |
| `https://` | HTTPS URL | `extends: https://policies.example.com/base.yaml` |
| `npm:` or `pypi:` or `crate:` | Package reference | `extends: npm:@org/policy`, `extends: pypi:org-policy` |
| `git:` | Git reference | `extends: git:github.com/org/policies@main:base.yaml` |
| `registry:` | HushSpec registry | `extends: registry:org/base@v1.2.0` |
| (no prefix, no path separator) | Bare reference | Resolved as built-in first, then local file |

**Reference parsing pseudocode:**

```
parse_reference(ref: string) -> ReferenceType:
    if ref starts with "builtin:":
        return Builtin { name: ref[8:] }
    if ref starts with "https://":
        return Https { url: ref }
    if ref starts with "npm:" or ref starts with "pypi:" or ref starts with "crate:":
        parts = split_package_ref(ref)
        return Package { manager: parts.manager, name: parts.name, version: parts.version }
    if ref starts with "git:":
        parts = split_git_ref(ref)
        return Git { repo: parts.repo, rev: parts.rev, path: parts.path }
    if ref starts with "registry:":
        parts = split_registry_ref(ref)
        return Registry { org: parts.org, name: parts.name, version: parts.version }
    if ref starts with "/" or ref starts with "./" or ref starts with "../":
        return File { path: ref }
    # Bare name: try builtin, fall back to file
    return BareRef { name: ref }
```

**Bare reference resolution order:**

When a bare reference (no prefix, no path separator) is encountered:

1. Attempt to load as `Builtin { name: ref }`.
2. If the builtin loader returns "not found" (not a hard error), attempt to
   load as `File { path: ref }`.
3. If both fail, return an error listing both attempts:
   `"could not resolve bare reference '{ref}': not a known builtin, and file
   not found at '{resolved_path}'"`.

**Git reference format:**

```
git:<host>/<org>/<repo>@<rev>:<path>
```

Where `<rev>` is a branch name, tag, or commit hash, and `<path>` is the
file path within the repository. Examples:

```yaml
extends: git:github.com/acme/policies@main:production.yaml
extends: git:github.com/acme/policies@v2.1.0:base.yaml
extends: git:github.com/acme/policies@abc1234:strict.yaml
```

**Package reference format:**

```
<manager>:<package-name>[@<version>][:<path>]
```

Where `<path>` defaults to `hushspec.yaml` within the package. Examples:

```yaml
extends: npm:@acme/hushspec-policy
extends: npm:@acme/hushspec-policy@^2.0.0
extends: pypi:acme-hushspec-policy:policies/strict.yaml
extends: crate:acme-hushspec:rulesets/default.yaml
```

**Registry reference format:**

```
registry:<org>/<name>[@<version>]
```

Where `<version>` defaults to `latest`. Examples:

```yaml
extends: registry:acme/production
extends: registry:acme/production@1.2.0
extends: registry:acme/production@~1.2
```

**Registry unavailability:** When the registry is unreachable and no cached
version exists, resolution fails with a hard error per fail-closed semantics.
When a version constraint matches no published version, resolution fails with
an error: `"no version of 'acme/production' matches constraint '~1.2'"`.

### 3.2 Resolution Algorithm

The resolution algorithm is recursive with cycle detection and depth limiting.

```
const MAX_DEPTH = 10

resolve(document, loader_chain, visited_set, depth) -> Result<HushSpec, Error>:
    // 1. Depth guard
    if depth > MAX_DEPTH:
        return Error(
            "extends chain too deep (>{MAX_DEPTH} levels); "
            "possible cycle or overly nested inheritance"
        )

    // 2. Base case: no extends
    if document.extends is None:
        return Ok(document)

    // 3. Parse reference
    ref = parse_reference(document.extends)

    // 4. Load parent document
    loaded = loader_chain.load(ref, current_source)
    // loaded = { source: canonical_id, spec: parsed_HushSpec }

    // 5. Cycle detection using canonical source identifiers
    if loaded.source in visited_set:
        cycle_path = visited_set.entries_from(loaded.source) + [loaded.source]
        return Error("circular extends detected: {cycle_path.join(' -> ')}")

    visited_set.add(loaded.source)

    // 6. Validate loaded parent
    validation = validate(loaded.spec)
    if validation.has_errors:
        return Error(
            "parent policy at {loaded.source} is invalid: {validation.errors}"
        )

    // 7. Version compatibility check
    if loaded.spec.hushspec != document.hushspec:
        parent_minor = parse_minor(loaded.spec.hushspec)
        child_minor = parse_minor(document.hushspec)
        if parent_minor != child_minor:
            // Different minor versions: configurable behavior
            if config.version_mismatch_policy == "error":
                return Error(
                    "parent version {loaded.spec.hushspec} incompatible "
                    "with child version {document.hushspec}"
                )
            else:
                log.warn(
                    "parent version {loaded.spec.hushspec} differs from "
                    "child version {document.hushspec}; proceeding with merge"
                )

    // 8. Recursively resolve the parent's own extends chain
    resolved_parent = resolve(loaded.spec, loader_chain, visited_set, depth + 1)
    if resolved_parent is Error:
        return resolved_parent

    visited_set.remove(loaded.source)

    // 9. Merge parent and child according to child's merge_strategy
    strategy = document.merge_strategy or "deep_merge"
    merged = merge(resolved_parent, document, strategy)

    // 10. merged.extends is always cleared by merge()
    return Ok(merged)
```

**Key differences from current implementations:**

1. **Depth limit** (`MAX_DEPTH = 10`): Prevents stack overflow from deep
   chains even if no cycle exists. Note: existing chains of depth > 10 will
   break. This is considered acceptable because chains that deep indicate a
   design problem.
2. **Validation of loaded parents**: Currently, loaded parents are parsed but
   not validated. Invalid parents should cause a hard error per fail-closed
   semantics.
3. **Reference type parsing**: Currently all references are treated as
   filesystem paths. The new algorithm dispatches to appropriate loaders.
4. **Version compatibility check**: Currently no version checking is
   performed across the extends chain.

### 3.3 Merge Strategy Semantics (Detailed)

This section provides exhaustive merge behavior for each field type under each
strategy. All examples show `(base, child) -> merged`.

#### 3.3.1 `replace` Strategy

The child document is the result. The base is discarded after confirming it is
loadable and valid.

```yaml
# BASE                          # CHILD (merge_strategy: replace)
hushspec: "0.1.0"               hushspec: "0.1.0"
name: base                      name: child
rules:                           extends: base.yaml
  egress:                        merge_strategy: replace
    allow: [a.com]               rules:
    default: block                 tool_access:
  forbidden_paths:                   block: [shell_exec]
    patterns: ["**/.ssh/**"]         default: allow

# MERGED RESULT
hushspec: "0.1.0"
name: child
merge_strategy: replace
rules:
  tool_access:
    block: [shell_exec]
    default: allow
# Note: egress and forbidden_paths from base are NOT present.
```

#### 3.3.2 `merge` Strategy

Shallow block-level merge. Each present child block replaces its base
counterpart entirely.

| Field Category | Behavior |
|---|---|
| Scalars (`name`, `description`) | Child wins if present; base value used if child is null/absent |
| `hushspec` | Always child value |
| `extends` | Always cleared to `None` |
| `merge_strategy` | Child value preserved |
| Rule blocks | If child defines a rule block, it replaces the base block entirely. If child omits a rule block, the base block is inherited. |
| Extension blocks | Same as rule blocks: child block replaces base block entirely. No field-level merging within extensions. |

```yaml
# BASE                          # CHILD (merge_strategy: merge)
hushspec: "0.1.0"               hushspec: "0.1.0"
name: base                      extends: base.yaml
rules:                           merge_strategy: merge
  egress:                        rules:
    allow: [a.com, b.com]         egress:
    default: block                  allow: [c.com]
  forbidden_paths:                  default: allow
    patterns: ["**/.ssh/**"]

# MERGED RESULT
hushspec: "0.1.0"
name: base                      # Inherited from base (child has no name)
merge_strategy: merge
rules:
  egress:                        # Child egress replaces base egress entirely
    allow: [c.com]               # Base allow list is NOT preserved
    default: allow
  forbidden_paths:               # Inherited from base (child has no forbidden_paths)
    patterns: ["**/.ssh/**"]
```

**`merge` vs `deep_merge` for extensions (critical difference):**

```yaml
# BASE
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: 0.5
      block_at_or_above: 0.9
    jailbreak:
      enabled: true
      block_threshold: 80

# CHILD (merge_strategy: merge)
hushspec: "0.1.0"
extends: base.yaml
merge_strategy: merge
extensions:
  detection:
    prompt_injection:
      block_at_or_above: 0.8

# MERGED RESULT with merge (NOT deep_merge)
hushspec: "0.1.0"
merge_strategy: merge
extensions:
  detection:                     # Child detection REPLACES base detection entirely
    prompt_injection:
      block_at_or_above: 0.8    # ONLY this field exists
    # jailbreak is GONE -- child detection had no jailbreak block
    # prompt_injection.enabled and warn_at_or_above are GONE too
```

Compare with `deep_merge` result in Section 3.3.3 below, where field-level
inheritance preserves unspecified fields.

#### 3.3.3 `deep_merge` Strategy (Default)

For core `rules`, deep_merge behaves identically to `merge`: each child rule
block replaces its base counterpart entirely. The "deep" aspect applies to
extensions only. (See Section 2.3 for why this is the case in v0.)

| Component | Behavior |
|---|---|
| Scalars | Same as `merge` |
| Rule blocks | Same as `merge` (block-level replacement) |
| `extensions.posture` | States merged by key (child overwrites matching keys, base keys preserved). Child `initial` and `transitions` replace base values. |
| `extensions.origins` | Profiles merged by `id` (child profile replaces matching base profile; unmatched base profiles preserved; unmatched child profiles appended). Child `default_behavior` replaces base. |
| `extensions.detection` | Each sub-block (`prompt_injection`, `jailbreak`, `threat_intel`) merged field-by-field. Child field values take precedence; absent child fields inherit from base. |

```yaml
# BASE
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: 0.5
      block_at_or_above: 0.9
      max_scan_bytes: 10000
    jailbreak:
      enabled: true
      block_threshold: 80

# CHILD (deep_merge, default)
hushspec: "0.1.0"
extends: base.yaml
extensions:
  detection:
    prompt_injection:
      block_at_or_above: 0.8   # Tighten threshold

# MERGED RESULT
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true             # Inherited from base
      warn_at_or_above: 0.5     # Inherited from base
      block_at_or_above: 0.8    # Child override
      max_scan_bytes: 10000     # Inherited from base
    jailbreak:                   # Inherited from base (child detection had no jailbreak)
      enabled: true
      block_threshold: 80
```

#### 3.3.4 Edge Cases and Conflict Resolution

| Scenario | Behavior |
|---|---|
| Child defines empty rule block `rules: {}` | Child has `rules` present with no blocks. All base rule blocks are inherited. |
| Child defines rule block with `enabled: false` | The disabled block replaces the base block. The rule is now explicitly disabled. |
| Child defines `rules:` with one block | That block replaces the base block. All other base blocks are inherited. |
| Base has extensions, child has no extensions | Base extensions inherited unchanged. |
| Both base and child define same origin profile ID | Child profile replaces base profile (under `deep_merge`). |
| Child has empty `patterns: []` in a rule block | The empty array is the merge result for that field. Base patterns are NOT inherited (the child block replaces the base block). |

### 3.4 Error Handling

All error conditions follow the fail-closed principle.

| Condition | Behavior | Configurable? |
|---|---|---|
| Missing parent (file not found, 404, etc.) | Hard error. Resolution fails. | No |
| Invalid parent (parse error, validation error) | Hard error. Resolution fails. | No |
| Circular reference | Hard error with diagnostic showing the cycle path. | No |
| Depth limit exceeded | Hard error. | Limit value configurable (default 10) |
| Network timeout | Hard error by default. Can be configured to fall back to cached version. | Yes, via `CachePolicy` |
| Network error (DNS, TLS, connection refused) | Hard error by default. Can fall back to cache. | Yes, via `CachePolicy` |
| Version mismatch (parent minor version != child minor version) | Warning logged. Resolution proceeds. | Configurable: `warn` (default) or `error` |
| Version mismatch (parent patch version != child patch version) | No warning. Resolution proceeds. | No |
| Content integrity failure (hash mismatch) | Hard error. | No |
| Download size exceeded | Hard error. | No |
| Bare reference resolution failure | Error listing both builtin and file lookup failures. | No |

**Error types by SDK:**

```rust
// Rust
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("failed to read HushSpec document at {path}: {message}")]
    Read { path: String, message: String },

    #[error("failed to parse HushSpec document at {path}: {message}")]
    Parse { path: String, message: String },

    #[error("failed to validate HushSpec document at {path}: {message}")]
    Validate { path: String, message: String },

    #[error("circular extends detected: {chain}")]
    Cycle { chain: String },

    #[error("extends chain too deep (>{max_depth} levels): {chain}")]
    TooDeep { max_depth: usize, chain: String },

    #[error("unsupported reference type: {reference}")]
    UnsupportedReference { reference: String },

    #[error("network error loading {url}: {message}")]
    Network { url: String, message: String },

    #[error("content integrity check failed for {source}: expected {expected}, got {actual}")]
    IntegrityFailure { source: String, expected: String, actual: String },

    #[error("download size limit exceeded for {source}: {size} > {limit}")]
    SizeExceeded { source: String, size: u64, limit: u64 },

    #[error("version mismatch: parent {parent_version} at {parent_source}, child {child_version}")]
    VersionMismatch {
        parent_source: String,
        parent_version: String,
        child_version: String,
    },
}
```

---

## 4. Loader Interface

### 4.1 Generic Loader Trait / Interface

Each SDK defines a loader abstraction that maps a parsed reference to a loaded
document.

#### Rust

```rust
use std::future::Future;
use std::pin::Pin;

/// A reference parsed from the `extends` field.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyRef {
    File { path: String },
    Builtin { name: String },
    Https { url: String },
    Package { manager: String, name: String, version: Option<String>, path: Option<String> },
    Git { repo: String, rev: String, path: String },
    Registry { org: String, name: String, version: Option<String> },
}

/// Synchronous policy loader.
pub trait PolicyLoader: Send + Sync {
    /// Load a policy document given a reference and the source of the referencing document.
    fn load(&self, reference: &PolicyRef, from: Option<&str>) -> Result<LoadedSpec, ResolveError>;

    /// Whether this loader can handle the given reference type.
    fn supports(&self, reference: &PolicyRef) -> bool;
}

/// Async policy loader for network-dependent resolution.
pub trait AsyncPolicyLoader: Send + Sync {
    fn load<'a>(
        &'a self,
        reference: &'a PolicyRef,
        from: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<LoadedSpec, ResolveError>> + Send + 'a>>;

    fn supports(&self, reference: &PolicyRef) -> bool;
}
```

#### TypeScript

```typescript
/** A parsed extends reference. */
export type PolicyRef =
  | { type: 'file'; path: string }
  | { type: 'builtin'; name: string }
  | { type: 'https'; url: string }
  | { type: 'package'; manager: string; name: string; version?: string; path?: string }
  | { type: 'git'; repo: string; rev: string; path: string }
  | { type: 'registry'; org: string; name: string; version?: string };

/** Async policy loader interface. */
export interface PolicyLoader {
  load(reference: PolicyRef, from?: string): Promise<LoadedSpec>;
  supports(reference: PolicyRef): boolean;
}

/** Synchronous policy loader (for environments without async support). */
export interface SyncPolicyLoader {
  load(reference: PolicyRef, from?: string): LoadedSpec;
  supports(reference: PolicyRef): boolean;
}
```

#### Python

```python
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FileRef:
    path: str

@dataclass(frozen=True)
class BuiltinRef:
    name: str

@dataclass(frozen=True)
class HttpsRef:
    url: str

@dataclass(frozen=True)
class PackageRef:
    manager: str
    name: str
    version: Optional[str] = None
    path: Optional[str] = None

@dataclass(frozen=True)
class GitRef:
    repo: str
    rev: str
    path: str

@dataclass(frozen=True)
class RegistryRef:
    org: str
    name: str
    version: Optional[str] = None

PolicyRef = FileRef | BuiltinRef | HttpsRef | PackageRef | GitRef | RegistryRef


class PolicyLoader(abc.ABC):
    """Base class for synchronous policy loaders."""

    @abc.abstractmethod
    def load(self, reference: PolicyRef, from_source: str | None = None) -> LoadedSpec:
        ...

    @abc.abstractmethod
    def supports(self, reference: PolicyRef) -> bool:
        ...


class AsyncPolicyLoader(abc.ABC):
    """Async variant for I/O-bound loaders."""

    @abc.abstractmethod
    async def load(self, reference: PolicyRef, from_source: str | None = None) -> LoadedSpec:
        ...

    @abc.abstractmethod
    def supports(self, reference: PolicyRef) -> bool:
        ...
```

#### Go

```go
// PolicyRef represents a parsed extends reference.
//
// Go does not have discriminated unions, so we use a struct with a Type field.
// Callers should switch on Type and read only the fields relevant to that type.
// This is an intentional trade-off: the Go SDK favors simplicity and
// idiomatic patterns over compile-time exhaustiveness checking.
type PolicyRef struct {
    Type    string // "file", "builtin", "https", "package", "git", "registry"
    Path    string // for file refs
    Name    string // for builtin/registry refs
    URL     string // for https refs
    Manager string // for package refs ("npm", "pypi", "crate")
    Repo    string // for git refs
    Rev     string // for git refs
    Org     string // for registry refs
    Version string // for package/registry refs
}

// PolicyLoader loads HushSpec documents from a reference.
type PolicyLoader interface {
    Load(ctx context.Context, ref PolicyRef, from string) (*LoadedSpec, error)
    Supports(ref PolicyRef) bool
}
```

**Go concurrency note:** Unlike Rust/TypeScript/Python which have separate
sync and async loader interfaces, Go uses `context.Context` for cancellation
and timeout on all loaders. The `ctx` parameter enables the caller to set
deadlines and cancel in-flight operations, which is the idiomatic Go approach
to async-like behavior.

### 4.2 Built-in Loaders

#### 4.2.1 FileLoader

Resolves references to local filesystem paths. This is the only loader
currently implemented.

**Configuration:**

| Option | Type | Default | Description |
|---|---|---|---|
| `base_path` | string | (cwd) | Base directory for resolving relative paths when no `from` source is available |
| `follow_symlinks` | bool | true | Whether to follow symbolic links |
| `allowed_paths` | string[] | [] | If non-empty, only allow loading from these directory prefixes (sandbox) |

**Behavior:**
- Relative references are resolved relative to the `from` source document's
  directory, or `base_path` if no `from` is provided.
- Paths are canonicalized using `realpath`/`fs::canonicalize` for cycle
  detection.
- When `allowed_paths` is configured, the canonical path MUST fall under one
  of the allowed prefixes. Otherwise, a `ResolveError::Read` is returned.

**Signatures:**

```rust
pub struct FileLoader {
    base_path: PathBuf,
    follow_symlinks: bool,
    allowed_paths: Vec<PathBuf>,
}

impl FileLoader {
    pub fn new() -> Self;
    pub fn with_base_path(self, base_path: impl Into<PathBuf>) -> Self;
    pub fn with_allowed_paths(self, paths: Vec<PathBuf>) -> Self;
}

impl PolicyLoader for FileLoader {
    fn load(&self, reference: &PolicyRef, from: Option<&str>) -> Result<LoadedSpec, ResolveError>;
    fn supports(&self, reference: &PolicyRef) -> bool;  // true for PolicyRef::File
}
```

```typescript
export class FileLoader implements SyncPolicyLoader {
  constructor(options?: {
    basePath?: string;
    followSymlinks?: boolean;
    allowedPaths?: string[];
  });
  load(reference: PolicyRef, from?: string): LoadedSpec;
  supports(reference: PolicyRef): boolean;
}
```

```python
class FileLoader(PolicyLoader):
    def __init__(
        self,
        *,
        base_path: str | Path | None = None,
        follow_symlinks: bool = True,
        allowed_paths: list[str | Path] | None = None,
    ) -> None: ...
```

```go
type FileLoaderConfig struct {
    BasePath       string
    FollowSymlinks bool
    AllowedPaths   []string
}

func NewFileLoader(config FileLoaderConfig) PolicyLoader
```

#### 4.2.2 BuiltinLoader

Resolves `builtin:` references by loading from rulesets embedded in the SDK
at compile/bundle time.

**Available built-in rulesets (from `rulesets/`):**

| Name | File | Description |
|---|---|---|
| `default` | `rulesets/default.yaml` | Balanced security for AI agent execution |
| `strict` | `rulesets/strict.yaml` | Maximum security with minimal permissions |
| `permissive` | `rulesets/permissive.yaml` | Minimal restrictions for trusted environments |
| `ai-agent` | `rulesets/ai-agent.yaml` | Tuned for autonomous AI agent workloads |
| `cicd` | `rulesets/cicd.yaml` | Optimized for CI/CD pipeline execution |
| `remote-desktop` | `rulesets/remote-desktop.yaml` | Computer use and remote desktop scenarios |

**Embedding strategy by SDK:**

| SDK | Mechanism | Implementation Detail |
|---|---|---|
| Rust | `include_str!` macro at compile time | Each ruleset is a `const &str` in a generated module; a `match` on the name returns the content |
| TypeScript | Bundled as string constants in a generated module | A build script reads `rulesets/*.yaml` and emits `generated/builtins.ts` exporting a `Record<string, string>` |
| Python | `importlib.resources` reading from package data | Rulesets are included in the package's `data/` directory via `pyproject.toml`; `importlib.resources.files()` loads them |
| Go | `//go:embed` directive | An `embed.FS` variable embeds `rulesets/` and the loader reads by name |

**Signatures:**

```rust
pub struct BuiltinLoader;

impl BuiltinLoader {
    pub fn new() -> Self;

    /// List all available built-in ruleset names.
    pub fn available() -> &'static [&'static str];
}

impl PolicyLoader for BuiltinLoader {
    fn load(&self, reference: &PolicyRef, from: Option<&str>) -> Result<LoadedSpec, ResolveError>;
    fn supports(&self, reference: &PolicyRef) -> bool;  // true for PolicyRef::Builtin
}
```

```typescript
export class BuiltinLoader implements SyncPolicyLoader {
  static available(): string[];
  load(reference: PolicyRef, from?: string): LoadedSpec;
  supports(reference: PolicyRef): boolean;
}
```

```python
class BuiltinLoader(PolicyLoader):
    @staticmethod
    def available() -> list[str]: ...

    def load(self, reference: PolicyRef, from_source: str | None = None) -> LoadedSpec: ...
    def supports(self, reference: PolicyRef) -> bool: ...
```

```go
func NewBuiltinLoader() PolicyLoader
func AvailableBuiltins() []string
```

#### 4.2.3 HTTPLoader

Resolves `https://` URL references by fetching over HTTPS.

**Configuration:**

| Option | Type | Default | Description |
|---|---|---|---|
| `timeout_ms` | u64 | 10000 | Request timeout in milliseconds |
| `max_size_bytes` | u64 | 1048576 (1 MiB) | Maximum response body size |
| `tls_verify` | bool | true | Verify TLS certificates |
| `ca_bundle` | string? | (system) | Path to custom CA certificate bundle |
| `auth` | AuthConfig? | None | Authentication configuration |
| `headers` | Map<String, String> | {} | Additional request headers |
| `allowed_hosts` | string[] | [] | If non-empty, only fetch from these hosts |
| `retry_count` | u32 | 2 | Number of retries on transient errors |
| `retry_delay_ms` | u64 | 1000 | Base delay between retries (exponential backoff) |

**Authentication types:**

```rust
/// AuthConfig deliberately does NOT implement Debug or Display to prevent
/// accidental credential exposure in logs. Use the `redacted_description()`
/// method for safe logging.
pub enum AuthConfig {
    /// Bearer token loaded from an environment variable at runtime.
    BearerEnv { env_var: String },
    /// Bearer token (literal). Prefer BearerEnv for production.
    BearerToken { token: String },
    /// Basic auth. Password loaded from environment variable.
    Basic { username: String, password_env: String },
    /// Mutual TLS client certificate.
    MtlsCert { cert_path: String, key_path: String },
}

impl AuthConfig {
    /// Returns a safe-to-log description (e.g., "BearerEnv(POLICY_TOKEN)").
    pub fn redacted_description(&self) -> String { ... }
}
```

**Security requirements:**
- `tls_verify` MUST default to `true`. Setting it to `false` MUST emit a
  warning.
- Redirects: follow up to 5 redirects but only to HTTPS URLs. An HTTP
  redirect target MUST cause a hard error.
- Response must have Content-Type containing `text/yaml`, `text/x-yaml`,
  `application/x-yaml`, `application/yaml`, or `text/plain`. Other types
  are rejected.
- The `User-Agent` header MUST include `hushspec-sdk/<version>`.
- TLS 1.2 is the minimum supported version. TLS 1.0 and 1.1 MUST be rejected.

**Signatures:**

```rust
pub struct HttpLoader {
    client: reqwest::Client,
    config: HttpLoaderConfig,
}

impl HttpLoader {
    pub fn new(config: HttpLoaderConfig) -> Result<Self, ResolveError>;
}

impl AsyncPolicyLoader for HttpLoader {
    fn load<'a>(&'a self, reference: &'a PolicyRef, from: Option<&'a str>)
        -> Pin<Box<dyn Future<Output = Result<LoadedSpec, ResolveError>> + Send + 'a>>;
    fn supports(&self, reference: &PolicyRef) -> bool;
}
```

```typescript
export class HTTPLoader implements PolicyLoader {
  constructor(options?: HTTPLoaderOptions);
  load(reference: PolicyRef, from?: string): Promise<LoadedSpec>;
  supports(reference: PolicyRef): boolean;
}

export interface HTTPLoaderOptions {
  timeoutMs?: number;
  maxSizeBytes?: number;
  tlsVerify?: boolean;
  auth?: AuthConfig;
  headers?: Record<string, string>;
  allowedHosts?: string[];
  retryCount?: number;
  retryDelayMs?: number;
}
```

```python
class HTTPLoader(AsyncPolicyLoader):
    def __init__(
        self,
        *,
        timeout_ms: int = 10000,
        max_size_bytes: int = 1_048_576,
        tls_verify: bool = True,
        ca_bundle: str | None = None,
        auth: AuthConfig | None = None,
        headers: dict[str, str] | None = None,
        allowed_hosts: list[str] | None = None,
        retry_count: int = 2,
        retry_delay_ms: int = 1000,
    ) -> None: ...
```

```go
type HTTPLoaderConfig struct {
    TimeoutMs    int
    MaxSizeBytes int64
    TLSVerify    bool
    CABundle     string
    Auth         *AuthConfig
    Headers      map[string]string
    AllowedHosts []string
    RetryCount   int
    RetryDelayMs int
}

func NewHTTPLoader(config HTTPLoaderConfig) (PolicyLoader, error)
```

#### 4.2.4 S3Loader

Resolves references to policies stored in AWS S3.

**Reference format:** The S3 loader does not have its own reference prefix.
It is typically used via an HTTPS URL with S3 virtual-host or path-style
syntax, or via `CompositeLoader` configuration that maps certain path
prefixes to S3 buckets.

**Configuration:**

| Option | Type | Default | Description |
|---|---|---|---|
| `bucket` | string | (required) | S3 bucket name |
| `region` | string | (required) | AWS region |
| `prefix` | string | "" | Key prefix within the bucket |
| `auth` | S3Auth | (default chain) | Authentication method |

**Authentication:** Uses the standard AWS credential chain (environment
variables, shared credentials file, IAM role, ECS task role, EC2 instance
profile). An explicit access key/secret pair can be provided but is
discouraged in production.

**Error handling:**

| S3 Error | ResolveError |
|---|---|
| `NoSuchKey` | `ResolveError::Read` with "object not found" message |
| `NoSuchBucket` | `ResolveError::Read` with "bucket not found" message |
| `AccessDenied` | `ResolveError::Read` with "access denied" message |
| Network error | `ResolveError::Network` |

```rust
pub struct S3Loader {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl S3Loader {
    pub async fn new(config: S3LoaderConfig) -> Result<Self, ResolveError>;
}

impl AsyncPolicyLoader for S3Loader { ... }
```

```typescript
export class S3Loader implements PolicyLoader {
  constructor(config: S3LoaderConfig);
  load(reference: PolicyRef, from?: string): Promise<LoadedSpec>;
  supports(reference: PolicyRef): boolean;
}
```

```python
class S3Loader(AsyncPolicyLoader):
    def __init__(
        self,
        *,
        bucket: str,
        region: str,
        prefix: str = "",
        # Auth via boto3 default credential chain
    ) -> None: ...
```

```go
type S3LoaderConfig struct {
    Bucket string
    Region string
    Prefix string
}

func NewS3Loader(config S3LoaderConfig) (PolicyLoader, error)
```

#### 4.2.5 GCSLoader

Resolves references to policies stored in Google Cloud Storage.
Configuration mirrors S3Loader with GCS-specific authentication (service
account JSON, application default credentials, workload identity).

**Error handling** follows the same pattern as S3Loader, mapping GCS-specific
errors to `ResolveError` variants.

#### 4.2.6 AzureBlobLoader

Resolves references to policies stored in Azure Blob Storage.
Authentication via managed identity, service principal, or connection string.

**Error handling** follows the same pattern as S3Loader, mapping Azure-specific
errors to `ResolveError` variants.

#### 4.2.7 VaultLoader

Resolves references to policies stored in HashiCorp Vault.

**Configuration:**

| Option | Type | Default | Description |
|---|---|---|---|
| `addr` | string | `VAULT_ADDR` env | Vault server address |
| `mount` | string | "secret" | KV secrets engine mount path |
| `auth` | VaultAuth | (token from env) | Authentication method |

**Authentication types:**
- Token (`VAULT_TOKEN` env or explicit)
- AppRole (role_id + secret_id)
- Kubernetes (service account token)
- AWS IAM

**Behavior:** The policy YAML is stored as a string value at a key in a KV
v2 secrets engine. The loader reads the latest version by default. A
specific version can be requested via the reference.

**Error handling:**

| Vault Error | ResolveError |
|---|---|
| Secret not found | `ResolveError::Read` |
| Authentication failure | `ResolveError::Read` with "authentication failed" |
| Permission denied | `ResolveError::Read` with "access denied" |
| Vault sealed | `ResolveError::Network` with "vault is sealed" |

```rust
pub struct VaultLoader {
    client: VaultClient,
    mount: String,
}

impl AsyncPolicyLoader for VaultLoader { ... }
```

```python
class VaultLoader(AsyncPolicyLoader):
    def __init__(
        self,
        *,
        addr: str | None = None,      # defaults to VAULT_ADDR env
        mount: str = "secret",
        token: str | None = None,      # defaults to VAULT_TOKEN env
        role_id: str | None = None,    # for AppRole auth
        secret_id: str | None = None,
    ) -> None: ...
```

```go
type VaultLoaderConfig struct {
    Addr    string // defaults to VAULT_ADDR env
    Mount   string // defaults to "secret"
    Auth    VaultAuth
}

func NewVaultLoader(config VaultLoaderConfig) (PolicyLoader, error)
```

#### 4.2.8 GitLoader

Resolves `git:` references by cloning or fetching from git repositories.

**Configuration:**

| Option | Type | Default | Description |
|---|---|---|---|
| `cache_dir` | string | (system temp) | Directory for local clones |
| `ssh_key` | string? | (ssh-agent) | Path to SSH private key |
| `auth` | GitAuth? | None | Authentication configuration |
| `depth` | u32 | 1 | Clone depth (shallow clone) |

**Behavior:**
1. Parse the reference into `(repo_url, rev, file_path)`.
2. Check if a local clone exists in `cache_dir`.
3. If yes, `git fetch` and `git checkout <rev>`.
4. If no, `git clone --depth <depth> <repo_url> <cache_dir>/<hash>`.
5. Read `file_path` from the checked-out working tree.

**Authentication:**
- SSH key (default, via ssh-agent or explicit key file)
- HTTPS with token (for GitHub/GitLab personal access tokens)
- HTTPS with basic auth

```rust
pub struct GitLoader {
    cache_dir: PathBuf,
    auth: Option<GitAuth>,
    depth: u32,
}

impl AsyncPolicyLoader for GitLoader { ... }
```

```typescript
export class GitLoader implements PolicyLoader {
  constructor(config?: GitLoaderConfig);
  load(reference: PolicyRef, from?: string): Promise<LoadedSpec>;
  supports(reference: PolicyRef): boolean;
}
```

```python
class GitLoader(AsyncPolicyLoader):
    def __init__(
        self,
        *,
        cache_dir: str | Path | None = None,
        auth: GitAuth | None = None,
        depth: int = 1,
    ) -> None: ...
```

```go
type GitLoaderConfig struct {
    CacheDir string
    Auth     *GitAuth
    Depth    int
}

func NewGitLoader(config GitLoaderConfig) (PolicyLoader, error)
```

#### 4.2.9 CompositeLoader

Chains multiple loaders in priority order. The first loader that reports
`supports() == true` for a given reference is used. If that loader fails,
the error propagates (no fallback to next loader).

**Request coalescing:** When multiple threads/goroutines/promises attempt to
load the same reference concurrently, the CompositeLoader SHOULD coalesce
them into a single underlying load operation. The first request triggers the
actual load; subsequent concurrent requests wait for and share the same
result. This prevents thundering-herd effects when many evaluations reference
the same parent policy simultaneously.

```rust
pub struct CompositeLoader {
    loaders: Vec<Box<dyn PolicyLoader>>,
}

impl CompositeLoader {
    pub fn new() -> Self;
    pub fn add(self, loader: impl PolicyLoader + 'static) -> Self;

    /// Create the default loader chain: [BuiltinLoader, FileLoader].
    pub fn default_chain() -> Self;

    /// Create a loader chain with HTTP support:
    /// [BuiltinLoader, FileLoader, HttpLoader].
    pub fn with_http(http_config: HttpLoaderConfig) -> Result<Self, ResolveError>;
}

impl PolicyLoader for CompositeLoader {
    fn load(&self, reference: &PolicyRef, from: Option<&str>) -> Result<LoadedSpec, ResolveError> {
        for loader in &self.loaders {
            if loader.supports(reference) {
                return loader.load(reference, from);
            }
        }
        Err(ResolveError::UnsupportedReference {
            reference: format!("{reference:?}"),
        })
    }

    fn supports(&self, reference: &PolicyRef) -> bool {
        self.loaders.iter().any(|l| l.supports(reference))
    }
}
```

```typescript
export class CompositeLoader implements PolicyLoader {
  constructor(loaders?: PolicyLoader[]);
  add(loader: PolicyLoader): this;
  static defaultChain(): CompositeLoader;
  static withHTTP(options?: HTTPLoaderOptions): CompositeLoader;

  async load(reference: PolicyRef, from?: string): Promise<LoadedSpec>;
  supports(reference: PolicyRef): boolean;
}
```

```python
class CompositeLoader(PolicyLoader):
    def __init__(self, loaders: list[PolicyLoader] | None = None) -> None: ...
    def add(self, loader: PolicyLoader) -> "CompositeLoader": ...

    @staticmethod
    def default_chain() -> "CompositeLoader": ...

    @staticmethod
    def with_http(**kwargs) -> "CompositeLoader": ...
```

```go
type CompositeLoader struct {
    loaders []PolicyLoader
}

func NewCompositeLoader(loaders ...PolicyLoader) *CompositeLoader
func DefaultLoaderChain() *CompositeLoader
func (cl *CompositeLoader) Add(loader PolicyLoader) *CompositeLoader
```

#### 4.2.10 ClosureLoader (Backward Compatibility Adapter)

Wraps a legacy-style closure/callback in the new `PolicyLoader` interface.
This enables callers currently using `resolve_with_loader` to migrate
incrementally.

```rust
/// Wraps a closure matching the old resolve_with_loader signature.
pub struct ClosureLoader<F>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> + Send + Sync,
{
    func: F,
}

impl<F> ClosureLoader<F>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> + Send + Sync,
{
    pub fn new(func: F) -> Self;
}

impl<F> PolicyLoader for ClosureLoader<F>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> + Send + Sync,
{
    fn load(&self, reference: &PolicyRef, from: Option<&str>) -> Result<LoadedSpec, ResolveError> {
        // Reconstruct the reference string from the PolicyRef and delegate
        let ref_string = reference.to_string();
        (self.func)(&ref_string, from)
    }

    fn supports(&self, _reference: &PolicyRef) -> bool {
        true // Accept all references; the closure decides
    }
}
```

```typescript
export class CallbackLoader implements SyncPolicyLoader {
  constructor(fn: (reference: string, from?: string) => LoadedSpec);
  load(reference: PolicyRef, from?: string): LoadedSpec;
  supports(reference: PolicyRef): boolean; // always true
}
```

```python
class CallbackLoader(PolicyLoader):
    """Wraps a (reference, from_source) -> LoadedSpec callable."""
    def __init__(self, func: Callable[[str, str | None], LoadedSpec]) -> None: ...
    def load(self, reference: PolicyRef, from_source: str | None = None) -> LoadedSpec: ...
    def supports(self, reference: PolicyRef) -> bool: ...  # always True
```

```go
// CallbackLoader wraps a ResolveLoader function in the PolicyLoader interface.
type CallbackLoader struct {
    fn ResolveLoader
}

func NewCallbackLoader(fn ResolveLoader) PolicyLoader
```

### 4.3 Loader Chain Configuration

Loaders can be configured declaratively via YAML or programmatically via the
SDK API. The declarative YAML configuration is intended for deployment-time
setup and is parsed by a shared helper function available in each SDK.

```yaml
# hushspec-loader.yaml
# Declarative loader chain configuration
version: "1"
max_depth: 10

loaders:
  - type: builtin

  - type: file
    base_path: /etc/hushspec/policies
    allowed_paths:
      - /etc/hushspec/policies
      - /opt/app/policies

  - type: https
    timeout_ms: 5000
    max_size_bytes: 524288
    allowed_hosts:
      - policies.internal.example.com
      - hushspec-cdn.example.com
    auth:
      type: bearer_env
      env_var: HUSHSPEC_POLICY_TOKEN
    retry_count: 3
    retry_delay_ms: 500

  - type: s3
    bucket: company-policies
    region: us-east-1
    prefix: hushspec/v1/

cache:
  l1:
    max_entries: 100
    ttl_seconds: 300
  l2:
    directory: /var/cache/hushspec
    ttl_seconds: 3600
```

**Parsing function in each SDK:**

```rust
/// Parse a loader chain configuration from YAML.
pub fn load_config(yaml: &str) -> Result<ResolveConfig, ResolveError>;

/// Parse from a file path.
pub fn load_config_from_file(path: impl AsRef<Path>) -> Result<ResolveConfig, ResolveError>;

pub struct ResolveConfig {
    pub max_depth: usize,
    pub loader: CompositeLoader,
    pub cache: CacheConfig,
}
```

```typescript
export function loadConfig(yaml: string): ResolveConfig;
export function loadConfigFromFile(path: string): ResolveConfig;
```

```python
def load_config(yaml_content: str) -> ResolveConfig: ...
def load_config_from_file(path: str | Path) -> ResolveConfig: ...
```

```go
func LoadConfig(yaml string) (*ResolveConfig, error)
func LoadConfigFromFile(path string) (*ResolveConfig, error)
```

**Programmatic equivalent (Rust):**

```rust
let loader = CompositeLoader::new()
    .add(BuiltinLoader::new())
    .add(FileLoader::new()
        .with_base_path("/etc/hushspec/policies")
        .with_allowed_paths(vec![
            "/etc/hushspec/policies".into(),
            "/opt/app/policies".into(),
        ]))
    .add(HttpLoader::new(HttpLoaderConfig {
        timeout_ms: 5000,
        max_size_bytes: 524288,
        allowed_hosts: vec![
            "policies.internal.example.com".into(),
            "hushspec-cdn.example.com".into(),
        ],
        auth: Some(AuthConfig::BearerEnv {
            env_var: "HUSHSPEC_POLICY_TOKEN".into(),
        }),
        retry_count: 3,
        retry_delay_ms: 500,
        ..Default::default()
    })?);
```

---

## 5. Caching Strategy

### 5.1 Cache Layers

Policy resolution is performance-critical because it happens on every agent
action evaluation. A three-layer cache minimizes latency while providing
configurable staleness guarantees.

```
+--------------+     +--------------+     +--------------+     +----------+
|  L1: Memory  |---->| L2: Filesys  |---->| L3: Shared   |---->|  Origin  |
|  (process)   |     |  (disk)      |     | (Redis, etc) |     | (remote) |
|  ~0.001ms    |     |  ~1ms        |     |  ~5ms        |     | ~100ms+  |
+--------------+     +--------------+     +--------------+     +----------+
```

#### L1: In-Memory Cache

- Scope: Per-process. Fastest access.
- Eviction: LRU with configurable max entries (default 100).
- TTL: Configurable per reference type (default 300s for remote, unlimited
  for builtin/file).
- Key: Canonical source identifier (the `LoadedSpec.source` string).
- Value: Parsed and validated `HushSpec` + content hash + timestamp.
- Thread safety: Protected by `RwLock` (Rust), `Map` with atomic swap (Go),
  or process-level singleton (TS/Python).

#### L2: Filesystem Cache

- Scope: Per-machine. Survives process restart.
- Location: Configurable directory (default: platform temp dir /
  `$XDG_CACHE_HOME/hushspec/`).
- Format: Each cached policy is stored as two files:
  - `<sha256-of-source>.yaml` -- the raw policy content.
  - `<sha256-of-source>.meta.json` -- metadata (source URL, content hash,
    fetch timestamp, TTL, HTTP ETag, Last-Modified).
- TTL: Configurable (default 3600s for remote sources).
- Locking: File-level advisory locks prevent concurrent writes to the same
  cache entry.

#### L3: Shared Cache (Optional)

- Scope: Multi-process, multi-machine.
- Backends: Redis, Memcached, or any key-value store implementing a simple
  interface.
- Purpose: Useful when many agent processes on different machines share the
  same policy set and the origin server should not be hit by each process
  independently.
- TTL: Configurable (default 600s).

**Shared cache interface:**

```rust
pub trait SharedCache: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError>;
    fn set(&self, key: &str, entry: &CacheEntry, ttl_seconds: u64) -> Result<(), CacheError>;
    fn delete(&self, key: &str) -> Result<(), CacheError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub content: String,
    pub content_hash: String,
    pub fetched_at: u64,       // Unix timestamp
    pub source: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}
```

```typescript
export interface SharedCache {
  get(key: string): Promise<CacheEntry | null>;
  set(key: string, entry: CacheEntry, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}
```

```python
class SharedCache(abc.ABC):
    @abc.abstractmethod
    async def get(self, key: str) -> CacheEntry | None: ...
    @abc.abstractmethod
    async def set(self, key: str, entry: CacheEntry, ttl_seconds: int) -> None: ...
    @abc.abstractmethod
    async def delete(self, key: str) -> None: ...
```

```go
type SharedCache interface {
    Get(ctx context.Context, key string) (*CacheEntry, error)
    Set(ctx context.Context, key string, entry *CacheEntry, ttlSeconds int) error
    Delete(ctx context.Context, key string) error
}
```

### 5.2 Cache Invalidation

#### TTL-Based

Each cache layer has a configurable TTL. When a cached entry's age exceeds
the TTL, it is considered stale. Default TTLs by source type:

| Source Type | L1 TTL | L2 TTL |
|---|---|---|
| Builtin | Infinite (never expires) | Infinite |
| File | 0 (always recheck; mtime-based) | N/A (file is the source) |
| HTTPS | 300s | 3600s |
| S3/GCS/Azure | 300s | 3600s |
| Git | 600s | 7200s |
| Vault | 60s | 300s |

#### Content-Hash Based

Every cached entry stores a SHA-256 hash of the policy content. On
revalidation, the loader can compare hashes to determine if the content
actually changed. If the hash matches, the cached parsed `HushSpec` is
reused without re-parsing and re-validating.

For HTTPS sources, this works with ETag/If-Modified-Since headers:

```
GET /policy.yaml
If-None-Match: "abc123"
If-Modified-Since: Sat, 15 Mar 2026 10:00:00 GMT

-> 304 Not Modified (use cached)
-> 200 OK (new content, update cache)
```

#### Event-Driven

Remote sources can push invalidation events to listeners. See Section 6.3.

#### Manual

```rust
impl CachedLoader {
    /// Invalidate a specific cached entry.
    pub fn invalidate(&self, source: &str);

    /// Invalidate all cached entries.
    pub fn invalidate_all(&self);

    /// Invalidate entries matching a prefix (e.g., all HTTPS entries).
    pub fn invalidate_prefix(&self, prefix: &str);
}
```

```typescript
export class CachedLoader {
  invalidate(source: string): void;
  invalidateAll(): void;
  invalidatePrefix(prefix: string): void;
}
```

```python
class CachedLoader:
    def invalidate(self, source: str) -> None: ...
    def invalidate_all(self) -> None: ...
    def invalidate_prefix(self, prefix: str) -> None: ...
```

```go
type CachedLoader struct { ... }
func (cl *CachedLoader) Invalidate(source string)
func (cl *CachedLoader) InvalidateAll()
func (cl *CachedLoader) InvalidatePrefix(prefix string)
```

### 5.3 Stale-While-Revalidate

When a cached entry is stale but the origin is unavailable, the system can
serve the stale entry while attempting to fetch a fresh version in the
background.

**Security warning:** Enabling stale-while-revalidate weakens the fail-closed
guarantee. A compromised or revoked policy could continue to be served from
cache for up to `max_stale_seconds` after the origin stops serving it. For
high-security environments, leave `stale_while_revalidate: false` (the
default) and accept the latency cost of synchronous revalidation.

**Configuration:**

```rust
pub struct CachePolicy {
    /// Maximum time to serve a stale entry when the origin is unreachable.
    /// None means never serve stale (hard error on origin failure).
    pub max_stale_seconds: Option<u64>,

    /// Whether to proactively revalidate in the background before TTL expires.
    /// When set, revalidation starts at (TTL - prefetch_seconds) before expiry.
    pub prefetch_seconds: Option<u64>,

    /// Whether to serve stale content while revalidating.
    pub stale_while_revalidate: bool,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            max_stale_seconds: None,  // fail-closed by default
            prefetch_seconds: None,
            stale_while_revalidate: false,
        }
    }
}
```

**Behavior matrix:**

| Origin Status | Cache Status | `stale_while_revalidate` | Result |
|---|---|---|---|
| Available | Fresh | N/A | Serve cached |
| Available | Stale | true | Serve stale, revalidate in background |
| Available | Stale | false | Block until revalidation completes |
| Available | Miss | N/A | Fetch, cache, serve |
| Unavailable | Fresh | N/A | Serve cached |
| Unavailable | Stale (within max_stale) | N/A | Serve stale with warning |
| Unavailable | Stale (beyond max_stale) | N/A | Hard error (fail-closed) |
| Unavailable | Miss | N/A | Hard error (fail-closed) |

---

## 6. Hot Reload

### 6.1 File Watching

For file-based policies, the runtime can watch for filesystem changes and
reload automatically.

**Implementation strategy by platform:**

| Platform | API |
|---|---|
| Linux | `inotify` (via `notify` crate / `chokidar` / `watchdog`) |
| macOS | `FSEvents` |
| Windows | `ReadDirectoryChangesW` |

**Debouncing:** File editors often write files in multiple steps (write temp,
rename). The watcher MUST debounce with a configurable delay (default 100ms)
to avoid reloading mid-write.

**Atomic swap:** The new policy is fully parsed, validated, and resolved
(including its entire extends chain) before replacing the active policy. If
any step fails, the old policy remains active and an error is emitted.
The swap itself is atomic (behind a lock or atomic pointer) to prevent
concurrent evaluations from seeing a partially-constructed policy.

```rust
pub struct PolicyWatcher {
    current: Arc<RwLock<HushSpec>>,
    watcher: notify::RecommendedWatcher,
    debounce_ms: u64,
}

impl PolicyWatcher {
    pub fn new(path: impl AsRef<Path>, config: WatcherConfig) -> Result<Self, ResolveError>;

    /// Get the current resolved policy.
    pub fn current(&self) -> Arc<HushSpec>;

    /// Subscribe to policy change events.
    pub fn on_change(&self, callback: impl Fn(&HushSpec) + Send + Sync + 'static);

    /// Subscribe to error events (e.g., invalid policy on disk).
    pub fn on_error(&self, callback: impl Fn(&ResolveError) + Send + Sync + 'static);

    /// Stop watching.
    pub fn stop(self);
}

pub struct WatcherConfig {
    pub debounce_ms: u64,          // default 100
    pub loader: CompositeLoader,    // for resolving extends in reloaded policies
}
```

```typescript
export class PolicyWatcher extends EventEmitter {
  constructor(filePath: string, options?: WatcherOptions);

  /** Get the current resolved policy. */
  current(): HushSpec;

  /** Start watching for changes. */
  start(): void;

  /** Stop watching. */
  stop(): void;

  // Events: 'change' (spec: HushSpec), 'error' (err: Error)
}

export interface WatcherOptions {
  debounceMs?: number;
  loader?: PolicyLoader;
}
```

```python
class PolicyWatcher:
    def __init__(
        self,
        path: str | Path,
        *,
        debounce_ms: int = 100,
        loader: PolicyLoader | None = None,
        on_change: Callable[[HushSpec], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None: ...

    @property
    def current(self) -> HushSpec: ...

    def start(self) -> None: ...
    def stop(self) -> None: ...
```

```go
type PolicyWatcher struct {
    current atomic.Pointer[HushSpec]
    // ...
}

type WatcherConfig struct {
    DebounceMs int
    Loader     PolicyLoader
    OnChange   func(*HushSpec)
    OnError    func(error)
}

func NewPolicyWatcher(path string, config WatcherConfig) (*PolicyWatcher, error)
func (w *PolicyWatcher) Current() *HushSpec
func (w *PolicyWatcher) Stop()
```

### 6.2 Polling

For remote policies that cannot be watched via filesystem events, polling
provides periodic revalidation.

**Configuration:**

| Option | Type | Default | Description |
|---|---|---|---|
| `interval_seconds` | u64 | 60 | Polling interval |
| `jitter_percent` | u32 | 10 | Random jitter to avoid thundering herd |
| `use_etag` | bool | true | Use ETag/If-Modified-Since for conditional GETs |

**Behavior:**
1. On each poll tick, the loader fetches the policy from the origin.
2. If the origin supports conditional requests (ETag, Last-Modified), a
   conditional GET is used. A 304 response means no change.
3. If the content hash differs from the cached version, the new content is
   parsed, validated, and atomically swapped.
4. If the origin is unreachable, the `CachePolicy` determines whether to
   keep serving the old policy or error out.

```rust
pub struct PolicyPoller {
    current: Arc<RwLock<HushSpec>>,
    handle: tokio::task::JoinHandle<()>,
}

impl PolicyPoller {
    pub async fn start(
        reference: &str,
        loader: Arc<dyn AsyncPolicyLoader>,
        config: PollerConfig,
    ) -> Result<Self, ResolveError>;

    pub fn current(&self) -> Arc<HushSpec>;

    /// Force an immediate poll (outside the regular interval).
    pub async fn poll_now(&self) -> Result<bool, ResolveError>;

    pub async fn stop(self);
}

pub struct PollerConfig {
    pub interval_seconds: u64,
    pub jitter_percent: u32,
    pub cache_policy: CachePolicy,
    pub on_change: Option<Box<dyn Fn(&HushSpec) + Send + Sync>>,
    pub on_error: Option<Box<dyn Fn(&ResolveError) + Send + Sync>>,
}
```

```typescript
export class PolicyPoller extends EventEmitter {
  constructor(reference: string, options: PollerOptions);
  current(): HushSpec;
  start(): void;
  pollNow(): Promise<boolean>;
  stop(): void;
  // Events: 'change', 'error', 'poll'
}
```

```python
class PolicyPoller:
    def __init__(
        self,
        reference: str,
        *,
        loader: AsyncPolicyLoader,
        interval_seconds: int = 60,
        jitter_percent: int = 10,
        cache_policy: CachePolicy | None = None,
        on_change: Callable[[HushSpec], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None: ...

    @property
    def current(self) -> HushSpec: ...

    async def start(self) -> None: ...
    async def poll_now(self) -> bool: ...
    async def stop(self) -> None: ...
```

```go
type PolicyPoller struct {
    current atomic.Pointer[HushSpec]
    cancel  context.CancelFunc
}

type PollerConfig struct {
    IntervalSeconds int
    JitterPercent   int
    Loader          PolicyLoader
    CachePolicy     *CachePolicy
    OnChange        func(*HushSpec)
    OnError         func(error)
}

func NewPolicyPoller(reference string, config PollerConfig) (*PolicyPoller, error)
func (p *PolicyPoller) Current() *HushSpec
func (p *PolicyPoller) PollNow() (changed bool, err error)
func (p *PolicyPoller) Stop()
```

### 6.3 Push-Based Reload

For high-frequency or low-latency update requirements, push-based
notification avoids polling overhead.

#### 6.3.1 Webhook Endpoint

The SDK can optionally expose an HTTP endpoint that receives POST requests
when policies are updated.

```
POST /hushspec/reload
Content-Type: application/json
X-HushSpec-Signature: sha256=<HMAC-SHA256-hex>

{
  "source": "https://policies.example.com/production.yaml",
  "action": "updated",
  "content_hash": "sha256:abcdef1234567890...",
  "timestamp": 1710500000
}
```

**Authentication and verification:**

The webhook endpoint MUST require authentication. The primary mechanism is
HMAC-SHA256 signature verification:

1. The shared secret is configured at deployment time (environment variable
   or configuration file).
2. The sender computes `HMAC-SHA256(secret, request_body_bytes)` and sends
   it in the `X-HushSpec-Signature` header as `sha256=<hex-digest>`.
3. The receiver recomputes the HMAC and compares using constant-time
   comparison. Mismatches are rejected with 403.
4. Replay protection: the `timestamp` field MUST be within 5 minutes of
   server time. Older payloads are rejected.

```rust
pub struct WebhookReloader {
    bind_addr: SocketAddr,
    secret: String,
    current: Arc<RwLock<HushSpec>>,
}

impl WebhookReloader {
    pub async fn start(
        bind_addr: SocketAddr,
        secret: String,
        loader: Arc<dyn AsyncPolicyLoader>,
    ) -> Result<Self, ResolveError>;

    pub fn current(&self) -> Arc<HushSpec>;
    pub async fn stop(self);
}
```

```typescript
export class WebhookReloader {
  constructor(options: WebhookReloaderOptions);
  current(): HushSpec;
  start(): Promise<void>;
  stop(): Promise<void>;
}

export interface WebhookReloaderOptions {
  port: number;
  secret: string;
  loader: PolicyLoader;
  path?: string;  // default: '/hushspec/reload'
}
```

```python
class WebhookReloader:
    def __init__(
        self,
        *,
        port: int,
        secret: str,
        loader: AsyncPolicyLoader,
        path: str = "/hushspec/reload",
    ) -> None: ...

    @property
    def current(self) -> HushSpec: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
```

```go
type WebhookReloaderConfig struct {
    Addr   string // bind address, e.g., ":8080"
    Secret string
    Loader PolicyLoader
    Path   string // default: "/hushspec/reload"
}

func NewWebhookReloader(config WebhookReloaderConfig) (*WebhookReloader, error)
```

#### 6.3.2 Message Queue Consumer

For deployments using message brokers, the SDK can consume policy update
events from a queue.

**Supported backends (via optional feature flags):**
- AWS SQS
- Google Pub/Sub
- Apache Kafka
- NATS
- Redis Pub/Sub

The message format follows the same schema as the webhook payload.

#### 6.3.3 gRPC Streaming

A bidirectional gRPC stream allows a central policy server to push updates
to all connected agent runtimes simultaneously.

```protobuf
service PolicyService {
    rpc WatchPolicy(WatchPolicyRequest) returns (stream PolicyUpdate);
}

message WatchPolicyRequest {
    string reference = 1;
    string current_hash = 2;  // Send only if content changed
}

message PolicyUpdate {
    string source = 1;
    string content = 2;
    string content_hash = 3;
    int64 timestamp = 4;
}
```

This is a future extension. The initial implementation focuses on webhooks
and message queues.

---

## 7. Resolution in Each SDK

### 7.1 Rust

**Updated public API:**

```rust
// crates/hushspec/src/resolve.rs

/// Resolve with the default loader chain (builtin + file).
pub fn resolve(spec: &HushSpec, source: Option<&str>) -> Result<HushSpec, ResolveError> {
    let loader = CompositeLoader::default_chain();
    resolve_with(&loader, spec, source)
}

/// Resolve with a custom loader.
pub fn resolve_with(
    loader: &dyn PolicyLoader,
    spec: &HushSpec,
    source: Option<&str>,
) -> Result<HushSpec, ResolveError> {
    let config = ResolveConfig::default();
    resolve_with_config(loader, spec, source, &config)
}

/// Resolve with a custom loader and configuration.
pub fn resolve_with_config(
    loader: &dyn PolicyLoader,
    spec: &HushSpec,
    source: Option<&str>,
    config: &ResolveConfig,
) -> Result<HushSpec, ResolveError> {
    let mut visited = HashSet::new();
    if let Some(s) = source {
        visited.insert(s.to_string());
    }
    resolve_inner(spec, source, loader, &mut visited, 0, config)
}

/// Async resolve with a custom async loader.
pub async fn resolve_async(
    loader: &dyn AsyncPolicyLoader,
    spec: &HushSpec,
    source: Option<&str>,
) -> Result<HushSpec, ResolveError> {
    let mut visited = HashSet::new();
    if let Some(s) = source {
        visited.insert(s.to_string());
    }
    resolve_inner_async(spec, source, loader, &mut visited, 0).await
}

/// Resolve from a file path using the default loader chain.
pub fn resolve_from_path(path: impl AsRef<Path>) -> Result<HushSpec, ResolveError> {
    // unchanged interface, updated internals
}

/// Parse the extends string into a typed reference.
pub fn parse_reference(extends: &str) -> PolicyRef { ... }

/// Deprecated: Use resolve() or resolve_with() instead.
#[deprecated(since = "0.2.0", note = "Use resolve_with() with a PolicyLoader")]
pub fn resolve_with_loader<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    resolve_with(&ClosureLoader::new(loader), spec, source)
}

pub struct ResolveConfig {
    pub max_depth: usize,                // default: 10
    pub version_mismatch: VersionMismatchPolicy,  // default: Warn
    pub validate_parents: bool,          // default: true
}

pub enum VersionMismatchPolicy {
    Warn,   // log warning, continue
    Error,  // hard error
    Ignore, // silent
}
```

**Integration example:**

```rust
use hushspec::{HushSpec, resolve, resolve_async};
use hushspec::resolve::{CompositeLoader, BuiltinLoader, FileLoader, HttpLoader};

// Synchronous: builtin + file (default)
let spec = HushSpec::parse(yaml_content)?;
let resolved = resolve(&spec, Some("policy.yaml"))?;

// Async: builtin + file + HTTPS
let loader = CompositeLoader::new()
    .add(BuiltinLoader::new())
    .add(FileLoader::new())
    .add(HttpLoader::new(HttpLoaderConfig::default())?);
let resolved = resolve_async(&loader, &spec, Some("policy.yaml")).await?;
```

**Error handling:**

```rust
match resolve(&spec, source) {
    Ok(resolved) => { /* use resolved policy */ }
    Err(ResolveError::Cycle { chain }) => {
        eprintln!("Circular dependency: {chain}");
    }
    Err(ResolveError::TooDeep { max_depth, chain }) => {
        eprintln!("Chain too deep (>{max_depth}): {chain}");
    }
    Err(ResolveError::Network { url, message }) => {
        eprintln!("Failed to fetch {url}: {message}");
    }
    Err(e) => {
        eprintln!("Resolution failed: {e}");
    }
}
```

### 7.2 TypeScript

**Updated public API:**

```typescript
// packages/hushspec/src/resolve.ts

export interface ResolveOptions {
  source?: string;
  loader?: PolicyLoader | SyncPolicyLoader;
  maxDepth?: number;
  versionMismatch?: 'warn' | 'error' | 'ignore';
  validateParents?: boolean;
}

/** Resolve extends chain (async, supports all loader types). */
export async function resolveAsync(
  spec: HushSpec,
  options?: ResolveOptions,
): Promise<ResolveResult>;

/** Resolve extends chain (sync, file + builtin only). */
export function resolve(
  spec: HushSpec,
  options?: ResolveOptions,
): ResolveResult;

/** Resolve from file path (sync). */
export function resolveFromFile(filePath: string): ResolveResult;

/** Parse an extends reference string. */
export function parseReference(extends_: string): PolicyRef;
```

**Integration example:**

```typescript
import { parse, resolveAsync } from '@hushspec/core';
import { CompositeLoader, HTTPLoader, BuiltinLoader, FileLoader } from '@hushspec/core/loaders';

const loader = new CompositeLoader([
  new BuiltinLoader(),
  new FileLoader(),
  new HTTPLoader({
    auth: { type: 'bearer_env', envVar: 'POLICY_TOKEN' },
    allowedHosts: ['policies.internal.example.com'],
  }),
]);

const parsed = parse(yamlContent);
if (!parsed.ok) throw new Error(parsed.error);

const result = await resolveAsync(parsed.value, { loader });
if (!result.ok) throw new Error(result.error);

const policy = result.value;
```

### 7.3 Python

**Updated public API:**

```python
# packages/python/hushspec/__init__.py

def resolve(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: PolicyLoader | None = None,
    max_depth: int = 10,
    version_mismatch: str = "warn",  # "warn", "error", "ignore"
    validate_parents: bool = True,
) -> tuple[bool, HushSpec | str]:
    """Resolve extends chain synchronously (file + builtin)."""
    ...

async def resolve_async(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: AsyncPolicyLoader | None = None,
    max_depth: int = 10,
    version_mismatch: str = "warn",
    validate_parents: bool = True,
) -> tuple[bool, HushSpec | str]:
    """Resolve extends chain asynchronously (supports remote loaders)."""
    ...

def resolve_file(path: str | Path) -> tuple[bool, HushSpec | str]:
    """Convenience: load and resolve from a file path."""
    ...

def parse_reference(extends: str) -> PolicyRef:
    """Parse an extends string into a typed reference."""
    ...
```

**Integration example:**

```python
import asyncio
from hushspec import parse_or_raise, resolve_async
from hushspec.loaders import CompositeLoader, BuiltinLoader, FileLoader, HTTPLoader

async def main():
    loader = CompositeLoader([
        BuiltinLoader(),
        FileLoader(),
        HTTPLoader(
            allowed_hosts=["policies.internal.example.com"],
            auth=BearerEnvAuth("POLICY_TOKEN"),
        ),
    ])

    spec = parse_or_raise(yaml_content)
    ok, result = await resolve_async(spec, loader=loader)
    if not ok:
        raise ValueError(result)

    policy = result

asyncio.run(main())
```

### 7.4 Go

**Updated public API:**

```go
// packages/go/hushspec/resolve.go

// Resolve resolves extends using the provided loader (or default chain).
// The context controls timeouts and cancellation for all I/O operations.
func Resolve(ctx context.Context, spec *HushSpec, source string, loader PolicyLoader) (*HushSpec, error)

// ResolveFile loads and resolves from a filesystem path.
func ResolveFile(path string) (*HushSpec, error)

// ParseReference parses an extends string into a PolicyRef.
func ParseReference(extends string) PolicyRef

// DefaultLoaderChain returns [BuiltinLoader, FileLoader].
func DefaultLoaderChain() *CompositeLoader

// ResolveConfig holds configuration for the resolution process.
type ResolveConfig struct {
    MaxDepth         int    // default: 10
    VersionMismatch  string // "warn" (default), "error", "ignore"
    ValidateParents  bool   // default: true
}

// ResolveWithConfig resolves with explicit configuration.
func ResolveWithConfig(ctx context.Context, spec *HushSpec, source string, loader PolicyLoader, config ResolveConfig) (*HushSpec, error)
```

**Integration example:**

```go
package main

import (
    "context"
    "fmt"
    "github.com/backbay-labs/hush/packages/go/hushspec"
)

func main() {
    ctx := context.Background()
    loader := hushspec.NewCompositeLoader(
        hushspec.NewBuiltinLoader(),
        hushspec.NewFileLoader(hushspec.FileLoaderConfig{}),
        hushspec.NewHTTPLoader(hushspec.HTTPLoaderConfig{
            AllowedHosts: []string{"policies.internal.example.com"},
            Auth: &hushspec.BearerEnvAuth{EnvVar: "POLICY_TOKEN"},
        }),
    )

    spec, err := hushspec.Parse(yamlContent)
    if err != nil {
        panic(err)
    }

    resolved, err := hushspec.Resolve(ctx, spec, "policy.yaml", loader)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Resolved policy: %s\n", resolved.Name)
}
```

---

## 8. Observability

### 8.1 Structured Logging

All resolution and loading operations MUST emit structured log events at
appropriate levels:

| Event | Level | Fields |
|---|---|---|
| Resolution started | DEBUG | `reference`, `from`, `depth` |
| Loader selected | DEBUG | `loader_type`, `reference_type` |
| Cache hit (L1) | DEBUG | `source`, `age_seconds` |
| Cache hit (L2) | DEBUG | `source`, `age_seconds` |
| Cache miss | DEBUG | `source` |
| Fetch started | INFO | `source`, `loader_type` |
| Fetch completed | INFO | `source`, `duration_ms`, `content_hash` |
| Stale entry served | WARN | `source`, `age_seconds`, `max_stale_seconds` |
| TLS verification disabled | WARN | `url` |
| Version mismatch | WARN | `parent_version`, `child_version`, `parent_source` |
| Resolution failed | ERROR | `reference`, `error`, `depth` |
| Integrity failure | ERROR | `source`, `expected_hash`, `actual_hash` |
| Policy reloaded | INFO | `source`, `old_hash`, `new_hash` |
| Policy reload failed (keeping old) | ERROR | `source`, `error` |

### 8.2 Metrics

SDKs SHOULD expose metrics via a pluggable metrics interface. Default
implementations are provided for common metrics backends.

| Metric | Type | Labels |
|---|---|---|
| `hushspec_resolve_total` | Counter | `status` (ok/error), `loader_type` |
| `hushspec_resolve_duration_seconds` | Histogram | `loader_type` |
| `hushspec_cache_hits_total` | Counter | `layer` (l1/l2/l3), `loader_type` |
| `hushspec_cache_misses_total` | Counter | `layer`, `loader_type` |
| `hushspec_cache_stale_serves_total` | Counter | `loader_type` |
| `hushspec_reload_total` | Counter | `status` (ok/error), `trigger` (watch/poll/webhook) |
| `hushspec_active_policy_age_seconds` | Gauge | `source` |

```rust
/// Optional metrics collector. Implementations are provided for
/// prometheus and opentelemetry behind feature flags.
pub trait MetricsCollector: Send + Sync {
    fn resolve_completed(&self, loader_type: &str, duration: Duration, success: bool);
    fn cache_access(&self, layer: &str, hit: bool, loader_type: &str);
    fn reload_completed(&self, trigger: &str, success: bool);
}
```

---

## 9. Testing Strategy

### 9.1 Unit Tests for Each Loader

Each loader receives focused unit tests in isolation.

**FileLoader tests:**

| Test Case | Description |
|---|---|
| `load_relative_path` | Resolve `./child.yaml` relative to parent directory |
| `load_absolute_path` | Resolve an absolute path |
| `load_missing_file` | Return `ResolveError::Read` for nonexistent file |
| `load_invalid_yaml` | Return `ResolveError::Parse` for malformed YAML |
| `load_invalid_spec` | Return `ResolveError::Validate` for valid YAML that fails HushSpec validation |
| `load_symlink` | Follow symlinks to canonical path |
| `load_sandbox_violation` | Reject paths outside `allowed_paths` |
| `load_path_traversal` | Reject `../../etc/passwd` when sandboxed |
| `load_null_byte_path` | Reject paths containing null bytes |

**BuiltinLoader tests:**

| Test Case | Description |
|---|---|
| `load_default` | Load `builtin:default` and verify it parses and validates |
| `load_strict` | Load `builtin:strict` and verify it parses and validates |
| `load_all_builtins` | Load each of the 6 built-in rulesets and verify all parse/validate |
| `load_unknown` | Return error for `builtin:nonexistent` |
| `available_lists_all` | `available()` returns all six built-in names |
| `builtin_canonical_source` | Verify canonical source ID is `builtin:<name>` |

**HTTPLoader tests (with mock server):**

| Test Case | Description |
|---|---|
| `load_200_ok` | Fetch valid YAML, parse and return |
| `load_404` | Return error for 404 response |
| `load_500` | Return error for server error, verify retry |
| `load_timeout` | Return error after timeout |
| `load_too_large` | Reject response exceeding `max_size_bytes` |
| `load_bad_content_type` | Reject non-YAML content type |
| `load_redirect_https` | Follow HTTPS redirect |
| `load_redirect_http` | Reject HTTP redirect |
| `load_bearer_auth` | Verify Authorization header sent |
| `load_etag_304` | Conditional GET returns 304, use cached |
| `load_allowed_hosts` | Reject URL to unlisted host |
| `load_ssrf_private_ip` | Reject resolved IP in private range |
| `load_integrity_hash_match` | URL with `#sha256:...` suffix, hash matches |
| `load_integrity_hash_mismatch` | URL with `#sha256:...` suffix, hash mismatch -> error |

**CompositeLoader tests:**

| Test Case | Description |
|---|---|
| `first_match_wins` | Use first loader that supports the reference |
| `no_match` | Return `UnsupportedReference` when no loader matches |
| `error_does_not_fall_through` | If matched loader errors, do not try next |
| `default_chain_builtin_and_file` | `default_chain()` supports both builtin and file refs |

**ClosureLoader tests:**

| Test Case | Description |
|---|---|
| `wraps_legacy_callback` | Legacy-style closure works through new interface |
| `supports_all_refs` | `supports()` returns true for all reference types |

**parse_reference tests:**

| Test Case | Description |
|---|---|
| `parse_file_relative` | `./base.yaml` -> `File { path: "./base.yaml" }` |
| `parse_file_absolute` | `/etc/policy.yaml` -> `File { path: "/etc/policy.yaml" }` |
| `parse_builtin` | `builtin:default` -> `Builtin { name: "default" }` |
| `parse_https` | `https://example.com/p.yaml` -> `Https { url: "..." }` |
| `parse_npm` | `npm:@org/policy@^2.0` -> `Package { ... }` |
| `parse_git` | `git:github.com/org/repo@main:f.yaml` -> `Git { ... }` |
| `parse_registry` | `registry:org/name@1.0` -> `Registry { ... }` |
| `parse_bare_name` | `default` -> `BareRef { name: "default" }` |
| `parse_https_with_hash` | `https://...#sha256:abc` -> `Https { url: "..." }` with integrity |

### 9.2 Integration Tests

| Test Case | Description |
|---|---|
| `three_level_chain` | A extends B extends C; all three policies merge correctly |
| `builtin_as_base` | `extends: builtin:default` with local overrides |
| `https_extends_file` | Remote policy extends local policy via file reference |
| `mixed_strategies` | Chain where each level uses a different merge strategy |
| `deep_merge_extensions` | Verify posture/origins/detection merge through extends chain |
| `merge_strategy_extensions` | Verify extensions are replaced wholesale (not deep-merged) with `merge` strategy |
| `bare_ref_builtin_hit` | Bare ref `default` resolves to `builtin:default` |
| `bare_ref_file_fallback` | Bare ref `custom.yaml` resolves to file when no builtin matches |
| `parent_validation_failure` | Parent policy with invalid fields causes hard error |

### 9.3 Circular Dependency Tests

| Test Case | Description |
|---|---|
| `direct_cycle` | A extends B, B extends A |
| `indirect_cycle` | A extends B, B extends C, C extends A |
| `self_reference` | A extends A |
| `cycle_with_different_refs` | A extends `./b.yaml`, B extends `../dir/a.yaml` (same file, different paths -- caught by canonical source IDs) |

### 9.4 Depth Limit Tests

| Test Case | Description |
|---|---|
| `max_depth_11` | Chain of 11 levels, verify `TooDeep` error |
| `max_depth_10` | Chain of exactly 10 levels, verify success |
| `custom_max_depth` | Set max_depth to 3, verify chain of 4 fails |

### 9.5 Cache Behavior Tests

| Test Case | Description |
|---|---|
| `l1_hit` | Second resolution of same policy uses in-memory cache |
| `l1_expiry` | After TTL, L1 cache entry is stale |
| `l2_hit` | After process restart simulation, L2 filesystem cache is used |
| `l2_expiry` | After L2 TTL, entry is revalidated from origin |
| `stale_while_revalidate` | Origin slow, stale L1 entry served while revalidating |
| `origin_down_within_max_stale` | Origin unreachable, stale entry within max_stale served |
| `origin_down_beyond_max_stale` | Origin unreachable, stale entry beyond max_stale, error |
| `invalidate_specific` | Manual invalidation of one entry |
| `invalidate_all` | Manual invalidation of all entries |
| `content_hash_unchanged` | Revalidation fetches same content, no re-parse |

### 9.6 Hot Reload Tests

| Test Case | Description |
|---|---|
| `file_change_triggers_reload` | Modify watched file, verify `on_change` fires |
| `invalid_file_keeps_old_policy` | Write invalid YAML, verify old policy retained and `on_error` fires |
| `debounce_rapid_writes` | Write 10 times in 50ms, verify only one reload |
| `poll_detects_remote_change` | Mock server returns new content, poller updates |
| `poll_304_no_change` | Mock server returns 304, no update |
| `poll_origin_down` | Mock server unreachable, behavior per CachePolicy |
| `webhook_valid_signature` | Valid HMAC signature triggers reload |
| `webhook_invalid_signature` | Invalid HMAC signature returns 403 |
| `webhook_replay_rejected` | Timestamp older than 5 minutes is rejected |

### 9.7 Conformance Fixtures

New fixture files for resolution testing:

```
fixtures/
  core/
    merge/
      base.yaml                 # (existing)
      child-deep-merge.yaml     # (existing)
      expected-deep-merge.yaml  # (existing)
      child-replace.yaml        # (existing)
      expected-replace.yaml     # (existing)
      child-merge.yaml          # NEW: merge strategy with extension override
      expected-merge.yaml       # NEW: expected output (extensions replaced wholesale)
    resolve/
      chain-base.yaml           # Root of a 3-level chain
      chain-middle.yaml         # extends: chain-base.yaml
      chain-leaf.yaml           # extends: chain-middle.yaml
      expected-chain.yaml       # Expected merged output
      cycle-a.yaml              # extends: cycle-b.yaml
      cycle-b.yaml              # extends: cycle-a.yaml
      self-ref.yaml             # extends: self-ref.yaml
      builtin-override.yaml     # extends: builtin:default, overrides egress
      expected-builtin.yaml     # Expected merged output
      mixed-strategy-base.yaml  # Base policy
      mixed-strategy-mid.yaml   # extends base with merge_strategy: merge
      mixed-strategy-leaf.yaml  # extends mid with merge_strategy: deep_merge
      expected-mixed.yaml       # Expected merged output
```

---

## 10. Security Considerations

### 10.1 TLS Certificate Validation

- `tls_verify` MUST default to `true` in all loaders.
- When `tls_verify` is set to `false`, the SDK MUST log a warning at the
  `WARN` level.
- Custom CA bundles MUST be supported for corporate environments with
  private certificate authorities.
- TLS 1.2 is the minimum supported version. TLS 1.0 and 1.1 MUST be
  rejected.

### 10.2 Policy Source Authentication

- Authentication credentials MUST NOT be logged at any level.
- Bearer tokens SHOULD be loaded from environment variables rather than
  hardcoded in configuration.
- The `AuthConfig` type MUST NOT implement `Debug` or `Display` in a way
  that exposes token values. Implement redacted display:
  `BearerEnv { env_var: "POLICY_TOKEN" }` (show env var name, not value).
- Mutual TLS (mTLS) SHOULD be supported for high-security environments.
- All authentication methods MUST use constant-time comparison for secret
  values to prevent timing attacks.

### 10.3 Content Integrity Verification

Policies loaded from remote sources can optionally be verified against a
content hash.

**Hash specification in extends reference:**

```yaml
# SHA-256 hash appended after '#'
extends: https://policies.example.com/base.yaml#sha256:abcdef1234...
```

**Behavior:**
- If a hash is present in the reference, the loaded content MUST be hashed
  and compared. A mismatch is a hard error (`IntegrityFailure`).
- If no hash is present, content integrity is not checked (unless the
  deployment configures a separate manifest).
- The hash fragment is stripped from the URL before fetching.

**Manifest-based verification (future extension):**

A deployment can configure a manifest file mapping policy sources to expected
hashes. This provides integrity verification even for references that do not
embed hashes.

```yaml
# hushspec-manifest.yaml
policies:
  - source: https://policies.example.com/base.yaml
    sha256: abcdef1234567890...
  - source: builtin:default
    sha256: 1234567890abcdef...
```

**Policy signing (future extension):**

For environments requiring cryptographic provenance, a future RFC will define:
- Ed25519 or ECDSA signature verification for policy documents.
- A trust store for authorized signing keys.
- Signature embedding (detached `.sig` files or inline YAML field).

This is tracked separately because it requires spec-level changes (a new
optional `signature` field) and is not needed for the initial remote loading
implementation.

### 10.4 Maximum Download Size

- All network-based loaders MUST enforce a maximum download size.
- Default: 1 MiB (1,048,576 bytes).
- Configurable per loader.
- The loader MUST stop reading the response body after the limit is reached
  and return a `SizeExceeded` error.
- The limit check MUST use `Content-Length` (if available) for an early
  reject, AND streaming byte counting for responses without `Content-Length`.

### 10.5 Timeout Enforcement

- All network operations MUST have a configurable timeout.
- Default: 10 seconds per request.
- The timeout covers the entire request-response cycle, not just connection
  establishment.
- DNS resolution timeouts SHOULD be included in the overall timeout.

### 10.6 Rate Limiting

- Loaders SHOULD implement client-side rate limiting to avoid overwhelming
  origin servers.
- Default: no more than 10 requests per second per host.
- The rate limiter MUST be per-host, not global.
- When rate-limited, the loader SHOULD serve from cache if available, or
  wait until the rate limit window expires.

### 10.7 SSRF Prevention

- The HTTPLoader MUST reject requests to private/internal IP ranges by
  default (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1).
- This check MUST happen after DNS resolution to prevent DNS rebinding
  attacks.
- The check can be disabled via `allow_private_ips: true` for deployments
  where the policy server is on a private network.
- The `allowed_hosts` allowlist, when configured, provides additional
  protection by restricting requests to known hosts.

### 10.8 Path Traversal Prevention

- The FileLoader MUST canonicalize paths before reading.
- When `allowed_paths` is configured, the canonical path MUST be verified
  to start with one of the allowed prefixes.
- Symbolic links MUST be resolved before the path prefix check.
- Null bytes in paths MUST be rejected.

---

## 11. Implementation Roadmap

### Phase 1: Resolution Algorithm + FileLoader + BuiltinLoader (All SDKs)

**Duration:** 2 weeks
**Priority:** P0

**Deliverables:**
- `parse_reference()` function that classifies extends references by type.
- `PolicyRef` enum/type in all four SDKs.
- `PolicyLoader` trait/interface in all four SDKs.
- `FileLoader` with sandbox (`allowed_paths`) support.
- `BuiltinLoader` with all six embedded rulesets (embedding via `include_str!`,
  bundled constants, `importlib.resources`, `//go:embed`).
- `CompositeLoader` with `default_chain()` factory.
- `ClosureLoader` / `CallbackLoader` adapter for backward compatibility.
- Depth limit enforcement (default 10).
- Parent validation during resolution.
- `ResolveConfig` with `max_depth`, `version_mismatch`, `validate_parents`.
- Updated `resolve()` and `resolve_from_path()` using the new loader system.
- Backward compatibility: existing `resolve_with_loader` function signatures
  preserved as deprecated wrappers.
- New conformance fixture files: `child-merge.yaml`/`expected-merge.yaml`
  (merge strategy), resolution chain fixtures, cycle fixtures.
- Unit tests for FileLoader, BuiltinLoader, CompositeLoader, ClosureLoader,
  parse_reference.
- Integration tests for 3-level chains, cycle detection, depth limits,
  builtin-as-base, bare reference resolution.

**Breaking changes:** None. New functions are additive. Old functions are
preserved with deprecation warnings.

### Phase 2: HTTPLoader with Caching

**Duration:** 2 weeks
**Priority:** P0

**Deliverables:**
- `HTTPLoader` with full configuration (auth, timeout, retry, size limit,
  host allowlist).
- L1 in-memory cache with LRU eviction and TTL.
- L2 filesystem cache with metadata files.
- `CachePolicy` configuration.
- ETag/If-Modified-Since conditional GET support.
- Content-hash integrity verification (including `#sha256:` fragment).
- SSRF prevention (private IP rejection).
- Rate limiting (per-host).
- Async resolve variants (`resolve_async` / `resolveAsync`).
- Go: `context.Context` integration for all loaders.
- Mock HTTP server test harness.
- Unit tests for HTTPLoader (all cases from Section 9.1).
- Cache behavior tests (Section 9.5).
- Structured logging for all resolution events (Section 8.1).

**Dependencies:** Phase 1 complete.

### Phase 3: Cloud Storage Loaders (S3, GCS, Azure)

**Duration:** 2 weeks
**Priority:** P1

**Deliverables:**
- `S3Loader` with AWS credential chain.
- `GCSLoader` with Google Cloud credential chain.
- `AzureBlobLoader` with Azure identity.
- Each loader behind an optional feature flag / optional dependency.
- Error mapping from cloud-specific errors to `ResolveError`.
- Integration tests with mock/local object storage (LocalStack for S3,
  etc.).

**Dependencies:** Phase 2 complete (reuses caching layer).

### Phase 4: Hot Reload (File Watching + Polling)

**Duration:** 2 weeks
**Priority:** P1

**Deliverables:**
- `PolicyWatcher` with platform-native file watching.
- Debouncing with configurable delay.
- Atomic swap with validation-before-replace.
- `PolicyPoller` with configurable interval and jitter.
- Stale-while-revalidate behavior.
- Change and error event callbacks.
- Hot reload tests (Section 9.6).

**Dependencies:** Phase 2 complete.

### Phase 5: VaultLoader + GitLoader

**Duration:** 2 weeks
**Priority:** P2

**Deliverables:**
- `VaultLoader` with token, AppRole, and Kubernetes auth.
- `GitLoader` with SSH and HTTPS auth, shallow clone caching.
- Package reference parsing (deferred to future: actual package manager
  integration).
- Each loader behind an optional feature flag.
- Integration tests with mock Vault server and local git repos.

**Dependencies:** Phase 2 complete.

### Phase 6: Push-Based Reload + Observability

**Duration:** 2 weeks
**Priority:** P2

**Deliverables:**
- Webhook endpoint (`WebhookReloader`).
- HMAC-SHA256 signature verification with constant-time comparison.
- Replay protection (timestamp validation).
- Event payload schema and documentation.
- Metrics interface with Prometheus and OpenTelemetry implementations
  (behind feature flags).
- Declarative loader chain configuration parser (`load_config()`).

**Dependencies:** Phase 4 complete.

### Phase 7: Shared Cache Layer

**Duration:** 1 week
**Priority:** P3

**Deliverables:**
- `SharedCache` trait/interface.
- Redis implementation.
- L3 cache integration into the cache hierarchy.
- Request coalescing in CompositeLoader.
- Cache miss/hit metrics integration.

**Dependencies:** Phase 2 complete.

### Phase 8: Registry Loader

**Duration:** 3 weeks
**Priority:** P3

**Deliverables:**
- HushSpec Registry API specification (separate document).
- `RegistryLoader` implementation.
- Version constraint parsing (semver ranges).
- Registry authentication and authorization.

**Dependencies:** Phase 2 complete.

---

## Appendix A. Migration Guide

### Migrating from Current resolve_with_loader

The existing `resolve_with_loader` functions accept a closure/callback. This
API is preserved but deprecated. Migration path:

**Before (Rust):**

```rust
let resolved = resolve_with_loader(&spec, Some("child.yaml"), &|reference, from| {
    // custom loading logic
    Ok(LoadedSpec { source, spec })
})?;
```

**After (Rust):**

```rust
// Option 1: Use built-in loader chain
let resolved = resolve(&spec, Some("child.yaml"))?;

// Option 2: Implement PolicyLoader trait
struct MyLoader;
impl PolicyLoader for MyLoader {
    fn load(&self, reference: &PolicyRef, from: Option<&str>) -> Result<LoadedSpec, ResolveError> {
        // custom loading logic
    }
    fn supports(&self, reference: &PolicyRef) -> bool { true }
}

let loader = CompositeLoader::new()
    .add(BuiltinLoader::new())
    .add(MyLoader);
let resolved = resolve_with(&loader, &spec, Some("child.yaml"))?;

// Option 3: Wrap old callback in a ClosureLoader adapter
let resolved = resolve_with(
    &ClosureLoader::new(|reference, from| { /* old logic */ }),
    &spec,
    Some("child.yaml"),
)?;
```

**Before (TypeScript):**

```typescript
const result = resolve(spec, {
  source: 'child.yaml',
  load: (reference, from) => { /* old logic */ },
});
```

**After (TypeScript):**

```typescript
// Option 1: Use built-in loader chain
const result = resolve(spec, { source: 'child.yaml' });

// Option 2: Use CallbackLoader adapter
const result = resolve(spec, {
  source: 'child.yaml',
  loader: new CallbackLoader((reference, from) => { /* old logic */ }),
});
```

**Before (Python):**

```python
ok, result = resolve(spec, source="child.yaml", loader=my_loader_fn)
```

**After (Python):**

```python
# Option 1: Use built-in loader chain
ok, result = resolve(spec, source="child.yaml")

# Option 2: Use CallbackLoader adapter
ok, result = resolve(spec, source="child.yaml", loader=CallbackLoader(my_loader_fn))
```

**Before (Go):**

```go
resolved, err := hushspec.Resolve(spec, source, myLoaderFunc)
```

**After (Go):**

```go
// Option 1: Use built-in loader chain
resolved, err := hushspec.Resolve(ctx, spec, source, hushspec.DefaultLoaderChain())

// Option 2: Use CallbackLoader adapter
resolved, err := hushspec.Resolve(ctx, spec, source, hushspec.NewCallbackLoader(myLoaderFunc))
```

### Backward Compatibility

- `resolve_with_loader` (Rust), `resolve(spec, { load })` (TS),
  `resolve(spec, loader=fn)` (Python), and `Resolve(spec, source, fn)` (Go)
  remain functional but are marked deprecated.
- A `ClosureLoader` / `CallbackLoader` adapter wraps the old-style function
  in the new `PolicyLoader` interface.
- No changes to merge semantics. The merge functions are untouched.
- No changes to the HushSpec document schema. The `extends` field remains a
  plain string.
- **Note for Go:** The addition of `context.Context` as the first parameter
  to `Resolve()` is a breaking change. The old signature
  `Resolve(spec, source, loader)` is preserved as `ResolveLegacy()` and
  marked deprecated.

---

## Appendix B. Configuration Reference

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `HUSHSPEC_MAX_DEPTH` | Maximum extends chain depth | 10 |
| `HUSHSPEC_CACHE_DIR` | L2 filesystem cache directory | `$XDG_CACHE_HOME/hushspec` or `$TMPDIR/hushspec-cache` |
| `HUSHSPEC_CACHE_TTL` | Default L2 cache TTL in seconds | 3600 |
| `HUSHSPEC_HTTP_TIMEOUT` | Default HTTP timeout in milliseconds | 10000 |
| `HUSHSPEC_HTTP_MAX_SIZE` | Maximum HTTP response size in bytes | 1048576 |
| `HUSHSPEC_ALLOW_PRIVATE_IPS` | Allow fetching from private IPs | false |
| `HUSHSPEC_LOG_LEVEL` | Logging level for resolution operations | `warn` |
| `HUSHSPEC_VERSION_MISMATCH` | Version mismatch behavior: `warn`, `error`, `ignore` | `warn` |
| `HUSHSPEC_LOADER_CONFIG` | Path to declarative loader chain YAML config | (none) |

---

## Appendix C. Glossary

| Term | Definition |
|---|---|
| **Bare reference** | An `extends` value with no prefix and no path separators. Resolved by trying builtin first, then file. |
| **Canonical source identifier** | A unique, normalized string identifying the origin of a loaded policy (e.g., an absolute file path, a URL, `builtin:default`). Used for cycle detection. |
| **Content hash** | SHA-256 hash of the raw YAML content of a policy document. Used for cache invalidation and integrity verification. |
| **Depth limit** | Maximum number of `extends` levels in an inheritance chain (default 10). |
| **Loader** | A component that resolves a `PolicyRef` to a `LoadedSpec` (raw content + canonical source). |
| **Loader chain** | An ordered list of loaders; the first loader that supports a given reference type handles it. |
| **Policy lifecycle** | The sequence: author -> publish -> resolve -> cache -> evaluate -> reload. |
| **Request coalescing** | Combining multiple concurrent requests for the same resource into a single underlying fetch. |
| **Stale-while-revalidate** | Pattern where a stale cached entry is served immediately while a fresh copy is fetched in the background. Weakens fail-closed guarantee. |
