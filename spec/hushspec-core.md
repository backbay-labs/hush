# HushSpec Core Specification

**Version:** 1.0.0
**Status:** Stable
**Date:** 2026-09-15
**Supersedes:** 0.1.0 (2026-03-15). See Appendix D for the list of changes.

---

## 1. Introduction

HushSpec is a portable, engine-neutral specification for declaring the security controls an AI agent operates under at the tool boundary. A HushSpec document declares security intent -- what actions are allowed, blocked, or require confirmation -- without prescribing how those rules are enforced.

The specification defines a YAML-based document format that any conformant engine can parse, validate, merge, and evaluate. HushSpec documents are designed to be authored by security and compliance teams, shared across organizations, and enforced by heterogeneous runtimes including CLI tools, SDKs, proxies, and embedded WebAssembly modules.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Test vector.** A fixture file under `fixtures/` in the reference repository that exercises a requirement. Where a requirement names a test vector, a conformant engine MUST produce the decisions that vector expects.

### 1.2 Design Principles

1. **Fail-closed.** Ambiguity or error in a HushSpec document, in evaluation inputs, or in the engine's own processing MUST result in denial, not allowance.
2. **Engine-neutral.** The specification declares intent. Enforcement mechanics are engine-specific.
3. **Portable.** A valid HushSpec document MUST produce identical decisions across conformant engines. Every matching algorithm in this document is specified to the level a third party can implement from the prose alone.
4. **Composable.** Documents support single inheritance via `extends` with well-defined merge semantics.

---

## 2. Document Structure

A HushSpec document is a YAML file (see Section 2.4 for the YAML profile) with the following top-level fields:

| Field            | Type   | Required | Default        | Description                                      |
|------------------|--------|----------|----------------|--------------------------------------------------|
| `hushspec`       | string | REQUIRED | --             | Spec version. See Section 2.2.                   |
| `name`           | string | OPTIONAL | --             | Human-readable policy name. MUST NOT be empty when present (`fixtures/core/invalid/empty-name.yaml`). |
| `description`    | string | OPTIONAL | --             | Policy description.                              |
| `extends`        | string | OPTIONAL | --             | Reference to a base policy.                      |
| `merge_strategy` | string | OPTIONAL | `"deep_merge"` | One of `replace`, `merge`, `deep_merge`.         |
| `rules`          | object | OPTIONAL | --             | Security rule declarations (Section 3).          |
| `extensions`     | object | OPTIONAL | --             | Extension modules (Section 9).                   |
| `metadata`       | object | OPTIONAL | --             | Governance metadata (Section 2.5).               |

### 2.1 Strictness

Conformant parsers MUST reject documents containing unknown top-level fields. This requirement extends recursively: unknown fields within `rules`, within individual rule objects, within `when` conditions, within `metadata`, and within `extensions` MUST also cause rejection. This ensures forward compatibility is explicit and prevents silent misconfiguration.

Test vectors: `fixtures/core/invalid/unknown-top-level.yaml`, `fixtures/core/invalid/unknown-rule.yaml`.

### 2.2 Version Field

The `hushspec` field is the only REQUIRED field. Its value MUST be a string of the form `MAJOR.MINOR.PATCH` (Appendix A; Grammars specification, Section 8). Parsers MUST reject documents where this field is absent, is not a string (a YAML float such as `0.1` MUST be rejected), or does not match that form.

**Version acceptance.** An engine that declares support for minor version `X.Y` MUST accept every document whose `hushspec` value is `X.Y.Z` for any non-negative integer `Z`. Patch versions contain only clarifications and errata (see Section 10.1) and never change document validity or evaluation semantics, so rejecting them is a conformance failure. Engines MUST reject documents whose `X.Y` they do not support.

Test vectors: `fixtures/core/invalid/missing-version.yaml`, `fixtures/core/invalid/float-version.yaml`, `fixtures/core/valid/version-patch-accept.yaml`, `fixtures/core/valid/version-1-0.yaml`, `fixtures/core/invalid/version-unsupported-minor.yaml`.

### 2.3 Extends Field

The `extends` field is a single string reference to a base policy document. Resolution of this reference (filesystem path, URL, registry identifier, built-in name) is engine-specific and outside the scope of this specification. Engines MUST document their resolution strategy. Circular inheritance MUST be detected and rejected.

**Digest pinning.** An `extends` reference MAY carry a fragment `#sha256:<64 lowercase hex>` naming the content hash of the referenced document **canonicalized on its own**, with its `extends` and `merge_strategy` fields removed before projection (Canonical Form specification, Section 3; the same value a receipt records for a chain link and `h2h hash --own` prints). A resolver MUST strip the fragment before loading, compute the loaded document's own content hash, and reject the resolution with reason `digest_mismatch` when it differs. A pin is checked whether or not the engine requires signatures; a matching pin satisfies the signature requirement for that document (Signing specification, Section 6.5). A malformed fragment MUST be rejected. Test vectors: `fixtures/core/resolve/`.

A **resolved document** is the output of merging the entire `extends` chain (Section 4). A resolved document MUST NOT contain the `extends` field and MUST NOT contain the `merge_strategy` field. Engines MUST evaluate only resolved documents: evaluating a document whose `extends` reference has not been resolved silently drops the base policy and is a conformance failure. An engine that cannot resolve a reference MUST refuse to evaluate the document rather than evaluate the child alone.

The identity of a resolved document is its **content hash**, defined by the Canonical Form specification (`hushspec-canonical.md`): a deterministic projection of the resolved document with schema defaults made explicit, serialized per RFC 8785 and hashed with SHA-256. Decision receipts (`hushspec-receipt.md`) and policy signatures (`hushspec-signing.md`) both identify a policy by that hash, never by file bytes or by an engine-specific serialization.

### 2.4 YAML Profile

HushSpec documents use a restricted YAML profile so that every conformant parser accepts and rejects the same byte sequences.

1. Documents MUST be parsed with the **YAML 1.2 Core schema**. In particular, only `true` and `false` are booleans; `yes`, `no`, `on`, `off`, `y`, and `n` are strings and MUST be rejected wherever a boolean is required.
2. A file MUST contain exactly one YAML document. Multi-document streams (`---` separators with content on both sides) MUST be rejected.
3. Duplicate mapping keys at any nesting level MUST be rejected.
4. Anchors (`&`), aliases (`*`), and merge keys (`<<`) MUST be rejected.
5. The `hushspec` value MUST be a string. Authors SHOULD quote it (`hushspec: "0.2.0"`).
6. Engines MUST enforce resource limits on the input: a maximum document size, a maximum nesting depth, and a maximum node count. The RECOMMENDED defaults are 1 MiB, 32 levels, and 100,000 nodes. Exceeding any limit MUST be reported as a parse error.
7. Tabs are not valid YAML indentation and MUST be rejected. Byte order marks MUST be accepted and ignored.

Test vectors: `fixtures/core/invalid/yaml-duplicate-key.yaml`, `fixtures/core/invalid/float-version.yaml`, `fixtures/core/invalid/yaml-alias.yaml`, `fixtures/core/invalid/yaml-multi-doc.yaml`, `fixtures/core/invalid/yaml-bool-yes.yaml`.

### 2.5 Metadata

The OPTIONAL `metadata` object carries governance information about the policy. It MUST NOT influence evaluation decisions. Its fields are:

| Field             | Type    | Required | Description                                                                 |
|-------------------|---------|----------|-----------------------------------------------------------------------------|
| `author`          | string  | OPTIONAL | Identity of the policy author (email, team name).                           |
| `approved_by`     | string  | OPTIONAL | Identity of the policy approver.                                            |
| `approval_date`   | string  | OPTIONAL | Date the policy was approved. MUST be an ISO 8601 calendar date.            |
| `classification`  | string  | OPTIONAL | One of `public`, `internal`, `confidential`, `restricted`.                  |
| `change_ticket`   | string  | OPTIONAL | Change-management reference.                                                |
| `lifecycle_state` | string  | OPTIONAL | One of `draft`, `review`, `approved`, `deployed`, `deprecated`, `archived`. |
| `policy_version`  | integer | OPTIONAL | Monotonically increasing version counter. MUST be >= 1.                     |
| `effective_date`  | string  | OPTIONAL | Date the policy becomes effective. MUST be an ISO 8601 calendar date.       |
| `expiry_date`     | string  | OPTIONAL | Date the policy expires. MUST be an ISO 8601 calendar date.                 |
| `owner`           | string  | OPTIONAL | Identity accountable for the policy over its lifetime, as distinct from the `author` of this revision. |
| `reviewers`       | array of string | OPTIONAL | Identities who reviewed the policy.                                 |
| `next_review_date`| string  | OPTIONAL | Date the policy is next due for review. MUST be an ISO 8601 calendar date.  |
| `changelog`       | array   | OPTIONAL | Revision history, newest first. See Section 2.5.2.                          |
| `supersedes`      | string  | OPTIONAL | The `policy_version` this document replaces. MUST NOT equal this document's own `policy_version`. |
| `controls`        | array   | OPTIONAL | Compliance control mappings. See Section 2.5.1.                             |

**Dates.** `approval_date`, `effective_date`, `expiry_date`, `next_review_date` and each `changelog` entry's `date` MUST be an ISO 8601 calendar date in `YYYY-MM-DD` form, naming a day that exists. A document carrying any other shape MUST be rejected. Tools compare these dates as strings -- lexicographic order is calendar order only for `YYYY-MM-DD` -- so an unchecked value would make an expired policy compare as current rather than fail.

Unknown keys under `metadata` MUST be rejected (Section 2.1). Under every merge strategy the child's `metadata` object, when present, replaces the base's `metadata` object entirely; when the child omits `metadata`, the base's is preserved.

**Governance checks.** Governance metadata never influences evaluation, so every check below is a tooling concern, reported by `h2h audit` with a stable code, a severity and the path it concerns. All but the last are advisory warnings, which `h2h audit --strict` promotes to a failure; `GOV_SELF_SUPERSEDES` describes a document that contradicts itself and is a validation error, so a conformant validator MUST reject it.

| Code                        | Severity | Condition                                                                 |
|-----------------------------|----------|---------------------------------------------------------------------------|
| `GOV_LIFECYCLE`             | warning  | `lifecycle_state` is `deprecated` or `archived`.                          |
| `GOV_EXPIRED`               | warning  | `expiry_date` is in the past.                                             |
| `GOV_MISSING_APPROVAL_DATE` | warning  | `approved_by` is set without `approval_date`.                             |
| `GOV_RESTRICTED_NO_APPROVER`| warning  | `classification` is `restricted` with no `approved_by`.                   |
| `GOV_SOD_VIOLATION`         | warning  | `author` and `approved_by` are the same identity, compared trimmed and case-insensitively. |
| `GOV_UNAPPROVED_STATE`      | warning  | `lifecycle_state` is `approved` or `deployed` with no `approved_by`.      |
| `GOV_REVIEW_OVERDUE`        | warning  | `next_review_date` is in the past.                                        |
| `GOV_CHANGELOG_ORDER`       | warning  | `changelog` entries are not in descending version, then date, order.      |
| `GOV_SELF_SUPERSEDES`       | error    | `supersedes` equals this document's own `policy_version`.                 |

#### 2.5.1 Control Mappings

The OPTIONAL `metadata.controls` array states which compliance controls the policy implements, and which parts of the document implement each one. Each entry is an object:

| Field        | Type             | Required | Description                                                                 |
|--------------|------------------|----------|-----------------------------------------------------------------------------|
| `framework`  | string           | REQUIRED | Framework identifier. MUST match `^[a-z0-9][a-z0-9.-]*$`.                   |
| `control_id` | string           | REQUIRED | Control identifier within the framework. MUST NOT be empty.                 |
| `rule_paths` | array of string  | REQUIRED | Paths to the parts of the document that implement the control. MUST contain at least one entry, and every entry MUST be non-empty. |
| `notes`      | string           | OPTIONAL | Free-text rationale.                                                        |

Unknown keys within a mapping MUST be rejected (Section 2.1).

**Control mappings MUST NOT influence evaluation.** An engine MUST produce the same decision for a document with mappings as for the same document with `metadata.controls` removed. They are a claim about the policy, checked by tooling, never an input to a rule.

**Path grammar.** Each `rule_paths` entry is a dot path into the *resolved* document (Section 2.3), optionally ending in a bracketed selector:

```abnf
rule-path = root *( "." segment ) [ selector ]
root      = "rules" / "extensions"
segment   = 1*( ALPHA / DIGIT / "_" )
selector  = "[" 1*( %x20-5A / %x5C-7C / %x7E ) "]"   ; any character except "[" and "]"
```

A selector names one entry of the list or mapping the preceding path resolves to, matching a list entry by its `name` or `id` field and a mapping by its key. Examples: `rules` (the whole rules object), `rules.egress` (one rule block), `rules.egress.allow` (one field), `rules.secret_patterns.patterns[ssn]` (one named secret pattern), `extensions.posture` (an extension subtree).

Because paths are resolved against the resolved document, a mapping in a child policy may name a rule block the child inherits from its base.

**Frameworks.** Framework identifiers are listed, together with a `control_id_pattern` for each, in `spec/registries/frameworks.yaml`. Registration is advisory: a document naming an unregistered framework, or a control id that does not match its framework's pattern, is still a valid HushSpec document and engines MUST NOT reject it. Linters SHOULD flag both (`h2h lint` reports them as L013), SHOULD flag a rule path that resolves to nothing (L012), and SHOULD flag a rule block left unmapped once a policy declares any mapping (L011).

#### 2.5.2 Changelog

The OPTIONAL `metadata.changelog` array records the policy's revision history, newest first. Each entry is an object:

| Field     | Type   | Required | Description                                                      |
|-----------|--------|----------|------------------------------------------------------------------|
| `version` | string | REQUIRED | The `policy_version` this entry describes, as a string. MUST NOT be empty. |
| `date`    | string | REQUIRED | ISO 8601 calendar date the revision was made.                    |
| `summary` | string | REQUIRED | What changed in this revision. MUST NOT be empty.                |
| `author`  | string | OPTIONAL | Identity that made the revision.                                 |

Unknown keys within an entry MUST be rejected (Section 2.1). Entries SHOULD run newest first: descending by `version` -- compared numerically when both versions are plain integers, lexicographically otherwise -- and, for equal versions, descending by `date`. A list in any other order is a valid document; linters report it (`GOV_CHANGELOG_ORDER`).

**Changelog entries MUST NOT influence evaluation.** Like control mappings, they are a claim about the policy, never an input to a rule.

Test vectors: `fixtures/core/valid/metadata.yaml`, `fixtures/core/valid/metadata-governance-full.yaml`, `fixtures/core/valid/metadata-controls.yaml`, `fixtures/core/invalid/metadata-bad-date.yaml`, `fixtures/core/invalid/metadata-changelog-unknown-key.yaml`, `fixtures/core/invalid/metadata-controls-unknown-key.yaml`, `fixtures/core/invalid/metadata-controls-empty-paths.yaml`, `fixtures/core/invalid/metadata-controls-bad-framework-id.yaml`.

---

### 2.6 Resolution

Resolution turns a document that declares `extends` into the resolved document Section 2.3 requires. This section defines the reference forms every engine MUST accept, the limits every resolver MUST enforce, and the loader an engine MAY provide for remote documents.

#### 2.6.1 Reference Forms

| Form | Example | Meaning |
|------|---------|---------|
| Built-in ruleset | `builtin:strict` | A ruleset embedded in the engine. The reference implementation embeds the documents under `rulesets/` and, under `builtin:library/`, the vertical policy library (`builtin:library/healthcare/hipaa-base`). |
| Bare built-in name | `strict` | Equivalent to `builtin:strict` when the name is a known built-in; otherwise a relative path. |
| Relative path | `../base.yaml` | Resolved against the directory of the referencing document. A document supplied in memory has no directory; a relative reference from it resolves against the working directory or is refused, as the engine documents. |
| Absolute path | `/etc/hush/base.yaml` | Loaded from the filesystem as given. |
| HTTPS URL | `https://policies.example.com/base.yaml` | Fetched with the loader of Section 2.6.4. An engine without an HTTPS loader MUST refuse the reference rather than treat it as a path. |

Any form MAY carry a digest pin fragment (Section 2.3). The `builtin:` prefix is stripped exactly once: `builtin:builtin:strict` names nothing. `http://` references MUST be refused.

The source recorded for a document in receipts and resolution results is the reference as the loader saw it (`builtin:strict`, the path, the URL); a document supplied in memory records the source `memory`.

#### 2.6.2 Chain Walk and Limits

A resolver walks the chain from the leaf to the root, loading each reference, then merges from the root back down (Section 4.2). It MUST:

1. Detect a cycle (a reference naming a document already on the chain) and reject the resolution, reporting the cycle.
2. Reject a chain of more than 32 `extends` hops: a leaf with 32 base documents is the longest chain that resolves.
3. Check every digest pin and reject on mismatch, whether or not signatures are required.
4. Verify signatures when required (Signing specification, Section 6.5) and refuse to produce a resolved document for a chain that fails verification.
5. Fail closed on any loader error: an unreadable file, a network failure, an unparseable document, or an unknown built-in name MUST refuse the resolution. A resolver MUST NOT fall back to evaluating the leaf alone.

#### 2.6.3 Loader Composition

The reference implementation's default loader tries, in order: the built-in loader for `builtin:` references and bare names that match a built-in; the HTTPS loader for `https://` references when one is compiled in; and the filesystem loader for everything else. Engines MAY offer additional loaders (a registry, an object store) and MUST document their order and the reference forms each accepts.

#### 2.6.4 HTTPS Loader

A URL in `extends` is a request an attacker partly controls: the URL comes out of a document. An engine that loads documents over the network MUST apply all of the following rules, and every SDK of the reference implementation enforces exactly these.

1. **TLS only.** The scheme MUST be `https`. An `http://` reference MUST be refused outright, never upgraded. Certificate verification MUST be on by default; an option to disable it exists for test harnesses only and MUST be documented as unsafe.
2. **Host allowlist, checked before DNS.** A loader MAY be configured with the set of hosts it may fetch from. When one is configured, a reference whose host is outside it MUST be refused before the host is resolved. Matching MUST be exact and case-insensitive, never a suffix rule: `evil-example.com` ends in nothing a suffix test would be safe about.
3. **Address filtering after resolution.** The host MUST be resolved before a connection is opened, and *every* address it resolves to MUST be checked -- one blocked address among several refuses the reference, because a name with one public and one private address is a name that reaches the private one. An address the loader cannot parse MUST be treated as blocked. These networks MUST be refused:

| Network | What it is |
|---------|------------|
| `0.0.0.0/8` | "this network", including `0.0.0.0` itself |
| `10.0.0.0/8` | private (RFC 1918) |
| `100.64.0.0/10` | carrier-grade NAT (RFC 6598) |
| `127.0.0.0/8` | loopback |
| `169.254.0.0/16` | link-local, including the cloud metadata endpoint |
| `172.16.0.0/12` | private (RFC 1918) |
| `192.0.0.0/24` | IETF protocol assignments |
| `192.168.0.0/16` | private (RFC 1918) |
| `198.18.0.0/15` | benchmarking |
| `224.0.0.0/4` | multicast |
| `240.0.0.0/4` | reserved, including the `255.255.255.255` broadcast address |
| `::/128` | unspecified |
| `::1/128` | loopback |
| `fc00::/7` | unique local, including the IPv6 metadata endpoint |
| `fe80::/10` | link-local |
| `ff00::/8` | multicast |

4. **IPv4-in-IPv6 unwrapping.** An IPv6 address carrying an IPv4 address in its low 32 bits MUST be unwrapped and judged on the address inside, in both the IPv4-mapped form (`::ffff:127.0.0.1`) and the deprecated IPv4-compatible form (`::7f00:1`, which is `127.0.0.1`). `::` and `::1` are covered by the table and are not unwrapped.
5. **Address pinning.** The connection MUST go to an address that passed rule 3, not to a name resolved a second time at connect time. The host name MUST still be used for SNI, for certificate validation and in the `Host` header, so a pinned connection is still authenticated against the name the document wrote. This is what closes DNS rebinding between the check and the connection.
6. **No redirects.** A 3xx response MUST be treated as a failure; a loader MUST NOT follow it, not even to the same host. A redirect moves the request to a location the scheme check, the allowlist and the address check never saw.
7. **Bounded body.** The response body MUST be capped at the document size limit of Section 2.4; a longer body is a failure. A body of exactly the limit is accepted.
8. **Bounded time.** Establishing the connection and reading the response MUST have separate budgets, so a server that accepts a connection and then stalls does not inherit the connect timeout's patience. The reference default is 10 seconds for each.
9. **Revalidation, not staleness.** A loader MAY cache a document by URL against the `ETag` the server returned, and MUST then revalidate it with `If-None-Match`. The server is asked every time: a cached body MAY be used only on a `304 Not Modified`, a `304` answered with no cached body to revalidate MUST be a failure rather than an empty document, and a cached document MUST NOT be served after a failed revalidation.
10. **The signature sidecar follows the same rules.** A detached envelope at `<url>.sig` (Signing specification, Section 7.1) MUST be fetched under every rule above -- the same allowlist, the same address check and pinning, no redirects, the same caps. A `404` or `410` means the policy is unsigned and is not itself a failure; every other failure is one. A `.sig` URL MUST NOT be able to reach anything the policy URL could not.

Integrity is not the loader's job. A URL is a location, never an identity: digest pins and detached signatures apply to remote documents as to local ones, and they are what makes a remote base trustworthy. The Security Considerations (`hushspec-security.md`, Section 4) discuss the residual risk rules 3 and 5 leave.

Test vectors: `fixtures/core/resolve/`, `fixtures/core/merge/`.

---

## 3. Rules

The `rules` object contains up to twelve named rule blocks. Each rule block controls a specific security domain.

If `rules` is absent or empty, no rules are active. Engines MUST NOT inject implicit rules beyond what the document (and its resolved `extends` chain) declares.

### 3.0 Fields Common to Every Rule Block

| Field     | Type    | Required | Default          | Description                                                        |
|-----------|---------|----------|------------------|--------------------------------------------------------------------|
| `enabled` | boolean | OPTIONAL | varies per block | When `false`, the rule block is inert and MUST NOT influence decisions. |
| `when`    | object  | OPTIONAL | --               | Condition gating whether the block is active. See Section 3.13.    |

### 3.1 `rules.forbidden_paths`

Block access to sensitive filesystem paths.

| Field        | Type            | Required | Default | Description                                     |
|--------------|-----------------|----------|---------|-------------------------------------------------|
| `enabled`    | boolean         | OPTIONAL | `true`  | Whether this rule is active.                    |
| `patterns`   | array of string | OPTIONAL | `[]`    | Path glob patterns matching forbidden paths.    |
| `exceptions` | array of string | OPTIONAL | `[]`    | Path glob patterns that override pattern matches. |

**Semantics:** The target path is normalized and matched as specified in Section 3.14.1. A path is forbidden if and only if:
1. It matches at least one entry in `patterns`, AND
2. It does NOT match any entry in `exceptions`.

A forbidden path produces **deny** with `matched_rule` `rules.forbidden_paths.patterns`. A path that matches an exception produces **allow** from this block with `matched_rule` `rules.forbidden_paths.exceptions`; that allow MUST NOT prevent other applicable blocks from being evaluated (Section 6.1). When `patterns` is empty, no paths are forbidden regardless of the `enabled` state.

Test vectors: `fixtures/core/evaluation/forbidden-paths.test.yaml`, `fixtures/core/evaluation/path-normalization.test.yaml`, `fixtures/core/evaluation/path-normalization-lexical.test.yaml`, `fixtures/core/evaluation/no-early-return.test.yaml`.

### 3.2 `rules.path_allowlist`

Allowlist-based path access control. When enabled, only paths matching the allowlist are permitted for the specified operation type.

| Field   | Type            | Required | Default | Description                                          |
|---------|-----------------|----------|---------|------------------------------------------------------|
| `enabled` | boolean       | OPTIONAL | `false` | Whether this rule is active.                         |
| `read`  | array of string | OPTIONAL | `[]`    | Path glob patterns allowed for read access.          |
| `write` | array of string | OPTIONAL | `[]`    | Path glob patterns allowed for write access.         |
| `patch` | array of string | OPTIONAL | `[]`    | Path glob patterns allowed for patch operations.     |

**Semantics:** When enabled, a file operation is allowed by this block only if the normalized target path (Section 3.14.1) matches at least one pattern in the corresponding array (`read`, `write`, or `patch`). If `patch` is empty, patch operations fall back to the `write` array. If the relevant array is empty (and no fallback applies), all operations of that type are denied. A match produces **allow** with `matched_rule` `rules.path_allowlist`; a non-match produces **deny** with the same `matched_rule`. An allow from this block MUST NOT prevent other applicable blocks (in particular `secret_patterns` and `patch_integrity`) from being evaluated (Section 6.1).

Test vector: `fixtures/core/evaluation/no-early-return.test.yaml`.

### 3.3 `rules.egress`

Network egress control by host.

| Field     | Type            | Required | Default   | Description                                       |
|-----------|-----------------|----------|-----------|---------------------------------------------------|
| `enabled` | boolean         | OPTIONAL | `true`    | Whether this rule is active.                      |
| `allow`   | array of string | OPTIONAL | `[]`      | Host patterns to allow.                           |
| `block`   | array of string | OPTIONAL | `[]`      | Host patterns to block.                           |
| `default` | string          | OPTIONAL | `"block"` | Default decision: `"allow"` or `"block"`.         |

**Semantics:** The target is normalized to a host as specified in Section 3.14.2, then:
1. If the host matches any entry in `block`, the decision is **deny** (`rules.egress.block`). Block takes precedence over allow.
2. If the host matches any entry in `allow`, the decision is **allow** (`rules.egress.allow`).
3. Otherwise, the `default` value applies (`rules.egress.default`).

Test vectors: `fixtures/core/evaluation/egress.test.yaml`, `fixtures/core/evaluation/egress-default-fail-closed.test.yaml`, `fixtures/core/evaluation/egress-normalization.test.yaml`, `fixtures/core/evaluation/egress-host-normalization.test.yaml`, `fixtures/core/evaluation/host-normalization-backslash.test.yaml`.

### 3.4 `rules.secret_patterns`

Detect secrets in content before it is written or transmitted.

| Field        | Type                    | Required | Default | Description                                  |
|--------------|-------------------------|----------|---------|----------------------------------------------|
| `enabled`    | boolean                 | OPTIONAL | `true`  | Whether this rule is active.                 |
| `patterns`   | array of SecretPattern  | OPTIONAL | `[]`    | Named regex patterns for secret detection.   |
| `skip_paths` | array of string         | OPTIONAL | `[]`    | Path glob patterns of paths to skip scanning. |

**SecretPattern object:**

| Field         | Type   | Required | Description                                          |
|---------------|--------|----------|------------------------------------------------------|
| `name`        | string | REQUIRED | Unique identifier for this pattern.                  |
| `pattern`     | string | REQUIRED | Regular expression (Section 3.14.3 profile).         |
| `severity`    | string | REQUIRED | One of `"critical"`, `"error"`, `"warn"`.            |
| `description` | string | OPTIONAL | Human-readable description of what this detects.     |

**Constraints:**
- The `name` field MUST be unique within the `patterns` array. Parsers MUST reject documents with duplicate names.
- The `pattern` field MUST conform to the HushSpec regex profile (Section 3.14.3). Non-conforming or invalid patterns MUST cause document rejection (fail-closed).
- The `severity` field MUST be one of the three enumerated values.

**Which actions are scanned.** The `content` of the action is scanned for `file_write` and `patch_apply` actions always, and for `egress` and `tool_call` actions whenever the action carries `content`. Other action types are not scanned by this block. `skip_paths` applies only to path-bearing actions (`file_write`, `patch_apply`): if the normalized target path matches any `skip_paths` entry, scanning is bypassed and this block produces **allow** with `matched_rule` `rules.secret_patterns.skip_paths`.

**Severity to decision.** Every pattern is tested against the content (unanchored search). The block's decision is determined by the highest severity among the patterns that matched:

| Highest matched severity | Decision | `matched_rule`                               |
|--------------------------|----------|----------------------------------------------|
| `critical`               | deny     | `rules.secret_patterns.patterns.<name>`      |
| `error`                  | deny     | `rules.secret_patterns.patterns.<name>`      |
| `warn`                   | warn     | `rules.secret_patterns.patterns.<name>`      |
| (no match)               | allow    | --                                           |

`<name>` is the first pattern in document order among those at the highest matched severity. Engines MUST NOT stop at the first match: a later `critical` pattern MUST outrank an earlier `warn` pattern.

Test vectors: `fixtures/core/evaluation/secret-patterns.test.yaml`, `fixtures/core/evaluation/severity-mapping.test.yaml`, `fixtures/core/evaluation/severity-precedence.test.yaml`, `fixtures/core/evaluation/content-scan-egress-tool.test.yaml`.

**Which actions are scanned.** `file_write` and `patch_apply` actions are always scanned, and `skip_paths` applies to their target path. `egress` and `tool_call` actions are scanned only when the action carries `content`; an egress or tool call without content is not a secret-scanning event. Other action types are never scanned by this block.

### 3.5 `rules.patch_integrity`

Validate the safety and reasonableness of patch/diff content.

| Field                  | Type            | Required | Default | Description                                       |
|------------------------|-----------------|----------|---------|---------------------------------------------------|
| `enabled`              | boolean         | OPTIONAL | `true`  | Whether this rule is active.                      |
| `max_additions`        | integer         | OPTIONAL | `1000`  | Maximum number of added lines permitted.          |
| `max_deletions`        | integer         | OPTIONAL | `500`   | Maximum number of deleted lines permitted.        |
| `forbidden_patterns`   | array of string | OPTIONAL | `[]`    | Regex patterns forbidden in patch content.        |
| `require_balance`      | boolean         | OPTIONAL | `false` | Whether additions/deletions must be balanced.     |
| `max_imbalance_ratio`  | number          | OPTIONAL | `10.0`  | Maximum ratio of additions to deletions (or vice versa). |

**Constraints:**
- `max_additions` and `max_deletions` MUST be non-negative integers.
- `max_imbalance_ratio` MUST be a positive number (> 0).
- Each `forbidden_patterns` entry MUST conform to the regex profile (Section 3.14.3).

**Counting.** Additions are lines of the patch content beginning with `+` but not `+++`; deletions are lines beginning with `-` but not `---`.

**Semantics:** A patch is denied if:
1. Any line in the patch matches a `forbidden_patterns` entry (`rules.patch_integrity.forbidden_patterns[<index>]`), OR
2. The number of added lines exceeds `max_additions` (`rules.patch_integrity.max_additions`), OR
3. The number of deleted lines exceeds `max_deletions` (`rules.patch_integrity.max_deletions`), OR
4. `require_balance` is `true` AND the ratio of the larger count to the smaller count exceeds `max_imbalance_ratio` (`rules.patch_integrity.max_imbalance_ratio`). When `require_balance` is `true` and exactly one of the two counts is zero while the other is nonzero, the patch MUST be denied regardless of `max_imbalance_ratio` (the ratio is treated as infinite). When both counts are zero the patch is balanced.

Checks are evaluated in the order listed; the first failing check determines `matched_rule`.

Test vectors: `fixtures/core/evaluation/patch-integrity.test.yaml`, `fixtures/core/evaluation/patch-integrity-defaults.test.yaml`, `fixtures/core/evaluation/patch-balance.test.yaml`, `fixtures/core/evaluation/patch-balance-zero.test.yaml`.

### 3.6 `rules.shell_commands`

Block dangerous shell commands before execution.

| Field                | Type            | Required | Default | Description                                   |
|----------------------|-----------------|----------|---------|-----------------------------------------------|
| `enabled`            | boolean         | OPTIONAL | `true`  | Whether this rule is active.                  |
| `forbidden_patterns` | array of string | OPTIONAL | `[]`    | Regex patterns forbidden in shell commands.   |

**Semantics:** A shell command is denied (`rules.shell_commands.forbidden_patterns[<index>]`) if any portion of the command string matches any `forbidden_patterns` entry (unanchored search per Section 3.14.3). Matching is performed against the complete command string as provided to the engine, including arguments and pipes. Empty `forbidden_patterns` means no commands are blocked by this rule.

Test vector: `fixtures/core/evaluation/shell-commands.test.yaml`.

### 3.7 `rules.tool_access`

Control tool and MCP (Model Context Protocol) invocations.

| Field                  | Type            | Required | Default   | Description                                      |
|------------------------|-----------------|----------|-----------|--------------------------------------------------|
| `enabled`              | boolean         | OPTIONAL | `true`    | Whether this rule is active.                     |
| `allow`                | array of string | OPTIONAL | `[]`      | Tool name allowlist.                             |
| `block`                | array of string | OPTIONAL | `[]`      | Tool name blocklist.                             |
| `require_confirmation` | array of string | OPTIONAL | `[]`      | Tools requiring user/operator approval.          |
| `default`              | string          | OPTIONAL | `"allow"` | Default decision: `"allow"` or `"block"`.        |
| `max_args_size`        | integer         | OPTIONAL | --        | Maximum argument payload size in bytes.          |

**Tool name matching.** Tool names MUST be compared as exact, case-sensitive strings after Unicode NFC normalization of both sides. Glob and regex metacharacters (`*`, `?`, `[`, `{`) have no special meaning in tool names: the entry `danger_*` matches only a tool literally named `danger_*`. Engines MUST NOT apply glob matching to tool names.

**Semantics:** For a given tool invocation:
1. If `max_args_size` is specified and `args_size` exceeds it, the decision is **deny** (`rules.tool_access.max_args_size`) regardless of other steps. `args_size` is supplied by the enforcement point; the evaluator never sees the arguments themselves. It MUST be the length in bytes of the UTF-8 encoding of the arguments serialized as JSON in the canonical form of the Canonical Form specification, Section 4 (RFC 8785). An enforcement point that receives arguments already serialized as compact JSON MAY measure the bytes it received; it MUST NOT measure a pretty-printed or re-encoded form, and MUST NOT report a count of UTF-16 code units or of escaped characters. The supplied value is what the decision uses and what a receipt records as `action.args_size`.
2. If the tool name equals any entry in `block`, the decision is **deny** (`rules.tool_access.block`). Block takes precedence.
3. If the tool name equals any entry in `require_confirmation`, the decision is **warn** (`rules.tool_access.require_confirmation`). Confirmation semantics are engine-specific; see Section 6.
4. If `allow` is non-empty and the tool name equals an entry, the decision is **allow** (`rules.tool_access.allow`).
5. If `allow` is non-empty and the tool name equals no entry, the decision is **deny** (`rules.tool_access.allow`, reason "tool is not in the allowlist"). This is allowlist mode; the `default` field MUST NOT be consulted when `allow` is non-empty.
6. Otherwise (`allow` is empty), the `default` value applies (`rules.tool_access.default`).

Test vectors: `fixtures/core/evaluation/tool-access.test.yaml`, `fixtures/core/evaluation/tool-exact-match.test.yaml`, `fixtures/core/evaluation/tool-glob-literal.test.yaml`, `fixtures/core/evaluation/tool-allowlist-deny.test.yaml`.

### 3.8 `rules.computer_use`

Control computer use agent (CUA) actions in remote desktop and browser automation contexts.

| Field             | Type            | Required | Default       | Description                                     |
|-------------------|-----------------|----------|---------------|-------------------------------------------------|
| `enabled`         | boolean         | OPTIONAL | `false`       | Whether this rule is active.                    |
| `mode`            | string          | OPTIONAL | `"guardrail"` | One of `"observe"`, `"guardrail"`, `"fail_closed"`. |
| `allowed_actions` | array of string | OPTIONAL | `[]`          | Action identifiers permitted.                   |

**Mode semantics:**
- `"observe"`: Log all actions but do not block. Unlisted actions produce **allow** (`rules.computer_use.mode`) with audit.
- `"guardrail"`: Actions in `allowed_actions` produce **allow** (`rules.computer_use.allowed_actions`); all other actions produce **deny** (`rules.computer_use.mode`).
- `"fail_closed"`: Identical reference semantics to `"guardrail"`: deny unless explicitly listed.

Version 0.1.0 described `guardrail` as permitting engine heuristics on borderline cases. That text is withdrawn: there is no defensible, portable distinction between the two blocking modes, so both MUST deny unlisted actions. `fail_closed` is retained so existing documents remain valid and to record the author's intent; engines MUST NOT treat `guardrail` more leniently than `fail_closed`.

Action identifiers are engine-defined strings (e.g., `"remote.session.connect"`, `"input.inject"`, `"clipboard.read"`) compared as exact strings. This specification does not mandate a fixed set of action identifiers.

Test vectors: `fixtures/core/evaluation/computer-use.test.yaml`, `fixtures/core/evaluation/computer-use-guardrail-deny.test.yaml`.

### 3.9 `rules.remote_desktop_channels`

Control side-channel capabilities in remote desktop sessions.

| Field           | Type    | Required | Default | Description                              |
|-----------------|---------|----------|---------|------------------------------------------|
| `enabled`       | boolean | OPTIONAL | `false` | Whether this rule is active.             |
| `clipboard`     | boolean | OPTIONAL | `false` | Allow clipboard sharing.                 |
| `file_transfer` | boolean | OPTIONAL | `false` | Allow file transfer.                     |
| `audio`         | boolean | OPTIONAL | `true`  | Allow audio redirection.                 |
| `drive_mapping` | boolean | OPTIONAL | `false` | Allow drive/filesystem mapping.          |

**Semantics:** When enabled, each boolean field controls whether the corresponding side channel is permitted. The channel is identified by the `computer_use` action target `remote.clipboard`, `remote.file_transfer`, `remote.audio`, or `remote.drive_mapping`. A value of `false` produces **deny** (`rules.remote_desktop_channels.<field>`); `true` produces **allow** with the same `matched_rule`. Targets that name no channel are not evaluated by this block. Engines that do not support a particular channel SHOULD ignore the corresponding field and document this behavior.

### 3.10 `rules.input_injection`

Control input injection capabilities in computer use agent environments.

| Field                        | Type            | Required | Default | Description                                          |
|------------------------------|-----------------|----------|---------|------------------------------------------------------|
| `enabled`                    | boolean         | OPTIONAL | `false` | Whether this rule is active.                         |
| `allowed_types`              | array of string | OPTIONAL | `[]`    | Input type identifiers permitted.                    |
| `require_postcondition_probe`| boolean         | OPTIONAL | `false` | Whether postcondition verification is required.      |

**Semantics:** When enabled, only input injection types listed in `allowed_types` are permitted (`rules.input_injection.allowed_types`). If `allowed_types` is empty, all input injection is denied (fail-closed). Standard type identifiers include `"keyboard"`, `"mouse"`, and `"touch"`, but engines MAY define additional types.

If `require_postcondition_probe` is `true`, the engine MUST verify that the injected input produced the expected effect before proceeding. The mechanism for postcondition verification is engine-specific.

Test vector: `fixtures/core/evaluation/input-injection.test.yaml`.

### 3.11 `rules.browser_automation`

Fine-grained controls for browser-automation tool calls: a host allowlist, a verb allowlist, and credential detection in typed input.

| Field                       | Type            | Required | Default | Description                                                                  |
|-----------------------------|-----------------|----------|---------|------------------------------------------------------------------------------|
| `enabled`                   | boolean         | OPTIONAL | `false` | Whether this rule is active.                                                 |
| `allowed_domains`           | array of string | OPTIONAL | `[]`    | Host patterns (Section 3.14.2) the agent may navigate to.                    |
| `blocked_domains`           | array of string | OPTIONAL | `[]`    | Host patterns that are always denied (evaluated before the allowlist).       |
| `allowed_verbs`             | array of string | OPTIONAL | `[]`    | Verbs the agent may issue. Empty means any verb.                             |
| `credential_detection`      | boolean         | OPTIONAL | `true`  | Check typed input for credential-shaped secrets.                             |
| `extra_credential_patterns` | array of string | OPTIONAL | `[]`    | Additional credential regex patterns (Section 3.14.3) layered on the built-ins. |

**Action shape.** A `browser_action` (Section 5) carries `target` = the verb (e.g. `navigate`, `click`, `type`, `screenshot`), and MAY carry `url` = the destination for navigation verbs and `content` = the typed text for input verbs.

**Semantics:** When enabled:
1. If `allowed_verbs` is non-empty and `target` equals no entry (exact match), the decision is **deny** (`rules.browser_automation.allowed_verbs`).
2. If the action carries a `url`, its normalized host (Section 3.14.2) is checked: a match in `blocked_domains` produces **deny** (`rules.browser_automation.blocked_domains`); otherwise, if `allowed_domains` is non-empty and the host matches no entry, the decision is **deny** (`rules.browser_automation.allowed_domains`); if `allowed_domains` is empty, any non-blocked host is permitted.
3. If `credential_detection` is `true` and the action carries `content`, the content is scanned against the engine's built-in credential detectors and every `extra_credential_patterns` entry; any match produces **deny** (`rules.browser_automation.credential_detection`). Engines MUST document their built-in credential detectors; a document that needs portable detection MUST list its patterns in `extra_credential_patterns`.
4. Otherwise the decision is **allow** (`rules.browser_automation`).

The block is evaluated only for `browser_action` actions.

Test vectors: `fixtures/core/valid/browser-automation-rule.yaml`, `fixtures/core/evaluation/browser-automation.test.yaml`.

### 3.12 `rules.code_execution`

Restrictions for sandboxed interpreter actions: a language allowlist, a dangerous-module denylist, network gating, and execution bounds.

| Field                   | Type            | Required | Default | Description                                                              |
|-------------------------|-----------------|----------|---------|--------------------------------------------------------------------------|
| `enabled`               | boolean         | OPTIONAL | `false` | Whether this rule is active.                                             |
| `language_allowlist`    | array of string | OPTIONAL | `[]`    | Allowed interpreter languages. Empty means any language.                 |
| `module_denylist`       | array of string | OPTIONAL | `[]`    | Module names whose use in the code body is denied.                       |
| `network_access`        | boolean         | OPTIONAL | `false` | Permit code-execution calls that request network access.                 |
| `max_execution_time_ms` | integer         | OPTIONAL | --      | Maximum execution time in milliseconds. MUST be >= 0 if present.         |
| `max_scan_bytes`        | integer         | OPTIONAL | --      | Maximum bytes of code to scan for module detection. MUST be >= 1 if present. |

**Action shape.** A `code_exec` action (Section 5) carries `target` = the language identifier (lowercase, e.g. `python`, `javascript`), `content` = the code body, and MAY carry `network: true` when the call requests network access and `timeout_ms` = the requested execution time.

**Semantics:** When enabled:
1. If `language_allowlist` is non-empty and `target` equals no entry (exact, case-sensitive), the decision is **deny** (`rules.code_execution.language_allowlist`).
2. If the action requests network access and `network_access` is `false`, the decision is **deny** (`rules.code_execution.network_access`).
3. If `max_execution_time_ms` is set and the action's `timeout_ms` exceeds it, the decision is **deny** (`rules.code_execution.max_execution_time_ms`).
4. For each `module_denylist` entry, the first `max_scan_bytes` bytes of `content` (all of it when unset) are searched for the entry as a literal word: the entry MUST be matched only where it is preceded and followed by a character that is not in `[A-Za-z0-9_]` or by the start/end of the scanned text. A match produces **deny** (`rules.code_execution.module_denylist`).
5. Otherwise the decision is **allow** (`rules.code_execution`).

When `content` is longer than `max_scan_bytes`, only the prefix is scanned; engines SHOULD warn that the scan was truncated. The block is evaluated only for `code_exec` actions.

Test vectors: `fixtures/core/valid/code-execution-rule.yaml`, `fixtures/core/evaluation/code-execution.test.yaml`.

### 3.13 Conditional Rule Blocks (`when`)

Any rule block MAY carry a `when` object that gates whether the block is active for a given evaluation. A block whose condition evaluates to `false` is inert for that evaluation, exactly as if `enabled` were `false`. Conditions are deterministic, not Turing-complete, and are evaluated against a **runtime context** supplied by the engine.

**Condition object.** All fields are OPTIONAL. When several fields are present on one condition object they are combined with AND: every present field must be satisfied.

| Field         | Type                    | Description                                                                                 |
|---------------|-------------------------|---------------------------------------------------------------------------------------------|
| `time_window` | object                  | Active during a daily time window. See below.                                               |
| `context`     | object (string -> any)  | Every key is a dot-delimited path into the runtime context; every value must equal the context value at that path. |
| `all_of`      | array of Condition      | Every sub-condition must be true.                                                           |
| `any_of`      | array of Condition      | At least one sub-condition must be true. An empty array is treated as absent.               |
| `not`         | Condition               | The sub-condition must be false. Unevaluable when the sub-condition is unevaluable.         |
| `capability`  | string                  | The effective posture state MUST grant this capability. Unevaluable when the policy has no posture extension. |
| `rate`        | object                  | An engine-supplied counter compared with a threshold. See below.                          |

**Time window object.**

| Field      | Type            | Required | Default   | Description                                                   |
|------------|-----------------|----------|-----------|---------------------------------------------------------------|
| `start`    | string          | REQUIRED | --        | `HH:MM`, 24-hour, ASCII digits only.                          |
| `end`      | string          | REQUIRED | --        | `HH:MM`, 24-hour, ASCII digits only.                          |
| `timezone` | string          | OPTIONAL | `"UTC"`   | IANA time zone identifier, or a fixed offset `+HH:MM`/`-HH:MM`. |
| `days`     | array of string | OPTIONAL | all days  | Any of `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun` (case-insensitive). |

**Rate condition object.**

| Field        | Type    | Required | Description                                                                                  |
|--------------|---------|----------|----------------------------------------------------------------------------------------------|
| `counter`    | string  | REQUIRED | Name of a counter in the runtime context's `counters` map (identifier grammar below).       |
| `threshold`  | integer | REQUIRED | Non-negative.                                                                                |
| `comparison` | string  | REQUIRED | `gte` (true when `counter >= threshold`) or `lt` (true when `counter < threshold`).          |

The engine owns the counter and its window (per session, per minute, per agent -- whatever it measures); HushSpec never stores state and never increments anything. A `rate` condition is a pure comparison of the value the engine supplied for this evaluation.

**Capability condition.** `capability` names a posture capability (Posture specification, Section 3). It is true when the effective posture state -- the state the engine resolves for this evaluation after origins profile selection and the action's posture input, exactly the state the posture guard uses -- lists that capability, and false when the state does not list it or is unknown. When the policy has no posture extension the predicate is unevaluable (see Evaluation below).

**Identifier grammar.** Capability names and counter names are one or more dot-separated segments, each a lowercase ASCII letter followed by lowercase ASCII letters, digits, or underscores:

```abnf
identifier = segment *("." segment)
segment    = %x61-7A *(%x61-7A / %x30-39 / "_")
```

The window is half-open: it contains the current local time `t` when `start <= t < end`. When `start > end` the window wraps midnight and contains `t` when `t >= start` or `t < end`; for wrapped windows, a time before `end` counts toward the *previous* calendar day when `days` is checked. When `start == end` the window is the whole day. The current time is the engine's clock converted to `timezone`, or the runtime context's `current_time` when supplied.

**Runtime context.** The engine supplies an object with the following top-level keys, each OPTIONAL: `user` (object), `environment` (string), `deployment` (object), `agent` (object), `session` (object), `request` (object), `custom` (object), `counters` (object of string to non-negative integer, consulted by `rate` conditions), and `current_time` (RFC 3339 string; used only for deterministic testing). A `context` condition key such as `user.role` resolves `user` then `role`; the key `environment` resolves the top-level string. Comparison is by JSON equality (type-sensitive: the number `1` does not equal the string `"1"`).

**Validation (parse time).** Parsers MUST reject a document when any `when` object:
- contains an unknown key;
- has a `time_window` whose `start` or `end` is not `HH:MM` with `00 <= HH <= 23` and `00 <= MM <= 59`;
- has a `timezone` that is neither an IANA identifier known to the engine nor a fixed offset;
- lists a `days` entry outside the seven abbreviations;
- has a `capability` or a `rate.counter` that does not match the identifier grammar;
- has a `rate` object missing `counter`, `threshold`, or `comparison`, a negative `threshold`, or a `comparison` other than `gte` / `lt`;
- nests condition objects (`all_of`, `any_of`, `not`) more than 8 levels deep. `capability` and `rate` are leaf predicates and do not add nesting.

**Evaluation (fail-closed toward enforcement).** A condition evaluates to one of three values: `true`, `false`, or **unevaluable**. A block is inert only when its condition evaluates to `false`; `true` and unevaluable both leave the block active. An unevaluable condition MUST NOT switch a security control off.
- A `context` key that is absent from the runtime context makes the condition `false`.
- A `time_window` the engine cannot evaluate -- because its time-zone database lacks the `timezone` identifier, or the runtime context's `current_time` does not parse -- is unevaluable: the block stays active, not inert.
- A `capability` predicate on a policy with no posture extension, and a `rate` predicate whose counter is absent from the runtime context, are unevaluable: the block stays active.
- Unevaluable propagates through the combinators instead of collapsing to a boolean. `not` of an unevaluable condition is unevaluable. `all_of` is `false` when any member is `false`, otherwise unevaluable when any member is unevaluable, otherwise `true`; the fields of one condition object combine the same way. `any_of` is `true` when any member is `true`, otherwise unevaluable when any member is unevaluable, otherwise `false`. A `not` over a missing counter or an absent posture extension therefore leaves the block active rather than switching it off.
- Conditions are evaluated before the block's own semantics; an inert block contributes nothing to Section 6.1 aggregation. Because `capability` depends on the effective posture state, engines resolve posture (and the origins profile it may come from) before evaluating conditions.

Engines MAY additionally accept an out-of-band map of conditions keyed by block name (the reference SDKs expose `evaluate_with_context`); when both are present the out-of-band condition is ANDed with the document's `when`.

Test vectors: `fixtures/core/valid/when-conditions.yaml`, `fixtures/core/invalid/when-*.yaml`, `fixtures/core/evaluation/conditions.test.yaml`, `fixtures/core/evaluation/conditions-capability.test.yaml`, `fixtures/core/evaluation/conditions-capability-unevaluable.test.yaml`, `fixtures/core/evaluation/conditions-rate.test.yaml`, `fixtures/core/evaluation/conditions-unevaluable-not.test.yaml`, `fixtures/core/evaluation/conditions-unevaluable-combinators.test.yaml`.

### 3.14 Pattern Matching

Three pattern classes exist. Engines MUST implement each exactly as specified here; the class is determined by the field, never by the pattern's shape.

| Class        | Fields                                                                                   |
|--------------|------------------------------------------------------------------------------------------|
| Path glob    | `forbidden_paths.patterns/exceptions`, `path_allowlist.read/write/patch`, `secret_patterns.skip_paths` |
| Host pattern | `egress.allow/block`, `browser_automation.allowed_domains/blocked_domains`, origin profile `egress` |
| Regex        | `secret_patterns.patterns[].pattern`, `patch_integrity.forbidden_patterns`, `shell_commands.forbidden_patterns`, `browser_automation.extra_credential_patterns` |

Tool names (`tool_access`), computer-use action identifiers, input types, verbs, and language identifiers are **exact strings** and belong to no pattern class.

#### 3.14.1 Path Globs

**Target normalization.** Before matching, the target path MUST be transformed, in order:
1. Unicode NFC normalization.
2. Every `\` is replaced by `/`.
3. Runs of consecutive `/` are collapsed to one.
4. Segments are resolved lexically, without consulting the filesystem: a `.` segment is removed; a `..` segment removes the preceding segment when one exists and is not itself `..`. In an absolute path a `..` that would climb above the root is discarded. In a relative path a leading `..` is retained.
5. A trailing `/` is removed unless the whole path is `/`.

Patterns MUST be written with `/` separators and are NFC-normalized; they are not otherwise transformed.

**Matching.** The pattern is matched against the entire normalized path (anchored at both ends). Matching is byte-wise case-sensitive; engines MUST NOT fold case. Engines on case-insensitive filesystems SHOULD present the canonical on-disk casing of the target to the evaluator.

| Token | Meaning                                                                                                   |
|-------|-----------------------------------------------------------------------------------------------------------|
| `*`   | Any sequence of zero or more characters other than `/`.                                                   |
| `?`   | Exactly one character other than `/`.                                                                     |
| `**/` | At the start of the pattern or after a `/`: zero or more complete leading segments (including their `/`). `**/.env` matches `.env`, `a/.env`, `a/b/.env`. |
| `**`  | Elsewhere (for example a trailing `/**` or `foo**`): any sequence of zero or more characters including `/`. `/home/**` matches `/home/x` and `/home/x/y` but not `/home` (the trailing slash is stripped from the target and the pattern requires the `/`). |
| other | Literal. `[`, `]`, `{`, `}`, `(`, `)`, `+`, `.`, `^`, `$`, `|`, `\` have no special meaning.               |

Test vectors: `fixtures/core/evaluation/path-normalization.test.yaml`, `fixtures/core/evaluation/forbidden-paths-leading-globstar.test.yaml`, `fixtures/core/evaluation/path-normalization-lexical.test.yaml`.

#### 3.14.2 Host Patterns

**Target normalization.** The egress target MAY be a bare host, a `host:port`, or a URL. It MUST be reduced to a host, in order:
1. If the target contains `://`, the authority is everything after it up to the first `/`, `\`, `?` or `#`; otherwise the whole target, cut at the same characters, is the authority. A backslash ends the authority exactly as a slash does, which is how browsers parse URLs with a special scheme: `http://blocked.example\@allowed.example` names the host `blocked.example`, never `allowed.example`.
2. Remove any userinfo (`user:pass@`).
3. If the authority begins with `[`, the host is the bracketed IPv6 literal including the brackets, and anything after the closing `]` (a `:port`) is removed. Otherwise remove a trailing `:` followed by one or more digits.
4. Remove any path, query, or fragment.
5. Convert ASCII letters to lowercase.
6. Remove one trailing `.`.
7. Convert any non-ASCII label to its IDNA A-label (punycode) form.

Patterns undergo steps 5-7 only.

**Matching.** After normalization, the host is compared with the pattern anchored at both ends:

| Token | Meaning                                                                                             |
|-------|-----------------------------------------------------------------------------------------------------|
| `*`   | One or more characters other than `.` (i.e. within a single label). `*.example.com` matches `api.example.com` but not `a.b.example.com` and not `example.com`. `api-*.example.com` matches `api-1.example.com`. |
| `**`  | One or more characters including `.` (one or more labels). `**.example.com` matches `a.example.com` and `a.b.example.com` but not `example.com`. |
| other | Literal, including `.`.                                                                             |

The apex host is never implied by a wildcard; a document that intends to allow `example.com` MUST list it. If the normalized host is an IPv4 literal or a bracketed IPv6 literal, it matches a pattern only when the pattern is character-for-character equal to it; wildcards MUST NOT match IP literals. A target that cannot be reduced to a syntactically valid host MUST be treated as matching nothing (so `default` applies).

Test vectors: `fixtures/core/evaluation/egress-normalization.test.yaml`, `fixtures/core/evaluation/egress-host-normalization.test.yaml`, `fixtures/core/evaluation/host-normalization-backslash.test.yaml`.

#### 3.14.3 Regex Profile

Regular expressions in HushSpec documents MUST conform to the **HushSpec regex profile**, a portable subset of RE2 syntax with fixed semantics. Version 0.1.0 said engines SHOULD support "PCRE2-compatible syntax"; that text is withdrawn.

**Syntax.** A pattern MAY use: literal characters and escapes (`\t`, `\n`, `\r`, `\f`, `\v`, `\xHH`, and `\` before any punctuation); `.`; bracket classes `[...]` and `[^...]` with ranges; the class escapes `\d`, `\D`, `\w`, `\W`, `\s`, `\S`; the assertions `^`, `$`, `\b`, `\B`; alternation `|`; capturing `( )` and non-capturing `(?: )` groups; the quantifiers `?`, `*`, `+`, `{n}`, `{n,}`, `{n,m}` and their lazy forms; and a single leading flag group `(?flags)` where `flags` is a non-empty subset of `i`, `m`, `s`.

A pattern MUST NOT use: lookahead or lookbehind; backreferences; possessive quantifiers or atomic groups; conditionals, recursion, or subroutine calls; named groups or named references; the assertions `\A`, `\z`, `\Z`, `\G`; inline flag groups anywhere other than the very start, or the `x` and `u` flags; Unicode property classes (`\p{...}`); or a quantified group whose body is itself unbounded (`(a+)+`, `(a*)*`, `(a|aa)*`). A pattern MUST NOT exceed 2048 bytes. Validators MUST reject any document containing a non-conforming pattern.

**Semantics.** Every engine MUST match with these semantics regardless of its host regex library:
- The subject is a sequence of Unicode scalar values; `.` and negated classes consume exactly one scalar value.
- A pattern matches when it matches any substring of the subject (unanchored search).
- `.` matches any scalar value except `\n` (any scalar value under the `s` flag).
- `^` and `$` match only at the start and end of the subject; `$` MUST NOT match before a trailing `\n`. Under the `m` flag they also match after and before every `\n`.
- `\d` is exactly `[0-9]`; `\w` is exactly `[A-Za-z0-9_]`; `\s` is exactly `[ \t\n\r\f\v]`; `\D`, `\W`, `\S` are their complements; `\b` and `\B` use the `\w` definition above. Non-ASCII digits, letters, and spaces MUST NOT match these escapes.
- The `i` flag folds ASCII letters only; engines MUST NOT apply Unicode case folding.
- Bracket classes are literal sets of scalar values; the class escapes inside them keep the ASCII definitions above.

**Failure handling.** A pattern that fails to compile at evaluation time (for example because a document bypassed validation) MUST produce **deny** from its block with `matched_rule` set to the pattern's path and a reason naming the compile failure. An engine that bounds matching time MUST treat exceeding the bound as **deny**.

Test vectors: `fixtures/core/evaluation/regex-dialect.test.yaml`, `fixtures/core/evaluation/regex-ascii-classes.test.yaml`, `fixtures/core/invalid/regex-*.yaml`.

---

## 4. Merge Semantics

When `extends` is present, the base document is resolved first, then the child document is overlaid according to `merge_strategy`.

### 4.1 Strategies

**`deep_merge` (default):**
For core `rules`, `deep_merge` is a rule-block merge in HushSpec v0:
- If the child defines a rule block (for example `rules.egress`), that entire child rule block, including its `when` condition, replaces the base rule block.
- Rule blocks absent in the child are preserved from the base.
- Arrays are never appended.

For `extensions`, `deep_merge` delegates to the companion extension specifications, which MAY define field-level merge behavior within an extension block.

**`merge`:**
Shallow merge at the `rules` level. If the child defines a rule block (e.g., `rules.egress`), the entire child rule block replaces the base rule block. Fields within the rule block are not individually merged. Top-level fields (`name`, `description`, etc.) follow scalar replacement.

**`replace`:**
The child document entirely replaces the base document. The base document is loaded only to validate that the reference is resolvable; its content is discarded.

Under every strategy the child's `metadata` object, when present, replaces the base's `metadata` object as a whole; a child without `metadata` inherits the base's. Members of `metadata` are never merged individually (Section 2.5).

**Extensions by strategy.** Under `merge`, an extension block present in the child (`extensions.posture`, `extensions.origins`, `extensions.detection`) replaces the base's block as a whole. Under `deep_merge`, each companion specification defines the field-level merge of its block (Posture specification Section 7, Origins specification Section 9, Detection specification Section 8); a block absent in the child is inherited unchanged. Under `replace`, the base's extensions are discarded with the rest of the base.

### 4.2 Merge Order

Merge is performed pairwise from the root of the inheritance chain to the leaf:
1. Resolve the `extends` chain to produce an ordered list: `[root, ..., parent, child]`.
2. Start with the root document.
3. Apply each subsequent document using the `merge_strategy` declared in that document.

The merged result is a resolved HushSpec document. The `extends` and `merge_strategy` fields are consumed during resolution and MUST NOT be present in the merged output (Section 2.3).

### 4.3 Engine-Specific Helpers

Convenience features such as `additional_patterns`, `remove_patterns`, or other additive/subtractive merge helpers are engine-specific extensions. They are NOT part of this specification. Engines that support such features MUST document them and MUST ensure that the result of applying helpers is expressible as a valid HushSpec document.

Test vectors: `fixtures/core/merge/`, `fixtures/posture/merge/`, `fixtures/origins/merge/`, `fixtures/detection/merge/`.

---

## 5. Action Types

HushSpec defines a standard taxonomy of action types. Engines use action types to route evaluation to the applicable rule blocks. The table is normative: for a given action type, exactly the listed blocks are applicable, and every applicable block that is enabled and whose `when` condition holds MUST be evaluated (Section 6.1).

| Action Type      | Description                                   | Inputs                                   | Applicable rule blocks, in evaluation order                                   |
|------------------|-----------------------------------------------|------------------------------------------|-------------------------------------------------------------------------------|
| `file_read`      | Reading a file from the filesystem            | `target` = path                          | `forbidden_paths`, `path_allowlist`                                           |
| `file_write`     | Writing or creating a file                    | `target` = path, `content`               | `forbidden_paths`, `path_allowlist`, `secret_patterns`                        |
| `patch_apply`    | Applying a patch or diff to a file            | `target` = path, `content` = patch       | `forbidden_paths`, `path_allowlist`, `patch_integrity`, `secret_patterns`     |
| `shell_command`  | Executing a shell command                     | `target` = command string                | `shell_commands`                                                              |
| `egress`         | Outbound network request                      | `target` = host or URL, `content`?       | `egress`, `secret_patterns` (only when `content` is present)                  |
| `tool_call`      | Invoking a tool or MCP endpoint               | `target` = tool name, `args_size`?, `content`? | `tool_access`, `secret_patterns` (only when `content` is present)        |
| `computer_use`   | Computer use agent action                     | `target` = action identifier             | `computer_use`, `remote_desktop_channels`                                     |
| `input_inject`   | Injecting keyboard/mouse/touch input          | `target` = input type                    | `input_injection`                                                             |
| `browser_action` | Browser automation step                       | `target` = verb, `url`?, `content`?      | `browser_automation`                                                          |
| `code_exec`      | Sandboxed interpreter invocation              | `target` = language, `content` = code, `network`?, `timeout_ms`? | `code_execution`                                      |
| `custom`         | Engine-defined action type                    | engine-defined                           | none (see below)                                                              |

**Unknown and custom action types.** An action whose type is not in the table above, or whose type is `custom`, has no applicable rule blocks. Because no declared control can vouch for it, the engine MUST produce **deny** with `matched_rule` `__unknown_action_type__` and a reason naming the type. Exception: when the posture extension is active and the current posture state lists the `custom` capability, a `custom` action is permitted by the reference evaluator (engine-specific rules MAY still restrict it). Engines MUST NOT allow an action merely because no rule mentions it.

Test vectors: `fixtures/core/evaluation/unknown-action.test.yaml`.

---

## 6. Decision Types

HushSpec defines three standard decision outcomes:

| Decision | Semantics                                                                   |
|----------|-----------------------------------------------------------------------------|
| `allow`  | The action is permitted. Execution may proceed.                             |
| `warn`   | The action is permitted pending confirmation. Engines determine how confirmation is obtained (interactive prompt, approval queue, auto-approve in CI, etc.). An engine that has no confirmation channel configured MUST treat `warn` as `deny`. |
| `deny`   | The action is blocked. Execution MUST NOT proceed.                          |

### 6.1 Aggregation and Precedence

Evaluation of one action proceeds as follows:

1. **Extension guards.** If the panic protocol is active, the result is **deny** (`__hushspec_panic__`). Otherwise the origins extension selects a profile or applies `default_behavior`, and the posture extension checks the required capability; a deny from either is final and no rule block is evaluated. See the companion specifications.
2. **Block evaluation.** Every applicable rule block for the action type (Section 5 table) that is present, `enabled`, and whose `when` condition holds is evaluated, in the order listed in the table. Each block yields exactly one of `allow`, `warn`, or `deny` and MAY name a `matched_rule` and `reason`. Engines MUST NOT stop after a block that allows: an allow from `path_allowlist` or from a `forbidden_paths` exception does not exempt the action from `secret_patterns` or `patch_integrity`.
3. **Aggregation.** The action's decision is the most restrictive block decision: **deny** if any block denied; otherwise **warn** if any block warned; otherwise **allow**. The reported `matched_rule` and `reason` are those of the first block, in evaluation order, whose decision equals the aggregate decision and which named a `matched_rule`; when no block named one they are absent.

Test vectors: `fixtures/core/evaluation/decision-precedence.test.yaml`, `fixtures/core/evaluation/no-early-return.test.yaml`.

### 6.2 Enforcement

A policy decision is what the evaluator computed; enforcement is what the enforcement point (an SDK guard, a proxy, a CLI) did with it. The two are recorded separately in a receipt (`decision` and `enforcement`, Receipt specification Sections 4.5 and 4.7). This section defines the enforcement configuration a conformant enforcement point MUST support and the outcomes it MUST record.

**Modes.** An enforcement point runs in one of two modes: `enforce`, in which `deny` blocks the action and `warn` requires confirmation, and `monitor`, in which every decision is computed and recorded but the action proceeds. Mode is engine configuration, never a property of the HushSpec document.

**Per-rule overrides.** An enforcement point MAY override the mode for a rule-path prefix (`rules.egress`, `rules.secret_patterns.patterns`, `extensions.detection`). An override applies to a decision whose `matched_rule` equals the prefix or continues past it at a segment boundary (`.` or `[`); the longest matching prefix wins over the mode. A prefix MUST begin with `rules.` and name a rule block of this specification, or begin with `extensions.` and name an extension module (Section 9); any other prefix MUST be rejected at configuration time. For override matching, the `matched_rule` value `detection` that the detection pipeline reports is treated as `extensions.detection`.

**Monitor mode fails closed.** An enforcement point configured so that monitor mode is reachable, as the mode or through an override, MUST refuse that configuration unless a receipt sink or an observer is attached: a shadow decision nobody records is indistinguishable from no policy.

**Outcomes.** Every enforcement records one of four outcomes:

| Decision | Mode | Outcome |
|----------|------|---------|
| `allow` | either | `allowed` |
| `warn` | `enforce`, confirmation obtained | `confirmed` |
| `warn` | `enforce`, no confirmation channel or confirmation refused | `blocked` |
| `deny` | `enforce` | `blocked` |
| `warn` or `deny` | `monitor` | `would_block` |

An enforcement point with no confirmation channel MUST treat `warn` as `deny` (Section 6). Whatever the configured mode, two decisions MUST always be enforced, and no override reaches them: a deny produced by panic mode (Section 6.3), and a deny produced because the enforcement point refused its policy after signature verification failed (`__hushspec_policy_unverified__`, Signing specification Section 6.5). The refused-policy state persists until a policy that verifies replaces it; every action in that state is denied and recorded.

Test vectors: `fixtures/receipts/expected/` (the `enforcement` member of every expected receipt).

### 6.3 Panic Mode

Panic mode is an operator-controlled kill switch that denies every action without consulting the policy.

- **Latch.** Panic is a boolean latch. While it is set, every evaluation MUST return `deny` with `matched_rule` `__hushspec_panic__`, the receipt's rule trace MUST contain a single `panic` entry and no rule block entries, and the decision MUST be enforced whatever the enforcement mode.
- **Activation.** The latch is set programmatically or through a sentinel file. An engine that supports the sentinel MUST arm the latch when the file exists at the configured path (the reference implementation's default is `.hushspec_panic` in the working directory, and its `h2h panic activate` creates that file). Checking the sentinel MUST fail closed: if the file's existence cannot be determined, the latch is armed.
- **Latching.** The absence of the sentinel does not disarm the latch; only an explicit deactivation does. An enforcement point SHOULD consult the sentinel before each evaluation or on a short interval so that activation takes effect within one evaluation cycle.
- **Scope.** The reference implementation's latch is process-wide by default; an embedder MAY give a policy or guard an independent latch so that arming one tenant's kill switch does not deny every tenant in the process. Which latch a guard consults MUST be documented.
- **Panic policy.** Engines MAY also expose a deny-all policy document (the reference implementation embeds `builtin:panic`) for deployments that prefer to swap policies rather than set a latch; the two mechanisms are independent.

Test vectors: the receipt vectors under `fixtures/receipts/valid/` include a panic receipt.

---

## 7. Validation Requirements

Conformant parsers and validators MUST enforce the following:

1. **YAML profile.** The input MUST satisfy Section 2.4.

2. **Unknown field rejection.** Documents containing fields not defined in this specification at any nesting level MUST be rejected. This is the fail-closed principle applied to schema validation.

3. **Version field.** The `hushspec` field MUST be present, MUST be a string matching `^0\.\d+\.\d+$`, and MUST name a supported minor version (Section 2.2).

4. **Type correctness.** All fields MUST conform to their declared types. A string where a boolean is expected MUST cause rejection.

5. **Enum constraints.** Fields with enumerated values (`severity`, `mode`, `default` in egress/tool_access, `merge_strategy`, `metadata.classification`, `metadata.lifecycle_state`) MUST contain one of the specified values.

6. **Uniqueness constraints.** The `name` field within each element of `secret_patterns.patterns` MUST be unique across the array. Duplicate names MUST cause rejection.

7. **Regex profile.** All fields designated as regex patterns MUST conform to Section 3.14.3. Non-conforming or unparseable patterns MUST cause document rejection.

8. **Numeric constraints.** `max_additions` and `max_deletions` MUST be non-negative integers. `max_imbalance_ratio` MUST be a positive number (strictly greater than zero). `max_args_size` MUST be a positive integer if present. `max_execution_time_ms` MUST be a non-negative integer and `max_scan_bytes` a positive integer if present. `metadata.policy_version` MUST be a positive integer if present.

9. **Boolean fields.** Boolean fields MUST be YAML booleans (`true`/`false`), not strings or integers.

10. **Conditions.** Every `when` object MUST satisfy the validation rules of Section 3.13.

Test vectors: `fixtures/core/invalid/`.

---

## 8. Conformance Levels

Implementations of HushSpec declare conformance at one of six levels. Each level subsumes all requirements of the levels below it: an implementation claiming Level N MUST satisfy every requirement of Levels 0 through N.

A conformance claim is made against a specific corpus. The vectors under `fixtures/` in the reference repository are inventoried by `fixtures/MANIFEST.json`, which records for every file its SHA-256, its category, and the level at which it becomes REQUIRED. A claim MUST name the corpus by the SHA-256 of that manifest. The machine-readable form of a claim is a document conforming to `schemas/hushspec-conformance-report.v1.schema.json`; a level reported as `not_attempted` is not a pass.


### Level 0: Parser

A Level 0 implementation can:
- Parse valid HushSpec YAML documents into a structured representation.
- Reject syntactically invalid YAML and input violating the YAML profile (Section 2.4).
- Reject documents missing the required `hushspec` field.

### Level 1: Validator

A Level 1 implementation additionally:
- Validates all field types and constraints as specified in Section 7.
- Rejects documents with unknown fields at any nesting level.
- Validates enum values, uniqueness constraints, numeric constraints, the regex profile, and conditions.
- Rejects every vector under `fixtures/<module>/invalid/`. An implementation that reports error codes MUST report, for each such vector, the code named in its `<name>.expect.yaml` sidecar and MUST include any `message_contains` substring the sidecar names. Codes are registered in `spec/registries/error-codes.yaml` and the sidecar format is `schemas/hushspec-error-codes.v1.schema.json`. An implementation that reports no codes at all still conforms at this level; one that reports codes from the registry MUST report the registered one.

### Level 2: Merger

A Level 2 implementation additionally:
- Resolves `extends` references (via at least one resolution strategy) and produces resolved documents per Section 2.3.
- Correctly implements all three merge strategies (`deep_merge`, `merge`, `replace`).
- Detects and rejects circular inheritance.

### Level 3: Evaluator

A Level 3 implementation additionally:
- Accepts an action (type + inputs) and a resolved HushSpec document.
- Produces a correct `allow`, `warn`, or `deny` decision per the semantics defined in Sections 3, 5, and 6, including the normalization and matching algorithms of Section 3.14.
- Implements aggregation and precedence as defined in Section 6.1 and denies unknown action types per Section 5.
- Passes every vector under `fixtures/<module>/evaluation/`: for each case, the decision, and each of `matched_rule`, `reason`, `origin_profile` and `posture` the case states. The vector format is `schemas/hushspec-evaluator-test.v1.schema.json`.

### Level 4: Auditor

Level 3 says an engine reaches the right decision. Level 4 says it can prove which document it reached it under, and why, to someone who was not there.

A Level 4 implementation additionally:
- Emits decision receipts at format version 0.2 that validate against `schemas/hushspec-receipt.v1.schema.json`, per the Receipt specification Section 2.
- Computes `policy.content_hash` as the canonical content hash of the **resolved** document, per the Canonical Form specification. Passes every vector under `fixtures/core/hash/`: for each, the canonical text byte for byte and the resulting digest.
- **Records** `rule_trace` during evaluation rather than reconstructing it afterwards, satisfying Receipt specification Section 4.3. Every applicable rule block MUST appear in evaluation order, with the closed `rule_block` identifiers of the receipt schema.
- Produces, for every case of every evaluation vector, a receipt byte-identical after RFC 8785 canonicalization to the committed vector under `fixtures/receipts/expected/<module>/<fixture stem>/<case index>.json`, under the fixed inputs that directory's README states.
- Accepts every vector under `fixtures/receipts/valid/` and rejects every vector under `fixtures/receipts/invalid/`.
- Resolves `extends` with chain provenance: passes every vector under `fixtures/core/resolve/`, producing the expected resolved `content_hash` and the expected chain of `{source, content_hash}` links, or the expected rejection reason. This includes `#sha256:` digest pinning (Section 2.3).

A Level 4 engine's output is audit evidence: given a receipt and the policy it names, a third party can recompute the hash, replay the trace, and get the same answer.

### Level 5: Attested

Level 4 evidence is only as trustworthy as the document it was produced under. Level 5 adds provenance: which policy was in force, who signed it, and whether the record has been tampered with since.

A Level 5 implementation additionally:
- Is a conforming **verifier** under the Signing specification Section 2: for every case in `fixtures/signing/vectors.yaml` it returns `valid`, or invalid with the exact reason code of Signing specification Section 6.4.
- Performs **verification on load** (Signing specification Section 6.5): every hop of an `extends` chain is verified against the trusted keyring or its digest pin, the load fails closed when a signature is required and absent or invalid, and the outcome is recorded in every receipt's `policy.signature`.
- Verifies a hash-linked log: passes every vector under `fixtures/log/valid/`, including the rotated pair as one chain, and rejects every vector under `fixtures/log/invalid/` **at the line the file name names**. Detecting that a log is broken is not enough; an implementation MUST identify where.
- Signs and verifies receipts: passes every vector under `fixtures/receipts/signed/valid/` and rejects every vector under `fixtures/receipts/signed/invalid/`.
- Verifies policy bundles: for every case in `fixtures/bundle/vectors.yaml` it returns `valid` or the exact reason code of the Bundle specification Section 5.4.

An implementation MAY conform at Level 5 for verification only. Producing signatures, logs and bundles is described by the same specifications, but a verifier is what a conformance claim at this level asserts, because verification is what a relying party depends on.

---

## 9. Extensions

Extension modules are declared under the `extensions` top-level field. Extensions provide optional capabilities beyond the core rule set.

### 9.1 `extensions.posture`

Stateful capability and budget management. Posture extensions define budgets (e.g., maximum number of tool calls per session), capability state machines, and degradation policies.

The posture extension schema is defined in a separate specification document. Core HushSpec parsers MUST accept the `posture` key without rejecting the document but MAY ignore its contents.

### 9.2 `extensions.origins`

Origin-aware policy profiles. Origins extensions allow policies to vary based on the source context of a request (e.g., Slack channel, GitHub repository, API client identity).

The origins extension schema is defined in a separate specification document. Core HushSpec parsers MUST accept the `origins` key without rejecting the document but MAY ignore its contents.

### 9.3 `extensions.detection`

Detection engine thresholds and configuration. Detection extensions configure prompt injection detection, jailbreak detection, threat intelligence screening, and other content analysis capabilities.

The detection extension schema is defined in a separate specification document. Core HushSpec parsers MUST accept the `detection` key without rejecting the document but MAY ignore its contents.

### 9.4 Extension Versioning

Extension modules are versioned with the core specification and do not declare independent version fields inside documents: a document's `hushspec` value names the release of the whole specification family, and the posture, origins, and detection companion specifications carry that release. The member name `version` under each extension block is reserved and MUST be rejected as unknown in 1.x. A future major version MAY introduce in-document extension versioning; the versioning policy (`versioning.md`) states the stability guarantee this rests on.

### 9.5 Unknown Extensions

Conformant parsers MUST reject unknown keys under `extensions`. Only the keys defined in this specification and its companion extension specifications are permitted.

---

## 10. Versioning

HushSpec uses semantic versioning (SemVer 2.0.0). The normative policy is `versioning.md`; this section summarizes it.

### 10.1 v0.x Series

The v0.x series was the development series. Breaking changes (field removals, semantic changes, structural reorganization) could occur between minor versions. Patch versions were reserved for clarifications and errata that do not change document validity or evaluation semantics; an engine supporting `0.2` MUST therefore accept every `0.2.Z` document (Section 2.2). Engines MUST document which v0.x minor version(s) they support.

### 10.2 v1.0 and Later

HushSpec 1.0.0 was declared on 2026-09-15 (`versioning.md`, Section 10; `CHANGELOG.md`). Its evaluation semantics are identical to 0.2.0: an engine that supports 1.0 MUST treat a `1.0.Z` document exactly as a `0.2.Z` document, because 1.0 freezes the 0.2 semantics without changing them, and the reference implementation accepts `0.1.Z`, `0.2.Z`, and `1.0.Z`. The one validation difference is that a present `name` MUST be non-empty (Section 2). The stability guarantee of `versioning.md` Section 5 applies from this release. Test vectors: `fixtures/core/valid/version-1-0.yaml`, `fixtures/core/evaluation/version-1-0.test.yaml`, `fixtures/core/invalid/version-unsupported-minor.yaml`.

From 1.0.0, within a major version:
- Minor versions MAY add new optional fields, rule blocks, and open-registry entries. Existing valid documents remain valid, keep their semantics, and keep their canonical content hash (Canonical Form specification, Section 3.2).
- Patch versions contain only clarifications and errata (`errata.md`).
- Major versions MAY introduce breaking changes.

What 1.0 freezes: the document format and validation rules, evaluation semantics, the canonical form and content hash, the receipt, log entry, signature envelope, keyring, and bundle wire formats, the error and reason codes, and the closed registries (`spec/registries/`).

### 10.3 Independence

HushSpec versioning is independent of any engine, SDK, or implementation. An engine at version 3.5.0 may implement HushSpec 0.2.0. There is no coupling between specification versions and implementation versions.

---

## 11. Security Considerations

The security considerations for the whole specification family are collected in `hushspec-security.md`. The ones that bear directly on this document are regular-expression denial of service (Section 3.14.3; Security Section 2), path traversal and normalization (Section 3.14.1; Security Section 3), remote resolution (Section 2.6.4; Security Section 4), and the panic sentinel (Section 6.3; Security Section 11).

---

## Appendix A. ABNF for Version Field

```abnf
hushspec-version = major "." minor "." patch
major            = 1*DIGIT
minor            = 1*DIGIT
patch            = 1*DIGIT
```

An engine accepts a document whose `major.minor` it supports (Section 2.2). The grammar collection for the whole family is `hushspec-grammars.md`.

## Appendix B. Minimal Valid Document

```yaml
hushspec: "0.2.0"
```

## Appendix C. Example Document

```yaml
hushspec: "0.2.0"
name: "production-agent-policy"
description: "Security policy for production AI agent deployments"
extends: "default"
merge_strategy: "deep_merge"

metadata:
  author: "security@example.com"
  lifecycle_state: "approved"
  policy_version: 3

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.env"
      - "**/.ssh/**"
      - "**/credentials*"
    exceptions:
      - "**/.env.example"

  egress:
    enabled: true
    allow:
      - "api.openai.com"
      - "**.googleapis.com"
    default: "block"

  secret_patterns:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
        description: "AWS access key ID"
      - name: "generic_api_key"
        pattern: "(?i)(api[_-]?key|apikey)[ \\t]*[=:][ \\t]*['\"]?[a-z0-9]{32,}"
        severity: "error"

  shell_commands:
    enabled: true
    when:
      context:
        environment: "production"
    forbidden_patterns:
      - "rm[ \\t]+-rf[ \\t]+/"
      - "curl.*\\|.*sh"
      - "wget.*\\|.*bash"

  tool_access:
    enabled: true
    block:
      - "dangerous_tool"
    require_confirmation:
      - "deploy"
      - "database_write"
    default: "allow"
```

## Appendix D. Changes from 0.1.0

Each entry names the section of this specification it changed. Changes to the
extension specifications are listed in their own appendices.

| Section        | Change                                                                                                   |
|----------------|----------------------------------------------------------------------------------------------------------|
| 2.2, 10.1      | Engines accept every patch version of a supported minor version.                                          |
| 2.3, 2.5, 4    | `metadata` documented; resolved documents exclude `extends` and `merge_strategy`; engines evaluate only resolved documents. |
| 2.4            | YAML 1.2 Core profile; duplicate keys, anchors, aliases, merge keys rejected; resource limits.             |
| 3.0, 3.13, 7   | `when` conditional rule blocks specified as a document field with parse-time validation.                   |
| 3.1, 3.14.1    | Path normalization algorithm (NFC, separators, `.`/`..`, trailing slash); `?` and `*` never cross `/`; brackets and braces literal. |
| 3.3, 3.14.2    | Host normalization algorithm (scheme, userinfo, port, path, case, trailing dot, IDNA); `*` is one label, `**` one or more; IP literals match exactly. |
| 3.4            | Severity-to-decision table; worst severity wins; scanned action types enumerated.                         |
| 3.5            | `require_balance` with a zero side denies; counting rule made explicit.                                    |
| 3.7            | Tool names are exact strings; glob matching of tool names is forbidden. Allowlist mode denies unlisted tools; `default` is consulted only when `allow` is empty. |
| 3.8            | `guardrail` denies unlisted actions; heuristic leniency withdrawn; `fail_closed` is an alias.             |
| 3.11, 3.12, 5  | `browser_automation` and `code_execution` documented; `browser_action` and `code_exec` action types added; twelve rule blocks. |
| 3.13           | `when` gains the `capability` and `rate` leaf predicates; the runtime context gains `counters`; identifier grammar for capability and counter names. |
| 3.14.3         | "PCRE2-compatible" replaced by the HushSpec regex profile with ASCII class semantics; compile failure at evaluation denies. |
| 5              | Unknown and `custom` action types deny (`__unknown_action_type__`) instead of allow.                       |
| 6              | `warn` without a confirmation channel MUST be treated as `deny`.                                           |
| 6.1, 5         | Every applicable block is evaluated and aggregated; allowlist and exception matches no longer short-circuit. Normative applicable-block table added. |
| posture 3      | Empty `capabilities` denies all (see posture spec Appendix C).                                             |
| posture 5.3    | Named `from` outranks `"*"` for the same trigger (see posture spec Appendix C).                             |
| origins 2, 3, 4| `default_behavior` enforced; priority by `space_id` then field count; tri-state profile overlays; absent `match` never matches (see origins spec Appendix B). |
| detection 3.5  | The normative `heuristic_injection@1` detector: integer scoring over a fixed signal table, reproduced exactly by every engine. |
