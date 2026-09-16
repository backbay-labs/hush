# HushSpec Canonical Form Specification

**Version:** 1.0.0
**Status:** Stable
**Date:** 2026-09-15
**Companion to:** HushSpec Core 0.2.0 (Section 2.3), Decision Receipts 0.2, Policy Signing 0.2

---

## 1. Introduction

Compliance evidence is only as good as the identity of the policy it refers to. A decision receipt says "this policy produced this decision"; a signature says "this policy was approved". Both need a policy identity that is the same in every SDK, on every platform, regardless of how the document was written, which keys were omitted, or which language serialized it.

This specification defines that identity: the **canonical form** of a HushSpec document and the **content hash** derived from it. It has three parts:

1. **Canonical projection** (Section 3): a deterministic transformation of a resolved document into a JSON value with every schema default made explicit and every resolution-only field removed.
2. **Canonical serialization** (Section 4): RFC 8785 (JSON Canonicalization Scheme) applied to the projected value.
3. **Content hash** (Section 5): SHA-256 over the canonical bytes, in a self-describing wire form.

Two conformant implementations given the same resolved document MUST produce byte-identical canonical output and the same content hash. The vectors in `fixtures/core/hash/` are normative (Section 7).

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

**Resolved document.** The output of resolving a document's `extends` chain (Core Section 2.3). It contains neither `extends` nor `merge_strategy`.

**Schema.** The JSON Schema documents under `schemas/`: `hushspec-core.v1.schema.json` and the three extension schemas (`posture`, `origins`, `detection`).

**Canonical projection.** The JSON value produced by Section 3.

**Canonical form.** The UTF-8 byte sequence produced by Section 4 from the canonical projection.

**Content hash.** The string produced by Section 5 from the canonical form.

### 1.2 Design Principles

1. **Schema-derived.** Every rule in Section 3 is derivable from the published schemas. A third party needs the schemas and this document, nothing else.
2. **Semantics-preserving.** Two documents with the same canonical form MUST evaluate identically under Core Section 3. The projection may only add information the schema already implies (defaults) or drop information that has no semantic effect (Section 3.3).
3. **Language-neutral.** Numbers, strings, and key order are defined by RFC 8785, not by any language's serializer.
4. **Self-describing hashes.** The content hash names its algorithm so a future algorithm can be introduced without ambiguity.

---

## 2. Scope and Inputs

### 2.1 What is canonicalized

The canonical form is defined for **resolved** HushSpec documents only. Implementations MUST resolve the `extends` chain before canonicalizing. Canonicalizing an unresolved document is a conformance failure because the resulting hash would identify a fragment, not the policy that is enforced.

### 2.2 From YAML to the JSON data model

A HushSpec document is authored in YAML (Core Section 2.4). Before projection it is converted to the JSON data model:

- YAML mappings become JSON objects. Keys are strings (the YAML profile forbids non-string keys).
- YAML sequences become JSON arrays.
- YAML strings become JSON strings, byte-for-byte after YAML escape processing. No Unicode normalization is applied to values. (Path and host normalization in Core Sections 3.1 and 3.3 happen at evaluation time, on action inputs, never on the document.)
- YAML integers become JSON numbers. YAML floats become JSON numbers. The distinction between `10` and `10.0` does not survive canonicalization (Section 4.3).
- YAML booleans `true`/`false` become JSON booleans. Under the YAML 1.2 Core schema required by Core Section 2.4, `yes`, `no`, `on`, and `off` are strings.
- YAML `null` becomes JSON `null`. HushSpec schemas define no nullable fields; a `null` written for a property the schema declares is a validation error and the document MUST NOT be canonicalized. Inside the free-form values the schema does not describe (`when.context` and everything below it) `null` is an ordinary JSON value and is canonicalized as one.

A document supplied as JSON is already in the data model.

### 2.3 Validity precondition

Only valid documents (Core Section 7) have a canonical form. Implementations MUST validate before canonicalizing and MUST NOT emit a canonical form or content hash for an invalid document. In particular, unknown fields at any level are a validation error, so the projection never has to decide what to do with them.

---

## 3. Canonical Projection

The canonical projection is computed by walking the resolved document alongside its schema. It is defined recursively over **schema objects** (JSON Schema nodes with a `properties` map), **schema arrays** (`type: array` with `items`), **schema maps** (`type: object` with an object-valued `additionalProperties`, e.g. posture `states`), and **leaf values**.

### 3.1 Top level

1. Start from the resolved document as a JSON object.
2. Remove `extends` and `merge_strategy` if present. These are resolution fields (Core Section 2.3). Their schema defaults are **not** materialized: `merge_strategy` has the default `deep_merge` in the schema, but it MUST NOT appear in the canonical projection.
3. If `metadata.signature` is present, remove it (Signing Section 7). This field is reserved for an inline signature and MUST NOT be covered by the hash it signs.
4. Project the remaining object against the core schema's top-level `properties` per Section 3.2, except that the `extensions` value is projected per Section 3.4.

`hushspec`, `name`, `description`, `rules`, and `metadata` are therefore included exactly as written (after projection of their contents). `name` and `description` have no defaults and are absent when not written.

### 3.2 Objects: defaults materialized

For a JSON object `V` projected against a schema object `S` with property map `P`:

1. Every key of `V` MUST be in `P` (Section 2.3).
2. No value in `V` may be `null` (Section 2.2). An implementation MUST refuse the document rather than emit `null` for a property the schema declares.
3. For each property `k` in `P`, in any order (order is irrelevant; serialization sorts keys):
   - If `k` is present in `V`, its value is projected against `P[k]` (following any `$ref`). The projected value is included unless Section 3.3 says to omit it.
   - If `k` is absent in `V` and `P[k]` declares a `default`, the default value is included verbatim. Defaults are leaf values in every HushSpec schema (booleans, strings, numbers, or empty arrays); they are never themselves projected further.
   - If `k` is absent and `P[k]` declares no `default`, it stays absent.

Defaults are materialized only inside objects that are **present** in the document. An absent optional object (for example a rule block that the policy never mentions, or the whole `rules` object) is not invented. This keeps "the policy says nothing about egress" distinct from "the policy declares egress with default settings", which evaluate differently (Core Section 3: an absent block is inert; a present block with defaults is active).

A schema map (`additionalProperties` as a schema, used by posture `states`) projects each entry's value against that schema and keeps every key as written.

A schema array projects each element against `items`. Element order is preserved; arrays are never sorted.

Leaf values, and free-form objects the schema does not describe (`when.context`, whose entries are arbitrary), are kept exactly as written.

### 3.3 Empty containers

Some fields have no schema default and mean the same thing whether they are absent or written as an empty array or object: `when: {}` is a condition that is always true, `days: []` is every day, `context: {}` constrains nothing, an empty `metadata: {}` says nothing. Because implementations model these fields differently (some cannot distinguish "absent" from "empty"), the projection normalizes them:

> After projecting a property value, if the property has no schema `default`, is not in the schema's `required` list, and the projected value is an empty array or an empty object, the property is **omitted**.

This rule applies at every level, including the top level (`rules: {}`, `extensions: {}`, `metadata: {}` are omitted) and inside extensions (`extensions.detection: {}` projects to `{}` and is omitted; `extensions.origins: {}` projects to `{"default_behavior":"deny"}` and is kept).

Properties whose default **is** an empty array (`patterns`, `allow`, `block`, `exceptions`, and so on) are unaffected: the empty array is the default and is materialized anyway.

**Presence-significant exception.** One field's empty value changes meaning and MUST be preserved:

| Schema | Property | Why presence matters |
|---|---|---|
| `OriginProfile` | `match` | `match: {}` is the explicit default profile; an absent `match` never matches (Origins Section 3). |

The origins profile overlay lists -- `ToolAccessRule.allow`, `block`, `require_confirmation` and `EgressRule.allow`, `block` -- are **not** presence-significant: Origins Section 4 gives an absent overlay list ("inherit the base") and a present-but-empty one ("contributes nothing") the same evaluation result, so a written-empty overlay list has no meaning for the canonical form to carry.

No other field in the current schemas is presence-significant. A future schema revision that adds one MUST extend this table in the same change.

### 3.4 Extensions

A present `extensions` MUST be a JSON object, and every one of its keys MUST name a published extension schema. An implementation that finds anything else refuses the document rather than passing the value through unprojected (Section 2.3).

The core schema declares `extensions.posture`, `extensions.origins`, and `extensions.detection` as opaque objects. For projection, each present extension block is projected against the **root** of its own schema document (`hushspec-posture.v1.schema.json`, `hushspec-origins.v1.schema.json`, `hushspec-detection.v1.schema.json`) using the same rules as Section 3.2, then subjected to Section 3.3. If every extension block projects to an omitted value, `extensions` itself is omitted.

### 3.5 Worked example

Document (resolved):

```yaml
hushspec: "0.1.0"
rules:
  egress:
    allow: ["api.example.com"]
  forbidden_paths:
    patterns: []
    when: {}
metadata: {}
```

Canonical projection (shown pretty-printed; the canonical form has no whitespace):

```json
{
  "hushspec": "0.1.0",
  "rules": {
    "egress": {"allow": ["api.example.com"], "block": [], "default": "block", "enabled": true},
    "forbidden_paths": {"enabled": true, "exceptions": [], "patterns": []}
  }
}
```

`enabled`, `block`, `default`, and `exceptions` were materialized from schema defaults; `when: {}` and `metadata: {}` were omitted; `patterns: []` stays because its default is `[]`.

### 3.6 Schema fields that needed a decision

The following points are ambiguous from the schemas alone. This section resolves them; the reference implementation and vectors follow these resolutions.

| Field | Ambiguity | Resolution |
|---|---|---|
| `merge_strategy` | Has a schema default but is a resolution field. | Never materialized (Section 3.1). |
| `TimeWindow.days` | No default; absent and `[]` both mean "all days". | Empty is omitted (Section 3.3). |
| `PostureState.capabilities`, `PostureState.budgets` | No default; absent and empty both mean "none". | Empty is omitted. |
| `Condition.all_of`, `Condition.any_of`, `Condition.context` | No default; empty is vacuous. | Empty is omitted. |
| `OriginProfile.match` | `{}` and absent differ. | Preserved (Section 3.3 table). |
| Origin overlays `allow`/`block`/`require_confirmation` | Absent inherits the base; written empty contributes nothing. | Both evaluate alike (Origins Section 4), so empty is omitted. |
| `origins.profiles` | No default; `[]` is the same as absent. | Empty is omitted. |
| Posture root `states`, `transitions` | Required. | Required properties are never omitted, even when empty. |
| `metadata` sub-fields | No defaults. | Written values only. `metadata.signature` is stripped (Section 3.1). |
| Numeric defaults written as floats (`max_imbalance_ratio: 10.0`) | Float vs. integer. | Indistinguishable after Section 4.3; the default `10.0` serializes as `10`. |

---

## 4. Canonical Serialization

The canonical form is the RFC 8785 (JSON Canonicalization Scheme, JCS) serialization of the canonical projection, encoded as UTF-8. This section restates the parts of RFC 8785 that matter and adds HushSpec-specific constraints. Where this section and RFC 8785 disagree, RFC 8785 governs.

### 4.1 Objects

- Members are emitted in ascending order of their keys, compared as sequences of UTF-16 code units (RFC 8785 Section 3.2.3). This is not code-point order for characters outside the Basic Multilingual Plane: `"€"` (U+20AC) sorts before `"😀"` (U+1F600, encoded as the surrogate pair D83D DE00).
- No whitespace anywhere. Members are separated by `,` and keys from values by `:`.
- Duplicate keys cannot occur (they are rejected by the YAML profile).

### 4.2 Strings

Strings are emitted between double quotes with exactly these escapes (RFC 8785 Section 3.2.2.2):

| Character | Emitted as |
|---|---|
| U+0022 quotation mark | `\"` |
| U+005C reverse solidus | `\\` |
| U+0008 backspace | `\b` |
| U+0009 tab | `\t` |
| U+000A line feed | `\n` |
| U+000C form feed | `\f` |
| U+000D carriage return | `\r` |
| other U+0000..U+001F | `\u` followed by four lowercase hex digits |
| everything else | the character itself, UTF-8 encoded |

Non-ASCII characters, U+007F, U+2028, U+2029, and astral characters are **not** escaped. Implementations that inherit a serializer which escapes `/`, non-ASCII, or line separators MUST override it.

### 4.3 Numbers

Numbers are emitted using the ECMAScript `Number::toString` algorithm (RFC 8785 Section 3.2.2.3), which yields the shortest decimal that round-trips through an IEEE 754 double:

- Whole values print without a decimal point or exponent: `10.0` → `10`, `1e16` → `10000000000000000`.
- Fractions print in positional notation between `1e-6` and `1e21`: `0.35` → `0.35`, `0.000001` → `0.000001`.
- Outside that range, exponent notation with a signed exponent and no leading zeros: `1e21` → `1e+21`, `1e-7` → `1e-7`, `2.5e-8` → `2.5e-8`.
- Negative zero prints as `0`.
- `NaN` and infinities have no JSON representation; a document containing one is invalid.

Consequently an integer `10` and a float `10.0` have the same canonical form. This is deliberate: it removes the most common cross-language divergence (serializers that print `10` versus `10.0`).

#### The safe-integer bound

A number written with **integer syntax** -- digits with an optional sign, no fraction and no exponent -- MUST have an absolute value of at most 2^53 − 1, the largest integer an IEEE 754 double represents exactly. An implementation that encounters a larger integer literal MUST refuse to canonicalize rather than round it.

A number written with **float syntax** -- a fraction, an exponent, or both -- carries no such bound. It denotes a double, and the algorithm above emits it at any magnitude: `1.0e+16` → `10000000000000000`, `1.0e+21` → `1e+21`, `1.5e+300` → `1.5e+300`.

The bound is syntactic because the syntax is the only thing that distinguishes the two cases: `10000000000000000` and `1.0e+16` denote the same double, and only the way each was written says whether the author meant an exact integer, which 2^53 − 1 bounds, or a double, which it does not. An implementation therefore applies the bound where the distinction still exists -- in its parser, which sees the literal -- rather than in its serializer, which sees a number.

A value handed to an implementation directly, as a number of the host language rather than as a document to parse, carries no syntax to read. Section 2.3 already requires such a value to have come from a valid document, so the bound has been applied by the parser that read it.

### 4.4 Other values

`true`, `false`, and `null` are emitted as those literals. Arrays are `[`, elements separated by `,`, `]`, with element order preserved.

### 4.5 Encoding

The canonical form is the UTF-8 encoding of the serialized text, with no byte order mark and no trailing newline.

---

## 5. Content Hash

The content hash is:

```
"sha256:" || lowercase-hex(SHA-256(canonical form))
```

That is, the literal prefix `sha256:` followed by 64 lowercase hexadecimal characters. The prefix is part of the wire value everywhere a content hash appears: receipts (`policy.content_hash`, `policy.extends_chain[].content_hash`, `action.content_hash`), signature envelopes (`content_hash`), and log entries.

Rationale for the prefix: HushSpec 0.1 receipts carried a bare 64-hex digest whose algorithm was implied. A self-describing value lets a verifier reject an unknown algorithm instead of guessing, and lets a future minor version add an algorithm without changing field names. Only `sha256` is defined in 0.2; verifiers MUST reject any other prefix.

**Migration.** Bare 64-hex hashes emitted by 0.1 SDKs are not valid 0.2 content hashes. A consumer that must accept both MAY treat a bare 64-hex string as `sha256:` for hashes computed by the same 0.1 code path, but MUST NOT compare a 0.1 hash to a 0.2 hash for equality: 0.1 hashes were computed over non-canonical serializations and differ per SDK.

---

## 6. Conformance

An implementation conforms to this specification if, for every vector in `fixtures/core/hash/`, it produces exactly the vector's `canonical` text and `content_hash` from the vector's `policy`.

Implementations SHOULD canonicalize from the generic JSON data model of the resolved document (a tree of maps, arrays, and scalars) rather than from typed language structures, because typed structures commonly lose the distinction between absent and empty (Section 3.3) or between integer and float. When an implementation canonicalizes from typed structures, it MUST still reproduce the vectors byte-for-byte.

The **reference implementation** is `scripts/canonical_json.py`, a standard-library-only Python program that performs projection, serialization, and hashing and that generated the vectors. Its documented limits: it does not resolve `extends` (resolve first, for example with `h2h resolve --format json`), and it assumes the input has already been validated.

---

## 7. Test Vectors

Vectors are YAML files under `fixtures/core/hash/` conforming to `schemas/hushspec-hash-vector.v1.schema.json`:

| Field | Meaning |
|---|---|
| `hushspec_hash_vector` | Vector format version, `"0.1.0"`. |
| `description` | What the vector exercises, with a section reference. |
| `source` | Optional, informational: the unresolved document `policy` came from. |
| `policy` | The **resolved** document to canonicalize. |
| `canonical` | The exact canonical text. |
| `content_hash` | The content hash. |

| Vector | Exercises |
|---|---|
| `minimal.yaml` | Section 3.1: nothing to materialize at the top level. |
| `all-rule-blocks-defaults.yaml` | Section 3.2: every rule block present and empty; full default materialization. |
| `defaults-partial.yaml` | Section 3.2: defaults fill only absent fields; absent blocks are not invented. |
| `numbers.yaml` | Section 4.3: whole floats, fractions, integers. |
| `numbers-large.yaml` | Section 4.3: float syntax beyond the safe-integer bound; negative zero. |
| `strings-escapes.yaml` | Section 4.2: every escape class, non-ASCII, U+2028, astral, DEL, NBSP. |
| `key-order-utf16.yaml` | Section 4.1: UTF-16 key order including a surrogate-pair key. |
| `empty-containers.yaml` | Section 3.3: omission of empty no-default containers. |
| `metadata-governance.yaml` | Section 3.1: metadata is covered by the hash. |
| `when-conditions.yaml` | Sections 3.2 and 3.3 applied to `when`; `timezone` default. |
| `extension-posture.yaml` | Section 3.4: schema maps, required-but-empty arrays. |
| `extension-origins.yaml` | Section 3.3: the presence-significant `match: {}`; origins defaults. |
| `origins-overlay-empties.yaml` | Section 3.3: overlay lists written empty are omitted; `match: {}` is kept. |
| `extension-detection.yaml` | Section 3.4: detector defaults. |
| `extends-resolved.yaml` | Section 2.1: canonicalized after resolution; `source` shows the unresolved child. |
| `empty-strings.yaml` | Sections 3.2 and 3.3: an optional string written `""` survives; only empty containers are omitted. |

Verify with:

```bash
python3 scripts/canonical_json.py --check fixtures/core/hash
```

All four SDKs walk `fixtures/core/hash/`, as does the conformance testkit's `hash` fixture category. `hushspec-difftest` additionally asserts that every SDK reports the same content hash for every generated policy.

---

## 8. Security Considerations

The security considerations for the whole specification family, including the shared threats this section relies on, are collected in `hushspec-security.md`.

- **Hash identity, not authenticity.** A content hash proves that two parties hold the same policy; it does not prove who wrote it. Authenticity comes from the signature specification.
- **Canonicalization must precede validation of nothing.** Validate first (Section 2.3). A canonicalizer that tolerates unknown fields could be made to hash a document that no conformant engine would accept.
- **Resolution is part of identity.** Because the hash covers the resolved document, changing a base policy changes the hash of every child, even if the child file is untouched. This is the intended behavior: the enforced policy changed.
- **Resource limits.** The canonical form of a document is bounded by the YAML profile's size limits (Core Section 2.4); canonicalizers need no additional limits.

## Appendix A. Changes from 0.1

HushSpec 0.1 defined no canonical form. Each SDK hashed its own serialization of the parsed document, so identical policies produced four different `content_hash` values. This specification replaces all of those with one definition and moves the wire form from bare hex to `sha256:`-prefixed hex.

Within the 0.2 draft, an earlier revision of Section 3.3 also declared the five origins profile overlay lists presence-significant. It no longer does: Origins Section 4 makes an absent overlay list and an empty one evaluate identically, so the distinction never reached a decision, while no SDK's typed model could express it. `OriginProfile.match` is now the only presence-significant field. A document that writes an empty overlay list has a different content hash under this revision than under that earlier draft.
