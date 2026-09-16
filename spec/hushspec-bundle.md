# HushSpec Policy Bundle Specification

**Version:** 1.0.0
**Status:** Stable
**Date:** 2026-09-15
**Companion to:** HushSpec Core 0.2.0, Canonical Form 0.2.0, Decision Receipts 0.2, Policy Signing 0.2

---

## 1. Introduction

A signature says a policy was approved. A receipt says a decision was made under it. Neither travels well on its own: the signature names a hash, the receipt names a hash, and the document those hashes identify lives in a repository an auditor may not be able to reach, behind an `extends` chain they would have to re-resolve.

A **policy bundle** closes that gap. It is a single self-contained file carrying the resolved policy itself, every hop of the chain that produced it, the resolver that produced it, and a signature over all of it, in a format the rest of the supply-chain ecosystem already reads: an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) inside a [DSSE](https://github.com/secure-systems-lab/dsse) envelope.

A bundle is evidence *about* a policy. It is not a new way to distribute policies, and an enforcement point never loads one in place of the policy file: the signing specification remains the mechanism that gates loading.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

**Content hash.** As defined in the Canonical Form specification, Section 5 (`sha256:` followed by 64 lowercase hex digits).

**Resolution.** The output of resolving a policy's `extends` chain: the merged document, its content hash, and one chain link per hop (Receipt specification, Section 4.2).

### 1.2 Design principles

1. **Standard envelope.** The wire format is DSSE plus an in-toto Statement, unchanged. A verifier that knows nothing about HushSpec can still check the signature and read the subject.
2. **Self-contained.** The resolved document travels inside the bundle, so verification never needs the original files. Re-resolution is an optional cross-check, not a precondition.
3. **One canonicalizer.** Everything a signature covers is serialized with RFC 8785, the same way policies, envelopes, and receipts are.
4. **Same keys.** Bundles are signed with the Ed25519 keys and the `key_id` convention of the Policy Signing specification. A deployment needs no second root of trust.
5. **Closed by default.** An unknown statement type, predicate type, or bundle version is a verification failure, not a warning.

---

## 2. Conformance

An implementation conforms as a **bundler** if every bundle it produces validates against `schemas/hushspec-bundle.v1.schema.json` and verifies under Section 5 with the corresponding public key.

An implementation conforms as a **bundle verifier** if, for every case in `fixtures/bundle/vectors.yaml`, it returns the expected outcome: `valid`, or invalid with the expected reason code (Section 5.4).

---

## 3. The envelope

A bundle is a JSON object that is a DSSE envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of the statement bytes>",
  "signatures": [{"keyid": "sha256:...", "sig": "<base64 of 64 signature bytes>"}]
}
```

| Member | Required | Value |
|---|---|---|
| `payloadType` | yes | `"application/vnd.in-toto+json"` |
| `payload` | yes | Standard base64 **with** padding (RFC 4648 Section 4) of the statement bytes (Section 4) |
| `signatures` | yes | Zero or more signatures over the PAE of the payload (Section 3.1) |

Each entry of `signatures` has:

| Member | Required | Value |
|---|---|---|
| `keyid` | yes | The signing key's `key_id` exactly as the Policy Signing specification defines it: `sha256:` + hex SHA-256 of the SPKI DER (Signing Section 5.2) |
| `sig` | yes | Standard base64 with padding of the 64-byte Ed25519 signature |

DSSE leaves `keyid` opaque. HushSpec fixes it to the signing specification's `key_id` so that one keyring serves policies, receipts, log entries, and bundles. A verifier MUST recompute the id from the public key it holds and MUST NOT trust the `keyid` a bundle declares (Signing Section 5.2).

`signatures` MAY be empty. An **unsigned bundle** transports the same evidence with no attestation attached; it is useful while building a pipeline, it is not evidence, and Section 5 rejects it. A tool that produces one MUST say so.

### 3.1 The signature input (PAE)

The signature is over the DSSE Pre-Authentication Encoding of the payload, which binds the payload type to the payload bytes:

```
PAE(t, b) = "DSSEv1" || SP || LEN(t) || SP || t || SP || LEN(b) || SP || b
```

where `SP` is a single U+0020 space, `t` is the UTF-8 of `payloadType`, `b` is the **decoded** payload bytes (not the base64 text), and `LEN(x)` is the byte length of `x` in ASCII decimal with no leading zeros. For a HushSpec bundle `t` is always `application/vnd.in-toto+json`, so the prefix is always `DSSEv1 28 application/vnd.in-toto+json ` followed by the payload length, a space, and the payload.

```
sig = base64(Ed25519_sign(private_key, PAE(payloadType, payload_bytes)))
```

Ed25519 here is RFC 8032 pure Ed25519: no pre-hash, no context, exactly as in the Policy Signing specification.

---

## 4. The statement

The decoded payload is an in-toto Statement v1:

| Member | Value |
|---|---|
| `_type` | `"https://in-toto.io/Statement/v1"` |
| `subject` | Exactly one subject (Section 4.1) |
| `predicateType` | `"https://hushspec.dev/attestation/policy-bundle/v0.1"` |
| `predicate` | The policy-bundle predicate (Section 4.2) |

The payload bytes are the RFC 8785 (JCS) canonical serialization of the statement, encoded as UTF-8 (Canonical Form Section 4). Two bundlers given the same resolution, the same `created_at`, and the same resolver therefore produce byte-identical payloads and -- Ed25519 being deterministic -- byte-identical bundles.

### 4.1 The subject

The attested artifact is the **canonical form of the resolved policy**, not the file the author wrote. There is exactly one subject:

| Member | Value |
|---|---|
| `name` | A label for the policy: its `name` when it has one, otherwise the file name of the leaf source. Informational. |
| `digest.sha256` | The resolved policy's content hash **without** the `sha256:` prefix -- 64 lowercase hex digits, as in-toto requires. |

`digest` MUST carry exactly the member `sha256`. The `sha256:` prefix is stripped here and only here: everywhere inside the predicate a content hash keeps its prefix, because that is the HushSpec wire form (Canonical Form Section 5).

### 4.2 The predicate

| Member | Required | Value |
|---|---|---|
| `bundle_version` | yes | `"0.1"` |
| `policy` | yes | Identity of the resolved policy (Section 4.3) |
| `chain` | yes | The `extends` chain, root first, leaf last; at least one link (Section 4.4) |
| `resolved` | yes | The **canonical projection** of the resolved document (Canonical Form Section 3), as a JSON object |
| `resolver` | yes | `{"tool": <string>, "version": <string>}` -- what produced the bundle; `"h2h"` for the reference CLI |
| `created_at` | yes | RFC 3339 UTC, millisecond precision, `Z` suffix |
| `signature_verification` | no | The leaf policy's own signature status at bundling time (Section 4.5) |

`resolved` is the projected value, not its serialization: the bundle embeds a JSON object, and re-serializing that object with RFC 8785 reproduces the canonical form whose digest the subject names. A verifier recomputes the digest from `resolved` alone (Section 5.2, check 3).

### 4.3 `policy`

| Member | Required | Value |
|---|---|---|
| `content_hash` | yes | The resolved policy's content hash, `sha256:`-prefixed. MUST equal the subject digest with the prefix restored. |
| `spec_version` | yes | The resolved document's `hushspec` field. |
| `name` | no | The resolved document's `name`. |
| `policy_version` | no | The resolved document's `metadata.policy_version`. An integer, never a string. |

These are the fields a receipt's `policy` block carries (Receipt Section 4.2), so a receipt and a bundle join on `content_hash`.

### 4.4 `chain`

Each link is a `ChainLink` in the shape the Receipt specification defines (Section 4.2):

| Member | Required | Value |
|---|---|---|
| `source` | yes | The reference as the resolver saw it: `builtin:strict`, a path, an `https:` URL. |
| `content_hash` | yes | The content hash of that document canonicalized **on its own**, with its `extends` and `merge_strategy` stripped. |
| `signature` | no | That hop's verification outcome, when verification was attempted (Section 4.5). |

A bundler SHOULD record a filesystem `source` relative to the directory the bundle was produced from when the file lies beneath it, and absolute otherwise, so a bundle built in CI neither leaks nor depends on a runner's workspace path. `source` is a **provenance label**: it says where a document came from, not which document it is. Identity is the `content_hash`, and Section 5.3 compares chains by content hash alone.

### 4.5 `signature_verification` and per-hop `signature`

Both are the `SignatureStatus` of the Receipt specification (Section 4.2): `verified`, and optionally `key_id`, `verified_at`, `reason`. `signature_verification` repeats the leaf link's status, which is the status of the policy the bundle is about.

A bundler given no keyring did not attempt verification and MUST omit these members rather than record `verified: false`, which would assert a check that never ran. A bundler configured to require signatures MUST refuse to produce a bundle for a policy that does not verify.

The bundle signature and the policy signature answer different questions. The policy signature says *this policy was approved*; the bundle signature says *this evidence about the policy was produced by this tool*. A bundle over an unverified policy is not a contradiction: it is an honest record, and `signature_verification` is where a verifier reads it.

---

## 5. Verification

### 5.1 Inputs

A verifier receives: the bundle, a keyring (Signing Section 5.3), the current time `now`, and optionally a policy file to re-resolve and compare against.

### 5.2 Algorithm

Verifiers MUST perform these checks in this order and stop at the first failure, reporting its reason code:

1. **Shape.** The document parses as JSON, validates against the bundle schema, the payload decodes as base64 into valid UTF-8 JSON, and that JSON is a statement whose `_type`, `predicateType`, and `predicate.bundle_version` are the constants of Sections 3 and 4, with exactly one subject. Else `malformed_bundle`.
2. **Signature.** At least one entry of `signatures` names a key the keyring holds, and at least one such entry's `sig` verifies as Ed25519 over `PAE(payloadType, payload_bytes)` under that key, with the key's id recomputed from the public key. If no entry names a key in the keyring, `unknown_key_id`; otherwise, if none verifies, `dsse_signature_mismatch`. An empty `signatures` array is `dsse_signature_mismatch`.
3. **Subject.** The RFC 8785 canonical form of `predicate.resolved` hashes to `predicate.policy.content_hash`, and `subject[0].digest.sha256` is that hash without its prefix. Else `subject_digest_mismatch`.
4. **Policy.** Only when the verifier was given a policy file: resolving that file yields a canonical form byte-identical to that of `predicate.resolved` -- equivalently, its content hash equals `predicate.policy.content_hash`, which check 3 has already tied to `predicate.resolved` -- and a chain whose `content_hash` values, in order, equal the bundle's. Else `policy_mismatch`. (A policy file that does not resolve or validate is `policy_mismatch` as well: there is nothing to compare.)

If every check passes the outcome is `valid`.

Check 2 precedes check 3 deliberately. Any edit to the payload -- including one that would make check 3 fail -- breaks the signature first, so a tampered bundle is reported as tampering rather than as an inconsistency. `subject_digest_mismatch` therefore means what it says: a bundle signed correctly over an internally inconsistent statement, which is a bundler bug or a compromised bundler, not an edit in transit.

### 5.3 Comparing against a policy

Check 4 compares **meaning**, not files:

- The resolved documents are compared through their canonical forms, so reformatting the policy, reordering its keys, or writing a default explicitly does not make the check fail. Comparing the projected JSON values directly would be wrong as well as fragile: a value tree that has been through a JSON round trip can hold `10` where the projection held `10.0`, which RFC 8785 serializes identically (Canonical Form Section 4.3).
- The chains are compared by `content_hash` in order. `source` is not compared: the same policy resolved on a different host, in a different checkout, or through a mirror is the same policy (Section 4.4).
- A difference in chain length is a mismatch even when the resolved documents agree: a policy that reaches the same result through a different chain is not the policy the bundle attests.

A verifier MAY report a `source` difference as informational detail. It MUST NOT fail on one.

### 5.4 Reason codes

| Code | Check |
|---|---|
| `malformed_bundle` | 1 |
| `unknown_key_id` | 2 |
| `dsse_signature_mismatch` | 2 |
| `subject_digest_mismatch` | 3 |
| `policy_mismatch` | 4 |

Verifiers MUST expose the reason code programmatically. Free-text detail MAY accompany it. The set is closed: a verifier never invents a code.

---

## 6. Tooling conventions

- `h2h bundle create <policy> [--key <key.pem>] [--keyring <ring.json>] [--require-signature] [--created-at <timestamp>] [--out <path>] [--format json]` resolves the policy with the verify-on-load options of Signing Section 6.5, builds the statement, and signs it when `--key` is given. Without `--key` it writes an unsigned bundle and warns.
- `h2h bundle verify <bundle.json> (--key <pub.pem> | --keyring <ring.json>) [--policy <policy.yaml>] [--now <timestamp>] [--format json]` runs Section 5.2, exiting 0 on `valid` and 1 otherwise, printing the reason code.
- `h2h bundle inspect <bundle.json> [--format json]` prints the predicate summary without verifying anything.

These are conventions for the reference tooling, not conformance requirements.

### 6.1 Interoperability

The envelope is ordinary DSSE and the payload is an ordinary in-toto Statement, so generic tooling reads a bundle without knowing this specification: `cosign verify-blob-attestation --key <pub.pem> --type https://hushspec.dev/attestation/policy-bundle/v0.1` checks the same signature over the same PAE bytes, and any in-toto consumer can read the subject. Such a tool checks Section 5.2 check 2 only; checks 1, 3, and 4 are HushSpec semantics and need a HushSpec verifier.

---

## 7. Test vectors

`fixtures/bundle/` contains bundles built from `library/healthcare/hipaa-base.yaml` and signed with the published test-only key of `fixtures/signing/keys/`, together with `vectors.yaml`, the case manifest. Each case names a bundle, optionally a keyring and a policy to cross-check, and the expected outcome.

| Case | Expected |
|---|---|
| `valid` | valid |
| `valid-with-policy` | valid (re-resolves `library/healthcare/hipaa-base.yaml`) |
| `tampered-payload` | `dsse_signature_mismatch` |
| `wrong-key` | `unknown_key_id` |
| `unsigned` | `dsse_signature_mismatch` |
| `subject-digest-mismatch` | `subject_digest_mismatch` |
| `policy-mismatch` | `policy_mismatch` |
| `malformed-predicate-type` | `malformed_bundle` |

`created_at` is fixed at `2026-09-15T12:00:00.000Z` in every vector so the bundles are byte-reproducible.

---

## 8. Security considerations

The security considerations for the whole specification family, including the shared threats this section relies on, are collected in `hushspec-security.md`.

- **A bundle is not a policy.** Nothing here authorizes loading `predicate.resolved` and enforcing it. An enforcement point loads policy files and verifies them under the Policy Signing specification; a bundle an attacker could feed to a loader would be a signed document its signer never intended to be enforced.
- **The bundler is in the trusted computing base.** The subject digest is computed by the bundler from the document the bundler resolved. A verifier that never re-resolves is trusting that resolution. Check 4 (`--policy`) is how an auditor removes that trust, and `chain` is what lets them see which bases were in force.
- **Key reuse.** One key for policies, receipts, log entries, and bundles keeps the trust model small, but one compromise then covers all four. The signing inputs are domain-separated in practice -- a policy envelope signs RFC 8785 JSON, a bundle signs a `DSSEv1`-prefixed PAE -- so a signature cannot be lifted from one context to the other. Deployments wanting stronger separation SHOULD use distinct keys and distinct keyrings.
- **Unsigned bundles.** An unsigned bundle carries a complete, readable statement and no attestation. It MUST NOT be treated as evidence, which is why Section 5.2 rejects it rather than reporting a weaker outcome.
- **Size.** A bundle embeds a whole resolved policy, which the YAML profile bounds at 1 MiB (Core Section 2.4); base64 and the predicate add a constant factor. Verifiers SHOULD bound the input they will parse.
- **Test key.** The key in `fixtures/signing/keys/` signs anything for anyone. A bundle it signed proves nothing outside the test suite.
