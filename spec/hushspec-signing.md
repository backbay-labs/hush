# HushSpec Policy Signing Specification

**Version:** 1.0.0
**Status:** Stable
**Date:** 2026-09-15
**Supersedes:** Signature format 0.1.0 (schemas/hushspec-signature.v1.schema.json as shipped with HushSpec 0.1.x)
**Companion to:** HushSpec Core 0.2.0, Canonical Form 0.2.0, Decision Receipts 0.2

---

## 1. Introduction

A signed policy lets an enforcement point prove that the controls it applied were the controls an authorized party approved. This specification defines how a HushSpec policy is signed, how the signature travels with the policy, which keys a verifier trusts, and exactly what a verifier checks before it lets a policy load.

Format 0.1 signed the raw bytes of the policy file. That tied the signature to whitespace and key order rather than to meaning, and it could not cover a base policy pulled in through `extends`. Format 0.2 signs the **content hash of the resolved policy** (Canonical Form specification), so a reformatted file still verifies and a changed base policy does not.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

**Envelope.** The JSON object that carries a signature and the claims it covers (Section 4).

**Keyring.** The set of public keys a verifier trusts (Section 5.3).

**Content hash.** As defined in the Canonical Form specification, Section 5.

### 1.2 Design principles

1. **Sign meaning, not bytes.** The signature covers the canonical content hash of the resolved document.
2. **Self-describing.** Algorithm, format version, and key id are inside the signed envelope. A verifier never guesses.
3. **Closed by default.** Unknown algorithm, unknown version, unknown key, missing signature when one is required: all fail closed.
4. **Standard key material.** Keys are PEM-encoded PKCS#8 and SubjectPublicKeyInfo, generatable and verifiable with OpenSSL and every mainstream crypto library.
5. **Deterministic.** Ed25519 signatures are deterministic, so vectors are reproducible byte-for-byte.

---

## 2. Conformance

An implementation conforms as a **signer** if every envelope it produces validates against the signature schema and verifies under Section 6 with the corresponding public key.

An implementation conforms as a **verifier** if, for every case in `fixtures/signing/vectors.yaml`, it returns the expected outcome: `valid`, or invalid with the expected reason code (Section 6.4).

An engine conforms at **Level 5, Attested** (Core Section 8) if it is a conforming verifier, performs verification on load (Section 6.5), and records the outcome in every receipt's `policy.signature`.

---

## 3. What is signed

The signed claim is the content hash of the **resolved** policy, computed as the Canonical Form specification defines. Consequences:

- Reformatting the YAML, reordering keys, or adding comments does not change the hash and does not invalidate the signature (vector `reformatted-yaml-still-verifies`).
- Writing a default explicitly (`enabled: true`) does not change the hash: defaults are materialized before hashing.
- A policy with `extends` is resolved first. The hash covers the merged result, so a change to `builtin:default` invalidates every signature over a policy that extends it (vector `extends-chain-resolved-before-hashing`). This is intended: the enforced policy changed.
- A signature made with format 0.1 over file bytes carries a `content_hash` that is not the canonical hash and MUST fail verification (vector `raw-bytes-hash-rejected`).

Signers MUST resolve and validate the policy before signing, using the same resolution the verifier will use. A signer that cannot resolve the chain MUST refuse to sign.

---

## 4. The envelope

An envelope is a JSON object validating against `schemas/hushspec-signature.v1.schema.json` (0.2). Every member except `signature` is a signed claim.

| Member | Required | Value |
|---|---|---|
| `format_version` | yes | `"0.2"` |
| `algorithm` | yes | `"ed25519"` (RFC 8032 pure Ed25519, no pre-hash, no context) |
| `key_id` | yes | `sha256:` + hex SHA-256 of the signing key's SubjectPublicKeyInfo DER (Section 5.2) |
| `signed_at` | yes | RFC 3339 UTC, millisecond precision, `Z` suffix |
| `expires_at` | no | Same format; the signature is invalid at or after this instant |
| `policy_version` | no | The policy's `metadata.policy_version` at signing time (integer) |
| `policy_name` | no | The policy's `name` at signing time |
| `content_hash` | yes | Content hash of the resolved policy |
| `signer` | no | Human-readable signer identity |
| `signature` | yes | base64url without padding (RFC 4648 Section 5) of the 64-byte Ed25519 signature |

### 4.1 Signing input

The signing input is the **canonical form** (Canonical Form specification, Section 4: RFC 8785, UTF-8) of the envelope object with the `signature` member absent. No projection step applies (envelopes have no schema defaults). Example, pretty-printed for readability; the actual input has no whitespace and keys in UTF-16 order:

```json
{"algorithm":"ed25519","content_hash":"sha256:…","format_version":"0.2","key_id":"sha256:…","policy_name":"signed-basic","policy_version":4,"signed_at":"2026-09-15T09:00:00.000Z","signer":"security@example.com"}
```

`signature = base64url_nopad(Ed25519_sign(private_key, signing_input))`.

Because every claim is inside the signing input, editing any member after signing invalidates the signature (vector `edited-envelope`).

### 4.2 Producing an envelope

1. Resolve and validate the policy. Compute `content_hash`.
2. Build the envelope with `format_version`, `algorithm`, `key_id` (Section 5.2), `signed_at` (now, milliseconds), `content_hash`, and any of `expires_at`, `policy_version` (copied from `metadata.policy_version` when present; signers SHOULD include it whenever the policy has one), `policy_name`, `signer`.
3. Compute the signing input (Section 4.1), sign, and add `signature`.

Signers SHOULD set `expires_at` for policies that are expected to be re-approved on a cadence and MUST NOT set it more than the deployment's approval interval into the future.

---

## 5. Keys

### 5.1 Key material

- Private keys are PEM-encoded PKCS#8 (`-----BEGIN PRIVATE KEY-----`, RFC 5958) carrying an Ed25519 key (RFC 8410 OID 1.3.101.112). Encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) MAY be supported by tooling; the encryption is outside this specification.
- Public keys are PEM-encoded SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`, RFC 7468 Section 13).
- Tooling MUST accept these formats. The bespoke raw-32-byte key files written by HushSpec 0.1 (`h2h keygen`) are not valid 0.2 key files; `h2h keygen` produces PEM from 0.2 on, and a one-time conversion is provided for existing keys.

`openssl genpkey -algorithm ed25519` and `openssl pkey -pubout` produce exactly these files.

### 5.2 Key identifier

```
key_id = "sha256:" || lowercase-hex(SHA-256(DER(SubjectPublicKeyInfo)))
```

The DER SubjectPublicKeyInfo for an Ed25519 key is the 44-byte structure `30 2a 30 05 06 03 2b 65 70 03 21 00 || 32-byte public key`. Deriving the id from the SPKI rather than from the raw key ties the id to the algorithm as well as the key bits. Verifiers MUST recompute `key_id` from the public key they hold and MUST NOT trust a keyring entry whose declared `key_id` differs from the recomputed one.

### 5.3 Keyring

A verifier's trust is a **keyring**: a JSON document validating against `schemas/hushspec-keyring.v1.schema.json`.

```json
{
  "keyring_version": "0.2",
  "keys": [
    {
      "key_id": "sha256:…",
      "algorithm": "ed25519",
      "public_key": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
      "name": "policy signing key 2026",
      "not_after": "2027-01-01T00:00:00.000Z",
      "revoked": false
    }
  ]
}
```

- Key selection is by exact `key_id` match. A verifier MUST NOT try other keys when the named key is absent (vector `untrusted-key`).
- `not_after` retires a key gracefully: signatures with `signed_at` at or after `not_after` are rejected (`key_retired`), earlier ones remain valid (vector `retired-key`).
- `revoked: true` rejects every signature by the key regardless of `signed_at` (`key_revoked`, vector `revoked-key`). Revocation is the response to key compromise; retirement is routine rotation.
- Keyrings are configuration and SHOULD be distributed through the same trusted channel as the enforcement point's own binaries. A keyring is not itself signed by this specification; that is a deployment concern (Section 10).

A single public key file MAY be accepted by tooling as a one-key keyring with `key_id` recomputed from it.

---

## 6. Verification

### 6.1 Inputs

A verifier receives: the policy (unresolved, as loaded), the envelope, a keyring, the current time `now`, a maximum clock skew (default 300 seconds), and optionally the last-seen `policy_version` for the policy's `name`.

### 6.2 Algorithm

Verifiers MUST perform these checks in this order and stop at the first failure, reporting its reason code:

1. **Envelope shape.** The envelope validates against the schema, with the `format_version` and `algorithm` value constraints deferred to checks 2 and 3 so that those reason codes remain reachable. Else `malformed_envelope`.
2. **Format.** `format_version` is `"0.2"`. Else `unsupported_format_version`.
3. **Algorithm.** `algorithm` is `"ed25519"`. Else `unsupported_algorithm`.
4. **Key lookup.** A keyring entry has `key_id` equal to the envelope's, and its recomputed id matches. Else `unknown_key_id`.
5. **Revocation.** The entry is not `revoked`. Else `key_revoked`.
6. **Retirement.** If the entry has `not_after`, `signed_at` is before it. Else `key_retired`.
7. **Time.** `signed_at` is not after `now + skew`. Else `signed_at_in_future`. If `expires_at` is present, `now` is before it. Else `expired`.
8. **Signature.** Ed25519 verification of `signature` over the signing input (Section 4.1) with the selected public key succeeds. Else `signature_mismatch`.
9. **Content.** Resolve and validate the policy; its content hash equals the envelope's `content_hash`. Else `content_hash_mismatch`. (A policy that fails to resolve or validate is `content_hash_mismatch` as well: there is no hash to compare.)
10. **Rollback.** If the verifier holds a last-seen `policy_version` for this `policy_name` and the envelope carries `policy_version`, the envelope's value is not lower. Else `policy_version_rollback`. A verifier that accepts an envelope SHOULD record its `policy_version` as the new last-seen value.

If every check passes the outcome is `valid`.

### 6.3 Clock skew

`signed_at_in_future` guards against a signer with a wrong clock or a fabricated future date. 300 seconds is the RECOMMENDED default; deployments with disciplined clocks MAY tighten it. Verifiers MUST NOT use `signed_at` to decide *freshness* (a two-year-old signature is valid unless expired, retired, or revoked).

### 6.4 Reason codes

| Code | Check |
|---|---|
| `malformed_envelope` | 1 |
| `unsupported_format_version` | 2 |
| `unsupported_algorithm` | 3 |
| `unknown_key_id` | 4 |
| `key_revoked` | 5 |
| `key_retired` | 6 |
| `signed_at_in_future`, `expired` | 7 |
| `signature_mismatch` | 8 |
| `content_hash_mismatch` | 9 |
| `policy_version_rollback` | 10 |

Verifiers MUST expose the reason code programmatically (it is what a receipt's `policy.signature.reason` and a CLI's exit message carry). Free-text detail MAY accompany it.

### 6.5 Verification on load

An enforcement point that is configured to require signatures (`require_signature`) MUST verify before the policy is used and MUST refuse to evaluate any action against a policy whose verification did not return `valid`, recording `policy.signature.verified: false` with the reason in receipts it emits for refused actions (Receipt specification, Section 4.2). Verification MUST cover every hop of the `extends` chain that is loaded from an untrusted source: a loader that fetches a base policy over the network MUST verify that base's own envelope or a digest pin before merging it. Loading from `builtin:` sources embedded in the engine needs no separate verification.

An enforcement point not configured to require signatures MAY verify opportunistically and SHOULD record the outcome when it does.

**Load-time reason codes.** When an enforcement point attempts verification on load (because signatures are required, or a keyring is configured), it records a `SignatureStatus` for every hop it attempted. Besides the Section 6.4 codes, the recorded `reason` MAY be one of these load-time conditions, spelled exactly:

| Code | Meaning |
|---|---|
| `missing_signature` | No detached envelope was found for the hop (Section 7.1 lookup order). |
| `no_keyring` | Verification was required but no keyring was configured. |
| `signing_unavailable` | The runtime lacks the cryptographic backend needed to verify. |
| `digest_mismatch` | The hop was pinned by digest (Core Specification, Section 2.3) and the loaded document's own content hash did not match. |
| `invalid_pin` | The `#sha256:` fragment was malformed. |

A hop satisfied by a matching digest pin needs no envelope; when an envelope is nevertheless present it MAY be verified opportunistically and its outcome recorded.

---

## 7. Detached and inline signatures

### 7.1 Detached (normative)

The envelope is stored in a separate JSON file next to the policy, named by appending `.sig` to the policy file name (`policy.yaml` and `policy.yaml.sig`; `h2h sign` also accepts `policy.sig` for compatibility with 0.1 layouts and tooling MUST look for both, preferring `policy.yaml.sig`). The detached form is what verification on load uses and what the vectors exercise.

### 7.2 Inline (reserved)

A future minor version may allow the envelope to be embedded in the policy under `metadata.signature`. That member is **reserved** in 0.2: the core schema does not define it, so conformant parsers reject it today, and the Canonical Form specification already excludes `metadata.signature` from the canonical projection so that, when it is introduced, a signature never covers itself. Implementations MUST NOT invent an inline form before the core schema defines it.

---

## 8. Tooling conventions

- `h2h keygen [--name <name>] [--output-dir <dir>] [--convert <old.key>]` writes `<name>.key.pem` (PKCS#8) and `<name>.pub.pem` (SPKI) and prints the `key_id`. `--convert` reads a HushSpec 0.1 key file and re-writes it as PEM; the signatures that key made stay format 0.1 and have to be re-made.
- `h2h sign <policy> --key <key.pem> [--expires-in <duration>] [--policy-version <n>] [--signer <id>] [--out <path>]` writes `<policy>.sig`. `policy_name` and `policy_version` default to the policy's own; `--policy-version` overrides.
- `h2h verify <policy> --keyring <keyring.json> [--sig <path>] [--now <timestamp>] [--max-skew <seconds>] [--last-seen-version <n>] [--format json]` exits 0 on `valid` and non-zero otherwise, printing the reason code. `--key <pub.pem>` is accepted as a one-key keyring.
- SDKs expose `sign_policy`, `verify_policy` returning the outcome and reason code, and a `Keyring` type that recomputes ids on load. The reference implementation pairs each with a hash-level primitive (`sign_content_hash`, `verify_content_hash`) so that an enforcement point can verify the in-memory resolved document it is about to evaluate rather than a file it would re-read (Section 10).

These are conventions for the reference tooling, not conformance requirements.

---

## 9. Test vectors

`fixtures/signing/` contains:

- `keys/test-signing.key.pem`, `keys/test-signing.pub.pem`: a **published, test-only** keypair. Every file carries a DO-NOT-USE header. Anyone can sign with this key; it MUST never appear in a production keyring.
- `keys/test-untrusted.key.pem`, `.pub.pem`: a second test key that is deliberately absent from the default keyring.
- `keys/keyring.json`, `keyring-retired.json`, `keyring-revoked.json`: keyrings for the trusted, retired, and revoked cases.
- `policies/*.yaml` and `*.sig`: policies and envelopes. `extends-child.resolved.json` shows the resolved document whose hash the child's envelope covers.
- `vectors.yaml`: the manifest. Each case names a policy, an envelope, optionally a keyring, `now`, and `last_seen_version`, and the expected outcome.

Signatures were produced with the reference canonicalizer for the signing input and `openssl pkeyutl -sign -rawin` for the Ed25519 operation; they can be re-verified with `openssl pkeyutl -verify -rawin` against the SPKI PEM.

| Case | Expected |
|---|---|
| `basic` | valid |
| `reformatted-yaml-still-verifies` | valid |
| `extends-chain-resolved-before-hashing` | valid |
| `rollback-protection-passes-when-newer` | valid (last seen 3, envelope 4) |
| `tampered-content` | `content_hash_mismatch` |
| `untrusted-key` | `unknown_key_id` |
| `expired` | `expired` |
| `signed-in-future` | `signed_at_in_future` |
| `rollback` | `policy_version_rollback` (last seen 4, envelope 3) |
| `raw-bytes-hash-rejected` | `content_hash_mismatch` |
| `bad-algorithm` | `unsupported_algorithm` |
| `bad-format-version` | `unsupported_format_version` |
| `corrupt-signature` | `signature_mismatch` |
| `edited-envelope` | `signature_mismatch` |
| `retired-key` | `key_retired` |
| `revoked-key` | `key_revoked` |

Every SDK runs these vectors; a divergence between engines is a conformance failure.

---

## 10. Security considerations

The security considerations for the whole specification family, including the shared threats this section relies on, are collected in `hushspec-security.md`.

- **Key compromise.** Revoke the key in every keyring (`revoked: true`), re-sign affected policies with a new key, and rotate. Because `key_id` is inside the signed envelope, an attacker cannot re-point an existing signature at a different key.
- **Replay.** A valid old envelope for an older policy version remains cryptographically valid forever. Rollback protection (`policy_version`, check 10) and expiry (`expires_at`) are the two defenses; deployments that need either MUST populate the corresponding fields.
- **Downgrade.** `format_version` and `algorithm` are signed and closed; a verifier never negotiates.
- **Hash, not bytes.** Signing the canonical hash means two byte-different files with the same meaning share a signature. It also means the verifier's resolver and canonicalizer are part of the trusted computing base: a bug that makes the verifier resolve a different base policy than the signer did is a verification bypass. Verifiers MUST use a conformant resolver and canonicalizer (Canonical Form specification, Section 6).
- **Time of check, time of use.** Verification on load MUST bind the verified resolved document to the document that is subsequently evaluated (verify the in-memory resolved document, not a file that is re-read afterwards).
- **Keyring integrity.** This specification does not sign keyrings. A keyring an attacker can edit is a root of trust an attacker owns; distribute keyrings with the enforcement point's own integrity guarantees.
- **Test key.** The published test key in `fixtures/signing/keys/` signs anything for anyone. Tooling SHOULD refuse to add its `key_id` to a keyring outside of test mode.

## Appendix A. Changes from 0.1

| 0.1 | 0.2 |
|---|---|
| `format_version: "0.1.0"` | `"0.2"` |
| `content_hash` = SHA-256 of raw file bytes, bare hex | Canonical content hash of the resolved policy, `sha256:` prefix |
| signature over an ad-hoc JSON envelope in struct order, standard base64 with padding | signature over the RFC 8785 canonical envelope, base64url without padding |
| `signed_at` any precision | milliseconds, `Z` |
| `key_id` opaque, chosen by the signer | `sha256:` of the SPKI DER, recomputed by verifiers |
| raw 32-byte keys in a bespoke wrapper | PEM PKCS#8 / SPKI |
| no expiry, no rollback protection, no keyring, no reason codes | `expires_at`, `policy_version`, keyring with retirement and revocation, closed reason-code set |
| `.sig` next to the policy | unchanged; `policy.yaml.sig` preferred, `policy.sig` accepted |
