# Policy Signing

The full normative specification is at [`spec/hushspec-signing.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-signing.md). The 0.2 envelope and keyring schemas are [`schemas/hushspec-signature.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-signature.v1.schema.json) and [`schemas/hushspec-keyring.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-keyring.v1.schema.json).

A policy signature is a detached JSON envelope (`policy.yaml.sig`) carrying an Ed25519 signature over the **canonical content hash of the resolved policy**, not over the file bytes. Reformatting the YAML keeps the signature valid; changing a base policy reached through `extends` invalidates it.

The envelope's claims (`format_version`, `algorithm`, `key_id`, `signed_at`, optional `expires_at`, `policy_version`, `policy_name`, `signer`, and `content_hash`) are all inside the signed input, which is the RFC 8785 canonical form of the envelope without `signature`.

Keys are standard PEM (PKCS#8 private, SubjectPublicKeyInfo public); `key_id` is the SHA-256 of the SPKI DER, which verifiers recompute. Trust is a keyring file listing public keys with optional retirement (`not_after`) and revocation.

Verification is an ordered list of ten checks, each with a fixed reason code, ending in `valid` or the first failure. Enforcement points configured to require signatures verify on load and refuse to evaluate against an unverified policy.

Vectors: `fixtures/signing/vectors.yaml` lists eighteen cases signed with a published, test-only key.

```bash
openssl genpkey -algorithm ed25519 -out signing.key.pem
openssl pkey -in signing.key.pem -pubout -out signing.pub.pem
```
