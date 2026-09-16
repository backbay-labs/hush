# Policy Bundles

The full normative specification is at [`spec/hushspec-bundle.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-bundle.md); the schema is [`schemas/hushspec-bundle.v0.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-bundle.v0.schema.json).

A signature says a policy was approved and a receipt says a decision was made under it, but both name the policy only by content hash. A **bundle** carries the thing that hash identifies: the resolved document, every hop of the `extends` chain that produced it, each hop's own hash and signature status, and the resolver that did the work — wrapped in an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) inside a [DSSE](https://github.com/secure-systems-lab/dsse) envelope, signed with the same Ed25519 keys and `key_id` convention as policies and receipts. An auditor can verify what was enforced without cloning the repository or re-resolving anything.

The subject is the **canonical form of the resolved policy**, so the subject digest is the policy's content hash with the `sha256:` prefix stripped, the way in-toto spells digests. `predicate.resolved` carries the canonical projection itself, and a verifier recomputes the digest from it.

```bash
h2h bundle create library/healthcare/hipaa-base.yaml --key signing.key.pem --out hipaa.bundle.json
h2h bundle verify hipaa.bundle.json --keyring keyring.json --policy library/healthcare/hipaa-base.yaml
h2h bundle inspect hipaa.bundle.json
```

Verification runs four ordered checks and stops at the first failure, reporting its reason code: shape (`malformed_bundle`), signature (`unknown_key_id`, `dsse_signature_mismatch`), subject digest (`subject_digest_mismatch`), and — only with `--policy` — a re-resolution cross-check (`policy_mismatch`). Signature verification comes before the digest check on purpose, so an edit in transit reads as tampering rather than as an inconsistency.

Because the envelope is ordinary DSSE, generic supply-chain tooling reads a bundle too: `cosign verify-blob-attestation` checks the same signature over the same PAE bytes, and `openssl pkeyutl -verify -rawin` checks it by hand. Such a tool covers the signature check only; the other three are HushSpec semantics.

Vectors: `fixtures/bundle/vectors.yaml`, eight cases over bundles built from `library/healthcare/hipaa-base.yaml` with `created_at` pinned so they are byte-reproducible. Every release attaches a bundle for each `library/` and `rulesets/` policy, covered by GitHub build provenance.
