# Policy Bundles

The full normative specification is at [`spec/hushspec-bundle.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-bundle.md); the schema is [`schemas/hushspec-bundle.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-bundle.v1.schema.json).

A signature says a policy was approved and a receipt says a decision was made under it, but both name the policy only by content hash. A **bundle** carries the thing that hash identifies: the resolved document, every hop of the `extends` chain that produced it, each hop's own hash and signature status, and the resolver that did the work — wrapped in an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) inside a [DSSE](https://github.com/secure-systems-lab/dsse) envelope, signed with the same Ed25519 keys and `key_id` convention as policies and receipts. An auditor can verify what was enforced without cloning the repository or re-resolving anything.

The subject is the **canonical form of the resolved policy**, so the subject digest is the policy's content hash with the `sha256:` prefix stripped, the way in-toto spells digests. `predicate.resolved` carries the canonical projection itself, and a verifier recomputes the digest from it.

```bash
h2h bundle create library/healthcare/hipaa-base.yaml --key signing.key.pem --out hipaa.bundle.json
h2h bundle verify hipaa.bundle.json --keyring keyring.json --policy library/healthcare/hipaa-base.yaml
h2h bundle inspect hipaa.bundle.json
```

Verification runs four ordered checks and stops at the first failure, reporting its reason code: shape (`malformed_bundle`), signature (`unknown_key_id`, `key_revoked`, `key_retired`, `dsse_signature_mismatch`), subject digest (`subject_digest_mismatch`), and — only with `--policy` — a re-resolution cross-check (`policy_mismatch`). Signature verification comes before the digest check on purpose, so an edit in transit reads as tampering rather than as an inconsistency.

Generic DSSE tooling may verify the envelope's signature when configured for
the same keys and payload type. That alone does not perform HushSpec's subject
digest or policy cross-checks. Use `h2h bundle verify` for the complete contract.

Vectors: `fixtures/bundle/vectors.yaml`, ten cases over bundles built from `library/healthcare/hipaa-base.yaml` with `created_at` pinned so they are byte-reproducible. Every release attaches a bundle for each `library/` and `rulesets/` policy, covered by GitHub build provenance.

## What a bundle establishes

A verified bundle authenticates its statement under your selected keyring and
binds its resolved policy to the subject digest. Supplying `--policy` also
compares your independently resolved local policy. Neither result establishes
that an agent loaded that policy, mediated every effect or satisfied a control
objective. Correlate [receipts](receipt-spec.md), [logs](log-spec.md) and runtime
evidence separately.

The bundle's signature authenticates the bundler. Per-hop signature status in
its predicate is the bundler's recorded claim; use a separately trusted policy
origin when that is required. Distribute trust roots independently of the
bundle you are asking someone to trust.

Run the [evidence lab](signing-spec.md#run-the-evidence-lab) to verify a real
bundle and observe a tampered payload fail with `dsse_signature_mismatch`.
