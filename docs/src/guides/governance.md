# Policy governance

Governance metadata answers who owns a policy and how it is reviewed.
It does not grant permissions, authenticate its author, or prove compliance.

## Keep the decision and the review separate

Use `metadata` for policy version, owner/author and approver records, lifecycle,
review dates, changelog entries, and control mappings. The field shapes are in
[core section 2.5](../../../spec/hushspec-core.md#25-governance-metadata).
Validation rejects malformed dates and control references; advisory checks look
for review and separation-of-duties concerns.

```sh
h2h validate --strict policy.yaml
h2h audit policy.yaml
h2h diff previous.yaml policy.yaml
```

The CLI and Rust SDK expose governance findings. Other SDKs validate the shared
metadata shape, but do not claim the same advisory API; see [SDK API](../reference/sdk-api.md).

## A reviewable policy change

1. Change the canonical policy source and its expected decision tests.
2. Resolve inheritance and compare the effective policy, not only the YAML diff.
3. Run validation, tests, and advisory audit.
4. Have an accountable owner approve the changed permissions.
5. Sign or bundle the reviewed policy with an operator-controlled key.
6. Deploy through a verified loader and retain the resulting policy identity.

A text `approver` field is not a cryptographic approval. Bind release approval
to the actual resolved digest and retain the separate organizational record.

## Control mappings and reports

A mapping identifies the controls an author associates with rule paths. It is
not evidence that the control was enforced on every runtime effect.
[Reports](reporting.md) aggregate observed receipts; [strict evidence profiles](evidence-verification.md)
add bounded experimental checks. Neither replaces an assurance practitioner's
judgment about organizational controls, coverage, or applicable obligations.

## Retention and privacy

Policy metadata and decision targets can reveal internal project names and
workflow structure. Minimize those fields, use synthetic examples in CI, and
set retention/access rules for logs. Keep private signing keys outside the
policy repository and rotate them through an explicit keyring lifecycle.
