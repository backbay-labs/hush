# Upgrade to v1

V1 freezes the portable policy and evidence contracts. Upgrade deliberately:
first establish existing behavior, then update packages and policy authoring,
then verify the evidence consumers.

## Supported policy lineages

The reference v1 SDKs accept supported 0.1, 0.2 and 1.0 minor versions, including
their patch versions. Existing built-in policies may retain 0.x identifiers.
New policies should use `hushspec: "1.0.0"`.

A policy name is optional. In a v1 document, a present name must not be empty.
Remove an intentionally absent name or give it a meaningful value; do not add
an empty placeholder merely to satisfy an example.

## Test before and after

1. Save representative allow, deny and warn actions as evaluation fixtures.
2. Validate and test the old policy with the new SDK or CLI.
3. Update your authored leaf's version and revalidate its full inheritance chain.
4. Compare resolved documents, decisions, rule traces, and hashes.
5. Review a changed hash before re-signing or distributing a bundle.

```sh
h2h validate --strict policy.yaml
h2h resolve policy.yaml
h2h test --policy policy.yaml policy.test.yaml
h2h hash policy.yaml
```

Validation reads the document's `hushspec` field. There is no target-version
flag for validation. The CLI's `--version` flag only prints its own version.

## Do not relabel evidence envelopes

Receipt and signature wire versions stay `0.2`; logs and bundles stay `0.1`.
The v1 schemas accept the supported policy lineage while preserving those
envelope contracts. Do not replace every `0.1` or `0.2` string in an evidence
store. Frozen v0 schema IDs and the bundle predicate URI remain unchanged.
See [versioning](../reference/versioning.md).

## Adapter changes

Recheck host-to-action mapping as part of the upgrade. Tool names are not
identities, and a mapper is not a sandbox. A `warn` in enforce mode requires
affirmative confirmation; treating it as automatic permission is incorrect.

For Python LangChain/CrewAI decorators, non-`tool_call` action types require
`action_mapper(args, kwargs)` returning an `EvaluationAction` with the same
type and a nonempty target. Explicitly map path, content and argument size.
The adapter rejects a missing mapper or an invalid result; it does not guess
that an arbitrary function argument is a trustworthy path.

Use the [integration guides](runtime-integration.md) and the [SDK API contract](../reference/sdk-api.md)
for exact return types, signing feature flags, providers, and callback restrictions.

## Rollout and rollback

Exercise the new runtime against synthetic traffic before changing production.
If using monitor mode, retain receipts and remember that `would_block` means
the action proceeded, not that enforcement was tested. Ordinary guard reload
retains its last good policy on a rejected update; initial load still fails.
Preserve the previous verified policy/bundle and its authorized keyring for a
deliberate rollback. Never weaken verification to make an update load.
