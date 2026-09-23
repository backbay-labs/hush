# Versioning

The full versioning policy is at [`spec/versioning.md`](https://github.com/backbay-labs/hush/blob/main/spec/versioning.md).

## Summary

- Versions are `MAJOR.MINOR.PATCH`; a document's `hushspec` field carries no suffix.
- An engine declares the `major.minor` pairs it supports and accepts every patch of each.
- From 1.0.0 the document format, evaluation semantics, canonical form, wire formats, error and reason codes, closed registries, and grammars are frozen for the major version.
- A minor version adds only what leaves existing documents valid, meaningful, and hashing to the same value.
- Patch versions carry clarifications and errata.
- Extensions are versioned with the core; a `version` member under an extension block is reserved.
- Schema files are named per major version (`.v0.` for the 0.x line, `.v1.` from 1.0.0) and resolved by `$id`.

## Policy and Package Versions

New policies use `hushspec: "1.0.0"`. V1 reference SDKs also accept the supported
0.1 and 0.2 minor lineages. V0 was the pre-stability line; v1 freezes the
portable contract for its major version. Package SemVer is independent from
document and envelope versions: installing a newer SDK does not rewrite a policy.

## Evidence Wire Versions

| Artifact | Version in the v1 release |
| --- | --- |
| Policy document | `1.0.0` for new authored policies |
| Decision receipt | `0.2` |
| Signature envelope | `0.2` |
| Receipt log | `0.1` |
| Policy bundle | `0.1` |

These are current wire versions, not stale documentation. Frozen v0 schema IDs
retain `hushspec.dev`; v1 schema IDs use `https://hushspec.org/schemas/`.
The published bundle predicate remains
`https://hushspec.dev/attestation/policy-bundle/v0.1`.

## Migration Between Versions

Validation reads the version inside the policy. `h2h --version` prints the CLI
version; it does not select a target policy version. Follow [migration](../guides/migration-v1.md)
to update policies and adapters, then re-run your decisions and evidence checks.

## Extension Module Versioning

Posture, origins and detection evolve with the core specification. Do not insert
an extension-local version field into a closed object. The [normative versioning
policy](../../../spec/versioning.md) defines compatible and breaking changes.

## Changelog

Read the [v1 release](https://github.com/backbay-labs/hush/releases/tag/v1.0.0)
alongside the [errata process](errata.md). Corrections do not silently redefine
already published hashes or wire formats.
