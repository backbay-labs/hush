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
