# Versioning

The full versioning policy is at [`spec/versioning.md`](https://github.com/backbay-labs/hush/blob/main/spec/versioning.md).

## Summary

HushSpec uses Semantic Versioning (SemVer 2.0.0). The specification version is independent of any engine or SDK version.

### v0.x: Unstable

The current series. Breaking changes are permitted between minor versions (e.g., 0.1.0 to 0.2.0). Patch versions (0.1.0 to 0.1.1) contain only clarifications and errata.

Implementations should pin to a specific minor version and document which v0.x version(s) they support.

### v1.0+: Stable

Upon reaching v1.0.0, backward compatibility is guaranteed within each major version:

- **Minor versions** (1.1, 1.2, ...) add new optional fields and rule blocks. Existing documents remain valid.
- **Patch versions** (1.0.1, 1.0.2, ...) contain clarifications and errata only.
- **Major versions** (2.0) may introduce breaking changes.

### Extension Module Versioning

In HushSpec v0.1.0, extensions do not declare separate per-document version
fields. The companion extension specs ship with the same repository release as
the core spec. A future major version may add explicit extension versioning if
it becomes necessary.

## Current Version

HushSpec Core: **v0.1.0** (Draft)

Extension modules: **v0.1.0** (Draft)
