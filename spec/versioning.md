# HushSpec Versioning Policy

**Applies to:** HushSpec Core and every companion specification (posture, origins, detection, canonical form, receipt, signing, log, bundle, grammars, security)
**Version:** 1.0.0-rc.1
**Status:** Release Candidate
**Date:** 2026-09-15

---

## 1. Specification Independence

HushSpec versioning is independent of any engine, SDK, runtime, or tool that consumes HushSpec documents. A security engine at version 5.0 may implement HushSpec 1.0.0; a CLI at version 0.3 may implement HushSpec 1.2.0. There is no coupling, implied or explicit, between specification version numbers and implementation version numbers.

The `hushspec` field of a document declares which version of the specification the document conforms to. Implementations declare which `major.minor` pairs they support. These are separate concerns.

## 2. Version Numbers

Versions follow Semantic Versioning 2.0.0 restricted to `MAJOR.MINOR.PATCH` (Grammars Section 8). A document's `hushspec` field never carries a pre-release or build suffix; a specification document's own header may (`1.0.0-rc.1`) while it is a candidate.

## 3. Acceptance Rule

An engine declares the `major.minor` pairs it supports and MUST accept every document whose `hushspec` value is `major.minor.patch` for any patch of a supported pair, because patch releases never change document validity or evaluation semantics (Core Section 2.2). An engine MUST reject a document whose `major.minor` it does not support. Within a major version, an engine supporting minor `n` SHOULD also support every earlier minor of that major, since minors are additive.

## 4. The 0.x Series

The 0.x series was the development series. Breaking changes were permitted between minor versions; patch versions were editorial. Engines that support 0.x document versions treat them under the semantics of the last 0.x release (0.2), and the reference implementation continues to accept `0.1.z` and `0.2.z` documents after 1.0.0 because 1.0 changed nothing that those documents express.

## 5. The 1.x Series: What Is Frozen

From 1.0.0, within the major version 1, the following are frozen. A change to any of them is a major-version change.

| Surface | Defined in | Frozen meaning |
|---|---|---|
| Document format and validation | Core Sections 2, 3, 7; the JSON Schemas | A document valid under 1.n is valid under every later 1.m, with the same meaning. |
| Evaluation semantics | Core Sections 3, 5, 6; Posture, Origins, Detection | The decision, `matched_rule`, and rule trace for a given document and action do not change. |
| Canonical form and content hash | Canonical Form specification | The canonical bytes and hash of an existing document do not change. |
| Receipt, log entry, signature envelope, keyring, and bundle wire formats | Receipt, Log, Signing, Bundle specifications | Existing members keep their names, types, and meaning; producers may add optional members only as Section 6 allows. |
| Error and reason codes | `spec/registries/error-codes.yaml`; Signing Section 6.4 | A code's meaning never changes and a code is never reused. |
| Closed registries | `spec/registries/` entries marked `closed` | Membership changes only in a major version. |
| Grammars | Grammars specification | A string accepted by a production stays accepted. |

## 6. The 1.x Series: What a Minor Version May Change

A minor version MAY:

- Add optional fields to documents, provided that a document written for an earlier minor keeps its canonical content hash. Concretely, a new field's schema default MUST be "absent" (no `default` in the schema), or the new field MUST live inside a new optional object that earlier documents do not contain. A new field with a materialized default inside an existing object would change every existing hash and is therefore a major-version change.
- Add rule blocks, action types, and companion specifications, with their own vectors.
- Add entries to open registries (capabilities, detectors, frameworks) and add new registries.
- Add lint rules, CLI commands and flags, and conformance vectors that pin already-required behavior.
- Add optional members to wire formats, subject to the same hash-stability rule for the canonical form of receipts and log entries: a consumer of an earlier minor MUST be able to ignore them, and producers MUST omit them when they carry no value.
- Correct prose without changing behavior (also permitted in a patch).

A minor version MUST NOT remove or rename anything, change a default, tighten or loosen validation of existing documents, or change any decision an existing document and action produce.

## 7. Patch Versions and Errata

A patch version contains clarifications, editorial corrections, and errata (`errata.md`). It MUST NOT change document validity, evaluation semantics, canonical form, or any wire format. Where a patch corrects prose that an implementation had followed to the letter, the corrected prose is what the vectors pin; implementations that diverged were nonconformant already.

## 8. Extension Versioning

Extension modules are versioned with the core specification. A document's `hushspec` value names one release of the whole family; the posture, origins, and detection specifications carry that release number, and their vectors ship in the same conformance bundle. No extension declares a version inside a document, and the member name `version` under an extension block is reserved (Core Section 9.4). A future major version MAY introduce in-document extension versioning if extensions need to evolve independently; until then, adding to an extension follows Section 6 exactly as adding to the core does.

## 9. Schema Files

JSON Schema files are named `hushspec-<name>.v<major>.schema.json` and carry an `$id` under `https://hushspec.dev/schemas/`. The `v0` files describe the 0.x line and stay published unchanged for documents that declare a 0.x version. The 1.0.0 release publishes `v1` files with new `$id`s; within the 1.x series those files are edited only as Section 6 allows, so a `v1` `$id` is stable for the life of the major version. Consumers SHOULD resolve schemas by `$id`; editor integrations SHOULD reference the `v1` files once 1.0.0 is released.

## 10. Declaring 1.0.0

The 1.0.0 release is declared when every specification in the family carries the version `1.0.0` with status Stable, the conformance bundle for `1.0.0` is published, and every reference SDK accepts `1.0.z` documents. Until then, the family is a release candidate: engines treat a `1.0.z` document exactly as a `0.2.z` document, because 1.0 freezes the 0.2 semantics without changing them.

## 11. Conformance Across Versions

A conformance statement (`docs/src/reference/conformance-statement.md`) names the fixture version the implementation passed. Vectors are additive across minors: an implementation conformant at 1.n passes the 1.n bundle; the 1.(n+1) bundle contains every 1.n vector plus vectors for the additions.
