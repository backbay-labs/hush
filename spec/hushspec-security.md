# HushSpec Security Considerations

**Version:** 1.0.0-rc.1
**Status:** Release Candidate
**Date:** 2026-09-15
**Applies to:** the whole HushSpec specification family

---

## 1. Introduction

HushSpec documents are security policy: they decide what an AI agent may do, and receipts and logs are the evidence that a policy was enforced. This document collects the threats that the family's design addresses, the residual risks an operator must manage, and the requirements that exist because of them. Each companion specification has a short security section that points here for the shared material.

The design principle behind every requirement below is fail-closed (Core Section 1.2): when an implementation cannot be sure, it denies, refuses, or reports an error; it never silently allows.

## 2. Regular-Expression Denial of Service

Policies carry user-authored regular expressions in several rule blocks, and detectors run patterns over attacker-controlled content. Catastrophic backtracking would let an attacker stall an enforcement point with a crafted input.

Requirements: the regex profile (Core Section 3.14.3; Grammars Section 9) excludes backreferences, lookaround, and nested unbounded quantifiers, and caps pattern length, so every conforming pattern is matchable in time linear in the input on an RE2-class engine. Validators MUST reject non-conforming patterns; evaluators MUST deny when a pattern fails to compile at evaluation time, and an engine that bounds matching time MUST deny on timeout. Content scanned by `secret_patterns`, `patch_integrity`, `shell_commands`, and the detection pipeline is truncated to the configured byte budgets before matching.

Residual risk: a host regex library that silently accepts a superset of the profile. The differential fuzzer and the regex-dialect vectors exist to catch such drift.

## 3. Path Traversal and Normalization

`forbidden_paths` and `path_allowlist` decide by matching paths. An unnormalized path (`/proj/../.env`, backslashes, doubled separators, NFD text) can slip past a pattern written for the normalized form.

Requirements: targets are normalized lexically before matching (Core Section 3.14.1): NFC, `\` to `/`, collapsed separators, `.` and `..` resolved without consulting the filesystem, trailing separator removed. Wildcards never cross `/`. Matching is byte-wise case-sensitive.

Residual risk: lexical normalization cannot see symlinks or case-insensitive filesystems. An enforcement point that opens the file after the decision SHOULD present the canonical on-disk path to the evaluator, SHOULD refuse to follow symlinks out of the allowed tree, and MUST accept that a time-of-check to time-of-use window exists between evaluation and the filesystem operation; the receipt records the path as requested, not the path finally opened.

## 4. Remote Resolution and Server-Side Request Forgery

An `extends` reference to an HTTPS URL makes the enforcement point fetch a document at policy-load time, which an attacker who controls a policy or a DNS answer could aim at internal services.

Requirements (Core Section 2.6.4): HTTPS only with certificate verification on; addresses checked after DNS resolution, refusing loopback, private, link-local, unspecified, and unique-local ranges including IPv4-mapped IPv6 forms; no redirects; bounded body and time; digest pins (Core Section 2.3) and detached signatures (Signing Section 6.5) for integrity and authenticity. Engines without a loader MUST refuse URL references rather than treat them as paths.

Residual risk: DNS rebinding between the check and the connection. Loaders that can pin the resolved address for the connection SHOULD do so; operators SHOULD prefer digest pins or signatures over trust in the transport, and SHOULD load remote policies at deployment time rather than per request.

## 5. Policy Integrity and Authenticity

A policy on disk or in transit can be edited to weaken it. Signing (Signing specification) binds a policy's canonical content hash to a key, and verification on load refuses a policy that fails to verify when signatures are required.

Requirements: signatures cover the canonical form of the resolved document, never file bytes, so reformatting cannot invalidate a signature and a base policy swapped underneath a child cannot pass. Verifiers check envelope shape, format and algorithm, key membership, revocation and retirement, `signed_at` against the verifier's clock with a bounded skew, `expires_at`, the signature itself, the content hash, and `policy_version` monotonicity for rollback protection, in that order, and report a stable reason code. A pinned digest satisfies the requirement for a hop; a matching pin plus a broken envelope still records the envelope's failure.

Residual risk: key compromise. Keyrings support `not_after` and `revoked`; operators SHOULD rotate keys, keep private keys out of the enforcement point, and treat `policy_version` as a monotonic counter they never reuse.

## 6. Clock Trust

Signature validity windows, receipt timestamps, `expires_at`, and log entry ordering all read a clock.

Requirements: verifiers apply a bounded clock skew and expose the reason codes `signed_at_in_future` and `expired` rather than a generic failure. Receipts carry `time_source` so an auditor can discount timestamps from an untrusted clock. Ordering inside a log comes from sequence numbers and hash links, never from timestamps.

## 7. Log Tampering and Rotation

A receipt log is evidence only if it cannot be edited after the fact.

Requirements (Log specification): every entry carries a sequence number, the previous entry's hash, and its own hash over its canonical form; an entry MAY be signed; rotation carries the chain across files through a `log_started` entry; verifiers report the first break by file and line. Chained sinks write with `fsync` and an exclusive lock so two writers cannot interleave.

Residual risk: an attacker with write access to the log and to the signing key can rewrite history from a point onward. Operators SHOULD ship entries to an append-only remote sink (the OTLP exporter or an equivalent) as they are written, so that a local rewrite diverges from the remote copy, and SHOULD verify chains from a trusted head.

## 8. Receipt Content Privacy

Receipts are shared with auditors and telemetry systems. Action content (file bodies, tool arguments, prompts) is frequently sensitive.

Requirements: a receipt carries `content_hash` and `content_size`, never the content, and the schema has no member for it; `origin` and `context` are recorded as supplied, and a runtime that redacts a context value MUST drop the key rather than substitute a placeholder. Detection traces carry scores and levels, not the matched text.

Residual risk: `target` strings (paths, hosts, tool names) and `reason` strings are recorded verbatim and may themselves be sensitive; operators SHOULD treat receipt logs as confidential.

## 9. Detection Limits

Detectors are heuristics. A false negative lets an injection through; a false positive blocks legitimate work and trains operators to loosen thresholds.

Requirements: the normative heuristic detector is fully specified so its behavior is the same everywhere and can be reasoned about; every detector's contribution is recorded in the receipt with its score and level; detection never weakens a decision made by a rule block. Policy authors SHOULD set thresholds from measured behavior on their own traffic and SHOULD keep `secret_patterns` and `shell_commands` rules as the primary controls rather than rely on detection alone.

## 10. Monitor Mode

Monitor mode evaluates without enforcing. It is the right tool for rolling out a policy, and the wrong one to forget about.

Requirements (Core Section 6.2): monitor mode MUST be refused without a receipt sink or an observer, so shadow decisions are always recorded as `would_block`; panic mode and a refused policy are always enforced; the receipt's `enforcement` disposition makes a monitored deny distinguishable from an enforced one. Operators SHOULD alert on `would_block` outcomes and SHOULD time-box monitor rollouts.

## 11. Panic Sentinel

The panic sentinel (Core Section 6.3) is a file whose presence denies everything. Its power cuts both ways: an attacker who can create the file has a denial-of-service lever, and one who can delete it cannot disarm an already-latched engine, but can prevent activation from taking effect on a fresh process.

Requirements: checking the sentinel fails closed when existence cannot be determined; the latch does not disarm on absence. Operators SHOULD place the sentinel where only the operator can write, SHOULD monitor its creation, and SHOULD prefer the programmatic latch in multi-tenant processes.

## 12. Canonicalization Pitfalls

Every hash in the family is over a canonical form. Two implementations that disagree on the projection or the serialization produce receipts that cannot be joined and signatures that cannot be verified.

Requirements (Canonical Form specification): defaults are materialized from the published schemas, absent objects are never invented, empty no-default containers are omitted, and serialization follows RFC 8785. Adding a defaulted field to a schema changes the canonical form of documents that omit it; the versioning policy (`versioning.md`) therefore requires that a minor version's new fields materialize only when present, or defines the default as absence, so existing hashes stay stable.

Residual risk: floating-point formatting. Implementations MUST use the ES6 number formatting RFC 8785 specifies and MUST NOT emit numbers that lose precision on round trip.

## 13. Supply Chain of the Policy Itself

A policy bundle (Bundle specification) wraps the resolved policy, its chain, and its verification state in a signed in-toto statement, so that what was enforced can be attested independently of the enforcement point. Bundles for shipped policies are attested in the release pipeline. Operators SHOULD verify a bundle against the policy they deploy and SHOULD pin the bundle's subject digest in their own deployment records.

## 14. Reporting

Vulnerabilities in the specifications or in the reference implementations are reported as described in `SECURITY.md` at the repository root.
