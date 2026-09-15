# HushSpec Receipt Log Specification

**Version:** 0.1 (Draft)
**Status:** Draft
**Date:** 2026-09-15
**Companion to:** Decision Receipt 0.2, Policy Signing 0.2, Canonical Form 0.2.0

---

## 1. Introduction

A decision receipt proves one evaluation. A receipt **log** proves a sequence of them: that nothing was removed, inserted, edited, or reordered between the first entry and the last, and which policy was in force at every point. This specification defines the log-entry format and the policy-in-effect record that a log carries alongside receipts.

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" are to be interpreted as described in RFC 2119.

## 2. Conformance

A writer conforms if every entry it emits validates against `schemas/hushspec-log-entry.v0.schema.json`, links to the previous entry as Section 4 requires, and carries a correct `entry_hash`. A verifier conforms if it accepts every file under `fixtures/log/valid/` and rejects every file under `fixtures/log/invalid/` with the first breaking line identified.

## 3. File layout

A log is a JSON Lines file: one entry per line, UTF-8, `\n`-terminated. Blank lines are ignored. Writers MUST append whole lines and MUST flush each line to durable storage before reporting the entry as written. A log file MUST have one writer at a time.

## 4. Entry structure

| Field | Required | Semantics |
|---|---|---|
| `log_version` | yes | `"0.1"`. Verifiers MUST reject unknown values. |
| `seq` | yes | 1 for the first entry of a file, then exactly +1 per entry. |
| `prev_hash` | yes | The previous entry's `entry_hash`. The first entry of a log that continues nothing carries the genesis value `sha256:` followed by 64 zeros. |
| `entry_type` | yes | `receipt`, `policy_loaded`, `policy_swapped`, or `log_started`. Exactly the payload member it names is present. |
| `receipt` | when `receipt` | A format 0.2 decision receipt, verbatim. |
| `policy_event` | when `policy_loaded` / `policy_swapped` | Section 6. |
| `log_started` | when `log_started` | Section 5. |
| `entry_hash` | yes | `sha256:` over the RFC 8785 canonical form (Canonical Form spec, Section 4; no projection) of the entry with `entry_hash` and `signature` removed. |
| `signature` | no | A policy-signature envelope (Signing spec, Section 4) whose `content_hash` is this entry's `entry_hash`. |

Because `prev_hash` is inside the hashed content, every entry's hash commits to the entire history before it. Editing any earlier line changes its `entry_hash` and breaks the link the next line declares.

## 5. Rotation

A writer MAY start a new file at any time. The new file's first entry MUST be a `log_started` entry with `seq: 1`, `prev_hash` equal to the previous file's last `entry_hash`, and `log_started.previous_entry_hash` repeating that value (with `previous_file` naming the file, when known). A verifier given the files in order MUST check that each file's first entry links to the previous file's last hash. A verifier given only the later file MUST accept the chain from `log_started.previous_entry_hash` onward; it cannot vouch for what came before.

## 6. Policy-in-effect records

An enforcement point MUST write a `policy_loaded` entry when it starts enforcing a policy and a `policy_swapped` entry when it replaces one (hot reload, panic policy), before any receipt evaluated under the new policy. The `policy_event` carries the same `policy` identity a receipt does (Receipt spec, Section 4.2: content hash, `extends_chain`, `signature` outcome), the `enforcement_mode` in force, the SDK name and version, and the HushSpec version the engine implements. `policy_swapped` also names the `previous_content_hash`. A reader can therefore map every receipt to the exact policy in force by walking back to the nearest policy event.

## 7. Signing

When a writer holds a signing key it SHOULD sign every entry: `signature` is the 0.2 envelope produced over the entry hash exactly as a policy signature is produced over a policy hash (Signing spec, Section 4.2), with `content_hash` set to `entry_hash`. A verifier with a keyring MUST verify every signed entry with the ordered checks of Signing spec Section 6.2 and MUST report a signed entry it cannot verify as a break. A verifier configured to require signatures MUST reject an unsigned entry (reason `entry_unsigned`).

## 8. Verification algorithm

For each file in order, for each non-blank line in order:

1. Parse the entry; unknown fields are a break.
2. `log_version` MUST be `"0.1"`.
3. `seq` MUST equal the expected value (1, then previous + 1).
4. Exactly the payload named by `entry_type` MUST be present.
5. For `seq` 1 of a continued file, the entry MUST be `log_started` and its `previous_entry_hash` MUST equal the previous file's last hash.
6. `prev_hash` MUST equal the previous entry's `entry_hash` (or the genesis value, or the carried hash).
7. Recomputing `entry_hash` from the canonical form MUST reproduce the stored value.
8. A `receipt` payload MUST carry `receipt_version` `"0.2"` and validate against the receipt schema.
9. `signature`, when present, MUST name this entry's `entry_hash` and verify against the keyring when one is supplied.

The first failing step identifies the break by file and line. Test vectors: `fixtures/log/valid/`, `fixtures/log/invalid/`.

## 9. Security considerations

- **Truncation.** Deleting entries from the end of a log leaves a valid chain. Detecting truncation needs an external anchor: the `entry_hash` a signer published, a receipt's presence in another system, or a `policy_swapped` entry expected on a schedule. Writers SHOULD publish the head hash periodically.
- **Key custody.** An entry signature proves the writer held the key; it does not prove the clock. Auditors weigh `timestamp` by the receipt's `time_source`.
- **Locking.** Two writers appending to one file interleave chains and corrupt both. The reference implementation uses a lock file and fails rather than bypasses a lock it cannot acquire.
