# Error reference

Use the code and the failing field, not only the exit status. `E004` means a
constraint violation; `E005` means a pattern is outside the portable regex profile.

```sh
h2h validate --format json policy.yaml
```

## Registered errors

Generated from the [error registry](../../../spec/registries/error-codes.yaml).
A parser that reports registry codes must use their registered meaning.

| Code | Summary | Phase | Meaning |
| --- | --- | --- | --- |
| `E000` | Input could not be read | io | The policy file does not exist, or reading it failed. A transport-level failure, not a statement about the document: nothing was parsed. |
| `E001` | YAML parse error | parse | The input is not a single YAML 1.2 Core document that deserializes into the HushSpec model. Covers syntax errors, YAML profile violations (anchors, merge keys, duplicate keys, multi-document streams; core Section 2.4), a missing required field, an unknown field at any nesting level, a value of the wrong type, and an unknown enum variant -- all of which are parse-time refusals because every HushSpec struct denies unknown fields. |
| `E002` | Unsupported hushspec version | validate | The document's `hushspec` field names a version this engine does not accept. An engine declaring support for `X.Y` accepts every `X.Y.*` (core Section 10), so this is reported only for an unknown major or minor, or for a value that is not a three-part version at all. |
| `E003` | Duplicate secret pattern name | validate | Two entries of `rules.secret_patterns.patterns` share a `name`. Names identify the matched rule in a decision and in a receipt's `rule_trace`, so they must be unique within a document (core Section 3.4). |
| `E004` | Constraint violation | validate | A structural constraint of core Section 7 or of an extension module is violated: a `when` condition that nests too deeply or names a bad timezone, day, or time; a posture `initial` that names no defined state; a posture timeout transition with no `after`; a duplicate origins profile id; an origins `match` enum value outside its module's set; a detection threshold outside its range; a `metadata.controls` entry with an ill-formed framework id or an empty `rule_paths`. |
| `E005` | Invalid regular expression | validate | A pattern field holds a regular expression outside the HushSpec regex profile (core Section 3.14): a construct the RE2 subset excludes (lookaround, backreferences), a non-leading inline flag group, a non-ASCII shorthand class, or a nested unbounded quantifier that would backtrack catastrophically on the SDKs with backtracking engines. |
| `E010` | Extends resolution failed | resolve | The `extends` chain could not be resolved: a reference no loader serves, a `#sha256:` pin that does not match the referenced document's content hash, a malformed pin, a cycle, a chain deeper than the depth cap, or a hop that fails a required signature check (core Section 2.3). |
| `E011` | Invalid governance date | validate | A `metadata` date field (`approval_date`, `effective_date`, `expiry_date`, `next_review_date`, a `changelog[].date`) is not an ISO 8601 calendar date (`YYYY-MM-DD`). Dates are compared as strings throughout the toolchain, so any other shape would compare wrong rather than fail, and an expired policy could read as current. |

## Next diagnostic

For syntax/type failures, reduce to the smallest invalid field; do not strip
unknown security fields to make a policy load. For resolution or signing
failures, retain the last known-good policy and inspect the load reason. See
[troubleshooting](../guides/troubleshooting.md) and [signing](../signing-spec.md).
