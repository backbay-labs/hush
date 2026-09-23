# Conformance Statement

A conformance statement is what an implementer publishes to say which
[conformance level](conformance.md) their engine reaches, against which corpus,
and with which caveats. It is a claim that can be checked: every line of it is
backed by a machine-readable report, and the report is backed by a corpus
pinned by digest.

Copy the template below, fill it in, and publish it wherever your users will
look for it — a `CONFORMANCE.md` in your repository, a page in your docs, or a
section of your security overview. Nothing about it requires our permission or
review; it requires only that the numbers are true.

## How to produce the evidence

1. **Get the corpus.** Download `hushspec-conformance-<version>.tar.gz` from a
   [HushSpec release](https://github.com/backbay-labs/hush/releases) and verify
   its build provenance attestation. The archive is reproducible: the same
   corpus always produces the same bytes.

2. **Verify the corpus before you use it**, so your results are about your
   implementation and not a corrupted download:

   ```bash
   python3 - <<'PY'
   import hashlib, json, pathlib
   manifest = json.load(open("fixtures/MANIFEST.json"))
   bad = [e["path"] for e in manifest["files"]
          if hashlib.sha256(pathlib.Path(e["path"]).read_bytes()).hexdigest() != e["sha256"]]
   print("corpus ok" if not bad else "MISMATCH: " + ", ".join(bad))
   raise SystemExit(1 if bad else 0)
   PY
   ```

   This verifies the listed files' bytes, not the provenance of the manifest
   itself. Obtain its expected digest through a trusted release channel. The
   external controller additionally rejects unlisted files and unsafe paths.

3. **Record the corpus digest.** `sha256sum fixtures/MANIFEST.json` is the
   `manifest_sha256` your report and your statement both cite.

4. **Run the vectors** against your implementation. Each level's vectors are
   the manifest entries whose `level` is at or below it. To test only HushSpec's
   reference implementation in Rust, use:

   ```bash
   hushspec-testkit --fixtures fixtures --report report.json
   ```

   This command does not invoke your engine, even if it is written in Rust.
   Arbitrary implementation identity overrides are rejected. For an external
   engine, use the [external controller](external-conformance.md) to invoke its
   captured executable and retain identity, inputs and outputs. It currently
   supports Linux static executables and L0-L3. The testkit version,
   corpus manifest digest and tested implementation identity are distinct.

5. **Emit a report** conforming to
   `schemas/hushspec-conformance-report.v1.schema.json`. Validate it with any
   JSON Schema 2020-12 validator before publishing. Publish it alongside the
   statement; the statement without the report is an assertion, not evidence.

## Rules for an honest statement

- **Claim only a fully passing level.** Levels subsume. If Level 3 fails, you
  do not have Level 4 even if every Level 4 vector passed.
- **`not_attempted` is not a pass.** A level whose vectors you did not run is
  not a level you reached. Say so in "Not claimed" below.
- **Name the corpus, not the version.** Two corpora can share a spec version.
  The manifest digest is what makes the claim reproducible.
- **List every deviation.** A vector you deliberately do not satisfy is a
  caveat, not an omission. Say which vector and why.
- **Date the run.** A claim is about a version of your software on a day.

---

## Template

```markdown
# HushSpec conformance statement — <Implementation name>

| | |
|---|---|
| **Implementation** | <name>, version <x.y.z> |
| **Language / runtime** | <e.g. Go 1.22> |
| **Claimed level** | Level <N> (<Parser / Validator / Merger / Evaluator / Auditor / Attested>) |
| **Specification version** | <e.g. 1.0.0> |
| **Corpus** | `hushspec-conformance-<version>.tar.gz` |
| **`manifest_sha256`** | `<64 hex characters>` |
| **Report** | <link to the conformance report JSON> |
| **Run on** | <YYYY-MM-DD> |
| **Statement author** | <name / team, contact> |

## Result

| Level | Name | Status | Passed | Failed | Not attempted |
|---|---|---|---|---|---|
| 0 | Parser | <pass/fail/not attempted> | | | |
| 1 | Validator | | | | |
| 2 | Merger | | | | |
| 3 | Evaluator | | | | |
| 4 | Auditor | | | | |
| 5 | Attested | | | | |

Copy these numbers from the `levels` object of the report; they must match it
exactly.

## Not claimed

<Every level above the claimed one, with one line on why: not implemented, not
applicable to this product, or planned for a named release. "Not attempted" is
a legitimate answer; leaving the row blank is not.>

## Deviations

<Every vector this implementation does not satisfy, by path, with the reason.
Write "None." if there are none — do not delete the section.>

## Scope

<What the claim covers: which entry points, which configuration. If the engine
reaches a level only in a particular mode (verification only at Level 5, say),
state it here.>

## How to reproduce

<The exact command or harness invocation that produced the report, and where
to get it.>
```

---

## A worked example

The reference implementation's own statement, for the shape of a filled-in one:

| | |
|---|---|
| **Implementation** | `hushspec` (the Rust crate), version 1.0.0 |
| **Language / runtime** | Rust 1.88+ |
| **Claimed level** | Level 5 (Attested) |
| **Specification version** | 1.0.0 |
| **Corpus** | the `fixtures/` tree of the commit under test |
| **Report** | produced by `hushspec-testkit --fixtures fixtures --report report.json` in CI |

Its "Deviations" section is `None.`, and its "Scope" says the claim covers the
library's public API and the `h2h` CLI, both of which run the same evaluator,
with the `signing` Cargo feature enabled. TypeScript, Python and Go reach
Level 5 too — Python with the `signing` extra installed. The vectors behind
each claim are in the [SDK Conformance Matrix](sdk-conformance.md).
