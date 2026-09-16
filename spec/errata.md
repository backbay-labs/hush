# HushSpec Errata Process

**Version:** 1.0.0-rc.1
**Status:** Release Candidate
**Date:** 2026-09-15

---

## 1. What an Erratum Is

An erratum is a correction to specification prose that does not change what a conformant implementation does: an ambiguous sentence, a typo in a field name, a table that disagrees with the vectors, a missing cross-reference, an example that does not validate. Errata are folded into patch versions (`versioning.md`, Section 7).

A correction that would change document validity, evaluation semantics, the canonical form, or a wire format is not an erratum. It is a change proposal and follows `GOVERNANCE.md`.

## 2. Filing

1. Open an issue titled `Erratum: <specification> <section>` describing the sentence at fault, why it is wrong or ambiguous, and the proposed wording.
2. If a conformance vector already pins the intended behavior, cite it. If none does and the behavior is observable, propose a vector; the vector is added with the erratum so the corrected prose is enforced, not just stated.
3. A maintainer labels the issue `erratum` and assigns it the next number in the sequence `E-<year>-<n>` (for example `E-2026-003`).

## 3. Resolution

A pull request resolving an erratum:

- edits only prose, examples, grammars (`hushspec-grammars.md`), and vectors that pin already-required behavior;
- records the erratum in the "Errata" table of the affected specification's change appendix, with its number, the section, and one sentence stating the correction;
- bumps the affected specification's patch version in its header;
- adds a `Fixed` entry to `CHANGELOG.md`.

If review finds that the correction changes behavior after all, the pull request is closed and the issue is relabeled as a change proposal.

## 4. Disputes

When implementers disagree about what the prose meant, the conformance vectors decide: an implementation that passes the vectors was conformant, and the prose is corrected to match them. When no vector covers the point and implementations differ, the maintainers choose the fail-closed reading, add a vector, and record the choice as an erratum.

## 5. Register

Errata are listed in each specification's change appendix. There are none against `1.0.0-rc.1`.
