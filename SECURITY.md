# Security Policy

HushSpec declares the security rules an AI agent runtime operates under. A vulnerability
in the specification or its reference implementations can mean a policy that looks
restrictive is not actually enforced. We treat these reports as high priority.

## Supported Versions

Security fixes are made against the `main` branch and released in the next version of the
`1.x` series. Support tracks the current major version: the latest `1.x` release of each
component is supported, and earlier releases receive no backports.

| Component | Version | Supported |
|---|---|---|
| Specification (`spec/`, `schemas/`) | latest `1.x` | Yes |
| Rust (`hushspec`, `hushspec-cli` / `h2h`) | latest published | Yes |
| TypeScript (`@hushspec/core`) | latest published | Yes |
| Python (`hushspec`) | latest published | Yes |
| Go (`hushspec`) | latest published | Yes |
| Anything older than the latest release | -- | No |

The reference implementation accepts `0.1.z` and `0.2.z` documents
([`spec/versioning.md`](./spec/versioning.md) Section 4), so a fail-open bug reachable
through a 0.x document is in scope; the 0.x releases themselves are not.

## Scope

In scope:

- The specification and JSON Schema documents (`spec/`, `schemas/`) -- e.g. a normative
  rule that is ambiguous or non-fail-closed in a way that lets a forbidden action be
  allowed.
- The four reference SDKs (`crates/hushspec`, `packages/hushspec`, `packages/python`,
  `packages/go`) -- e.g. a parsing, validation, merge, resolution, evaluation, detection,
  or signing bug that causes an action to be allowed when the policy says it should be
  denied (a **fail-open** bug), a ReDoS-vulnerable regex path, path-traversal or SSRF in
  policy loaders, or a signature-verification bypass.
- The `h2h` CLI and `hushspec-testkit`.
- Built-in and library policies (`rulesets/`, `library/`) that ship with the project.

Out of scope:

- Vulnerabilities in how a downstream project *enforces* the decisions HushSpec returns
  (HushSpec defines *what* is allowed, not *how* it is enforced at the tool boundary).
- Third-party dependencies -- report those upstream, though we welcome a heads-up so we
  can track and update pinned versions.
- Issues that require an attacker to already control the policy file's author (HushSpec's
  threat model assumes the policy author is trusted; a malicious policy author can always
  author a permissive policy).

If you are unsure whether something is in scope, report it anyway and we will triage it.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately using GitHub's private vulnerability reporting feature on this repository:

1. Go to <https://github.com/backbay-labs/hush/security/advisories/new>, or
2. From the repository, open the **Security** tab -> **Advisories** -> **Report a
   vulnerability**.

Include, where possible:

- A description of the vulnerability and its impact (in particular, whether it causes a
  **fail-open** decision -- an action that should have been denied or warned being allowed).
- Steps to reproduce, a minimal policy document, and the action being evaluated.
- The affected component(s) and version(s) / commit SHA.
- Whether the issue reproduces across multiple SDKs or is specific to one.

## Disclosure Timeline

We aim to follow this timeline from the point a report is submitted through GitHub
private vulnerability reporting:

| Milestone | Target |
|---|---|
| Acknowledgment of the report | 3 business days |
| Initial triage and severity assessment | 7 business days |
| Fix or mitigation developed | Depends on severity; fail-closed regressions and fail-open bugs are treated as highest priority |
| Coordinated disclosure / advisory publication | After a fix is released, or 90 days from acknowledgment, whichever is sooner, unless the reporter and maintainers agree to a different timeline |

We will credit reporters in the published GitHub Security Advisory unless you ask to
remain anonymous. We do not currently operate a paid bug bounty program.

## Fail-Closed Design

HushSpec's core design philosophy is fail-closed: invalid documents must be rejected at
parse time, and ambiguous rules must deny access. A bug that causes an evaluator to
**allow** an action it should deny or warn on is considered a security vulnerability even
if it does not otherwise meet a classic definition of "vulnerability" (e.g. memory safety,
injection). Please report these through the process above rather than as a regular bug.
