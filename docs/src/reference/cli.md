# CLI Reference

For executable conformance testing, see the separate
[`hushspec-testkit external` reference](external-conformance.md). Its execution
packet, supported platforms and exit semantics are separate from `h2h` below.

`h2h` is the reference command-line tool for HushSpec documents. It validates,
resolves, lints, formats, diffs, evaluates, signs and scaffolds policies, and
every reporting subcommand is scriptable: machine-readable output through
`--format json` and exit codes that mean the same thing everywhere. The
exceptions are `init`, `keygen`, `sign`, `panic` and `completions`, which
take no `--format`, and `hash`, whose `--format` selects `digest` or
`canonical`.

```bash
h2h --help            # subcommand list
h2h <command> --help  # flags for one command
h2h version           # CLI, build and spec versions
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success: the document is valid, the check passed, the action was allowed. |
| `1` | Policy-level failure: invalid document, lint findings, failing test cases, a denied action, a signature that did not verify, a refused rewrite, or a `--fail-on` class that was found. |
| `2` | Input or usage failure: file not found, unreadable input, a document `fmt` could not parse, an unknown flag or value (clap's own usage errors also exit `2`). |
| `4` | `eval` / `explain` only: the action's decision was `warn`. |

The split is deliberate: `1` means "the tool worked and the answer is no", `2`
means "the tool could not run the check at all". CI can therefore treat `2` as a
pipeline bug and `1` as a policy failure.

## Reading from stdin

`validate`, `lint` and `fmt` accept `-` in place of a path and read the document
from stdin. Diagnostics name it `<stdin>`.

```bash
cat policy.yaml | h2h validate -
kubectl get cm policy -o jsonpath='{.data.policy\.yaml}' | h2h lint -
h2h fmt - < policy.yaml > formatted.yaml
```

Two restrictions follow from stdin having no file to write back to:

- `h2h lint - --fix` is refused (exit `2`). Use `--dry-run` to see the diff, or
  write the document to a file first.
- `h2h fmt -` writes the formatted document to **stdout** and prints no status
  lines, so it can be used as a filter. (With `--format json` stdout carries the
  JSON summary instead, not the document.)

For `validate --strict`, a document read from stdin has no path to resolve
relative `extends` against, so relative references resolve from the working
directory. `builtin:` references work unchanged.

---

## `h2h validate`

Validate documents against the HushSpec schema: YAML parse, structural
validation, and (with `--strict`) extends resolution.

```bash
h2h validate rulesets/default.yaml
h2h validate --strict --format json policy.yaml
cat policy.yaml | h2h validate -
```

| Flag | Description |
|---|---|
| `<FILES>...` | One or more policy files; `-` reads stdin. |
| `-f, --format <text\|json>` | Output format (default `text`). |
| `--strict` | Also check that `extends` references resolve. |

Exit: `0` valid · `1` invalid · `2` a file was missing.

Error codes in the output: `E000` I/O, `E001` YAML parse, `E002` unsupported
version, `E003` duplicate pattern name, `E004` other validation error, `E005`
invalid regex, `E010` extends resolution failure, `E011` a `metadata` date that
is not an ISO 8601 calendar date (`YYYY-MM-DD`).

## `h2h resolve`

Print a policy with its `extends` chain fully resolved and merged — the exact
document an enforcement engine would evaluate. `extends` is consumed by the
merge, so the output has no `extends` key.

```bash
h2h resolve policy.yaml                 # canonical YAML on stdout
h2h resolve policy.yaml --format json   # same document as JSON
h2h resolve builtin:strict              # builtins work too
h2h resolve --strict policy.yaml        # warnings become failures
```

| Flag | Description |
|---|---|
| `<POLICY>` | Policy file, or a builtin reference (`builtin:default`). |
| `-f, --format <yaml\|json>` | Output format (default `yaml`). |
| `--strict` | Fail when the resolved document produces validation warnings, such as unknown extension keys (an unknown posture capability or budget key). |

The resolved document is validated before it is printed; a document that only
becomes invalid after merging (a duplicate pattern name contributed by two
layers, say) fails rather than being emitted. Warnings go to stderr, so
`h2h resolve policy.yaml > resolved.yaml` stays clean.

Exit: `0` success · `1` parse, resolve or validation failure (including strict
warnings) · `2` the policy file was not found.

## `h2h hash`

Print a policy's **content hash** — the portable identity defined by the canonical form
specification (`spec/hushspec-canonical.md`). Two parties holding the same policy get the
same digest in every SDK, regardless of which optional keys the author omitted or which
language wrote the file.

```bash
h2h hash policy.yaml                      # sha256:<64 hex>
h2h hash policy.yaml --format canonical   # the RFC 8785 JSON the digest covers
h2h hash builtin:default                  # builtins work too
h2h resolve policy.yaml | h2h hash -      # read an already-resolved document
```

| Flag | Description |
|---|---|
| `<POLICY>` | Policy file, a builtin reference (`builtin:default`), or `-` for stdin. |
| `-f, --format <digest\|canonical>` | Print the `sha256:` digest (default) or the canonical JSON text it is computed over. |
| `--strict` | Fail when the document produces validation warnings. |

The hash covers the **resolved** document, so a policy that declares `extends` is resolved
through the same chain `h2h resolve` walks before it is hashed. Changing a base therefore
changes the identity of every policy that extends it, even when the child file is
untouched — that is the point: the enforced policy changed. `merge_strategy` is a
resolution field and never appears in the canonical form.

The document is validated first: an invalid document has no canonical form, because a
digest for something no engine would accept is worse than no digest at all.

Exit: `0` success · `1` parse, resolve, validation or canonicalization failure · `2` the
policy file was not found.

## `h2h lint`

Static analysis for policies: empty rule blocks, overlapping patterns, shadowed
exceptions, over-broad allow lists, regex complexity, disabled rules,
duplicates, control mappings, credential coverage, permissive defaults and
unreachable extension configuration.

```bash
h2h lint policy.yaml
h2h lint --format json --fail-on-warnings policy.yaml
h2h lint --format sarif --out lint.sarif policy.yaml
h2h lint policy.yaml --fix
h2h lint policy.yaml --dry-run
```

| Flag | Description |
|---|---|
| `<FILES>...` | One or more policy files; `-` reads stdin. |
| `-f, --format <text\|json\|sarif>` | Output format (default `text`). |
| `--out <PATH>` | Write the report to a file instead of stdout (`json` and `sarif` only). |
| `--fail-on-warnings` | Exit `1` on warnings, not just errors. |
| `--fix` | Apply decision-neutral auto-fixes in place. Refused for `-`. |
| `--dry-run` | Show what `--fix` would change without writing. |

Exit: `0` clean · `1` findings (or a parse error) · `2` a file was missing or
unreadable, a write failed, the report could not be serialized, `--out` was
combined with `--format text`, or `--fix` was pointed at stdin.

> `--fix` rewrites the file through the canonical formatter, which does not
> preserve comments. Run it on documents whose comments you can afford to lose,
> or review the `--dry-run` diff first.

### Source positions

Every finding is located at the **key or list entry it is about**, not at the
file. Text output prints `file:line:column` followed by the document path:

```
warning[L008]: rules.egress.allow[1]: duplicate pattern "api.example.com"
  --> rulesets/example.yaml:8:9
   | rules.egress.allow[1]
```

Positions come from a second pass over the same bytes with a real YAML event
parser (`saphyr-parser`), which keeps quoted keys, block scalars, flow
sequences and comments between entries correctly aligned — a line scanner does
not. Lint reports the **resolved** document, so a finding about a block a policy
inherits names the base that declares it:

```
warning[L004]: rules.egress.allow[0] contains wildcard pattern "*" ...
  --> builtin:permissive:9:9
   | rules.egress.allow[0]
```

JSON findings carry `code`, `severity`, `message`, `location`, `fixable`, the
document `path`, and a `span` object (`file`, `line`, `column`, `end_line`,
`end_column`; 1-based, with `end_column` pointing at the character after the
region). Each file also reports the `fixed` codes that `--fix` actually applied.
A finding whose key could not be located — an inherited default no document
writes, or a base fetched over HTTP — omits `span` and still carries `location`.

### SARIF

`--format sarif` emits a SARIF 2.1.0 document: one run, a `tool.driver` for
`h2h` carrying the full rule catalog below (each with `shortDescription`,
`fullDescription` and a `defaultConfiguration.level`), and one `result` per
finding with `ruleId`, `level`, `message`, a `physicalLocation` region, a
`logicalLocations` entry naming the document path, and — for fixable findings —
a `fixes` entry describing the deletion `--fix` would perform. Severities map
`error → error`, `warning → warning`, `info → note`.

```bash
h2h lint --format sarif --out lint.sarif rulesets/*.yaml
```

Upload the file with `github/codeql-action/upload-sarif` and findings appear as
code-scanning annotations on the pull request that introduced them. This repo's
own `Policy Lint` job does exactly that.

### Lint rules

Severity is a function of provability. `error` means the document contains
configuration that can never take effect under the spec's own rules; `warning`
means a construct defeats something else the same document declares; `info`
means the construct is coherent but easy to arrive at by accident. Two codes
(`L016`, `L018`) report at two severities for exactly that reason — see their
rows.

| Code | Level | Rule | Why it fires |
|---|---|---|---|
| `E000` | error | file-unreadable | The path does not exist, or the file is not readable UTF-8. Nothing was linted. |
| `E001` | error | parse-error | YAML parsing or deserialization failed. HushSpec rejects unknown keys, so a typo in a field name lands here rather than being silently ignored. |
| `E010` | error | unresolvable-extends | A base could not be loaded, the chain is circular or too deep, or a pinned digest did not match. Lint reports the resolved document, so an unresolvable chain leaves nothing to lint. |
| `L001` | warning | empty-rule-block | The block is enabled but declares nothing to allow or deny, so it makes no decision. A block that looks like enforcement and is not is worse than an absent one. |
| `L002` | warning | overlapping-patterns | Sampled synthetic targets matched two patterns in the same list. Overlap is not itself a defect, but a redundant pair is dead weight. |
| `L003` | warning | shadowed-exception | A `forbidden_paths` exception re-permits a path that nothing denies, so it has no effect. |
| `L004` | warning | overly-broad-allow | `allow: ["*"]` permits every target, which makes the rest of the list decorative. |
| `L006` | warning | regex-complexity | Nested quantifiers are a ReDoS risk; very long or heavily alternated patterns are hard to review. |
| `L007` | info | disabled-rule | `enabled: false` makes a block inert, which **permits** what it would otherwise govern. Reported for all twelve rule blocks, so a disabled control is never invisible. |
| `L008` | warning | duplicate-pattern | A byte-identical repeat of an earlier entry contributes nothing. The one finding whose removal is provably decision-neutral, so `--fix` always applies it. |
| `L009` | info | missing-secret-patterns | Without secret detection, a `file_write` carrying a credential is indistinguishable from any other write. |
| `L010` | warning | unreachable-allow | Block takes precedence over allow, so an entry in both can never decide anything. |
| `L011` | warning | unmapped-rule-block | Once a policy maps controls, an unmapped block is enforcement with no stated reason. Policies that map nothing are silent. |
| `L012` | error | broken-control-mapping | A mapping claims a control is implemented through a rule path that resolves to nothing — a false compliance claim. |
| `L013` | warning | unregistered-control | The framework is not in `spec/registries/frameworks.yaml`, or the control id does not match that framework's pattern. The registry is advisory, so this is an unverifiable claim, not an invalid document. |
| `L014` | warning / info | credential-paths-uncovered | `.env`, `.ssh`, `.aws`, `.gnupg`, `.kube` and `id_rsa` are where agent credentials actually live, and the message names the ones a denylist does not reach. A policy running a `path_allowlist` is silent (everything outside it is already denied). A policy with **neither** block reports `info`: a capability-scoped document meant to be composed onto a base legitimately says nothing about the filesystem. |
| `L015` | warning | under-graded-credential-pattern | Severity drives what an engine does with a match, so a pattern that recognizes an AWS key id (`AKIA`/`ASIA`), a GitHub token (`gh[opsur]_`, `github_pat_`), a PEM private key header or an OpenAI `sk-` key and grades it below `critical` has downgraded a credential leak to a note. |
| `L016` | warning / info | overbroad-forbidden-pattern | Forbidden patterns are unanchored, so `.*`, `.+`, a bare single character, or anything matching the empty string matches every command or diff. Beside other patterns that is a defect — they become dead — and reports `warning`. As the **only** entry in its list it is a coherent deny-all (the sole way this block can express one) and reports `info`. |
| `L017` | warning | permissive-default | `egress.default: allow` permits every host outside `block`, making the allow list decorative; `tool_access.default: allow` with empty `block` and `require_confirmation` permits every tool. Supersedes `L005`, which reported the same shape as `info` and only when the allow list was non-empty; `L005` is retired and will not be reused. |
| `L018` | warning / info | empty-capability-allowlist | `enabled: false` makes a block inert, which *permits* the capability, so `enabled: true` with an empty allowlist is the spec's only way to deny one outright — reported `info` (this is what `rulesets/panic.yaml` does deliberately). Promoted to `warning` where the document contradicts itself (`computer_use.allowed_actions` permits `input.inject` while `input_injection.allowed_types` is empty) or where the block does nothing at all (`computer_use` in `observe` mode with nothing allowed: observe never denies). |
| `L019` | error | unreachable-extension | A posture state that is neither `initial` nor the target of any transition is never entered; a transition naming an undefined state never fires; an origin profile with no `match` object is never a candidate ([origins spec §3](../extensions/origins.md)) and one repeating an earlier profile's `match` always loses the document-order tie; a literal overlay `allow` entry the base allowlist does not match can never allow anything (origins spec §4.1, overlay allowlists intersect). |
| `L021` | warning | ungranted-capability | A `when.capability` naming a capability no posture state grants can never be true while the policy has a posture extension, so the block is permanently inert. Without a posture extension the predicate is unevaluable and the block stays active (core spec 3.13), so nothing is reported. |
| `L022` | warning | empty-list-entry | An empty string in `tool_access.allow`, `block`, or `require_confirmation`, or in an origins overlay list, can never match a tool or host (core spec 3.3, 3.7) and is usually an editing mistake. |
| `L020` | info | inert-condition | The engine reads `start == end` as an always-open 24-hour window and an empty `days` as every day, so a window written that way reads like a restriction and is not one. Listing all seven days is likewise the default. An `all_of`/`any_of` with no members is always true. (There is no "never true" window to report: core spec 3.13 keeps a block active when a window cannot be evaluated.) |

## `h2h fmt`

Format policies canonically: fixed rule-block order, sorted and de-duplicated
lists, consistent quoting.

```bash
h2h fmt policy.yaml
h2h fmt --check policy.yaml        # CI gate, does not write
h2h fmt --diff policy.yaml         # unified diff of what would change
h2h fmt - < policy.yaml            # filter mode
h2h fmt --strip-comments policy.yaml
```

| Flag | Description |
|---|---|
| `<FILES>...` | One or more policy files; `-` reads stdin and writes stdout. |
| `--check` | Report without writing; exit `1` if anything would be reformatted. |
| `--diff` | Print a unified diff instead of writing. |
| `--strip-comments` | Reformat even though comments will be discarded. |
| `-f, --format <text\|json>` | Output format (default `text`). |

### Comments

Canonical formatting is a structural re-render, so every comment except a
leading `# yaml-language-server:` modeline would be lost. Audited policies carry
control-mapping comments (`# --- 45 CFR 164.312(a)(1): Access Control ---`), so
`fmt` refuses to rewrite a document that has any other comment:

```
error refusing to reformat hipaa-base.yaml: 25 comment line(s) would be
discarded (first at line 2); pass --strip-comments to reformat anyway
```

- A refused rewrite exits `1` and leaves the file untouched.
- `--check` and `--diff` report `has comments; would not reformat` and treat it
  as a skip, not a failure — a commented policy does not fail a `fmt --check` CI
  gate.
- `--strip-comments` discards the comments and reformats anyway.
- The modeline alone never triggers the refusal; it is preserved verbatim.

JSON output carries `has_comments`, `comment_count`, `first_comment_line` and
`skipped` alongside `changed` and `diff`.

Exit: `0` formatted or already formatted · `1` `--check` would reformat, or a
rewrite was refused to protect comments · `2` file missing, unreadable,
unparseable, or a write failed.

## `h2h diff`

Compare two policies by *effective decision*: probes are generated from both
documents' rules, evaluated against each, and only decision changes are shown.

```bash
h2h diff old.yaml new.yaml
h2h diff old.yaml new.yaml --format json
h2h diff main.yaml pr.yaml --fail-on relaxed   # CI guard
```

| Flag | Description |
|---|---|
| `<OLD> <NEW>` | Base and updated policy files. |
| `-f, --format <text\|json>` | Output format (default `text`). |
| `--sentinel <PATH>` | Panic sentinel to consult before evaluating. |
| `--fail-on <relaxed\|tightened\|any>` | Exit `1` when a change of that class is present. |

Each change is classified from the old and new decisions:

| `change_type` | Transition | Class |
|---|---|---|
| `relaxed` | deny/warn → allow | relaxing |
| `demoted` | deny → warn | relaxing |
| `tightened` | allow → warn/deny | tightening |
| `escalated` | warn → deny | tightening |
| `unchanged` | same decision | neither |

`--fail-on relaxed` therefore catches anything that can turn a deny into an
allow or a warn, `--fail-on tightened` catches the reverse, and `--fail-on any`
catches both. Without the flag `diff` is purely informational and exits `0`.

Exit: `0` no matching change · `1` a matching change was found · `2` a policy
could not be loaded.

## `h2h eval` / `h2h explain`

Evaluate a single action against a policy. `explain` is `eval` with the
rule-by-rule trace forced on.

```bash
h2h eval policy.yaml --type egress --target api.example.com
h2h explain builtin:default --type file_read --target /etc/passwd
h2h eval policy.yaml --action-json '{"type":"tool_call","target":"bash"}'
h2h eval policy.yaml --action-file - --format receipt   # action from stdin
```

| Flag | Description |
|---|---|
| `<POLICY>` | Policy file or builtin reference. |
| `--type <TYPE>` | `file_read`, `file_write`, `patch_apply`, `shell_command`, `tool_call`, `egress`, `computer_use`, `input_inject`, `browser_action`, `code_exec`, `custom`. Any other type is denied fail-closed. |
| `--target <TARGET>` | Path, domain, tool name, command or channel. |
| `--content <STRING>` / `--content-file <PATH>` | Action content. |
| `--args-size <N>` | Serialized tool-argument size in bytes. |
| `--origin <KEY=VALUE>` | Origin context field (repeatable). |
| `--url <URL>` | `browser_action`: navigation destination. |
| `--network` | `code_exec`: the call requests network access. |
| `--timeout-ms <MS>` | `code_exec`: requested execution time in milliseconds. |
| `--context <JSON\|@PATH>` | Runtime context for `when` conditions: inline JSON object or `@PATH` to a YAML/JSON file. |
| `--posture <STATE>` / `--signal <SIGNAL>` | Posture state and transition signal. |
| `--action-json <JSON>` / `--action-file <PATH>` | Full action document; `-` reads stdin. Conflicts with every flag above: the document carries the whole action. |
| `--sentinel <PATH>` | Panic sentinel to consult before evaluating. |
| `--explain` | Render the trace (implied by `h2h explain`). |
| `-f, --format <text\|json\|receipt>` | Output format (default `text`); `receipt` emits a full decision receipt. |

Exit: `0` allow · `1` deny · `4` warn · `2` the policy or action could not be
loaded.

## `h2h test`

Run evaluation test suites (`*.test.yaml` fixtures).

```bash
h2h test --fixtures fixtures/core/evaluation
h2h test policy.test.yaml --format tap
h2h test --policy policy.yaml --fixtures ./tests
h2h test --fixtures fixtures/library --fail-on-uncovered \
  --format junit --report-file target/library-suites.xml
```

| Flag | Description |
|---|---|
| `<TESTS>...` | Fixture files or directories. |
| `--fixtures <PATH>` | Directory (or file) of fixtures to collect. |
| `-p, --policy <PATH>` | Policy that overrides the one embedded in fixtures. |
| `--sentinel <PATH>` | Panic sentinel to consult before evaluating. |
| `-f, --format <text\|tap\|json\|junit>` | Output format (default `text`). |
| `--report-file <PATH>` | Write the report in `--format` here; stdout then carries the readable summary. |
| `--fail-on-uncovered` | Exit non-zero when a declared rule path was never hit. |

Fixtures are validated against
[`hushspec-evaluator-test.v0`](./json-schema.md) before any case runs, and both
fixture-format versions are accepted: `0.1.0`, and `0.2.0` with its per-case
`controls` / `tags` and its `expect.rule_trace` / `expect.receipt` assertions.
A case that declares either assertion is checked against the receipt the
document produces under the fixed inputs of
`fixtures/receipts/expected/README.md`.

**Rule coverage.** Every run compares the rule paths each policy under test
*declares* -- every rule block of the resolved document, plus every named
secret pattern -- with the paths a *passing* case hit, through `matched_rule`
and through each `rule_trace` entry's `rule_path`. A failing case credits
nothing: coverage says a control was exercised, and a case that failed showed
the opposite. A path inside a block credits
the block, so `rules.egress.allow` covers `rules.egress` and
`rules.secret_patterns.patterns.ssn` covers both the block and that pattern.
The table prints after the run; `--fail-on-uncovered` turns a gap into a
non-zero exit, which is how the library suites are gated in CI.

**JUnit.** `--format junit` emits one `<testsuite>` per fixture file and one
`<testcase>` per case, carrying each case's controls and tags as
`<property name="control">` / `<property name="tag">` and each failure as a
`<failure>` with the expected and actual values. A final `rule coverage`
suite reports the declared/covered counts per policy, and fails there too
under `--fail-on-uncovered`.

**JSON.** `--format json` prints an object: `passed`, `failed`, `fixtures[]`
(per file, with each case's `controls` and `tags`), and `coverage` with the
per-policy `declared`, `covered` and `uncovered` paths.

Exit: `0` all cases passed · `1` a case failed, or a declared rule path was
never hit under `--fail-on-uncovered` · `2` an argument named neither a file
nor a directory, no fixture files were found, a fixture did not match the
schema, or the policy could not be read.

## `h2h audit`

Show a policy's governance metadata (author, approver, classification,
lifecycle, change ticket, effective and expiry dates), run the governance
checks, and optionally print the control → rule-path matrix.

```bash
h2h audit policy.yaml
h2h audit policy.yaml --format json
h2h audit policy.yaml --controls        # control -> rule-path matrix + coverage
h2h audit policy.yaml --strict          # every finding is fatal
```

| Flag | Description |
|---|---|
| `<FILE>` | Policy file to audit. |
| `-f, --format <text\|json>` | Output format (default `text`). |
| `--controls` | Also report the control → rule-path matrix and rule-block coverage. |
| `--strict` | Exit non-zero when a check fails, a governance finding is reported, or a control rule path does not resolve (L012). |

Every governance check that fires is listed with its code, severity and the
document path it concerns — `GOV_SOD_VIOLATION` (author is also the approver),
`GOV_UNAPPROVED_STATE`, `GOV_REVIEW_OVERDUE`, `GOV_CHANGELOG_ORDER`,
`GOV_EXPIRED`, `GOV_LIFECYCLE`, `GOV_MISSING_APPROVAL_DATE`,
`GOV_RESTRICTED_NO_APPROVER` (core spec 2.5). Warnings are advisory: without
`--strict` they are reported and the command still exits `0`. The one
error-severity finding, `GOV_SELF_SUPERSEDES`, fails the audit either way,
because `h2h validate` rejects that document too.

Exit: `0` report produced · `1` the document did not parse, an error-severity
finding fired, or `--strict` saw a failing check or finding · `2` file not
found or unreadable.

## `h2h init`

Scaffold a `.hushspec/` directory with a starter policy and test suite.

```bash
h2h init --preset strict
h2h init --dir ./service-a --preset default
```

| Flag | Description |
|---|---|
| `--preset <permissive\|default\|strict>` | Starter policy (default `default`). |
| `--dir <PATH>` | Where to create `.hushspec/` (default `.`). |

Exit: `0` created · `1` the directory already exists or could not be written.

## `h2h schema`

Print a published HushSpec JSON Schema. The schemas are embedded in the binary,
so this works offline and from an installed release.

```bash
h2h schema core > hushspec-core.v1.schema.json
h2h schema hushspec-receipt.v1.schema.json     # full file name also accepted
h2h schema core.v0                              # the frozen 0.x lineage
h2h schema --list
h2h schema --list --format json
```

| Flag | Description |
|---|---|
| `[NAME]` | A short name for the current `.v1.` lineage — `core`, `posture`, `origins`, `detection`, `evaluator-test`, `hash-vector`, `receipt`, `log-entry`, `signature`, `keyring`, `bundle`, `report`, `error-codes`, `merge-vector` — the same name with a `.v0` suffix for the frozen 0.x file (`core.v0`), or the published file name. Required unless `--list`. |
| `--list` | List the available schemas instead of printing one. |
| `-f, --format <text\|json>` | Format for `--list` (the schema body is always JSON). |

Output is byte-identical to the corresponding file in `schemas/`.

Exit: `0` printed · `2` unknown schema name, or neither a name nor `--list`.

## `h2h sign` / `h2h verify` / `h2h keygen`

Ed25519 detached signatures, envelope format 0.2
([`spec/hushspec-signing.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-signing.md)).

```bash
h2h keygen --output-dir ~/.hushspec
h2h sign policy.yaml --key ~/.hushspec/h2h.key.pem --expires-in 90d --signer security@example.com
h2h verify policy.yaml --keyring ~/.hushspec/keyring.json --last-seen-version 4
```

| Command | Flags |
|---|---|
| `keygen` | `--output-dir <DIR>` (default `.`), `--name <NAME>` (default `h2h`), `--convert <OLD_KEY>`, `--force`; writes `<NAME>.key.pem` (PKCS#8, mode `0600`) and `<NAME>.pub.pem` (SPKI), and prints the `key_id`. |
| `sign` | `<POLICY>`, `-k, --key <PATH>`, `--expires-in <DURATION>` (`30d`, `12h`, `90m`, `3600s`), `--policy-version <N>`, `--signer <IDENTITY>`, `-o, --out <PATH>` (default `<POLICY>.sig`), `--allow-unapproved`. |
| `verify` | `<POLICY>`, `-s, --sig <PATH>`, `-k, --key <PATH>` **or** `--keyring <PATH>`, `--now <TIMESTAMP>`, `--max-skew <SECONDS>` (default `300`), `--last-seen-version <N>`, `-f, --format <text\|json>`. |

### What is signed

The envelope covers the **content hash of the resolved policy**, not the file's
bytes — the same digest `h2h hash` prints. So reformatting a signed policy keeps
its signature valid, and a change to a base policy reached through `extends`
invalidates every signature over the policies that extend it, because the
enforced policy changed. `sign` resolves and validates the chain first and
refuses to sign when it cannot.

### Keys and trust

Keys are standard PEM: PKCS#8 private, SubjectPublicKeyInfo public — exactly
what `openssl genpkey -algorithm ed25519` and `openssl pkey -pubout` produce. A
key is named by `sha256:` plus the digest of its SPKI DER, and `verify`
recomputes that id from the public key rather than trusting a keyring's claim.

`--keyring` takes a [keyring document](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-keyring.v1.schema.json)
listing the trusted keys, each of which may carry `not_after` (retire a key
without invalidating older signatures) or `revoked: true` (reject everything it
signed). `--key` is the one-key shorthand.

### Reason codes

A failed `verify` prints the reason code of the first check that failed, the
same string a receipt's `policy.signature.reason` carries:

`malformed_envelope`, `unsupported_format_version`, `unsupported_algorithm`,
`unknown_key_id`, `key_revoked`, `key_retired`, `signed_at_in_future`,
`expired`, `signature_mismatch`, `content_hash_mismatch`,
`policy_version_rollback`.

### Migrating from 0.1

HushSpec 0.1 signed raw file bytes with bespoke 32-byte key files. Convert the
key with `h2h keygen --convert old.key` and re-sign: a 0.1 signature attests
something 0.2 does not claim, so `verify` reports
`unsupported_format_version` and says to re-sign rather than failing obscurely.

`sign` refuses a policy whose `metadata.lifecycle_state` is not `approved` or
`deployed`, and a policy that does not parse: a signature is a durable
attestation that this exact document was approved, so signing a draft would
attest something that never happened. `--allow-unapproved` overrides the gate
for development.

Exit: `0` signed / signature valid · `1` a signing or verification failure
(invalid key or keyring, any reason code) · `2` usage (missing policy or
signature file, nothing to trust, unparseable `--now` or `--expires-in`).

## `h2h panic`

File-sentinel kill switch. While the sentinel exists, evaluating subcommands
(`eval`, `explain`, `test`, `diff`) deny every action.

```bash
h2h panic activate --sentinel /tmp/hushspec.panic
h2h panic status --sentinel /tmp/hushspec.panic
h2h panic deactivate --sentinel /tmp/hushspec.panic
```

| Subcommand | Description |
|---|---|
| `activate` | Create the sentinel file. |
| `deactivate` | Remove it. |
| `status` | Report whether panic mode is active. |

All three take `--sentinel <PATH>` (default `.hushspec_panic` in the working
directory).

Exit: `activate`/`deactivate` return `0` on success and `1` on an I/O failure;
`status` returns `1` when panic mode is **active** and `0` when it is not, so a
script can gate on it directly.

## `h2h completions`

Generate a shell completion script on stdout.

```bash
h2h completions bash > /etc/bash_completion.d/h2h
h2h completions zsh  > "${fpath[1]}/_h2h"
h2h completions fish > ~/.config/fish/completions/h2h.fish
h2h completions powershell | Out-String | Invoke-Expression
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

Exit: `0` generated · `2` unknown shell.

## `h2h version`

Print the CLI version alongside build and spec provenance.

```bash
h2h version
h2h version --format json
h2h --version          # clap's short form, CLI version only
```

| Field | Meaning |
|---|---|
| `version` | `h2h` crate version. |
| `git_sha` | Short git SHA of the build, or `unknown` when built without git metadata (a published source tarball, for example). |
| `spec_version` | HushSpec version this build writes. |
| `supported_spec_versions` | Every document version this build accepts. |
| `target` | Rust target triple the binary was built for. |

Exit: always `0`.

## Evidence chain

### Verify-on-load flags (`eval`, `explain`, `resolve`)

| Flag | Meaning |
|---|---|
| `--require-signature` | Every non-builtin document in the `extends` chain must carry a detached signature that verifies, or a matching `#sha256:` pin. A policy that does not verify is refused: `eval` emits a deny receipt with `matched_rule: __hushspec_policy_unverified__` and `policy.signature.verified: false`, and exits 1. |
| `--keyring <PATH>` / `--key <PATH>` | Trusted keys (keyring JSON, or one SPKI PEM). With `--keyring` and no `--require-signature`, verification runs opportunistically and the outcome is recorded in the receipt. |
| `--now`, `--max-skew`, `--last-seen-version` | Verifier clock, allowed signer skew, rollback floor (signing spec 6). |

Digest pins: `extends: "builtin:default#sha256:<hex>"` is checked always; the pinned value is the base's *own* content hash, which `h2h hash <policy> --own` prints. A mismatch is reported as `digest_mismatch` (exit 2 on `eval`).

### Receipt fields on `eval`

| Flag | Meaning |
|---|---|
| `--agent-id`, `--session-id`, `--principal` | The `actor` recorded in the receipt (`runtime` is always `h2h/<version>`). |
| `--monitor` | Record the disposition in monitor mode (`would_block` instead of `blocked`). |
| `--log <PATH>` | Append a `policy_loaded` entry and the receipt to a hash-linked log (log spec). |
| `--log-key <PATH>` | Sign every log entry with this Ed25519 private key. |

### `h2h log verify <files...>`

Checks a hash-linked log: sequence continuity, `prev_hash` links, `entry_hash` recomputation, payload/entry-type agreement, receipt schema validity, and entry signatures. Pass rotated files oldest first; each continued file must start with a `log_started` entry that names the previous file's last hash.

| Flag | Meaning |
|---|---|
| `--keyring` / `--key` | Verify entry signatures. |
| `--require-signatures` | Every entry must be signed and verify. |
| `--now`, `--max-skew` | Verifier clock and skew. |
| `--format json` | Machine-readable report. |

Exit 0 when the chain verifies, 1 at the first break (reported as `file:line: reason`), 2 for unusable inputs.

### `h2h receipts verify <files...>`

Validates receipts from `.jsonl` logs, JSON receipt files, or signed receipts (`{receipt, signature}`). With `--policy`, every receipt must name that policy's canonical content hash, and receipts whose action can be replayed (no content, not `browser_action`/`code_exec`) have their decision re-derived under the posture state the receipt records, and a recorded `origin` or `context` the engine cannot read back fails the check rather than being replayed without it. With `--keyring`/`--key`, signatures are verified; `--require-signatures` makes an unsigned receipt a failure.

Exit 0 when every receipt passes, 1 otherwise, 2 for unusable inputs.

### `h2h hash --own`

Prints the document's own content hash with `extends` and `merge_strategy` stripped and no resolution: the value a digest pin names and a receipt records for a chain link.

## `h2h report <files...>`

Aggregates recorded policy decisions, enforcement outcomes and mapped rule activity over a window. Ordinary mode is exploratory; a rule/control mapping is not an assessment conclusion. Use an explicit evidence profile for authenticated, stream-scoped reporting.

```bash
h2h report audit.jsonl                                     # the whole log, as tables
h2h report audit.jsonl --since 2026-09-01T00:00:00Z --until 2026-09-30T23:59:59Z
h2h report audit.jsonl --policy library/healthcare/hipaa-base.yaml --by control
h2h report audit.jsonl --format json > report.json         # validates against the report schema
h2h report audit.jsonl --format csv --out ./evidence/      # one CSV per table
```

Input is a hash-linked log (`policy_loaded` / `policy_swapped` events plus `receipt` entries), a plain receipt JSONL, or signed receipts (`{receipt, signature}`) -- classified line by line. A file holding any log entry is a log and is chain-verified as a whole, so a plain receipt among log entries is reported as a mixed file and breaks the chain rather than slipping past verification. A line that is neither is refused with its file and line number (exit 2); `--lenient` skips it instead and records the count as `totals.skipped_lines`. A receipt whose `timestamp` is not RFC 3339 counts as malformed: a record that will not place itself in time cannot be placed in a window.

When the input is a log, its chain is verified before anything is counted (the same checks as `h2h log verify`, the receipt schema pass and the entry signatures included, each file on its own -- checking the link *between* rotated files is `h2h log verify`'s job, and it takes them oldest first). A chain that does not verify refuses to report (exit 1) unless `--unverified` is passed, and the report is then stamped `chain_verified: false`.

| Flag | Meaning |
|---|---|
| `--since` / `--until <TIMESTAMP>` | RFC 3339 bounds on receipts and policy events. Both inclusive. The window narrows what is *counted*, never what is *verified*. |
| `--policy <PATH>` | Join `metadata.controls` (core spec 2.5.1) against the receipts. Without it, a policy named by a log's `extends_chain` is resolved when it still resolves from here. |
| `--format text\|json\|csv\|oscal` | Default `text`. |
| `--by control\|rule\|decision\|policy` | Report on one table only; also picks the table `--format csv` writes to stdout. |
| `--out <PATH>` | A directory for `--format csv` (one CSV per table), a file for every other format. |
| `--lenient` | Skip unparsable lines instead of refusing. |
| `--unverified` | Report on a log whose chain did not verify. |
| `--keyring <PATH>` | Trusted keyring JSON for entry signatures. Without one, signed entries are counted but not verified. |
| `--key <PATH>` | A single trusted public key (PEM), as a one-key keyring. Mutually exclusive with `--keyring`. |
| `--require-signatures` | Legacy mode: log entries only, not standalone receipt envelopes. Every log entry must carry a verifying signature; an unsigned entry or missing keyring breaks the chain. Strict mode always authenticates every declared record. |
| `--max-skew <SECONDS>` | Allowed signer clock skew while verifying entry signatures (default 300). |
| `--now <TIMESTAMP>` | Stamp `generated_at` with this instead of the wall clock (reproducible reports). It is also the verifier's clock for entry signatures, so a report pinned to an instant verifies them as of the moment it describes. |
| `--top-paths <N>` | How many `rule_path`s each rule-block row lists (default 5). |
| `--experimental-oscal` | Required by `--format oscal`. |
| `--evidence-profile <PATH>` | Experimental strict profile. Requires JSON or contextual OSCAL, exactly one key/keyring, `--out` and `--verification-out`. |
| `--verification-out <PATH>` | New verification sidecar file; published last as the completion marker. |
| `--assessment-context <PATH>` | OSCAL only: local manifest binding AP, SSP and resolved catalog. |
| `--native-report-out <PATH>` | OSCAL only: new accompanying native JSON report. |
| `--max-evidence-file-bytes <N>` | Strict-only file cap: default 16 MiB, maximum 1 GiB. |
| `--max-evidence-total-bytes <N>` | Strict-only shared input budget: default 64 MiB, maximum 1 GiB. |
| `--max-evidence-line-bytes <N>` | Strict-only JSONL line cap: default 1 MiB, maximum 16 MiB. Require `0 < line <= file <= total`. |

### What it aggregates

- **Totals** by decision (`allow`/`warn`/`deny`), by enforcement mode (`enforce`/`monitor`), and by disposition (`allowed`/`confirmed`/`blocked`/`would_block`).
- **Per rule block**: evaluated and skipped trace entries, `fired` (an evaluated entry whose outcome was not `allow`, so exactly warn + deny), the deny and warn split, and the most frequent `rule_path`s.
- **Per action type**, **per policy `content_hash`** with first and last seen, and the **`policy_loaded` / `policy_swapped` timeline**.
- **Per actor** (`agent_id` / `session_id` / `principal`).
- **Signature status** as each receipt recorded it at load time, with failures grouped by reason.
- **Detections** by `detector_id`, with the level histogram and how many findings met a threshold.
- **Control evidence**, with `--policy`: for each framework and control, the `rule_paths` it maps to, the rule blocks those were observed under, and the receipts / evaluations / fired / denied counts with a last-seen timestamp -- plus `unmapped_fired_rule_blocks`, the blocks that fired with no control behind them (lint L011's static gap, observed dynamically).

A mapping that names a rule block (`rules.egress`) is evidenced by everything that block recorded. A deeper mapping (`rules.egress.block`) is only evidenced by an evaluation whose recorded `rule_path` is at or under it, so a control is never credited with an evaluation that matched the allowlist instead. Only receipts naming the policy's own content hash count toward its controls; the report says how many did (`receipts_matching_policy`).

### Formats

`--format json` emits one document validated by [`schemas/hushspec-report.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-report.v1.schema.json) (`h2h schema report`). `--format csv` with `--out <dir>` writes `totals.csv`, `rule_blocks.csv`, `action_types.csv`, `policies.csv`, `policy_timeline.csv`, `actors.csv`, `signatures.csv`, `detections.csv`, and -- with `--policy` -- `controls.csv` and `unmapped_rule_blocks.csv`; without `--out` it writes the single table `--by` names to stdout.

`--format oscal --experimental-oscal` requires the strict profile, trusted keys,
`--assessment-context`, `--native-report-out`, `--out`, and
`--verification-out`. The pinned OSCAL 1.1.2 exporter emits receipt-derived
`EXAMINE` observations, not findings, risks or objective satisfaction. It
validates both the local AP/SSP/catalog context and generated result. Older
experimental commands without context now fail; `--unverified` is prohibited.

Strict mode authenticates captured source bytes before window filtering,
verifies ordered rotations per stream, checks policy transitions and optionally
matches independently obtained inventory. Completeness remains not-established
without that inventory. Supplied optional policy signatures must still verify.
The sidecar binds native report, profile, trust-input and source byte digests;
an unsigned sidecar is not itself an attestation. Native `signatures` retains
runtime-reported policy-signature semantics. Multi-policy controls are separate
interval summaries in the sidecar.

Strict outputs must be distinct new files in one existing operator-controlled
directory; no input aliases or overwrites. Files must match the profile's
flattened source order. Strict mode rejects `--lenient`, `--unverified`, `--by`,
stdout, negative clock skew and mismatched explicit windows. `--policy` may only
select an already-declared resolved artifact. See [Evidence Verification](../guides/evidence-verification.md)
for runnable examples, bounds, trust assumptions and publication/crash limits.

Exit 0 when the report was produced, 1 for a broken chain without `--unverified`, 2 for unusable inputs or flags.

Strict mode also uses exit 1 for digest, signature, signer-role, duplicate
receipt, policy-binding and required-boundary failures; context/output/limit
errors use exit 2. Refused strict inputs publish no success packet.

Vectors: [`fixtures/report/`](https://github.com/backbay-labs/hush/tree/main/fixtures/report) -- a synthetic 24-hour log and the exact report it must produce.

## `h2h bundle`

Policy bundle attestation ([bundle spec](../bundle-spec.md)). A bundle is a DSSE
envelope whose payload is an in-toto Statement v1: the subject is the canonical
form of the *resolved* policy, and the predicate carries that document, every
`extends` hop with its own hash and signature status, and the resolver that
produced them. It is signed with the same Ed25519 keys as policies and receipts,
so `h2h keygen` output works unchanged.

### `h2h bundle create <policy>`

Resolves the policy (builtin references included), validates the merged
document, builds the statement, and signs it.

| Flag | Meaning |
|---|---|
| `--key <PATH>` | PEM PKCS#8 Ed25519 **private** key that signs the bundle. Without it the bundle is unsigned: it still carries the evidence, attests nothing, and `h2h bundle verify` rejects it -- so `create` warns. |
| `--keyring <PATH>` | Trusted keys used to verify the *policy's own* signature while loading it. The outcome is recorded in `predicate.signature_verification` and per chain link. Omitted keyring means no verification was attempted, and those members are absent rather than `false`. |
| `--require-signature` | Refuse to bundle unless every non-builtin hop carries a verifying signature or a matching `#sha256:` pin. |
| `--max-skew <SECONDS>` | Allowed signer clock skew while verifying on load (default 300). |
| `--created-at <TIMESTAMP>` | Pin `predicate.created_at` instead of reading the clock. With it, the same policy, key and resolver produce a byte-identical bundle: JCS payload plus deterministic Ed25519. |
| `--subject-name <NAME>` | Override the subject label (defaults to the policy's `name`, then the leaf file name). |
| `--out <PATH>` | Output path (defaults to `<policy file name>.bundle.json` in the working directory). |
| `--format json` | Machine-readable summary. |

Filesystem chain sources are recorded relative to the working directory when
they lie beneath it, so a bundle built in CI carries no runner workspace path.

Exit 0 on success, 1 when the policy will not resolve, will not validate, or is
refused by `--require-signature`, 2 for unusable inputs.

### `h2h bundle verify <bundle.json>`

Runs the four ordered checks of bundle spec 5.2 and stops at the first failure.

| Flag | Meaning |
|---|---|
| `--keyring <PATH>` / `--key <PATH>` | Trusted keys (keyring JSON, or one SPKI PEM taken as a one-key keyring). One of the two is required. |
| `--policy <PATH>` | Re-resolve this policy and assert the bundle attests it (check 4): the canonical forms must match and every chain hop's hash must match, in order. Chain `source` labels are not compared -- the same policy resolved on another host is the same policy. |
| `--now <TIMESTAMP>` | Verifier clock. A bundle carries no expiry, so this only stamps `verified_at` in the report. |
| `--format json` | Machine-readable report carrying `valid` and, on failure, `reason` and `detail`. |

| Reason code | Check |
|---|---|
| `malformed_bundle` | 1: not a well-formed envelope, statement, or predicate; an unknown `predicateType` or `bundle_version` lands here. |
| `unknown_key_id` | 2: no signature names a key in the keyring. |
| `key_revoked` | 2: the only keys that signed are revoked in the keyring. |
| `key_retired` | 2: the only keys that signed were retired before `predicate.created_at`. |
| `dsse_signature_mismatch` | 2: a usable key was found but no signature verifies over the PAE. An unsigned bundle reports this. |
| `subject_digest_mismatch` | 3: `predicate.resolved` does not hash to the declared subject. |
| `policy_mismatch` | 4: `--policy` resolves to something else, or does not resolve at all. |

Exit 0 on `valid`, 1 with the reason code otherwise, 2 for unusable inputs.

### `h2h bundle inspect <bundle.json>`

Prints the predicate summary -- subject, content hash, policy identity,
resolver, `created_at`, every chain hop with its signature status, and the
signing key ids -- without verifying anything. `--format json` prints the whole
decoded statement.

Exit 0, or 1 when the bundle cannot be decoded.
