# CLI Reference

`h2h` is the reference command-line tool for HushSpec documents. It validates,
resolves, lints, formats, diffs, evaluates, signs and scaffolds policies, and
every subcommand is scriptable: machine-readable output through `--format json`
and exit codes that mean the same thing everywhere.

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
invalid regex, `E010` extends resolution failure.

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

## `h2h lint`

Static analysis for policies: empty rule blocks, overlapping patterns, shadowed
exceptions, over-broad egress, regex complexity, disabled rules, duplicates.

```bash
h2h lint policy.yaml
h2h lint --format json --fail-on-warnings policy.yaml
h2h lint policy.yaml --fix
h2h lint policy.yaml --dry-run
```

| Flag | Description |
|---|---|
| `<FILES>...` | One or more policy files; `-` reads stdin. |
| `-f, --format <text\|json>` | Output format (default `text`). |
| `--fail-on-warnings` | Exit `1` on warnings, not just errors. |
| `--fix` | Apply decision-neutral auto-fixes in place. Refused for `-`. |
| `--dry-run` | Show what `--fix` would change without writing. |

JSON findings carry `code`, `severity`, `message`, `location` and `fixable`;
each file also reports the `fixed` codes that `--fix` actually applied.

Exit: `0` clean · `1` findings (or a parse error) · `2` a write failed, or
`--fix` was pointed at stdin.

> `--fix` rewrites the file through the canonical formatter, which does not
> preserve comments. Run it on documents whose comments you can afford to lose,
> or review the `--dry-run` diff first.

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
- `--strip-comments` opts in to the old behavior and reformats anyway.
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
h2h eval policy.yaml --action-json '{"action_type":"tool_call","target":"bash"}'
h2h eval policy.yaml --action-file - --format receipt   # action from stdin
```

| Flag | Description |
|---|---|
| `<POLICY>` | Policy file or builtin reference. |
| `--type <TYPE>` | `file_read`, `file_write`, `patch_apply`, `shell_command`, `tool_call`, `egress`, `computer_use`, `input_inject`. |
| `--target <TARGET>` | Path, domain, tool name, command or channel. |
| `--content <STRING>` / `--content-file <PATH>` | Action content. |
| `--args-size <N>` | Serialized tool-argument size in bytes. |
| `--origin <KEY=VALUE>` | Origin context field (repeatable). |
| `--posture <STATE>` / `--signal <SIGNAL>` | Posture state and transition signal. |
| `--action-json <JSON>` / `--action-file <PATH>` | Full action document; `-` reads stdin. |
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
```

| Flag | Description |
|---|---|
| `<TESTS>...` | Fixture files or directories. |
| `--fixtures <PATH>` | Directory (or file) of fixtures to collect. |
| `-p, --policy <PATH>` | Policy that overrides the one embedded in fixtures. |
| `--sentinel <PATH>` | Panic sentinel to consult before evaluating. |
| `-f, --format <text\|tap\|json>` | Output format (default `text`). |

Exit: `0` all cases passed · `1` a case failed · `2` no fixture files were
found or the policy could not be read.

## `h2h audit`

Show a policy's governance metadata (author, approver, classification,
lifecycle, change ticket, effective and expiry dates) and run advisory
governance checks.

```bash
h2h audit policy.yaml
h2h audit policy.yaml --format json
```

| Flag | Description |
|---|---|
| `<FILE>` | Policy file to audit. |
| `-f, --format <text\|json>` | Output format (default `text`). |

Checks are advisory: a failing check is reported but does not by itself change
the exit code.

Exit: `0` report produced · `1` the document did not parse · `2` file not found
or unreadable.

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
h2h schema core > hushspec-core.v0.schema.json
h2h schema hushspec-receipt.v0.schema.json     # full file name also accepted
h2h schema --list
h2h schema --list --format json
```

| Flag | Description |
|---|---|
| `[NAME]` | `core`, `detection`, `evaluator-test`, `origins`, `posture`, `receipt`, `signature` — or the published file name. Required unless `--list`. |
| `--list` | List the available schemas instead of printing one. |
| `-f, --format <text\|json>` | Format for `--list` (the schema body is always JSON). |

Output is byte-identical to the corresponding file in `schemas/`.

Exit: `0` printed · `2` unknown schema name, or neither a name nor `--list`.

## `h2h sign` / `h2h verify` / `h2h keygen`

Ed25519 detached signatures over the raw policy bytes.

```bash
h2h keygen --output-dir ~/.hushspec
h2h sign policy.yaml --key h2h.key --signer security@example.com
h2h verify policy.yaml --key h2h.pub
```

| Command | Flags |
|---|---|
| `keygen` | `--output-dir <DIR>` (default `.`); writes `h2h.key` (mode `0600`) and `h2h.pub`. |
| `sign` | `<POLICY>`, `-k, --key <PATH>`, `--key-id <ID>`, `--signer <IDENTITY>`, `-o, --output <PATH>` (default `<POLICY>.sig`). |
| `verify` | `<POLICY>`, `-k, --key <PATH>`, `-s, --sig <PATH>` (default `<POLICY>.sig`). |

Signatures cover the file's exact bytes, so reformatting a signed policy
invalidates its signature — sign after `h2h fmt`, not before.

Exit: `0` signed / signature valid · `1` any failure (unreadable file, invalid
key, missing or invalid signature).

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
