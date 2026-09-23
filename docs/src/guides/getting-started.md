# Quickstart

Make your first policy decision in a few minutes, then put the same policy in
front of a real tool. This walkthrough uses synthetic paths and a local CLI;
it needs no model API, credentials, or production data.

## 1. Install

On macOS or glibc Linux (x64 or ARM64):

```sh
curl -fsSL https://hushspec.org/install.sh -o install-h2h.sh
sh install-h2h.sh --version v1.0.0
export PATH="$HOME/.local/bin:$PATH"
h2h --version
```

The installer verifies SHA-256 before extracting the executable, uses no sudo,
and changes no shell profile. Review the downloaded script before running it.
For Windows, Homebrew, npm, Cargo, containers and SDKs, see [installation](installation.md).

## 2. Create a workspace

Create an empty directory and save these two downloads there:
[policy.yaml](../../examples/quickstart/policy.yaml) and
[policy.test.yaml](../../examples/quickstart/policy.test.yaml).
Keep their filenames. Open `policy.yaml` in your editor.

The policy allows read/search tools, blocks `deploy`, requires confirmation for
`write_file`, and denies reads or writes targeting `.env` or `.ssh`.
It is a focused demonstration, not a complete shell/network sandbox.
[Your first policy](first-policy.md) explains every field.

## 3. Validate

Run from the directory containing the two files:

<!-- docs-run: quickstart -->
```sh
set -e
h2h validate --strict policy.yaml
```

A valid policy exits 0. Unknown fields and invalid values are refused.
Validation alone does not test the decisions you intended.

## 4. Evaluate

<!-- docs-run: quickstart -->
```sh
set -e
h2h eval policy.yaml --type tool_call --target search
h2h eval policy.yaml --type file_read --target /workspace/src/main.ts
```

Both decisions are `allow` (exit 0). Now check the negative paths.
The following commands intentionally capture nonzero statuses so an expected
denial is not mistaken for a broken tutorial.

<!-- docs-run: quickstart -->
```sh
h2h eval policy.yaml --type file_read --target /workspace/.env
result=$?
test "$result" -eq 1 || exit 1

h2h eval policy.yaml --type tool_call --target deploy
result=$?
test "$result" -eq 1 || exit 1

h2h eval policy.yaml --type tool_call --target write_file
result=$?
test "$result" -eq 4 || exit 1
```

| Action | Decision | Exit |
| --- | --- | --- |
| Search or ordinary read | `allow` | 0 |
| Protected path or deploy | `deny` | 1 |
| Write tool | `warn` | 4 |

`h2h eval` describes a proposed action. It does not run a tool or open those
paths. With no confirmation channel, a warning is recorded as blocked.

## 5. Explain the refusal

<!-- docs-run: quickstart -->
```sh
h2h explain policy.yaml --type file_read --target /workspace/.env
result=$?
test "$result" -eq 1 || exit 1
```

The winning match is `rules.forbidden_paths.patterns`. The trace shows which
other applicable rules ran or were skipped. A denial remains a denial even if
another rule allows.

## 6. Test the policy

<!-- docs-run: quickstart -->
```sh
set -e
h2h test --policy policy.yaml policy.test.yaml
```

Expected: **5 passed, 0 failed**. The test fixture's `hushspec_test: "0.1.0"`
is its current fixture format, not the policy version. Add a regression case
before changing a permission.

## 7. Integrate before dispatch

Choose [TypeScript](sdks/typescript.md), [Python](sdks/python.md),
[Rust](sdks/rust.md), or [Go](sdks/go.md). Each guide uses a real owned handler
and tests that a denial never calls it, an unconfirmed warning stays blocked,
and a confirmed warning calls it exactly once.

For MCP, start with [trusted action mapping](integrations/mcp.md). Do not treat
an adapter's evaluation result as proof that all server effects were mediated.

## Next steps

Read [runtime integration](runtime-integration.md) for enforcement and sink
failures, [receipts](../receipt-spec.md) for evidence, and [policy tests in
CI](ci.md) for safe changes. The [SDK API contract](../reference/sdk-api.md)
covers parsing, resolution, actors, providers and language-specific return types.
