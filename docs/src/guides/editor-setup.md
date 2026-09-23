# Editor setup

Connect your YAML editor to the v1 schema for completion, hover descriptions and
structural validation. Then run `h2h validate --strict` and policy tests: editor
validation does not resolve inheritance, enforce a policy or prove decisions.

## Use a modeline

Add this first line to any policy filename. It works with editors using the
YAML language server's schema modeline, including VS Code with a YAML extension.

```yaml
# yaml-language-server: $schema=https://hushspec.org/schemas/hushspec-core.v1.schema.json
hushspec: "1.0.0"
name: editor-example
```

Evaluator-test files use
`https://hushspec.org/schemas/hushspec-evaluator-test.v1.schema.json`.
`h2h init` writes schema modelines in its scaffolds, and `h2h fmt` preserves them.

## Map a workspace explicitly

In VS Code, merge this JSON into `.vscode/settings.json`; preserve your existing
settings and narrow the glob to your own policy directory:

```json
{
  "yaml.schemas": {
    "https://hushspec.org/schemas/hushspec-core.v1.schema.json": [
      "policies/*.yaml"
    ]
  }
}
```

In JetBrains IDEs, create a JSON Schema mapping for the same URL and file pattern.
Other YAML-aware editors can use a modeline or a language-server schema mapping.
Automatic filename discovery depends on your editor and its catalog version;
explicit association avoids that dependency.

HushSpec-specific names such as `hushspec.yaml`, `.hushspec.yaml` and
`*.hushspec.yaml` also make policies easier to identify. Do not apply the core
policy schema to every YAML file in a repository.

## Filename associations

The [prepared catalog entries](https://github.com/backbay-labs/hush/blob/main/docs/schemastore-entry.json)
define these exact associations. Automatic discovery still depends on your
editor's catalog version; use the explicit mapping above when it is unavailable.

| Entry | Schema | Matches |
| --- | --- | --- |
| HushSpec | core policy | `hushspec.yaml` / `hushspec.yml`, `.hushspec.yaml` / `.hushspec.yml`, `*.hushspec.yaml` / `*.hushspec.yml` |
| HushSpec Evaluator Test | evaluator test | `*.hushspec.test.yaml` / `*.hushspec.test.yml`, `**/fixtures/**/*.test.yaml` |
| HushSpec Decision Receipt | receipt | `*.receipt.json` |
| HushSpec Log Entry | log entry | `*.log-entry.json` |
| HushSpec Policy Bundle | bundle | `*.bundle.json` |

The default `policy.yaml` and `policy.test.yaml` files from `h2h init` rely on
their schema modelines, not these filename patterns. A standalone log-entry
JSON file is distinct from a JSONL stream.

## Validate JSON evidence and logs

Select the appropriate [published schema](../reference/json-schema.md) for a
receipt, keyring, bundle or individual log entry. A JSONL log contains multiple
JSON documents: validating it against the single-entry schema is not log
verification. Use `h2h log verify receipts.jsonl` for chain continuity and add
your keyring/signature requirements when authenticating it.

## Work offline or pin a release

`h2h schema --list` lists embedded schemas; `h2h schema core` prints the exact
core schema shipped in that binary. Save it locally and associate your editor
with that file for offline work.

The public [schema index](https://hushspec.org/schemas/index.json) records source
commit and digests. A release-pinned fallback is:

```text
https://raw.githubusercontent.com/backbay-labs/hush/v1.0.0/schemas/hushspec-core.v1.schema.json
```

Current v1 schema IDs use `.org`. Frozen v0 schemas retain their historical
`.dev` identifiers and are retrievable from the `.org` mirror; the project
does not operate the legacy `.dev` host. Do not silently rewrite IDs in old
evidence when configuring retrieval.

## Check what your editor cannot

Run `h2h validate --strict policy.yaml` to include resolution, then execute
your [policy tests](getting-started.md#6-test-the-policy). Test both permission
and refusal paths. A green editor gutter is not a runtime enforcement result.
