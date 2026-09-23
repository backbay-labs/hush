# Your first policy

A useful policy starts with the effects your runtime owns. The
[quickstart](getting-started.md) supplies one tested policy and five decisions.
This page explains that policy and how to extend it safely.

## Start with a complete document

Save [the tested policy](https://hushspec.org/docs-examples/quickstart/policy.yaml) as `policy.yaml`:

```yaml
hushspec: "1.0.0"
name: coding-agent-quickstart
rules:
  forbidden_paths:
    patterns: ["**/.env", "**/.ssh/**"]
  tool_access:
    allow: [read_file, search]
    block: [deploy]
    require_confirmation: [write_file]
    default: block
```

The version is a string. `name` is optional, but cannot be empty when present.
The `rules` object is closed: a misspelled rule does not silently disappear.

## Block sensitive paths

The `forbidden_paths` block applies to reads, writes and patches. Patterns use
portable path globs, not shell expansion. The host must map the real target path
and prevent symlink/TOCTOU bypasses when it opens files.

`**/.env` deliberately does not match every `.env.*` variant. Add the paths
your threat model actually requires and test both protected files and intended
exceptions. See [pattern grammars](../reference/patterns.md).

## Control tool access

The tool block uses exact names. Block entries take precedence; confirmation
entries are checked before the allowlist. Unknown tools fail this allowlist.
A `write_file` warning is not permission to execute automatically.

This does not authorize a known tool's hidden side effects. For host-owned MCP
tools, evaluate the tool gate and the mapped file/shell/network effects at the
appropriate execution boundaries. See [MCP integration](integrations/mcp.md).

## Add metadata

Use a meaningful name and description first. Governance `metadata` can carry
ownership and review information, but it never changes a decision or proves
who signed the policy. See [governance](governance.md).

## Add network and content controls

The quickstart intentionally leaves egress and secret detection unconfigured.
For a runtime that exposes them, add an `egress` block with an explicit
default and a `secret_patterns` block containing portable regexes. The
[rule reference](../rules-reference.md) supplies classified fragments and field
defaults. An allowed host does not exempt transmitted content from scanning.

## Add extensions only with trusted context

[Posture](../extensions/posture.md) needs host-owned state and counters.
[Origins](../extensions/origins.md) needs authenticated request context.
[Detection](../extensions/detection.md) adds analysis, not a guarantee of finding
every attack. Test missing context as well as expected context.

## Validate and test

```sh
h2h validate --strict policy.yaml
h2h test --policy policy.yaml policy.test.yaml
```

Use the [quickstart test file](https://hushspec.org/docs-examples/quickstart/policy.test.yaml).
Five cases pin read/search, protected path/deploy, and confirmation behavior.
Use `h2h explain` to inspect a changed result; it keeps the evaluation exit
code, including 1 for deny and 4 for warn.

## Extend a baseline deliberately

[Built-in rulesets](policy-library.md) resolve without network access.
A supplied child rule block replaces that entire base block. Review
`h2h resolve policy.yaml` and the effective policy diff before deployment.

## Next steps

Connect a [guard](runtime-integration.md), record [receipts](../receipt-spec.md),
and gate future policy changes in [CI](ci.md). A valid policy only controls
effects that your runtime actually routes through enforcement.
