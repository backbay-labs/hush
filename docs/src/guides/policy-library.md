# Policy library

Built-in policies are starting points, not compliance attestations. Choose a
baseline for the runtime you own, inspect the resolved result, and add tests for
your allowed and forbidden effects.

## Built-in rulesets

| Name | Starting posture |
| --- | --- |
| `default` | General-purpose baseline |
| `strict` | More restrictive baseline |
| `permissive` | Broad permissions for controlled development |
| `ai-agent` | Agent-oriented rules |
| `cicd` | CI/CD-oriented rules |
| `remote-desktop` | Computer-use and desktop rules |
| `panic` | Emergency deny policy |

Read the exact [ruleset sources](https://github.com/backbay-labs/hush/tree/v1.0.0/rulesets)
before selecting one. Inheritance replaces supplied core rule blocks; it does not
append to their arrays.

```yaml
hushspec: "1.0.0"
name: repository-agent
extends: builtin:ai-agent
rules:
  tool_access:
    allow: [read_file, search]
    require_confirmation: [write_file]
    block: [deploy]
    default: block
```

## Inspect and test

```sh
h2h resolve policy.yaml
h2h validate --strict policy.yaml
h2h test policy.test.yaml
```

Use [the quickstart test suite](getting-started.md) as the shape for your
test file. Review the full resolved policy whenever replacing a baseline block.
A child can intentionally weaken a base during inheritance; origin projection
is the separate mechanism that only narrows permissions.

## Domain-oriented templates

The `builtin:library/<vertical>/<name>` namespace includes general,
healthcare, finance, government, education, and DevOps templates.
For example, `builtin:library/general/recommended` is a general starting point.
See the [library catalog](https://github.com/backbay-labs/hush/tree/v1.0.0/library)
for names and rationale. Labels such as HIPAA or SOC 2 identify intended
control mappings, not a legal conclusion or audit opinion.

Built-in policy bytes can retain a supported 0.x version. Do not rewrite those
bytes merely for visual consistency: doing so changes hashes and evidence.
Your new authored leaf should use `1.0.0`.
