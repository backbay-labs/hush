# JSON Schema

HushSpec provides JSON Schema files for document validation. These schemas are the machine-readable counterpart to the prose specification and can be used with any JSON Schema validator.

## Available Schemas

The schemas are in the [`schemas/`](https://github.com/backbay-labs/hush/tree/main/schemas) directory:

| File | Description |
|------|-------------|
| `hushspec-core.v0.schema.json` | Core HushSpec document schema (v0.x): rules, extensions, metadata, `when` conditions |
| `hushspec-posture.v0.schema.json` | Posture extension schema (v0.x) |
| `hushspec-origins.v0.schema.json` | Origins extension schema (v0.x) |
| `hushspec-detection.v0.schema.json` | Detection extension schema (v0.x) |
| `hushspec-evaluator-test.v0.schema.json` | Evaluation test fixture format used by `h2h test`, the testkit, and every SDK's shared-fixture runner. Format `0.2.0` adds per-case `controls` and `tags` and the `expect.rule_trace` / `expect.receipt` assertions; `0.1.0` fixtures stay valid |
| `hushspec-hash-vector.v0.schema.json` | Canonical-form test vector format ([`fixtures/core/hash/`](https://github.com/backbay-labs/hush/tree/main/fixtures/core/hash)); see the [canonical form spec](../canonical-spec.md) |
| `hushspec-receipt.v0.schema.json` | Decision receipt format 0.2; see the [receipt spec](../receipt-spec.md) |
| `hushspec-log-entry.v0.schema.json` | Hash-linked log entry (receipts and policy events) written by chained sinks and checked by `h2h log verify` |
| `hushspec-signature.v0.schema.json` | Detached policy signature envelope 0.2; see the [signing spec](../signing-spec.md) |
| `hushspec-keyring.v0.schema.json` | Trusted keyring consumed by verify-on-load and `h2h verify --keyring` |
| `hushspec-bundle.v0.schema.json` | Policy bundle attestation (DSSE envelope with an in-toto statement) produced by `h2h bundle create` |
| `hushspec-framework-registry.v0.schema.json` | Schema for [`spec/registries/frameworks.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/frameworks.yaml), the compliance frameworks `metadata.controls[].framework` may name |
| `hushspec-error-codes.v0.schema.json` | Schema for [`spec/registries/error-codes.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/error-codes.yaml) and for the `<name>.expect.yaml` sidecars that pin the code each `invalid/` vector is rejected with |
| `hushspec-merge-vector.v0.schema.json` | The merge-vector directory convention under `fixtures/*/merge/` (`base.yaml`, `child-*.yaml`, `expected-*.yaml`, optional `fixture.yaml`) |
| `hushspec-conformance-report.v0.schema.json` | Conformance report emitted by `hushspec-testkit --report`; see [Conformance Levels](conformance.md) |

Every schema is embedded in the `h2h` binary; `h2h schema --list` prints the names and `h2h schema <name>` prints one to stdout.

## Where the schemas are served

Each schema declares its own `$id`, and that `$id` is the URL it is published
at:

```
https://hushspec.dev/schemas/<file>
```

The docs deployment (`.github/workflows/docs.yml`) copies `schemas/` into the
built site at `schemas/`, so the host serves exactly the directory this
repository ships. Alongside them it publishes:

- `https://hushspec.dev/schemas/index.json` -- every schema with its title,
  description, and `$id`, built from the directory at deploy time, so it can
  never name a schema the site does not serve.
- `https://hushspec.dev/registries/<file>` -- the spec registries
  (`frameworks.yaml`, `error-codes.yaml`) the schemas and lint rules
  reference.

`hushspec.dev` resolving depends on one maintainer-side step outside the
workflow: pointing the domain's DNS at GitHub Pages and setting it as the
repository's custom domain. The deploy does not depend on that having happened
-- the site is also served at its `github.io` address -- so until the domain is
confirmed live, fetch any schema from raw GitHub instead, which always resolves
and tracks `main` directly:

```
https://raw.githubusercontent.com/backbay-labs/hush/main/schemas/hushspec-core.v0.schema.json
```

The two URLs serve the same bytes. Only the canonical one is what a schema's
`$id` declares, so prefer it once it resolves.

## Usage

### Validate with `ajv` (Node.js)

```bash
npm install -g ajv-cli

ajv validate -s schemas/hushspec-core.v0.schema.json -d policy.yaml
```

### Validate with `check-jsonschema` (Python)

```bash
pip install check-jsonschema

check-jsonschema --schemafile schemas/hushspec-core.v0.schema.json policy.yaml
```

### Editor Integration

Add a `$schema` comment to your HushSpec YAML files for editor autocompletion and validation:

```yaml
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v0.schema.json
hushspec: "0.1.0"
name: "my-policy"

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
```

See [Where the schemas are served](#where-the-schemas-are-served) for the raw
GitHub URL to substitute until `hushspec.dev` is confirmed live.

Most YAML-aware editors (VS Code with the YAML extension, IntelliJ, etc.) will pick up the schema directive and provide autocompletion, hover documentation, and inline validation. See the [Editor Setup](../guides/editor-setup.md) guide for the SchemaStore zero-configuration option and workspace-settings alternative.

## Schema Structure

The core schema uses `additionalProperties: false` at every level, enforcing the fail-closed principle. Any field not defined in the specification will cause validation failure.

That holds inside `extensions` too. The core schema is a **compound schema
document**: `extensions.posture`, `extensions.origins` and
`extensions.detection` each `$ref` their companion schema by that schema's own
`$id`, and the three companion documents are carried verbatim in the core
schema's `$defs`. So a validator resolves the whole composition from the one
file, with no network access, and an unknown key inside an extension block is
a rejection rather than an annotation (core spec 2.1 and 9.5). Each reference
also carries `unevaluatedProperties: false`, which keeps the block closed even
if a companion schema's root ever stops setting `additionalProperties: false`.

The embedded copies are byte-for-byte the published companion files; the test
suites compare them, so a companion schema and the copy inside the core schema
cannot drift apart.
