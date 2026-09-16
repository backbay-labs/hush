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

`hushspec.dev` is the canonical host declared in each schema's own `$id`. Until it's
confirmed live, fall back to the raw GitHub URL, which always resolves and tracks
`main` directly:

```
https://raw.githubusercontent.com/backbay-labs/hush/main/schemas/hushspec-core.v0.schema.json
```

Most YAML-aware editors (VS Code with the YAML extension, IntelliJ, etc.) will pick up the schema directive and provide autocompletion, hover documentation, and inline validation. See the [Editor Setup](../guides/editor-setup.md) guide for the SchemaStore zero-configuration option and workspace-settings alternative.

## Schema Structure

The core schema uses `additionalProperties: false` at every level, enforcing the fail-closed principle. Any field not defined in the specification will cause validation failure.

Extension schemas are designed to be composed with the core schema. The core schema's `extensions` object accepts the known extension keys; each extension key references its own schema.
