# JSON Schema

HushSpec provides JSON Schema files for document validation. These schemas are the machine-readable counterpart to the prose specification and can be used with any JSON Schema validator.

## Available Schemas

The schemas are in the [`schemas/`](https://github.com/backbay-labs/hush/tree/main/schemas) directory:

| File | Description |
|------|-------------|
| `hushspec-core.v0.schema.json` | Core HushSpec document schema (v0.x) |
| `hushspec-posture.v0.schema.json` | Posture extension schema (v0.x) |
| `hushspec-origins.v0.schema.json` | Origins extension schema (v0.x) |
| `hushspec-detection.v0.schema.json` | Detection extension schema (v0.x) |

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
