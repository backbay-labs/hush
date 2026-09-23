# JSON Schema

HushSpec provides JSON Schema files for document validation. These schemas are the machine-readable counterpart to the prose specification and can be used with any JSON Schema validator.

## Available Schemas

The schemas are in the [`schemas/`](https://github.com/backbay-labs/hush/tree/main/schemas) directory:

| File | Description |
|------|-------------|
| `hushspec-core.v1.schema.json` | Core HushSpec document schema: rules, extensions, metadata, `when` conditions |
| `hushspec-posture.v1.schema.json` | Posture extension schema |
| `hushspec-origins.v1.schema.json` | Origins extension schema |
| `hushspec-detection.v1.schema.json` | Detection extension schema |
| `hushspec-evaluator-test.v1.schema.json` | Evaluation test fixture format used by `h2h test`, the testkit, and every SDK's shared-fixture runner. Format `0.2.0` adds per-case `controls` and `tags` and the `expect.rule_trace` / `expect.receipt` assertions; `0.1.0` fixtures stay valid |
| `hushspec-hash-vector.v1.schema.json` | Canonical-form test vector format ([`fixtures/core/hash/`](https://github.com/backbay-labs/hush/tree/main/fixtures/core/hash)); see the [canonical form spec](../canonical-spec.md) |
| `hushspec-receipt.v1.schema.json` | Decision receipt format 0.2; see the [receipt spec](../receipt-spec.md) |
| `hushspec-log-entry.v1.schema.json` | Hash-linked log entry (receipts and policy events) written by chained sinks and checked by `h2h log verify` |
| `hushspec-signature.v1.schema.json` | Detached policy signature envelope 0.2; see the [signing spec](../signing-spec.md) |
| `hushspec-keyring.v1.schema.json` | Trusted keyring consumed by verify-on-load and `h2h verify --keyring` |
| `hushspec-bundle.v1.schema.json` | Policy bundle attestation (DSSE envelope with an in-toto statement) produced by `h2h bundle create` |
| `hushspec-framework-registry.v1.schema.json` | Schema for [`spec/registries/frameworks.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/frameworks.yaml), the compliance frameworks `metadata.controls[].framework` may name |
| `hushspec-error-codes.v1.schema.json` | Schema for [`spec/registries/error-codes.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/error-codes.yaml) and for the `<name>.expect.yaml` sidecars that pin the code each `invalid/` vector is rejected with |
| `hushspec-merge-vector.v1.schema.json` | The merge-vector directory convention under `fixtures/*/merge/` (`base.yaml`, `child-*.yaml`, `expected-*.yaml`, optional `fixture.yaml`) |
| `hushspec-conformance-report.v1.schema.json` | Conformance report emitted by `hushspec-testkit --report`; see [Conformance Levels](conformance.md) |
| `hushspec-engine-profile-experimental.v1.schema.json` | Experimental external engine identity, executable digest, arguments and build materials |
| `hushspec-engine-request-experimental.v1.schema.json` | Experimental digest-bound external engine request, without expected answers |
| `hushspec-engine-response-experimental.v1.schema.json` | Experimental engine observation and echoed request binding |
| `hushspec-conformance-execution-experimental.v1.schema.json` | Experimental execution packet completion record, artifact digests and planned result slots |
| `hushspec-report.v1.schema.json` | Evidence report 0.1: an aggregation over receipts and policy-in-effect events for one window, emitted by `h2h report --format json` |
| `hushspec-evidence-profile-experimental.v1.schema.json` | Experimental 0.1.0 operator scope, ordered sources, byte digests and signer authorization |
| `hushspec-evidence-inventory-experimental.v1.schema.json` | Experimental 0.1.0 independently acquired stream inventory and boundaries |
| `hushspec-evidence-verification-experimental.v1.schema.json` | Experimental 0.1.0 verification result bound to native report bytes |
| `hushspec-assessment-context-experimental.v1.schema.json` | Experimental 0.1.0 local assessment-plan, SSP and resolved catalog references |
| `hushspec-registry-action-types.v0.schema.json` | Shape of [`spec/registries/action-types.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/action-types.yaml), the action types an evaluator dispatches on |
| `hushspec-registry-capabilities.v0.schema.json` | Shape of [`spec/registries/capabilities.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/capabilities.yaml), the capabilities a posture state may grant |
| `hushspec-registry-condition-types.v0.schema.json` | Shape of [`spec/registries/condition-types.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/condition-types.yaml), the `when` condition keys |
| `hushspec-registry-detectors.v0.schema.json` | Shape of [`spec/registries/detectors.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/detectors.yaml), the reference detectors the detection extension names |
| `hushspec-registry-media-types.v0.schema.json` | Shape of [`spec/registries/media-types.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/media-types.yaml), the media types registered for HushSpec documents |
| `hushspec-registry-rule-blocks.v0.schema.json` | Shape of [`spec/registries/rule-blocks.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/rule-blocks.yaml), the rule blocks `rules` may carry |
| `hushspec-registry-rule-paths.v0.schema.json` | Shape of [`spec/registries/rule-paths.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/rule-paths.yaml), the rule paths a receipt may cite |

The table is the whole of `schemas/`, and a test keeps it that way. Every
schema is also embedded in the `h2h` binary; `h2h schema --list` prints the
names and `h2h schema <name>` prints one to stdout.


## Schema lineage

The `*-experimental.v1.schema.json` companion artifacts declare their own
`0.1.0` contract version. Their filename lineage does not make them stable or
change the existing policy, receipt, log, report or conformance-report formats.

Document-format schemas are named per major version (`spec/versioning.md` section 9). The `.v1.` files above are the current lineage: the schemas HushSpec 1.0.0 published, referenced by every SDK, the CLI, the testkit, and the fixture modelines. The `.v0.` files describe the 0.x line and are frozen: each carries a `$comment` saying so, [`schemas/frozen-v0.json`](https://github.com/backbay-labs/hush/blob/main/schemas/frozen-v0.json) records their `sha256:` digests, and a test in the reference implementation fails when one of them changes. A document that declares a 0.x `hushspec` version validates against its `.v0.` schema; a document declaring `1.0.z` validates against `.v1.`.

`hushspec-core.v1.schema.json` differs from `hushspec-core.v0.schema.json` in two keywords: `hushspec` matches `^(0|1)\.\d+\.\d+$`, and `name` carries `minLength: 1`. The receipt, log-entry, and report schemas widen their `spec_version` patterns the same way, so a receipt for a `1.0.z` policy validates. Those four are the only validation differences between the lineages: every other `.v1.` file constrains exactly what its `.v0.` predecessor constrained.

The `.v1.` files also carry their own identity, which never affects validation. Each has a `v1` `$id` and no frozen `$comment`, a `title` naming the lineage it belongs to (a title ending in a minor -- `HushSpec Decision Receipt v0.2`, `HushSpec Log Entry v0.1` -- names a *wire format* version, which 1.0.0 did not change), and prose that points at `.v1.` companions: `hushspec-bundle.v1` sends a verifier to `hushspec-core.v1` for the canonical projection, and `hushspec-log-entry.v1` to `hushspec-receipt.v1` for an entry's receipt. The `.v0.` file of each pair still points at the `.v0.` companion, which is what a 0.x document needs.

The registry schemas (`hushspec-registry-*.v0.schema.json`) describe the files under `spec/registries/` rather than documents and keep the `.v0.` name.

`h2h schema <name>` prints the current lineage by bare name (`h2h schema core`); the frozen file is addressed as `core.v0`. `h2h schema --list` names both.

## Where the schemas are served

Each schema declares its own `$id`, and that `$id` is the URL it is published
at:

```
https://hushspec.dev/schemas/<file>
```

The docs deployment (`.github/workflows/docs.yml`) copies `schemas/*.json`
into the built site at `schemas/`, so the host serves exactly the schemas this
repository ships. Alongside them it publishes:

- `https://hushspec.dev/schemas/index.json` -- one entry per schema, carrying
  its file name, `$id`, title and description, under a `host` field and the
  `commit` the deploy was built from. It is built from the directory being
  copied at deploy time, so it can never name a schema the site does not
  serve.
- `https://hushspec.dev/registries/<file>` -- every registry under
  [`spec/registries/`](https://github.com/backbay-labs/hush/tree/main/spec/registries),
  published so the normative lists are readable at a stable URL. Nothing
  resolves these over the network: the schemas above pin the registries by
  shape, and the SDKs embed them.

`hushspec.dev` resolving depends on one maintainer-side step outside the
workflow: pointing the domain's DNS at GitHub Pages and setting it as the
repository's custom domain. The deploy does not depend on that having happened
-- the site is also served at its `github.io` address -- so until the domain is
confirmed live, fetch any schema from raw GitHub instead, which always resolves
and tracks `main` directly:

```
https://raw.githubusercontent.com/backbay-labs/hush/main/schemas/hushspec-core.v1.schema.json
```

Both URLs serve the same file. They can differ for as long as it takes a
deploy to run -- raw GitHub tracks `main` directly, while the canonical host
serves the last successful docs deploy. Only the canonical one is what a
schema's `$id` declares, so prefer it once it resolves.

## Usage

### Validate with `ajv` (Node.js)

```bash
npm install -g ajv-cli

ajv validate -s schemas/hushspec-core.v1.schema.json -d policy.yaml
```

### Validate with `check-jsonschema` (Python)

```bash
pip install check-jsonschema

check-jsonschema --schemafile schemas/hushspec-core.v1.schema.json policy.yaml
```

### Editor Integration

Add a `$schema` comment to your HushSpec YAML files for editor autocompletion and validation:

```yaml
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v1.schema.json
hushspec: "1.0.0"
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
