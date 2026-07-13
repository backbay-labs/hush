# Editor Setup

HushSpec documents are backed by JSON Schemas, published at stable URLs under
their own `$id` (for example,
`https://hushspec.dev/schemas/hushspec-core.v0.schema.json`). Any YAML-aware
editor that speaks [`yaml-language-server`](https://github.com/redhat-developer/yaml-language-server)
conventions -- VS Code (with the YAML extension), Neovim, JetBrains IDEs, and
others -- can use these schemas for autocompletion, hover documentation, and
inline validation as you write a policy.

There are three ways to associate a HushSpec file with its schema, from most
to least automatic.

## 1. SchemaStore (zero configuration, once submitted)

[SchemaStore](https://www.schemastore.org/) is a community-maintained catalog
that maps filenames to schema URLs. Editors and extensions that consult it
(VS Code's YAML extension, JetBrains IDEs, and others) associate a schema
automatically -- no per-file comment or workspace setting required.

HushSpec's prepared catalog entry (checked in at
[`docs/schemastore-entry.json`](https://github.com/backbay-labs/hush/blob/main/docs/schemastore-entry.json))
matches these filenames:

- `hushspec.yaml` / `hushspec.yml`
- `.hushspec.yaml` / `.hushspec.yml`
- `*.hushspec.yaml` / `*.hushspec.yml`

This is the same filename convention used elsewhere in HushSpec-aware tooling
-- for example, the Claude Code hook's policy discovery walks up the
directory tree looking for a `.hushspec.yaml`. Name your policy file to match
one of these patterns and, once the SchemaStore submission below has merged,
you get validation and autocomplete with no configuration at all.

This layer isn't live yet -- see the [submission checklist](#schemastore-submission-checklist)
below for what's still pending.

## 2. Modeline (works today, any filename)

Add a `yaml-language-server` modeline as the **first line** of the file:

```yaml
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v0.schema.json
hushspec: "0.1.0"
name: "my-policy"
```

This works regardless of filename and needs no editor or workspace
configuration beyond the YAML extension itself. It's what every shipped
ruleset and library policy in this repository carries, and what `h2h init`
writes into scaffolded files automatically. `h2h fmt` preserves this line
across reformatting.

Evaluator test files (the `*.test.yaml` fixtures `h2h init` scaffolds
alongside a policy) use the evaluator-test schema instead:

```yaml
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-evaluator-test.v0.schema.json
```

See the [JSON Schema reference](../reference/json-schema.md) for the full
list of published schemas.

## 3. Workspace settings (works today, any filename, explicit)

If you'd rather not add a modeline to every file, or your editor doesn't
support SchemaStore auto-detection, map a glob pattern to a schema URL in
your workspace settings:

```yaml
# .vscode/settings.json
"yaml.schemas": {
  "https://hushspec.dev/schemas/hushspec-core.v0.schema.json": ["policies/*.yaml"]
}
```

(JetBrains IDEs: **Preferences → Languages & Frameworks → Schemas and DTDs →
JSON Schema Mappings**, using the same URL and glob.)

## Interim fallback: raw GitHub URL

`hushspec.dev` resolving to these schemas depends on a docs deploy that
publishes `schemas/*.json` alongside the mdBook site, plus the domain's DNS
being pointed at GitHub Pages -- both maintainer-side, one-time setup steps.
Until `hushspec.dev` is confirmed live, substitute the raw GitHub URL
anywhere above; it always resolves and tracks `main` directly:

```
https://raw.githubusercontent.com/backbay-labs/hush/main/schemas/hushspec-core.v0.schema.json
```

Once `hushspec.dev` is live, prefer the canonical URL -- it's the one the
schemas' own `$id` fields declare, and the one the SchemaStore entry above
points to.

## SchemaStore submission checklist

Submitting the catalog entry to the upstream
[`SchemaStore/schemastore`](https://github.com/SchemaStore/schemastore)
repository is a separate, external PR, gated on the URLs above actually
resolving. Roughly:

1. Confirm `https://hushspec.dev/schemas/hushspec-core.v0.schema.json` (and
   the other six published schemas) resolve over HTTPS.
2. Fork `SchemaStore/schemastore`.
3. Add the contents of [`docs/schemastore-entry.json`](https://github.com/backbay-labs/hush/blob/main/docs/schemastore-entry.json)
   as a new entry in `src/api/json/catalog.json`'s `schemas` array (check the
   file for its current sort order convention before inserting).
4. Run SchemaStore's own catalog validation locally and address anything it
   flags -- it will fetch `url` and validate the entry shape, so this step
   only makes sense after step 1 is confirmed.
5. Open the PR against `SchemaStore/schemastore` referencing this repository
   and the `fileMatch` patterns above.

No vendored copy of the schema is needed in the SchemaStore repository itself
-- the entry references HushSpec's externally hosted `url`, so only the
catalog entry needs to land there.

## What Next

- [Writing Your First Policy](first-policy.md)
- [JSON Schema Reference](../reference/json-schema.md)
