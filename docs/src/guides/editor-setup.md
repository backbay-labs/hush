# Editor Setup

HushSpec documents are backed by JSON Schemas, published at stable URLs under
their own `$id` (for example,
`https://hushspec.dev/schemas/hushspec-core.v1.schema.json`). Any YAML-aware
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

HushSpec's prepared catalog entries (checked in at
[`docs/schemastore-entry.json`](https://github.com/backbay-labs/hush/blob/main/docs/schemastore-entry.json))
cover five document kinds:

| Entry | Schema | Matches |
|-------|--------|---------|
| HushSpec | core policy | `hushspec.yaml` / `hushspec.yml`, `.hushspec.yaml` / `.hushspec.yml`, `*.hushspec.yaml` / `*.hushspec.yml` |
| HushSpec Evaluator Test | evaluator test | `*.hushspec.test.yaml` / `*.hushspec.test.yml`, `**/fixtures/**/*.test.yaml` |
| HushSpec Decision Receipt | receipt | `*.receipt.json` |
| HushSpec Log Entry | log entry | `*.log-entry.json` |
| HushSpec Policy Bundle | bundle | `*.bundle.json` |

Every pattern names something, and that is deliberate. A catalog entry is
consulted in every project its reader ever opens, not just this one: a
pattern like `rulesets/*.yaml` reads naturally from inside this repository
but claims every YAML file in every `rulesets/` directory anywhere, and the
reward for that is a wall of validation errors on somebody else's unrelated
file. A directory name plus an extension the whole ecosystem uses is not a
claim a global catalog gets to make. `**/fixtures/**/*.test.yaml` is the one
pattern here that doesn't carry `hushspec`; `.test.yaml` under `fixtures/` is
specific enough to be worth the reach, since that is where evaluator tests
actually live.

So name a policy `hushspec.yaml`, `.hushspec.yaml`, or `<something>.hushspec.yaml`
and, once the SchemaStore submission below has merged, you get validation and
autocomplete with no configuration at all. The convention already shows up
elsewhere in HushSpec-aware tooling: the Claude Code hook's policy discovery
walks up the directory tree looking for a `.hushspec.yaml`. Files `h2h init`
scaffolds -- `policy.yaml` beside `tests/policy.test.yaml` -- are outside these
patterns by name, and are covered instead by the modeline `h2h init` writes
into them.

A hash-linked log is a `.jsonl` stream with one entry per line, which no
editor can validate against a schema that describes a single entry; use
`h2h log verify` for those. The log-entry pattern above is for an entry
extracted to its own file.

This layer isn't live yet -- see the [submission checklist](#schemastore-submission-checklist)
below for what's still pending.

## 2. Modeline (works today, any filename)

Add a `yaml-language-server` modeline as the **first line** of the file:

```yaml
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v1.schema.json
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
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-evaluator-test.v1.schema.json
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
  "https://hushspec.dev/schemas/hushspec-core.v1.schema.json": ["policies/*.yaml"]
}
```

(JetBrains IDEs: **Preferences → Languages & Frameworks → Schemas and DTDs →
JSON Schema Mappings**, using the same URL and glob.)

## Interim fallback: raw GitHub URL

The docs deploy publishes `schemas/*.json` alongside the mdBook site, so the
host serves every schema at the `$id` its own document declares. What is left
is maintainer-side and one-time: pointing the domain's DNS at GitHub Pages and
setting it as the repository's custom domain. Until `hushspec.dev` is confirmed
live, substitute the raw GitHub URL anywhere above; it always resolves and
tracks `main` directly:

```
https://raw.githubusercontent.com/backbay-labs/hush/main/schemas/hushspec-core.v1.schema.json
```

Both URLs serve the same file, and can differ only for as long as it takes a
docs deploy to run -- raw GitHub tracks `main` directly, while the canonical
host serves the last successful deploy of it. Once `hushspec.dev` is live,
prefer the canonical URL: it's the one the
schemas' own `$id` fields declare, and the one the SchemaStore entries above
point to. `https://hushspec.dev/schemas/index.json` lists everything the host
serves, and is the quickest way to check whether it is live.

Offline, `h2h schema --list` and `h2h schema <name>` print the same schemas
from the binary itself, with no network access at all.

## SchemaStore submission checklist

Submitting the catalog entry to the upstream
[`SchemaStore/schemastore`](https://github.com/SchemaStore/schemastore)
repository is a separate, external PR, gated on the URLs above actually
resolving. Roughly:

1. Confirm every URL the entries name resolves over HTTPS.
   `https://hushspec.dev/schemas/index.json` lists them all.
2. Fork `SchemaStore/schemastore`.
3. Insert the objects from [`docs/schemastore-entry.json`](https://github.com/backbay-labs/hush/blob/main/docs/schemastore-entry.json)'s
   `schemas` array into `src/api/json/catalog.json`'s own `schemas` array,
   which is sorted by `name`. The objects carry only the keys that array
   accepts, so they paste in verbatim; the `$comment` and the wrapper around
   them are local and do not go upstream.
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
