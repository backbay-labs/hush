# Merge Semantics

HushSpec supports policy inheritance via the `extends` field. When a child policy extends a base, the `merge_strategy` controls how they combine.

## Strategies

### `deep_merge` (default)

Child rules override base rules at the individual rule-block level. If the child
defines `rules.egress`, it replaces the base's `rules.egress` entirely. Rules
not defined in the child are preserved from the base.

Extensions use their companion-spec merge rules under `deep_merge`:

- `posture` merges states by name and replaces transitions with the child's list
- `origins` merges profiles by `id` and preserves `default_behavior` when omitted
- `detection` merges subsections independently and preserves omitted subsection fields

### `merge`

For core `rules`, `merge` matches `deep_merge` in HushSpec v0.

For `extensions`, `merge` is shallower: if the child defines an extension block,
that block replaces the base extension block entirely. Unspecified extension
blocks are still preserved from the base.

### `replace`

The child document entirely replaces the base. No fields from the base are preserved.

## Example

```yaml
# base.yaml
hushspec: "0.1.0"
name: base
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
```

```yaml
# child.yaml
hushspec: "0.1.0"
name: child
extends: base.yaml
rules:
  egress:
    allow: ["b.com"]
    default: allow
```

Result: `egress` uses child's config (`b.com`, allow). `forbidden_paths` preserved from base.

## Note on Merge Helpers

HushSpec does **not** support `additional_*` or `remove_*` fields. These are engine-specific features. If you need additive pattern management, use your engine's native format.
