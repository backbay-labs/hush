# Origins Extension

The full normative specification is at [`spec/hushspec-origins.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-origins.md).

## Overview

The Origins extension provides origin-aware policy projection. When an agent receives work from different sources -- Slack channels, GitHub repositories, email threads, Discord servers -- different security profiles can apply based on the source context.

Origin profiles **narrow** the base policy. They can only make rules more restrictive, never more permissive. The base policy remains the security floor.

Origins is declared under `extensions.origins` in a HushSpec document.

## Key Concepts

- **Profiles** match incoming requests by provider, space type, visibility, tags, and other criteria.
- **Match priority** is deterministic: candidates must satisfy every supplied field; the first candidate with `space_id` wins, otherwise most fields wins, with ties broken by document order. No candidate means `default_behavior`.
- **Composition** uses intersection for allowlists and union for blocklists, ensuring the most restrictive rule always wins.
- **Bridge policy** controls cross-origin data flow between contexts.
- **Data policy** controls external sharing, redaction, and sensitive output blocking.

## Example

```yaml
extensions:
  origins:
    default_behavior: "deny"
    profiles:
      - id: "eng-private"
        match:
          provider: slack
          space_type: channel
          visibility: private
          tags: ["engineering"]
        tool_access:
          allow: ["read_file", "write_file", "search"]
        data:
          allow_external_sharing: false
        bridge:
          allow_cross_origin: true
          allowed_targets:
            - provider: github
              space_type: pull_request
          require_approval: false
        explanation: "Full access for private engineering channels"

      - id: "shared-external"
        match:
          provider: slack
          external_participants: true
        tool_access:
          allow: ["read_file", "search"]
          block: ["deploy"]
        data:
          redact_before_send: true
          block_sensitive_outputs: true
        bridge:
          allow_cross_origin: false
        explanation: "Restricted access for shared channels"
```

## Standard Providers

`slack`, `teams`, `github`, `jira`, `email`, `discord`, `webhook`, `custom`

## Composition Rules

- **Allowlists**: intersection when both lists are nonempty; otherwise the nonempty list applies
- **Blocklists**: union of base and origin profile (blocked by either means blocked)
- **Defaults**: if either specifies `"block"`, the effective default is `"block"`
- **Budgets**: the smaller value wins

## Schema and Field Reference

The [origins schema](../../../spec/hushspec-origins.md#2-schema) defines
`default_behavior` and `profiles`. Each profile has an `id`, optional `match`,
and narrowing `tool_access`, `egress`, `budgets`, `posture`, `data`, and `bridge`
settings. An omitted overlay field inherits the base; do not insert defaults
into overlays. `enabled` is not an overlay field.

## Match Priority

An absent `match` never qualifies. An explicitly empty `match: {}` is a
zero-specificity candidate. `tags` requires all listed tags and counts as one
matched field, not one per tag. The runtime authenticates and supplies provider,
tenant, space, visibility, and participant context. Merely passing a string
called `tenant_id` from a model does not authenticate a tenant.
See [origins section 3](../../../spec/hushspec-origins.md#3-match-priority).

## Space Types and Visibility

Space types include channel, group, DM, thread, issue, ticket, pull request,
and custom; use the [exact enum vocabulary](../../../spec/hushspec-origins.md#52-space-types).
Visibility is `private`, `internal`, `public`, or `external_shared`.

## Tool, Egress, Budget and Posture Composition

Nonempty allowlists intersect; blocks and confirmation lists union. The smaller
argument limit or shared budget wins. A specified `block` default wins; an
omitted default inherits. A profile's posture state replaces the initial state
for that origin, and must name an existing state. See [origins section 4](../../../spec/hushspec-origins.md#4-composition-semantics).

## Data Policy

`allow_external_sharing`, `redact_before_send`, and `block_sensitive_outputs`
all default to false. Redaction requires an engine implementation and documented
strategy. The policy does not itself intercept outbound content. See
[origins section 6](../../../spec/hushspec-origins.md#6-data-policy).

## Bridge Policy

`allow_cross_origin: false` forbids transfer. When true, a nonempty
`allowed_targets` list restricts destinations, while an empty list does not.
Every specified target field must match; `require_approval` adds operator
approval before transfer. The host owns the actual bridge and its enforcement.
See [origins section 7](../../../spec/hushspec-origins.md#7-bridge-policy).

## More Examples

For GitHub code review, constrain the trusted provider and pull-request space,
then allow only read/search tools. For a multi-provider bridge, retain a deny
fallback and enumerate destination constraints. Do not transplant Slack
visibility assumptions into GitHub authentication. The [normative examples](../../../spec/hushspec-origins.md#appendix-a-example)
show complete match and bridge shapes.

## Merge Rules

Under `deep_merge`, profiles merge by ID, with a child's profile replacing the
matching base profile; omitted default behavior is inherited. This is policy
inheritance, not the narrowing composition for a selected request. See
[origins section 9](../../../spec/hushspec-origins.md#9-merge-semantics).
