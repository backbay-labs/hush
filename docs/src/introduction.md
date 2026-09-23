# HushSpec documentation

Declare what an agent may do. Enforce it before a side effect. Keep evidence
that another implementation can read and verify.

HushSpec v1 is a portable policy and evidence specification with a CLI and
reference SDKs for Rust, TypeScript, Python and Go. Start with a small tested
boundary, then expand its coverage deliberately.

## Write a policy

Follow the [quickstart](guides/getting-started.md), download the policy and tests,
and see allow, deny and confirmation-required decisions.
[All twelve rule blocks](rules-reference.md) cover paths, tools, egress,
content, shell, desktop, browser and code-execution actions.

## Integrate an agent

Use a [runtime guard](guides/runtime-integration.md) immediately before dispatch.
The [MCP guide](guides/integrations/mcp.md) explains trusted mapping and the
difference between checking a tool name and controlling its effects.
Pick a [language SDK](reference/sdk-api.md) for exact APIs and return conventions.

## Inspect evidence

Understand [canonical policy identity](canonical-spec.md),
[decision receipts](receipt-spec.md), [signing](signing-spec.md),
[logs](log-spec.md), and [bundles](bundle-spec.md).
Authenticity, continuity, completeness, and runtime truth are separate claims.

## Implement the specification

Read the [normative library](reference/specifications.md), then run a
[conformance corpus](reference/conformance.md) against a specific implementation.
Use [schemas](reference/json-schema.md) and [registries](reference/registries.md)
as machine-readable companions, not substitutes for evaluation semantics.

## What v1 guarantees

The v1 portable contract is stable under the [versioning policy](reference/versioning.md).
Receipt/signature wire version 0.2 and log/bundle version 0.1 remain current.
Strict evidence profiles, external-engine execution packets, and the
[trusted-invocation pilot](reference/trusted-invocation.md) remain experimental.

## Where the boundary ends

HushSpec evaluates descriptions of actions. The host owns authentication,
dispatch, filesystem/network containment, counters and evidence delivery.
A policy file alone is not a sandbox; a signed receipt is not certification.
The [security model](security-spec.md) makes those assumptions explicit.
