# Security Considerations

The full document is at [`spec/hushspec-security.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-security.md).

It collects the threats the family addresses and the residual risks an operator manages: regular-expression denial of service, path traversal, remote resolution and server-side request forgery, policy integrity and key management, clock trust, log tampering, receipt privacy, detection limits, monitor mode, the panic sentinel, canonicalization, and the supply chain of the policy itself. Each companion specification's security section points here.

## Deploy an enforcement boundary, not just a policy

- Put the guard before every side-effecting dispatch path, including retries,
  fallbacks, background jobs and framework-provided tools.
- Derive action, origin, identity and context from trusted host state. A model's
  assertion that it is an administrator is not authenticated context.
- An egress allowlist evaluates described destinations; it does not contain a
  network stack. A lexical path pattern is not symlink-safe filesystem access.
  Own and constrain the actual file/network operations.
- Map every supported effect of a tool. Refuse opaque effects rather than
  treating a familiar tool name as permission for everything it might do.
- Validate policy changes and test denied/warned handlers for **zero dispatch**.
  Use [MCP integration](guides/integrations/mcp.md) as a concrete starting point.

## Keep trust out of untrusted input

Pin policy origin, public keys, expected versions and permitted remote hosts
through operator-controlled configuration. Bounded HTTPS loaders reject
disallowed/reserved addresses and redirects; they are not permission to fetch
arbitrary model-selected URLs. Preserve verification options on every reload.
See [signing](signing-spec.md) and [hot reload](guides/hot-reload.md).

## Protect the evidence itself

Stable receipts omit raw action content but may retain sensitive paths, targets,
identifiers and context. Logs, exception messages and observability exporters
can widen that exposure. The experimental invocation journal deliberately
retains arguments and content for reconciliation, so treat it as confidential.

Define access control, encryption, retention, deletion and incident-response
rules for evidence. Redact a derived view, not signed source bytes you intend
to verify later. Retain separately trusted stream boundaries if you need a
completeness claim; valid signatures do not establish that nothing is missing.

## Roll out with explicit failure handling

Use a bounded monitor phase to understand legitimate traffic, then enforce.
Monitor is not prevention, and panic/refused-policy states still deny. Give
exceptions an owner, scope, reason and expiry; do not turn a temporary override
into a silent permanent allow. Alert on reload and sink failures, rehearse
panic/reset procedures, and retain the last known policy and trust state.

No rule template, detector score, conformance report or signed packet is by
itself a compliance certification. See [governance](guides/governance.md) for
control mapping and [reporting](guides/reporting.md) for bounded claims.
