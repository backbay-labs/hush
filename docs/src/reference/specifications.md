# Normative library

These are the immutable HushSpec v1.0.0 release documents. They define the
portable contracts. The adjacent guides explain how to use them; a guide is
not an alternate specification.

| Contract | Read it when you need to know |
| --- | --- |
| [Core](../../../spec/hushspec-core.md) | Document validity, twelve rules, conditions, decisions, enforcement, and L0-L5 |
| [Canonical form](../../../spec/hushspec-canonical.md) | Exactly which bytes determine a policy hash |
| [Receipts](../../../spec/hushspec-receipt.md) | The v0.2 decision evidence structure |
| [Signing](../../../spec/hushspec-signing.md) | Ed25519 envelopes, trust, verify-on-load and receipt signing |
| [Receipt log](../../../spec/hushspec-log.md) | Hash links, rotation and ordering |
| [Bundles](../../../spec/hushspec-bundle.md) | DSSE / in-toto policy distribution |
| [Grammars](../../../spec/hushspec-grammars.md) | Portable identifiers, patterns and wire strings |
| [Security](../../../spec/hushspec-security.md) | Threat assumptions and enforcement boundaries |
| [Posture](../../../spec/hushspec-posture.md) | Capabilities, budgets and state transitions |
| [Origins](../../../spec/hushspec-origins.md) | Trusted origin selection and narrowing |
| [Detection](../../../spec/hushspec-detection.md) | Exact heuristic scoring and detector traces |
| [Versioning](../../../spec/versioning.md) | Compatibility and frozen contracts |
| [Errata](../../../spec/errata.md) | Corrections without silent semantic drift |

Every page exposes its pinned source and raw Markdown. The site records the
release commit separately from the revision of its explanatory guides.
[Registries](registries.md) and [JSON Schemas](json-schema.md) supply
machine-readable companions; schema validation alone is not evaluator conformance.
