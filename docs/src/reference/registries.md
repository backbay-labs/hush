# Registries

Registries define portable vocabulary, not permission to extend a closed object.
An unknown action is denied; an unknown document field is rejected. Capability
extensions are separately described by the posture specification.

## Published inventory

| Registry | Download | Role |
| --- | --- | --- |
| [action-types](../../../spec/registries/action-types.yaml) | [YAML](https://hushspec.org/registries/action-types.yaml) | Closed portable vocabulary |
| [capabilities](../../../spec/registries/capabilities.yaml) | [YAML](https://hushspec.org/registries/capabilities.yaml) | Registered identifiers and compatibility rules |
| [condition-types](../../../spec/registries/condition-types.yaml) | [YAML](https://hushspec.org/registries/condition-types.yaml) | Closed portable vocabulary |
| [detectors](../../../spec/registries/detectors.yaml) | [YAML](https://hushspec.org/registries/detectors.yaml) | Registered identifiers and compatibility rules |
| [error-codes](../../../spec/registries/error-codes.yaml) | [YAML](https://hushspec.org/registries/error-codes.yaml) | Registered identifiers and compatibility rules |
| [frameworks](../../../spec/registries/frameworks.yaml) | [YAML](https://hushspec.org/registries/frameworks.yaml) | Registered identifiers and compatibility rules |
| [media-types](../../../spec/registries/media-types.yaml) | [YAML](https://hushspec.org/registries/media-types.yaml) | Closed portable vocabulary |
| [rule-blocks](../../../spec/registries/rule-blocks.yaml) | [YAML](https://hushspec.org/registries/rule-blocks.yaml) | Closed portable vocabulary |
| [rule-paths](../../../spec/registries/rule-paths.yaml) | [YAML](https://hushspec.org/registries/rule-paths.yaml) | Closed portable vocabulary |

## Version and ownership

A registry can retain its original registry version while shipping in HushSpec
v1. Read the registry header for its extension policy. Do not infer that an
arbitrary capability, detector or framework is supported merely because a
string fits its identifier grammar. [Conformance](conformance.md) is a separate
claim about behavior against a named corpus.
