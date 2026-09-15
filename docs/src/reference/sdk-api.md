# SDK API Contract

The four reference SDKs -- Rust (`hushspec`), TypeScript (`@hushspec/core`),
Python (`hushspec`) and Go (`github.com/backbay-labs/hush/packages/go/hushspec`)
-- are meant to be *isomorphic*: the same policy, the same decision, the same
evidence, and as far as each language allows, the same names for the same
things. This page is the contract. It lists, capability area by capability
area, the entry point each SDK publishes today, what the four are required to
agree on, and where they deliberately differ because the language does.

Every name below is the name in the source on `main`. Three tests pin the core
of this surface so a rename is a deliberate act rather than a silent
divergence:

- [`packages/hushspec/tests/exports.test.ts`](https://github.com/backbay-labs/hush/blob/main/packages/hushspec/tests/exports.test.ts) -- `REQUIRED`, plus identity assertions for the aliases
- [`packages/python/tests/test_public_surface.py`](https://github.com/backbay-labs/hush/blob/main/packages/python/tests/test_public_surface.py) -- `ISOMORPHIC_NAMES`, plus `__all__` honesty checks
- [`packages/go/hushspec/isomorphism_test.go`](https://github.com/backbay-labs/hush/blob/main/packages/go/hushspec/isomorphism_test.go) -- `isomorphicEntryPoints`, read off the package AST

Rust is the oracle the other three are differentially fuzzed against, so it has
no pinning test of its own; `crates/hushspec/src/lib.rs` is its surface.

## Reading the tables

- A bare name is exported at the package root (`hushspec::parse`,
  `import { parse }`, `from hushspec import parse`, `hushspec.Parse`).
- A qualified name is reachable only through its module
  (`hushspec::signing::sign_policy`, `hushspec.adapters.*`).
- `--` means the capability does not exist in that SDK under any name.
- Rust items marked *(feature)* need the named Cargo feature; Python items
  marked *(extra)* need the named optional dependency.

## Result conventions

The largest deliberate difference. Each SDK reports failure the way its
language does, and the *shape* differs even though the outcome does not.

| SDK | Fallible call returns | Throwing variant |
|---|---|---|
| Rust | `Result<T, E>` with a `thiserror` error enum | none -- `?` is the idiom |
| TypeScript | `ParseResult` / `ResolveResult`: `{ ok: true, value }` or `{ ok: false, error, code }` | `parseOrThrow`, `resolvePolicyOrThrow` |
| Python | `(ok, value \| ErrorMessage)` tuples | `parse_or_raise`, `resolve_or_raise`, `resolve_with_options_or_raise` |
| Go | `(T, error)` | none -- `if err != nil` is the idiom |

Only four Python functions use the tuple convention: `parse`, `resolve`,
`resolve_file` and `resolve_with_options`; everything else returns a result
object. Likewise in TypeScript only `parse` and `resolve` return the `ok`
union -- `resolveWithOptions`, `merge`, the `evaluate*` family and
`compilePolicy` return directly and throw.

Verification results are *not* errors in any SDK. An invalid signature is a
value, not an exception, because "this did not verify, and here is the reason
code" is the answer a relying party needs:

| SDK | Verification result |
|---|---|
| Rust | `Result<Verified, VerifyError>`; `VerifyError::reason_code()` |
| TypeScript | `VerificationOutcome`: `{ ok: true, ... }` or `{ ok: false, reason, detail }` |
| Python | `VerifyResult` (`.valid`, `.reason`) |
| Go | `VerifyResult` (`.Valid`, `.Reason`) |

## Parse and validate

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Parse YAML to a document | `HushSpec::parse` | `parse`, `parseOrThrow` | `parse`, `parse_or_raise` | `Parse` | Fail-closed: unknown members at any depth, YAML aliases, merge keys, duplicate keys, multi-document streams and `yes`/`no` booleans are all parse errors (core spec 2.4) | Rust uses serde `deny_unknown_fields`; the ports check the closed key sets of their generated contract |
| Serialize back to YAML | `HushSpec::to_yaml` | -- | -- | `Marshal` | Round-trips a parsed document | TS and Python callers use their own YAML library |
| YAML profile check alone | `schema::yaml_profile_violation` | `yamlProfileViolation` | -- | -- | Reports the profile violation without a full parse | Python and Go fold the check into `parse` / `Parse` |
| Validate a document | `validate` | `validate` | `validate` | `Validate` | Types, enums, uniqueness, numeric bounds, the regex profile and `when` conditions. Never throws; collects every error | |
| Validation result | `ValidationResult::is_valid` | `ValidationResult.valid` | `ValidationResult.is_valid` | `(*ValidationResult).IsValid` | A boolean plus `errors` and `warnings` | Python's is a property, Go's a method, TS's a plain field |
| One validation error | `ValidationError` (enum) | `ValidationError` (`.code`) | `ValidationError` (`.code`, `.kind`) | `ValidationError` (`.Code`, `.Kind`) | Carries the document path and message | Rust's is a typed enum with no code string; see [Error codes](#error-codes) |
| Condition validation | `conditions::validate_condition` | `validateCondition`, `validateConditions` | `validate_condition`, `validate_conditions` | `ValidateCondition`, `ValidateConditions` | A malformed `when` is a document error, not a runtime deny | |
| Regex profile | `compile_profile_regex` | `isSafeRegex` | `is_safe_regex` | `CompileProfileRegex` | The ReDoS-safe profile of core spec 3.14; a pattern outside it is `E005` | Rust and Go return the compiled regex, TS and Python a boolean |
| Document limits | `schema::MAX_DOCUMENT_BYTES`, `MAX_NESTING_DEPTH`, `MAX_NODE_COUNT` | `MAX_DOCUMENT_BYTES`, `MAX_DOCUMENT_DEPTH`, `MAX_NODE_COUNT` | `parse.MAX_DOCUMENT_BYTES`, `parse.MAX_NESTING_DEPTH`, `parse.MAX_NODE_COUNT` | `MaxDocumentBytes`, `MaxDocumentNestingDepth`, `MaxDocumentNodeCount` | 1 MiB, depth 32, 100 000 nodes -- identical in all four | TS spells the depth limit `MAX_DOCUMENT_DEPTH`; Python's three are module-level, not in `__all__` |
| Governance findings | `validate_governance`, `GovernanceWarning` | -- | -- | -- | Separation of duties, overdue review, changelog order (core spec 2.5) | Rust and `h2h audit` only. The `metadata` date format (`E011`) is checked inside `validate` in all four |

## Merge, resolve, verify-on-load, digest pins

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Merge two documents | `merge` | `merge` | `merge` | `Merge` | `deep_merge` (default), `merge`, `replace`, per merge spec 4.1 | |
| Resolve `extends` | `resolve_with_loader`, `resolve_from_path` | `resolve`, `resolveFromFile` | `resolve`, `resolve_file` | `Resolve`, `ResolveFile` | Folds the chain root to leaf. A cycle, a missing base or an over-deep chain is a refusal, never a partial document | |
| Resolve with provenance | `resolve_with_options`, `resolve_path_with_options` | `resolveWithOptions`, `resolveFromFileWithOptions` | `resolve_with_options` (+ `_or_raise`) | `ResolveWithOptions`, `ResolveFileWithOptions` | Returns a `Resolution`: the folded document, its canonical `content_hash`, and one chain link per hop | The Level 4 entry point -- a receipt needs the `Resolution`, not the document |
| Resolution value | `Resolution`, `ChainLink` | `Resolution`, `ChainLink` | `Resolution`, `ChainLink` | `Resolution`, `ChainLink` | `{source, content_hash, signature}` per hop, leaf last | |
| Wrap an already-resolved document | `Resolution::from_resolved` | `resolutionFromResolved` | `Resolution` | `NewResolutionFromResolved` | An in-memory leaf records `source: "memory"` | |
| In-memory source | `MEMORY_SOURCE` | `MEMORY_SOURCE` (`INLINE_POLICY_SOURCE` deprecated alias) | `MEMORY_SOURCE` | `MemorySource` | `"memory"` | |
| Verify-on-load options | `ResolveOptions` (`require_signature`, `keyring`, `verify`) | `ResolveOptions` (`requireSignature`, `keyring`, `verify`) | `ResolveOptions` (`require_signature`, `keyring`, `verify`) | `ResolveOptions` (`RequireSignature`, `Keyring`, `Verify`) | Signing spec 6.5: every hop is checked, the load fails closed when a signature is required and absent or bad, and the outcome is recorded in `receipt.policy.signature` | Rust's `keyring` / `verify` fields need the `signing` feature; Python's need the `signing` extra |
| Signature outcome per hop | `SignatureStatus` | `SignatureStatus` | `SignatureStatus` | `SignatureStatus` | `{verified, key_id, verified_at, reason}` | `verified_at` is the verifier's clock, not the envelope's `signed_at` |
| Signature locator | `SignatureLocator` | `defaultSignatureLocator` | `default_signature_locator` | `DefaultSignatureLocator` | `<policy>.sig` beside the document | |
| Digest pin | `split_digest_pin`, `own_content_hash` | `splitDigestPin` | `resolve.DIGEST_PIN_MARKER` | `ReasonInvalidPin`, `ReasonDigestMismatch`, `OwnContentHash` | `extends: "<ref>#sha256:<hex>"`. A mismatch always rejects, and a matching pin satisfies `require_signature` for that hop | Enforced identically in all four; only the helper spelling differs |
| Built-in rulesets | `load_builtin`, `BUILTIN_NAMES` | `loadBuiltin`, `BUILTIN_NAMES` | `load_builtin`, `BUILTIN_NAMES` | `LoadBuiltin`, `BuiltinNames` | `builtin:<name>` and `builtin:library/<vertical>/<name>` resolve with no file system | Generated from `rulesets/` and `library/` by `scripts/generate_*_builtins.py` |
| Composite loader | `create_composite_loader` | `createCompositeLoader`, `createBuiltinLoader` | `create_composite_loader`, `create_builtin_loader` | `ResolveLoader` | Builtin first, then file | Go takes a loader function rather than a factory |
| HTTPS loader | `resolve::http::load_from_https` *(feature `http`)* | `createHttpLoader`, `createSyncHttpLoader` | -- | -- | ETag caching, SSRF and IPv6 hardening, redirect limits | **Rust and TypeScript only.** Python and Go ship no HTTP client and reject an `https:` reference outright rather than resolving it unverified -- supply your own loader, or resolve ahead of time and hand them the `Resolution` |
| Resolve failure reason | `ResolveError` | `ResolveError`, `resolveErrorReason` | `ResolveRejected` | `ResolveReason`, `InvalidPinError`, `NotFoundError`, `CycleError`, `MaxDepthError` | A machine-readable reason (`invalid_pin`, `not_found`, `cycle`, `max_depth`, ...) rather than a bare string | |

## Compiled policies

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Compile a document | `CompiledPolicy::compile` | `compilePolicy` | `compile_policy` | `CompilePolicy` | Every regex, path glob, host pattern, tool set, `when` condition, severity table and detector is prepared once. Decisions, traces, hashes and receipts are unchanged from the uncompiled path | |
| Compile a `Resolution` | `CompiledPolicy::from_resolution` | `compileResolution` | `compile_policy` (accepts either) | `CompilePolicy` (accepts either) | Keeps the resolved chain so receipts can name it | |
| Compile error | `CompileError` | `CompileError` | `CompileError` | `CompileError` | Strict by default: a pattern outside the regex profile fails at compile time, naming the offending rule path | Non-strict keeps the evaluator's deferred deny: TS `{ strict: false }`, Python `strict=False` |
| Cached content hash | `CompiledPolicy::content_hash` | `CompiledPolicy` (cached on first use) | `CompiledPolicy` (cached) | `(*CompiledPolicy).ContentHash` | Computed once, reused by every receipt | |
| Loading facade | `Policy` (`from_path`, `from_str`, `resolve`, `verify`, `compile`) | -- | -- | -- | `load -> resolve -> verify -> validate -> compile` as one chain | Rust only; the other three compose the free functions |
| Cache behind the free functions | (explicit) | `WeakMap` keyed on the document | small compiled-policy cache | (explicit) | The free `evaluate*` functions never recompile per call | Rust and Go make the caller hold the `CompiledPolicy` |

## Evaluation

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Evaluate | `evaluate`, `CompiledPolicy::evaluate` | `evaluate` | `evaluate` | `Evaluate`, `(*CompiledPolicy).Evaluate` | `allow`, `warn` or `deny` with `matched_rule` and `reason`. Precedence `deny > warn > allow`; an unknown action type denies; no early return on an allowlist match | Core spec 5 and 6.1 |
| Evaluate with a recorded trace | `evaluate::evaluate_traced` | `evaluateTraced` | `evaluate_traced` | `EvaluateTraced` | The trace is *recorded during* evaluation, never reconstructed: every applicable block in evaluation order under the receipt schema's closed `rule_block` ids | Receipt spec 4.3 -- the Level 4 requirement |
| Evaluate with runtime context | `evaluate_with_context` | `evaluateWithContext` | `evaluate_with_context` | `EvaluateWithContext` | Supplies the `RuntimeContext` a `when` clause reads | |
| Evaluate with detection | `evaluate_with_detection` | `evaluateWithDetection` | `evaluate_with_detection` | `EvaluateWithDetection` | Runs the detector registry, then folds the result into the decision | Traced forms: `evaluate_with_detection_traced`, `evaluateWithDetectionTraced`, `EvaluateWithDetectionTraced` |
| Action | `EvaluationAction` | `EvaluationAction` | `EvaluationAction` | `EvaluationAction` | `{type, target, content?, origin?, posture?, args_size?, url?, network?, timeout_ms?, context?}` | Rust's field is `action_type`, serialized as `type`; Go's `Content` is a `*string` so absent and empty stay distinct |
| Result | `EvaluationResult`, `Decision` | `EvaluationResult`, `Decision` | `EvaluationResult`, `Decision` | `EvaluationResult`, `Decision` | `{decision, matched_rule, reason, origin_profile, posture}` | Go's values are `DecisionAllow`, `DecisionWarn`, `DecisionDeny` |
| Traced result | `evaluate::TracedEvaluation` | `TracedEvaluation` | `TracedEvaluation` | `TracedEvaluation` | The result plus the ordered `rule_trace` | |
| Unknown-action sentinel | `evaluate::UNKNOWN_ACTION_TYPE_RULE` | `UNKNOWN_ACTION_TYPE_RULE` | `UNKNOWN_ACTION_TYPE_RULE` | `UnknownActionTypeRule` | `"__unknown_action_type__"` | |
| Normalization | `evaluate::normalize_host`, `normalize_path`, `host_pattern_matches`, `path_glob_matches`, `punycode_encode` | `normalizeHost`, `normalizePath`, `hostPatternMatches`, `pathGlobMatches`, `punycodeEncode` | `normalize_host`, `normalize_path`, `host_pattern_matches`, `path_glob_matches`, `punycode_encode` | `NormalizeHost`, `NormalizePath`, `HostPatternMatches`, `PathGlobMatches`, `PunycodeEncode` | Core spec 3.14, byte for byte across the four | `glob_matches` is crate-private in Rust |

## Conditions

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Condition value | `Condition` | `Condition` | `Condition` | `Condition` | `time_window`, `context`, `all_of`, `any_of`, `not`, `capability`, `rate` | |
| Evaluate a condition | `evaluate_condition` | `evaluateCondition` | `evaluate_condition` | `EvaluateCondition` | An unevaluable condition means **active**: the rule block still runs and can still deny | Fail-closed -- a `when` clause never turns a deny into an allow by failing |
| With posture capabilities | `evaluate_condition_with_capabilities` | `evaluateConditionWithCapabilities` | `evaluate_condition_with_capabilities` | `EvaluateConditionWithCapabilities` | `when.capability` holds when the effective posture state grants that capability (core spec 3.13, D19) | |
| Capability identifier | `is_capability_identifier` | `isCapabilityIdentifier` | `is_capability_identifier` | `IsCapabilityIdentifier` | The grammar a capability name must match | Lint `L021` flags a capability no posture state grants |
| Rate condition | `RateCondition`, `RateComparison` | `RateCondition`, `RateComparison`, `RATE_COMPARISONS` | `RateCondition`, `RateComparison` | `RateCondition`, `RateComparison`, `RateComparisonGte`, `RateComparisonLt`, `RateComparisons` | `{counter, threshold, comparison}` against `RuntimeContext.counters`, supplied by the engine. A missing counter is unevaluable, so the block stays active | The closed comparison set is `gte`, `lt` |
| Runtime context | `RuntimeContext` | `RuntimeContext` | `RuntimeContext` | `RuntimeContext` | `user`, `environment`, `deployment`, `agent`, `session`, `request`, `custom`, `counters`, `current_time` | |
| Nesting limit | `conditions::MAX_NESTING_DEPTH` | `MAX_NESTING_DEPTH` | `conditions.MAX_NESTING_DEPTH` | `MaxNestingDepth` | 8 | |
| Timezone check | `conditions::timezone_is_known` | `timezoneIsKnown` | `timezone_is_known` | `TimezoneIsKnown` | An unknown zone is a validation error, not a silent UTC fallback | Python needs `tzdata` where there is no system zoneinfo |

## Detection

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Detector interface | `Detector` | `Detector` | `Detector` | `Detector` | `name`, `category`, `detect` | |
| Registry | `DetectorRegistry` | `DetectorRegistry` | `DetectorRegistry` | `DetectorRegistry`, `NewDetectorRegistry` | Custom detectors register beside the built-ins | |
| Default registry | `DetectorRegistry::with_defaults`, `default_detector_registry` | `DetectorRegistry.withDefaults` | `default_detector_registry` | `WithDefaultDetectors`, `NewDefaultDetectorRegistry` | The same four detectors in the same order | `NewDefaultDetectorRegistry` is the isomorphism alias of `WithDefaultDetectors`; both build the same registry |
| Regex detectors | `RegexInjectionDetector`, `RegexJailbreakDetector`, `RegexExfiltrationDetector` | the same three | the same three | `NewRegexInjectionDetector`, `NewRegexJailbreakDetector`, `NewRegexExfiltrationDetector` | `regex_injection@1`, `regex_jailbreak@1`, `regex_exfiltration@1` | |
| `heuristic_injection@1` | `detection::HeuristicInjectionDetector` | `HeuristicInjectionDetector` | `HeuristicInjectionDetector` | `NewHeuristicInjectionDetector` | The normative integer-scored detector of detection spec 3.5 (D20). The signal table and the uppercase rule are fixed, so every engine reproduces the same score for the same input | Rust does not re-export it at the crate root -- reach it as `hushspec::detection::HeuristicInjectionDetector` |
| Detector name | `detection::HEURISTIC_DETECTOR_NAME` | `HEURISTIC_DETECTOR_NAME` | `HEURISTIC_DETECTOR_NAME` | `HeuristicDetectorName` | `"heuristic_injection"` | The `@1` suffix is appended from a private `DETECTOR_ID_VERSION` in all four, so a receipt's `detector_id` reads `heuristic_injection@1` |
| Signal table | `detection::HEURISTIC_FAMILIES`, `HEURISTIC_UPPERCASE_WEIGHT`, `HEURISTIC_UPPERCASE_MIN_LETTERS`, `HEURISTIC_UPPERCASE_MIN_PERCENT` | the same four | `HEURISTIC_FAMILIES` (weights module-level) | `HeuristicFamilies`, `HeuristicUppercaseWeight`, `HeuristicUppercaseMinLetters`, `HeuristicUppercaseMinPercent` | Published so a third-party engine can reproduce the score without reading the source | |
| Level from score | `DetectorLevel::from_score` | `detectorLevel` | `DetectionResult` | `DetectorLevelFromScore` | `none`, `low`, `suspicious`, `high`, `critical` | |
| Result types | `DetectionResult`, `DetectionCategory`, `MatchedPattern`, `DetectorEvaluation` | the same four | the same four | the same four | `detection_trace` in a receipt is built from `DetectorEvaluation` | |

## Canonical form and content hash

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Canonical JSON of a document | `canonical_json` | `canonicalJson` | `canonical_json` | `CanonicalJSON` | Schema defaults materialized, then RFC 8785 (JCS). Byte-identical across the four for the same resolved document | Canonical form spec |
| Canonical JSON of any value | `canonical_json_value`, `serialize_jcs` | `canonicalizeValue` | `canonical_json_value` | `DigestOf` | Plain JCS with no schema step -- what receipts and log entries hash | |
| Content hash | `content_hash` | `contentHash` | `content_hash` | `ContentHash` | `sha256:` plus 64 lowercase hex over the canonical form of the **resolved** document | The portable identity of a policy; `h2h hash` prints it |
| Hash prefix | `CONTENT_HASH_PREFIX` | inline | inline | unexported | `"sha256:"` | |
| Single-hop hash | `own_content_hash` | internal | internal | `OwnContentHash` | One hop with `extends` and `merge_strategy` stripped -- what a digest pin compares | |
| Error | `CanonicalError` | `CanonicalError` | `CanonicalError` | `error` | A value JCS cannot represent (NaN, a non-string key) is an error, never a lossy encoding | |

## Receipts and receipt hash

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Format version | `RECEIPT_VERSION` | `RECEIPT_VERSION` | `RECEIPT_VERSION` | `ReceiptVersion` | `"0.2"` | |
| Evaluate and record | `evaluate_audited` | `evaluateAudited` | `evaluate_audited` | `EvaluateAudited` | Takes a **`Resolution`**, an action, an `AuditConfig` and an `AuditContext`; returns a format 0.2 receipt | Content is never carried -- only `action.content_hash` and `content_size` |
| From a bare document | `evaluate_audited_spec` | `evaluateAuditedSpec` | `evaluate_audited_spec` | `EvaluateAuditedSpec` | Resolves the leaf as `memory` first | |
| Receipt value | `DecisionReceipt` | `DecisionReceipt` | `DecisionReceipt` | `DecisionReceipt` | `receipt_version`, UUID v7 `receipt_id`, millisecond `timestamp` with `time_source`, `actor`, `policy`, `action`, decision, recorded `rule_trace`, `detection_trace`, required `enforcement` | Validates against `hushspec-receipt.v0.schema.json` |
| Parse a receipt | `DecisionReceipt::parse` | `parseReceipt` | `parse_receipt` | `ParseReceipt` | Accepts exactly what the 0.2 schema accepts; every `receipts/invalid/` vector is rejected | |
| Receipt hash | `DecisionReceipt::receipt_hash` | `receiptHash` | `receipt_hash` | `(*DecisionReceipt).ReceiptHash` | `sha256:` over the JCS form of the receipt -- what the log chains and the signer signs | |
| Receipt canonical JSON | `DecisionReceipt::canonical_json` | `receiptCanonicalJson` | `receipt_to_dict` + `canonical_json_value` | `(*DecisionReceipt).CanonicalJSON` | | TS re-exports `canonicalJson as receiptCanonicalJson` so the policy one stays unambiguous |
| Policy summary | `policy_summary`, `PolicySummary` | `policySummary`, `PolicySummary` | `policy_summary`, `PolicySummary` | `NewPolicySummary`, `PolicySummary` | `content_hash`, `extends_chain`, `signature` -- the policy identity every receipt embeds | |
| Policy hash | `content_hash` | `computePolicyHash` | `compute_policy_hash` | `ComputePolicyHash` | The canonical `sha256:` hash; 0.1's per-SDK digest is gone | |
| Unverified-policy receipt | `unverified_policy_receipt`, `POLICY_UNVERIFIED_RULE` | `unverifiedPolicyReceipt`, `POLICY_UNVERIFIED_RULE` | `unverified_policy_receipt`, `POLICY_SIGNATURE_RULE` | `UnverifiedPolicyReceipt`, `PolicyUnverifiedRule` | The receipt a refused guard emits for every action; `matched_rule` is `"__hushspec_policy_unverified__"` | TS exports both spellings -- `POLICY_SIGNATURE_RULE` aliases `POLICY_UNVERIFIED_RULE` |
| Deterministic ids and time | `deterministic_uuid_v7`, `format_timestamp` | `deterministicUuidV7`, `uuidV7`, `formatTimestamp` | `deterministic_uuid_v7`, `format_timestamp` | `DeterministicUUIDv7`, `NewUUIDv7`, `FormatTimestamp` | The fixed inputs `fixtures/receipts/expected/README.md` pins, so the expected-receipt vectors reproduce byte for byte | |
| Audit config and context | `AuditConfig`, `AuditContext`, `Actor` | `AuditConfig`, `AuditContext`, `Actor` | `AuditConfig`, `AuditContext`, `Actor` | `AuditConfig`, `DefaultAuditConfig`, `AuditContext`, `Actor` | `AuditConfig` is `{enabled, include_rule_trace, record_duration}` | 0.1's `redact_content` is gone: a 0.2 receipt never carries content |

## Hash-linked log

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Format version | `LOG_VERSION` | `LOG_VERSION` | `LOG_VERSION` | `LogVersion` | `"0.1"` | |
| Genesis hash | `GENESIS_HASH` | `GENESIS_HASH` | `GENESIS_HASH` | `GenesisHash` | `sha256:` plus 64 zeros -- `prev_hash` of the first entry | |
| Chained sink | `ChainedFileSink::open` | `ChainedFileSink` | `ChainedFileSink` | `OpenChainedFileSink` | Appends JSONL with an fsync and an exclusive lock per entry; rotation carries `prev_hash` through a `log_started` entry; per-entry signatures optional | |
| Entry | `LogEntry`, `EntryType`, `Payload` | `LogEntry`, `EntryType`, `Payload` | `LogEntry`, `EntryType` | `LogEntry`, `EntryType`, `LogPayload` | `receipt`, `policy_loaded`, `policy_swapped`, `log_started` | |
| Entry hash | `LogEntry::compute_entry_hash` | `computeEntryHash` | `LogEntry` | `(*LogEntry).ComputeEntryHash` | JCS over the entry minus its own hash | |
| Verify one file | `verify_log` | `verifyLog` | `verify_log` | `VerifyLog` | Reports the **first** break by line number; a broken chain is never a partial pass | Level 5 requires naming the line |
| Verify a rotated set | `verify_logs`, `verify_log_files` | `verifyLogs`, `verifyLogFiles` | `verify_logs`, `verify_log_files` | `VerifyLogs`, `VerifyLogFiles` | Oldest first; the link *between* files is checked too | |
| Report | `LogVerifyReport`, `LogError` | `LogVerifyReport`, `LogBreak` | `LogVerifyReport` | `LogVerifyReport`, `LogError` | Counters plus the break's file, line and message | |
| Policy events | `PolicyEvent::loaded`, `PolicyEvent::swapped` | `policyLoadedEvent`, `policySwappedEvent` | `PolicyEvent`, `policy_event_to_dict` | `NewPolicyLoadedEvent`, `NewPolicySwappedEvent` | Which policy came into force when, and what it replaced | Delivered through the sink's `record_policy_event` |
| SDK identity | `SdkInfo::this_sdk` (`hushspec-rs`) | `thisSdk` (`@hushspec/core`) | `SdkInfo` (`hushspec-python`) | `ThisSDK`, `SDKName` (`hushspec-go`) | Recorded in every entry (log spec 6) | Deliberately distinct -- this member says who wrote the line |

## Signing, keyrings, receipt signing

Rust needs the `signing` Cargo feature; Python needs the `signing` extra
(`pip install "hushspec[signing]"`), without which every entry point below
raises `SigningUnavailable` rather than reporting an unverified signature as
good.

| Operation | Rust *(feature `signing`)* | TypeScript | Python *(extra `signing`)* | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Envelope version | `signing::FORMAT_VERSION` | `SIGNATURE_FORMAT_VERSION` | `ENVELOPE_FORMAT_VERSION` | `SignatureFormatVersion` | `"0.2"` | Format 0.1 signed file bytes and cannot be verified by 0.2 |
| Algorithm | `signing::ALGORITHM` | `SIGNATURE_ALGORITHM` | `SIGNATURE_ALGORITHM` | `SignatureAlgorithm` | `"ed25519"` | |
| Sign a policy | `signing::sign_policy` | `signPolicy` | `sign_policy` | `SignPolicy` | Signs the **content hash of the resolved policy**, not the file's bytes: reformatting keeps a signature valid, changing a base reached through `extends` invalidates it | |
| Verify a policy | `signing::verify_policy` | `verifyPolicy` | `verify_policy` | `VerifyPolicy` | Returns valid, or invalid with one of the eleven closed reason codes of signing spec 6.4 | All four pass all 16 `fixtures/signing/vectors.yaml` cases |
| Sign / verify a bare hash | `signing::sign_content_hash`, `verify_content_hash` | `signContentHash`, `verifyContentHash` | `sign_content_hash`, `verify_content_hash` | `SignContentHash`, `VerifyContentHash` | The primitive the policy, receipt and log signers share | |
| Envelope | `signing::Envelope` | `Envelope`, `parseEnvelope`, `envelopeSigningInput` | `Envelope`, `parse_envelope`, `signing_input` | `Envelope`, `ParseEnvelope`, `MarshalEnvelope` | `hushspec-signature.v0.schema.json` | |
| Reason codes | `signing::ReasonCode` (`ALL`, `as_str`, `from_code`) | `ReasonCode` | `REASON_CODES` | `ReasonMalformedEnvelope` ... `ReasonPolicyVersionRollback` | The closed set of signing spec 6.4 -- identical strings in all four | Rust's is an enum with a `&'static str` wire form; TS's is a type-level union only |
| Keyring | `signing::Keyring` | `Keyring`, `loadKeyring`, `keyringFromPublicKey` | `Keyring`, `load_keyring` | `Keyring`, `LoadKeyring`, `KeyringFromPublicKey` | `hushspec-keyring.v0.schema.json`, with retirement and revocation | |
| Key id | `signing::key_id` | `keyIdFromPublicKey` | `key_id_from_public_key` | `KeyIDFromPublicKey` | SHA-256 of the SPKI DER -- never chosen by the signer | |
| Keypair | `signing::generate_keypair` | `generateKeypair` | `cryptography` | `ParsePrivateKeyPEM`, `MarshalPrivateKeyPEM` | PKCS#8 and SubjectPublicKeyInfo PEM | |
| Sign a receipt | `signing::sign_receipt` | `signReceipt` | `sign_receipt` | `SignReceipt` | Signs the receipt hash | `SignedReceipt` in all four |
| Verify a receipt | `signing::verify_receipt` | `verifyReceipt` | `verify_receipt` | `VerifyReceipt` | | |
| Clock skew default | `signing::DEFAULT_MAX_CLOCK_SKEW_SECONDS` | `DEFAULT_MAX_CLOCK_SKEW_SECONDS` | `verify_policy` | `DefaultMaxClockSkewSeconds` | 300 seconds | |

## Policy bundles

| Operation | Rust *(feature `signing`)* | TypeScript | Python *(extra `signing`)* | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Parse a bundle | `DsseEnvelope::parse` | `parseBundle` | `parse_bundle` | `ParseBundle` | A DSSE envelope over an in-toto Statement v1 | Readable by generic DSSE and in-toto tooling |
| Verify a bundle | `verify_bundle` | `verifyBundle` | `verify_bundle` | `VerifyBundle` | The four ordered checks of bundle spec 5.2, returning valid or one of the five closed reason codes of 5.4 | All four pass all 8 `fixtures/bundle/vectors.yaml` cases |
| Reason codes | `BundleReason` | `BUNDLE_REASONS`, `BundleReason` | `BUNDLE_REASON_CODES` | `BundleReasons`, `BundleReasonMalformed` ... | `malformed_bundle`, `unknown_key_id`, `dsse_signature_mismatch`, `subject_digest_mismatch`, `policy_mismatch` | |
| Statement and predicate | `Statement`, `PolicyBundlePredicate`, `Subject` | `BundleStatement`, `PolicyBundlePredicate`, `BundleSubject` | `hushspec.bundle` | `BundleStatement`, `PolicyBundlePredicate`, `BundleSubject` | The subject is the canonical form of the resolved document; the predicate carries every hop with its hash and signature status | |
| PAE | `pae` | `pae` | `hushspec.bundle` | `BundlePAE` | DSSE pre-authentication encoding | |
| Create and sign | `build_statement`, `sign_statement`, `unsigned_envelope` | -- | -- | -- | Production is Rust and `h2h bundle create` only | Verification is what a relying party depends on, and all four verify |
| Version and types | `BUNDLE_VERSION`, `PAYLOAD_TYPE`, `STATEMENT_TYPE`, `PREDICATE_TYPE` | `BUNDLE_VERSION`, `BUNDLE_PAYLOAD_TYPE`, `BUNDLE_STATEMENT_TYPE`, `BUNDLE_PREDICATE_TYPE` | `BUNDLE_VERSION`, `PAYLOAD_TYPE`, `STATEMENT_TYPE`, `PREDICATE_TYPE` | `BundleVersion`, `BundlePayloadType`, `BundleStatementType`, `BundlePredicateType` | `"0.1"` plus the three URIs | TS prefixes the three type constants |

## Guard, enforcement modes, refused state

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| The enforcement point | `HushGuard` | `HushGuard` | `HushGuard` | `Guard` | Compiled policy, enforcement mode, warn channel, sink, observers, actor and clock behind `check` / `evaluate` / `enforce` | **Go spells it `Guard`** -- `HushGuard` would stutter as `hushspec.HushGuard` |
| Construct | `HushGuard::from_path`, `from_policy`, `from_resolution`, `builder` | `HushGuard.fromFile`, `fromYaml`, `fromProvider` | `HushGuard.from_file`, `from_provider` | `NewGuard`, `NewGuardFromFile`, `NewGuardFromProvider` | Compiles once at construction | Rust uses a builder (`HushGuardBuilder`); the others use options structs or keyword arguments |
| Check without throwing | `check` | `check` | `check` | `Check` | Returns the decision plus the receipt, the enforced flag and the duration | `GuardDecision` in all four |
| Enforce | `enforce` -> `Result<_, Denied>` | `enforce` (throws `HushSpecDenied`) | `enforce` (raises `HushSpecDenied`) | `Check` plus `GuardDecision.Allowed` | A deny stops the tool call before its body runs | Go has no exceptions, so the caller branches on `Allowed()` |
| Record without enforcing | `evaluate` | `evaluate` | `evaluate` | `Evaluate` | Monitor-mode observation | |
| Enforcement mode | `EnforcementMode`, `EnforcementConfig` | `EnforcementMode`, `EnforcementConfig` | `EnforcementMode`, `EnforcementConfig` | `EnforcementMode`, `GuardOptions.RuleOverrides` | `enforce` or `monitor`, with per-rule-path overrides; **longest prefix wins** | Monitor mode is refused without a sink or an observer: an unrecorded observation is not evidence |
| Outcome | `EnforcementOutcome`, `EnforcementSummary` | `EnforcementOutcome`, `EnforcementSummary` | `EnforcementOutcome`, `EnforcementSummary` | `EnforcementOutcome`, `EnforcementSummary`, `ImpliedEnforcement` | `allowed`, `confirmed`, `blocked`, `would_block` -- required on every receipt | |
| Rule-path prefix match | `matches_rule_path_prefix` | `matchesRulePathPrefix` | `matches_rule_path_prefix` | `MatchesRulePathPrefix` | How an override key matches a `matched_rule` | |
| Warn confirmation | `on_warn` (`WarnHandler`) | `onWarn` (`WarnHandler`) | `on_warn` | `GuardOptions.OnWarn` (`WarnHandler`) | **Absent, a `warn` denies** (core spec D16) | The one place the guard is stricter than the evaluator |
| Refused state | `refused`, `refusal` | denials carry `POLICY_SIGNATURE_RULE` | `HushGuard.refusal` | `(*Guard).Refused`, `GuardRefusal` | A policy that fails verification under `require_signature` does not fail construction -- it builds a guard that denies **every** action with `__hushspec_policy_unverified__` and an unverified-policy receipt | Failing to build would tempt a caller into running with no policy at all |
| Hot swap | `swap_policy` | `swapPolicy` | `swap_policy`, `swap_resolution` | `SwapPolicy` | Atomic. A new policy that will not validate or compile leaves the last good one in force and is reported through `on_error` | |
| Panic and refusal | always enforce | always enforce | always enforce | always enforce | Neither monitor mode nor a warn handler can let a panic-mode or refused-policy deny through | |

## Observers and metrics

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Observer interface | `EvaluationObserver` | `EvaluationObserver` | `EvaluationObserver` | `EvaluationObserver` | `on_policy_loaded`, `on_evaluation`, `on_error`, all defaulted. **An observer sees every decision and can change none** | Action `content` is stripped before any observer sees it |
| Fan-out wrapper | `ObservableEvaluator` | `ObservableEvaluator` | `ObservableEvaluator` | `NewObservableEvaluator` | One evaluation, every registered observer | |
| JSON lines | `JsonLineObserver` | `JsonLineObserver` | `JsonLineObserver` | `NewJSONLineObserver` | One JSON object per event | |
| Console / stderr | `StderrObserver` | `ConsoleObserver` | `ConsoleObserver` | `NewStderrObserver`, `NewDenyOnlyStderrObserver` | Human-readable | TS and Python kept `ConsoleObserver`; Rust and Go say where it writes |
| Metrics | `MetricsCollector`, `MetricsSnapshot` | `MetricsCollector` | `MetricsCollector` | `NewMetricsCollector`, `MetricsSnapshot` | Counters by decision, action type and rule block, plus a latency histogram | |
| Prometheus exposition | `render_prometheus` | `toPrometheus` | `to_prometheus` | `RenderPrometheus` | The `hushspec_evaluate_total`, `hushspec_evaluate_duration_us`, `hushspec_rule_match_total` and `hushspec_policy_load_total` series | The one method whose name is not isomorphic: Rust and Go say `render`, TS and Python say `to` |
| Latency buckets | `DURATION_BUCKETS_US` | internal | internal | `DefaultDurationBucketsUs` | 10, 25, 50, 100, 250, 500, 1000, 5000, 10000 microseconds | |
| Webhook | `WebhookObserver` *(feature `http`)* | -- | -- | `NewWebhookObserver` | Bounded queue; drops with a counter rather than blocking an evaluation | |

## Providers and hot reload

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Provider interface | `PolicyProvider` | `PolicyProvider` | `PolicyProvider` | `PolicyProvider` | `load() -> Resolution` plus a `source` | A provider carries its own `ResolveOptions`, so `require_signature` applies to every reload |
| File provider | `FileProvider` | `FileProvider` | `FileProvider` | `NewFileProvider` | | |
| HTTP provider | `HttpProvider` *(feature `http`)* | `HttpProvider` | -- | -- | ETag-aware | Python and Go reload from a file or a callback |
| Callback provider | closure | closure | `CallbackProvider` | interface | | |
| Watcher | `PolicyWatcher` | `PolicyWatcher` | `PolicyWatcher` | `NewPolicyWatcher`, `PolicyWatcher` | Stats one file per tick; delivers only on a real change (mtime **and** content hash) | |
| Poller | `PolicyPoller` | `PolicyPoller` | `PolicyPoller` | `NewPolicyPoller` | Reloads through any provider on an interval; delivers only on a `content_hash` change | |
| Manual tick | `PolicyHandle` | `PollerOptions` | `check_once` | `CheckOnce` | For tests, and for callers driving their own loop | |
| Panic sentinel per tick | `panic_sentinel` | watcher option | watcher option | `ReloadOptions.PanicSentinel` | The kill switch is checked on the same tick as the reload | |
| Failure handling | `on_error` plus last good policy | `onError` plus last good policy | `on_error` plus last good policy | `ReportError` plus last good policy | A reload that cannot be read, parsed, resolved, verified or compiled **leaves the policy in force untouched**, reports, and retries | There is never a window with no policy |

## Receipt sinks

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Sink interface | `ReceiptSink` | `ReceiptSink` | `ReceiptSink` | `ReceiptSink` | `send(receipt)`, plus an optional `record_policy_event` | A sink that fails must not break an evaluation |
| File | `FileReceiptSink` | `FileReceiptSink` | `FileReceiptSink` | `NewFileReceiptSink` | JSONL | |
| Stderr | `StderrReceiptSink` | `StderrReceiptSink` (alias of `ConsoleReceiptSink`) | `StderrReceiptSink` | `StderrReceiptSink` | | `StderrReceiptSink` is the isomorphic name; TS keeps `ConsoleReceiptSink` as the original and pins the alias by identity |
| Filtered | `FilteredSink` | `FilteredSink` | `FilteredSink` | `NewFilteredSink`, `NewDenyOnlySink` | Route only the decisions you keep | |
| Multi | `MultiSink` | `MultiSink` | `MultiSink` | `NewMultiSink` | | |
| Callback | `CallbackSink` | `CallbackSink` | `CallbackSink` | `NewCallbackSink` | | |
| Null | `NullSink` | `NullSink` | `NullSink` | `NullSink` | | |
| Chained (hash-linked) | `ChainedFileSink` | `ChainedFileSink` | `ChainedFileSink` | `OpenChainedFileSink` | See [Hash-linked log](#hash-linked-log) | |
| OTLP | `OtlpSink`, `OtlpConfig` *(feature `otlp`)* | `OtlpReceiptSink` | `OtlpReceiptSink` | `NewOTLPReceiptSink`, `OTLPOptions` | `POST <endpoint>/v1/logs`: one `logRecord` per entry, `INFO`/`WARN`/`ERROR` by decision, `body.stringValue` the entry's canonical JSON, and the same `hushspec.*` attributes and resource attributes in all four | Background thread or goroutine, bounded queue, batching, backoff on 429 and 5xx. Export **never blocks an evaluation**; overflow drops, counts and reports rather than silently losing evidence |

## Framework adapters

| Framework | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Anthropic / Claude | -- | `mapClaudeToolToAction`, `createSecureToolHandler` | `adapters.map_claude_tool_to_action`, `adapters.create_secure_tool_handler` | `MapAnthropicToolUse`, `GuardedAnthropicToolHandler` | Maps a `tool_use` block onto the action a policy evaluates: `bash` to `shell_command`, text editor to `file_read` / `file_write`, `computer` to `computer_use`, `web_fetch` to `egress` on the host, `mcp__server__tool` to the inner tool name | No adapter imports the framework it adapts -- blocks are read structurally |
| OpenAI | -- | `mapOpenAIToolCall`, `createOpenAIGuard` | `adapters.map_openai_tool_call`, `adapters.create_openai_guard` | `MapOpenAIToolCall`, `GuardedOpenAIToolHandler` | | |
| MCP | -- | `mapMCPToolCall`, `extractDomain`, `createMCPGuard` | `adapters.map_mcp_tool_call`, `adapters.extract_domain`, `adapters.create_mcp_guard` | `MapMCPToolCall`, `ExtractDomain`, `GuardedMCPToolHandler` | | |
| Vercel AI SDK | -- | `mapVercelToolCall`, `createVercelGuard` | -- | -- | Gates each tool's `execute` | |
| LangChain | -- | `mapLangChainToolCall`, `wrapLangChainTool`, `createLangChainCallbackHandler` | `adapters.hush_tool` | -- | | TS wraps with a proxy, so the tool keeps its prototype, fields and `instanceof` |
| CrewAI | -- | -- | `adapters.secure_tool` | -- | | |
| Generic | -- | -- | -- | `ToolActionMapper[T]`, `ToolHandler[T]`, `GuardedToolHandler[T]` | | Go's adapters are one generic wrapper plus three mappers |

Rust has no adapter module. Its analogue is the worked example
`cargo run --example guarded_agent --features otlp`, which wires a policy
through a guard, a chained sink and an OTLP sink.

## Panic mode

| Operation | Rust | TypeScript | Python | Go | Semantics | Notes |
|---|---|---|---|---|---|---|
| Activate / deactivate | `activate_panic`, `deactivate_panic` | `activatePanic`, `deactivatePanic` | `activate_panic`, `deactivate_panic` | `ActivatePanic`, `DeactivatePanic` | While active, **every** evaluation returns `deny` with `__hushspec_panic__` | |
| Query | `is_panic_active` | `isPanicActive` | `is_panic_active` | `IsPanicActive` | | |
| Sentinel file | `check_panic_sentinel` | watcher option | `check_panic_sentinel` | `CheckPanicSentinel` | Fail-closed: an I/O error reading the sentinel is treated as *present* | |
| Deny-all policy | `panic_policy` | `panicPolicy` | `panic_policy` | `PanicRule` | The document panic mode evaluates as | |
| Scoped state | `PanicState` (`new`, `shared`) | -- | -- | -- | Rust can mint an independent latch per policy instead of the process-wide one | `PanicState::default()` is the shared latch, so the free functions keep working |
| Rule name | `evaluate::PANIC_RULE` | `PANIC_RULE` | `PANIC_RULE` | `PanicRule` | `"__hushspec_panic__"` | |

## Version constants

| Constant | Rust | TypeScript | Python | Go | Value |
|---|---|---|---|---|---|
| Spec version written | `HUSHSPEC_VERSION` | `HUSHSPEC_VERSION` | `HUSHSPEC_VERSION` | `Version` | `"0.2.0"` |
| Minors accepted | `version::HUSHSPEC_SUPPORTED_MINORS` | `HUSHSPEC_SUPPORTED_MINORS` | `HUSHSPEC_SUPPORTED_MINORS`, `SUPPORTED_MINORS` | `SupportedMinors` | `["0.1", "0.2"]` |
| Representative versions | `version::HUSHSPEC_SUPPORTED_VERSIONS` | `HUSHSPEC_SUPPORTED_VERSIONS`, `SUPPORTED_VERSIONS` | `HUSHSPEC_SUPPORTED_VERSIONS`, `SUPPORTED_VERSIONS` | `SupportedVersions` | `["0.1.0", "0.2.0"]` |
| Acceptance test | `version::is_supported` | `isSupported` | `is_supported` | `IsSupported` | Accepts every `X.Y.Z` of a supported minor (core spec 2.2, D14) |
| Minor of a version | `version::supported_minor` | `supportedMinor` | `supported_minor` | `SupportedMinor` | |
| Package identity | Cargo metadata | `SDK_NAME`, `SDK_VERSION` | `__version__` | `SDKName` | The SDK's own release, distinct from the spec version |
| Artifact formats | `RECEIPT_VERSION`, `LOG_VERSION`, `signing::FORMAT_VERSION`, `signing::KEYRING_VERSION`, `BUNDLE_VERSION`, `REPORT_VERSION` | `RECEIPT_VERSION`, `LOG_VERSION`, `SIGNATURE_FORMAT_VERSION`, `KEYRING_VERSION`, `BUNDLE_VERSION` | `RECEIPT_VERSION`, `LOG_VERSION`, `ENVELOPE_FORMAT_VERSION`, `KEYRING_VERSION`, `BUNDLE_VERSION` | `ReceiptVersion`, `LogVersion`, `SignatureFormatVersion`, `KeyringFormatVersion`, `BundleVersion` | `0.2`, `0.1`, `0.2`, `0.2`, `0.1` |

`SUPPORTED_VERSIONS` in TypeScript and Python, and `SUPPORTED_MINORS` in
Python, are aliases of the `HUSHSPEC_`-prefixed names, kept because the shorter
spelling predates the prefix. The exports tests assert identity rather than
equality, so they cannot drift apart.

## Error codes

Every `fixtures/<module>/invalid/` vector carries a `<name>.expect.yaml`
sidecar naming the code its refusal must report, drawn from
[`spec/registries/error-codes.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/error-codes.yaml).
All four fixture runners assert it -- see the
[SDK Conformance Matrix](sdk-conformance.md).

| Code | Meaning | Rust | TypeScript | Python | Go |
|---|---|---|---|---|---|
| `E000` | Input could not be read | CLI | `ErrorCode` | `ERROR_IO` | `ErrorCodeInput` |
| `E001` | YAML parse, profile, shape, type or unknown-member error | CLI, testkit | `ErrorCode` | `ERROR_PARSE` | `ErrorCodeParse` |
| `E002` | Unsupported `hushspec` version | `ValidationError::UnsupportedVersion` | `ErrorCode` | `ERROR_UNSUPPORTED_VERSION` | `ErrorCodeUnsupportedVersion` |
| `E003` | Duplicate secret pattern name | `ValidationError::DuplicatePatternName` | `ErrorCode` | `ERROR_DUPLICATE_PATTERN_NAME` | `ErrorCodeDuplicatePatternName` |
| `E004` | Constraint violation | `ValidationError::Custom` | `ErrorCode` | `ERROR_CONSTRAINT_VIOLATION` | `ErrorCodeConstraint` |
| `E005` | Regex outside the HushSpec profile | `ValidationError::InvalidRegex` | `ErrorCode` | `ERROR_INVALID_REGEX` | `ErrorCodeInvalidRegex` |
| `E010` | `extends` resolution failed | `ResolveError` | `ResolveResult.code` | `ERROR_EXTENDS` | `ErrorCodeExtends` |
| `E011` | A `metadata` date that is not an ISO 8601 calendar date | `ValidationError::InvalidDate` | `ErrorCode` | `ERROR_INVALID_DATE` | `ErrorCodeInvalidDate` |

Three deliberate differences:

- **Rust's library does not carry the code strings.** `ValidationError` is a
  typed enum; the mapping to `E00x` lives in
  `hushspec_testkit::expect::validation_error_code` and in
  `crates/hushspec-cli/src/cmd_validate.rs`. An embedder that needs codes maps
  the enum itself or uses the testkit helper.
- **TypeScript's `ErrorCode` is a type, not a value.** There is no runtime
  `ERROR_CODES` array; the codes appear on `ParseResult.code`,
  `ResolveResult.code` and `ValidationError.code`.
- **Python and Go expose both.** `hushspec.ERROR_CODES` (a tuple) and
  `hushspec.ErrorCodes` (a slice) list the eight in registry order, beside
  named constants and per-value `.code` / `.Code` members. Go adds
  `ErrorCodeOf(err)` and `RegistryErrorCode(kind)`.

The signing (11 codes), bundle (5 codes) and resolve reason sets are separate
closed registries and never overlap with `E0xx`. They are normative in the
[signing](../signing-spec.md) and [bundle](../bundle-spec.md) specifications.

## Cross-SDK invariants

These are the properties the four SDKs must share. They are not aspirations:
each is enforced by a check that fails CI.

| Invariant | Enforced by |
|---|---|
| **Identical decisions.** For any document and action, all four return the same `decision`, `matched_rule`, `reason`, `origin_profile` and `posture`. | The shared corpus (`fixtures/{core,posture,origins,detection}/evaluation`) run natively by each SDK, plus `hushspec-difftest` over 500 generated policy groups per commit, comparing each port against the Rust oracle. |
| **Identical canonical form and content hash.** The same resolved document canonicalizes to the same bytes and hashes to the same `sha256:` in all four. | `fixtures/core/hash/` (14 vectors) run by all four; `scripts/check_cross_sdk_roundtrip.py`; `content_hash` compared per group by `hushspec-difftest`. |
| **Byte-identical receipts after JCS under fixed inputs.** With the actor, clock, receipt id and audit config that `fixtures/receipts/expected/README.md` pins, every evaluation case produces the committed receipt byte for byte after RFC 8785. | `fixtures/receipts/expected/<module>/<fixture>/<case>.json` run by all four; `receipt_hash` compared per group by `hushspec-difftest`. |
| **Identical recorded rule traces.** The same entries, in the same order, under the same closed `rule_block` ids. | The `expect.rule_trace` assertions of evaluator-test format 0.2, plus the expected receipts. |
| **Identical reason codes.** The 11 signing reasons, the 5 bundle reasons and the resolve reasons are the same strings everywhere. | `fixtures/signing/vectors.yaml` (16 cases) and `fixtures/bundle/vectors.yaml` (8 cases), each asserting the exact code, run by all four. |
| **Identical error codes.** Every `invalid/` vector is rejected with the code its sidecar names. | The four fixture runners, against the `.expect.yaml` sidecars. |
| **Identical public names.** One concept, one name across the four, modulo language casing. | `tests/exports.test.ts`, `tests/test_public_surface.py`, `isomorphism_test.go`. |
| **Identical parse refusals.** The YAML profile, the document limits and the closed key sets reject the same inputs. | `fixtures/*/invalid/` plus the generated contract (`scripts/generate_sdk_contracts.py`), checked for drift by the `generated-sources` CI job. |

Anyone can reproduce these outside this repository: every release attaches
`hushspec-conformance-<version>.tar.gz` with the prose, the schemas, the
vectors and `fixtures/MANIFEST.json`, which pins the corpus by digest. See
[Conformance Levels](conformance.md) and the
[Conformance Statement](conformance-statement.md) template.

## Fail-closed rules the four share

Stated once, because they are why the surface looks the way it does.

1. **An invalid document is never a partially valid one.** Parse and validate
   reject; they do not repair, coerce, or drop unknown members.
2. **An ambiguous rule denies.** An unknown action type, an unknown guard type
   and a malformed pattern all deny.
3. **An unevaluable `when` means the block is active.** A condition that cannot
   be decided never removes a rule from consideration.
4. **A warn with no confirmation channel denies** (core spec D16).
5. **A required signature that cannot be verified refuses the whole policy**,
   and the refusal is itself recorded as a receipt.
6. **A failed reload keeps the last good policy.** There is no window in which
   no policy is in force.
7. **Monitor mode needs somewhere to record.** A guard in monitor mode with no
   sink and no observer is refused at construction.
8. **Panic mode and a refused policy always enforce.** Neither monitor mode nor
   a warn handler can let them through.
9. **Evidence is never silently dropped.** A full OTLP queue drops with a
   counter and an error callback; a sink that fails does not break the
   evaluation but does surface through `on_error`.
