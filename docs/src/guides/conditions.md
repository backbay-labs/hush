# Conditional rules

A `when` condition decides whether one rule block participates in an evaluation.
Use it for runtime-dependent restrictions, not for authenticating the runtime's
claims. The host supplies trusted context; the policy does not discover identity,
count operations, or read clocks on its own.

## The condition vocabulary

| Field | Meaning | Important edge |
| --- | --- | --- |
| `context` | Match dot-delimited runtime keys | Missing keys are false, not unevaluable |
| `time_window` | Daily start/end in an IANA zone or fixed offset | Invalid runtime time is unevaluable |
| `capability` | Effective posture grants the named capability | No posture extension is unevaluable |
| `rate` | Compare a host counter with `gte` or `lt` | Missing or malformed counter is unevaluable |
| `all_of` | Every child holds | False wins over unevaluable |
| `any_of` | Some child holds | True wins over unevaluable; empty list is treated as absent |
| `not` | Negate a child | Unevaluable stays unevaluable |

Multiple fields in one object combine with AND. Nesting beyond eight condition
levels is rejected. See [core section 3.13](../../../spec/hushspec-core.md#313-conditional-rule-blocks-when)
for the complete three-valued evaluation and field grammar.

## A conditional restriction

This complete policy denies the named tool in production. It is deliberately
not a default-deny tool policy: other tools and other environments are not
restricted by this block.

```yaml
hushspec: "1.0.0"
name: production-deploy-gate
rules:
  tool_access:
    when:
      context:
        environment: production
    block: [deploy]
```

When `environment` is absent, this particular condition is false and the block
is inactive. If deployment is security-critical, require the host to supply
validated environment context and keep an unconditional restriction underneath.

## Missing context does not have one universal meaning

A false condition makes the block inert. A true or unevaluable condition leaves
it active. Missing `context` keys are false, but missing `rate` counters and
unavailable posture capabilities are unevaluable. Negating a missing counter
does not turn a restriction off.

Context comparisons are type-sensitive. The number `1` does not equal
the string `"1"` or boolean `true`; numeric comparisons are exact, not
approximate. Expected objects and null do not match. Arrays use the
[scalar/array comparison table](../../../spec/hushspec-core.md#313-conditional-rule-blocks-when),
not structural JSON equality.

## Time and rate inputs

Times use exact `HH:MM` fields. Fixed offsets look like `+05:30` or `-08`,
not `+5` or `+0530`. The host's `current_time` is a complete RFC 3339
timestamp, not a date alone. Test window boundaries, overnight windows and the
chosen zone using deterministic context.

A `rate` predicate consumes `counter`, non-negative `threshold`, and
`comparison`. It never increments the counter. Define who owns its scope and
updates; reserve capacity before dispatch when concurrent tools share a limit.
For action-to-capability mapping, see [posture](../extensions/posture.md).
