# Raw YAML scalar conformance

`scalars.json` stores complete YAML source strings in a JSON container. Every
runner must pass the decoded `yaml` string directly to the public policy parser.
Parsing the YAML into an object and serializing it again before the SDK sees it
would erase the spelling under test.

Each vector declares whether parsing must succeed (`accept`). Successful vectors
carry a `value_path` and literal JSON `value`, checked against the parsed policy's
canonical JSON. JSON numeric equality treats integral doubles and integers as the
same value, but strings, booleans and null must retain their types.
When traversal reaches an array, the next path component is its decimal index
as a string (for example `"0"`).

When `canonical` is present it is a hand-derived canonical JSON string, including
schema defaults. Compare its bytes with the SDK canonical output and compute its
SHA-256 independently to check the SDK content hash. When `decision` is present,
evaluate an action of type `egress`, target `example.com`, with runtime context
`{"counters":{"requests":9}}`. All rate cases use comparison `lt`; a threshold
of ten activates the default blocking rule and denies, while a threshold of nine
or zero disables it and allows.

The corpus covers decimal leading zeros, octal/hexadecimal forms, legacy scalars
that Core treats as strings, exponents, integral floats, quoted and tagged values,
booleans/null, timestamps, finite-double and portable-integer limits, recursive
conditions, posture budgets, and Unicode preceding rewritten scalar tokens.
Explicit Core tags validate their payloads; non-Core tags are refused. The
non-specific scalar tag `!` retains strings. Nested condition contexts keep
fractions and large doubles through `all_of`, `any_of`, and `not`.
Existing profile suites continue to cover duplicate/unknown fields, aliases,
anchors, merge keys, document streams and resource bounds.
