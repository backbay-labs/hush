# Library test suites

One control-tagged evaluation suite per vertical-library policy
(`library/<vertical>/<name>.yaml` → `<vertical>/<name>.test.yaml`), in the
`hushspec-evaluator-test` 0.2 format.

```bash
h2h test --fixtures fixtures/library --fail-on-uncovered
cargo run -p hushspec-testkit --bin hushspec-testkit -- --fixtures fixtures
```

## What a suite is

Each case declares the control it is evidence for, in the same `framework` /
`control_id` vocabulary the policy uses in `metadata.controls`, so a passing
run answers "which control does this prove?" rather than only "did it pass?":

```yaml
- description: "PHI directories are unreachable"
  controls:
    - framework: hipaa-2013
      control_id: "164.312(a)(1)"
  tags: ["deny", "paths"]
  action:
    type: file_read
    target: "/srv/app/medical-records/2026/intake.csv"
  expect:
    decision: deny
    matched_rule: rules.forbidden_paths.patterns
```

`h2h test --format junit` turns those into `<property name="control">` entries,
which is how the suites reach a CI test summary.

## The invariant

Between them, the cases of a suite hit **every rule block and every named
secret pattern** of the resolved policy. `h2h test` compares the declared rule
paths with the paths the cases hit (through `matched_rule` and through each
recorded `rule_trace` entry) and `--fail-on-uncovered` fails the run when one
was never exercised, which is how CI gates these suites at 100%.

A rule that cannot be reached shows up here as an uncovered path. That is a
finding about the policy, not about the suite: the first matching secret
pattern names the finding, so a specific pattern listed after a general one
that subsumes it can never be attributed, and belongs before it.

## How a suite loads its policy

Each suite is a leaf that extends the **embedded** copy of the policy:

```yaml
policy:
  hushspec: "0.1.0"
  name: hipaa-base-suite
  extends: "builtin:library/healthcare/hipaa-base"
```

so it runs against exactly the bytes the four SDKs ship.
`scripts/generate_*_builtins.py --check` (the Generated Sources CI job) is what
keeps that copy equal to the file in `library/`; after editing a library policy,
regenerate the four tables or the suite will be testing the previous version.

## Adding a case

Every case needs a `controls` entry naming a control the policy declares, a
`tags` list (`allow` / `deny` / `warn` plus the block), and an `expect` that
says what the control requires -- not what the engine currently returns. A
suite is allowed to have no `warn` case only when the policy has no warn path
at all (`general/air-gapped`, which has no `require_confirmation` list and no
warn-severity pattern); those suites state that outright with a case showing
the action is denied rather than escalated.
