# Turn receipts into a bounded report

Start by deciding what question you need to answer. Counting decisions,
authenticating evidence and establishing completeness are different jobs.

## Four questions, four kinds of evidence

| Question | Evidence to inspect | Remaining assumption |
|---|---|---|
| Authenticity: who signed these bytes? | Signature, authorized key and verifier trust configuration | Key custody and signer honesty |
| Continuity: do supplied records link in order? | Hash links, sequence and policy events across rotations | A trusted head/start when the run is only a prefix |
| Completeness: is the declared interval present? | Independently retained stream identities and expected boundaries | The independence and coverage of that collection process |
| Runtime truth: what effects actually happened? | Trusted mediation and independently observed effects | Host, engine, transport and operating-system assumptions |

An ordinary receipt log covers no more than the records supplied. A signature
cannot establish that a denied handler never ran or that an unrecorded action
did not happen.

## Explore ordinary receipts

For existing local receipts or logs, these read-only commands summarize the
supplied inputs. Choose your own file paths:

```sh
h2h report receipts.jsonl
h2h report receipts.jsonl --format json --out report.json
h2h receipts verify receipts.jsonl --policy policy.yaml
h2h log verify receipts.jsonl --keyring keyring.json --require-signatures
```

Read policy decisions and enforcement outcomes separately. `deny` plus
`would_block` is a monitoring observation, not prevented execution. `warn`
plus `confirmed` means the host reported confirmation, not that the eventual
side effect completed successfully.

Ordinary `h2h report --require-signatures` checks log-entry signatures, not
standalone signed-receipt envelopes. A report is an aggregate view, not a new
signature over its source inputs or an independent assessment.

## Verify before publishing evidence

When you need authenticated inputs, authorized stream signers and declared
boundaries, use the separately versioned **experimental**
[strict evidence profile](evidence-verification.md). It refuses invalid inputs
before publishing the report/completion sidecar, verifies records before time
filtering, and keeps independent streams separate.

Without a trusted boundary inventory, completeness remains `not-established`.
An empty time window is no observations, not automatic satisfaction. The
verification sidecar binds the report's bytes but is not itself an independent
trust root; a recipient must trust its producer or reverify source evidence.

## Export observations to OSCAL

The experimental OSCAL path requires an explicit validated assessment context:
assessment plan, its system security plan and an already-resolved catalog.
It emits observations, not findings, risks or objective satisfaction. Use the
[signed monitor walkthrough](evidence-verification.md#a-runnable-signed-example)
to see `would_block` preserved in the result.

Keep source evidence, report bytes, profile, independently provisioned trust
inputs and collection boundaries together in your retention process. Document
which parts are authenticated, independently bounded, runtime-observed or
merely supplied by the producer.
