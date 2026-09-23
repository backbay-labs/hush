# Engine compatibility

HushSpec is portable across implementations of the same contract. A product
name, a parser import, or support for an older HushSpec version is not by itself
a v1 conformance claim.

## Clawdstrike and Chio

This historical URL is retained for existing links. Check an engine's exact
version, policy lineage, action mappings and evidence formats before deploying a
v1 policy. The Rust HushSpec SDK is the reference implementation in this
repository; this page does not designate Clawdstrike or Chio as an independently
qualified v1 engine.

## Validate and test before runtime

Run the engine's own policy-loader and evaluator tests with your policy, then
check its behavior against a named [conformance corpus](../reference/conformance.md).
The HushSpec CLI tests the HushSpec reference evaluator, not whichever external
engine happens to be installed on the same machine.

## Translation and engine-specific features

Native-policy compilation or decompilation can lose information. Require an
explicit mapping for each source rule, extension, condition and enforcement
mode, and reject unsupported controls rather than dropping them. Compare
effective decisions and evidence, not only a successful translation.

Async scheduling, filesystem/network containment, identity and redaction belong
to the host. Portable receipt signing is part of HushSpec's evidence contract,
not a reason to assume one particular engine enforces all effects.

## Built-in rulesets and library

HushSpec supplies `default`, `strict`, `permissive`, `ai-agent`, `cicd`,
`remote-desktop`, and `panic` baselines plus domain-oriented library templates.
Read the [policy library](policy-library.md) and inspect a resolved policy before
adapting one to another engine. A compliance-themed filename is not certification.

## Make a bounded claim

Record engine bytes/version, corpus digest, options, supported levels, and
known limitations. Use the [conformance statement](../reference/conformance-statement.md).
The experimental [external controller](../reference/external-conformance.md)
can capture Linux static-ELF L0-L3 runs; it is not a universal sandbox or an
independent endorsement.
