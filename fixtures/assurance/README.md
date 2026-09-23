# Experimental assurance integration fixtures

These are supplemental integration fixtures, not core-engine conformance vectors.
`profile-shape.json` demonstrates the experimental 0.1.0 contract only. Its zero
source digest does not authenticate a file and must not be used as verified evidence.

`monitor/` is a reproducible signed warn/monitor example with a resolved policy
and exact-byte profile. Its committed signing key is public test material.
The CLI regression verifies the fixture against a real audited evaluation;
see the evidence-verification guide for generation and runnable commands.

`oscal/` is a synthetic local AP/SSP/catalog context with a digest manifest,
not a customer inventory or an assessment conclusion. Its scope contains one
declared component and the `tool-access` control.
