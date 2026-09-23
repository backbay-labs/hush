# Quickstart fixtures

Read the [rendered quickstart](https://www.hushspec.org/docs/getting-started/).
`policy.yaml` is the single policy used by the tutorial and SDK examples.
The test command explicitly supplies `--policy policy.yaml`; CI also checks
that the fixture's embedded policy is identical to the standalone document.

```sh
h2h validate --strict policy.yaml
h2h test --policy policy.yaml policy.test.yaml
```

Expected decisions: source read/search allow, protected path/deploy deny,
write tool warn. `h2h eval` exits 0, 1, and 4 respectively. A warning receipt
records `enforcement.outcome: blocked` when there is no confirmation channel.
The CLI evaluates proposed actions; it does not execute a tool or touch the
synthetic `/workspace` paths. SDK examples test actual host-owned dispatch.
