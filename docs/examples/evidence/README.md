# Evidence lab

Download `verify.py` and the quickstart `policy.yaml`, then run:

```sh
python3 verify.py --policy policy.yaml
```

Requires Python 3.10+ and `h2h 1.0.0` on PATH (or `--h2h /path/to/h2h`).
No Python packages, credentials or network access are needed. Keys are fresh
test material, confined to an owned temporary directory and removed on normal
exit. A hard process kill can leave that private temporary directory behind;
do not reuse its keys as production trust.

The JSON output records exact refusal categories for policy, signature, key,
expiry and bundle tampering, plus the first broken log link. It also demonstrates
that truncating a signed log can leave a valid prefix: validity alone is not
completeness. `receipt.json` is a real-schema synthetic receipt from the v1 CLI;
tests recheck its decision-bearing fields against the quickstart policy.

The repository's separate strict-evidence and invocation-pilot tests cover
trusted boundary inventories and missing terminal records. These experimental
contracts are not silently attributed to the stable log format.
