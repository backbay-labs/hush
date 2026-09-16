# Policy bundle vectors

Normative verification vectors for [`spec/hushspec-bundle.md`](../../spec/hushspec-bundle.md),
bundle format 0.1. Every bundle attests
[`library/healthcare/hipaa-base.yaml`](../../library/healthcare/hipaa-base.yaml) resolved through
`builtin:strict`, with `predicate.created_at` pinned to `2026-09-15T12:00:00.000Z`.

> **The keys in [`../signing/keys/`](../signing/keys) are published test keys. Anyone can sign with
> them. A bundle they signed proves nothing outside this test suite.**

| Path | What it is | Expected |
|---|---|---|
| `bundles/valid.bundle.json` | Signed with `test-signing`. | valid |
| `bundles/tampered-payload.bundle.json` | `created_at` edited in transit, signature untouched. | `dsse_signature_mismatch` |
| `bundles/wrong-key.bundle.json` | Signed with `test-untrusted`, absent from the keyring. | `unknown_key_id` |
| `bundles/unsigned.bundle.json` | A well-formed envelope with no signatures. | `dsse_signature_mismatch` |
| `bundles/subject-digest-mismatch.bundle.json` | Correctly signed over a statement whose subject digest is not the digest of `predicate.resolved`. | `subject_digest_mismatch` |
| `bundles/malformed-predicate-type.bundle.json` | Correctly signed over a `.../policy-bundle/v0.2` predicate. | `malformed_bundle` |
| `vectors.yaml` | The case manifest: bundle, keyring, policy to cross-check, expected outcome. | |

`policy-mismatch` reuses `valid.bundle.json` and checks it against a different library policy, so
there is no seventh bundle file.

`crates/hushspec/tests/bundle_vectors.rs` walks the manifest and also validates every bundle
against [`schemas/hushspec-bundle.v1.schema.json`](../../schemas/hushspec-bundle.v1.schema.json).

## Regenerating

The first three bundles come from the CLI, run from the repository root:

```bash
cargo build -p hushspec-cli
H2H=target/debug/h2h

"$H2H" bundle create library/healthcare/hipaa-base.yaml \
  --key fixtures/signing/keys/test-signing.key.pem \
  --created-at 2026-09-15T12:00:00.000Z \
  --out fixtures/bundle/bundles/valid.bundle.json

"$H2H" bundle create library/healthcare/hipaa-base.yaml \
  --key fixtures/signing/keys/test-untrusted.key.pem \
  --created-at 2026-09-15T12:00:00.000Z \
  --out fixtures/bundle/bundles/wrong-key.bundle.json

"$H2H" bundle create library/healthcare/hipaa-base.yaml \
  --created-at 2026-09-15T12:00:00.000Z \
  --out fixtures/bundle/bundles/unsigned.bundle.json
```

The remaining three cannot come from the CLI: they are bundles *correctly signed* over a statement
that is wrong, which `h2h bundle create` will not produce. They are derived from `valid.bundle.json`
by a script that signs with `openssl pkeyutl -sign -rawin`, independently of the Rust signer:

```bash
python3 scripts/generate_bundle_vectors.py          # rewrite
python3 scripts/generate_bundle_vectors.py --check  # fail if stale
```

Because the CLI's verifier accepts those two signatures (both get past check 2 and fail at check 3
or check 1), the vectors are a standing cross-check between OpenSSL's Ed25519 and the reference
implementation's.

## Checking a signature by hand

The signature covers the DSSE PAE of the payload (bundle spec 3.1), not the payload itself:

```bash
python3 - <<'EOF'
import base64, json, subprocess, tempfile, pathlib
b = json.loads(pathlib.Path("fixtures/bundle/bundles/valid.bundle.json").read_text())
payload = base64.b64decode(b["payload"])
t = b["payloadType"].encode()
pae = b"DSSEv1 %d %s %d " % (len(t), t, len(payload)) + payload
sig = base64.b64decode(b["signatures"][0]["sig"])
pub = pathlib.Path("fixtures/signing/keys/test-signing.pub.pem").read_text()
pub = pub[pub.index("-----BEGIN"):]          # the published key carries a DO-NOT-USE header
with tempfile.TemporaryDirectory() as d:
    d = pathlib.Path(d)
    (d/"pub.pem").write_text(pub)
    (d/"sig.bin").write_bytes(sig)
    # `-rawin` needs a seekable input, so the PAE goes to a file rather than stdin.
    (d/"pae.bin").write_bytes(pae)
    print(subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(d/"pub.pem"),
                          "-rawin", "-sigfile", str(d/"sig.bin"), "-in", str(d/"pae.bin")],
                         capture_output=True, text=True).stdout.strip())
EOF
# Signature Verified Successfully
```

The PAE of every bundle begins `DSSEv1 28 application/vnd.in-toto+json <len> ` -- `28` is the byte
length of `application/vnd.in-toto+json`, and `<len>` the byte length of the JSON payload.

`h2h` walks these vectors too:

```bash
h2h bundle verify fixtures/bundle/bundles/valid.bundle.json \
  --keyring fixtures/signing/keys/keyring.json \
  --policy library/healthcare/hipaa-base.yaml
h2h bundle inspect fixtures/bundle/bundles/valid.bundle.json
```

## cosign

The envelope is ordinary DSSE and the payload an ordinary in-toto Statement, so
`cosign verify-blob-attestation` checks the same signature over the same PAE bytes. The blob it
checks the subject digest against is the **canonical form** of the resolved policy, not the YAML
file -- that is what the subject names (bundle spec 4.1), and `h2h hash --format canonical` is how
you get it (with the trailing newline `println` adds trimmed off):

```bash
h2h hash library/healthcare/hipaa-base.yaml --format canonical | head -c -1 > resolved.canonical.json
cosign verify-blob-attestation \
  --key fixtures/signing/keys/test-signing.pub.pem \
  --type https://hushspec.dev/attestation/policy-bundle/v0.1 \
  --signature fixtures/bundle/bundles/valid.bundle.json \
  resolved.canonical.json
```

cosign is deliberately **not** a CI dependency, and the command above has not been exercised in
this repository (cosign is not installed in the development environment): it checks bundle spec 5.2
check 2 only, while the Rust runner covers checks 1, 3, and 4 as well, and the OpenSSL check above
already cross-checks the cryptography against a second implementation. Expected outcomes and reason
codes are defined in spec sections 5.2 and 5.4.
