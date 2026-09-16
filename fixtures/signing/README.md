# Policy signing vectors

Normative verification vectors for [`spec/hushspec-signing.md`](../../spec/hushspec-signing.md),
format 0.2.

> **The keys in `keys/` are published test keys. Anyone can sign with them. Never add their
> `key_id` to a production keyring.**

| Path | What it is |
|---|---|
| `keys/test-signing.key.pem`, `keys/test-signing.pub.pem` | The trusted test keypair (PKCS#8 / SPKI PEM, with a DO-NOT-USE header). |
| `keys/test-untrusted.key.pem`, `keys/test-untrusted.pub.pem` | A second test key, absent from the default keyring. |
| `keys/keyring.json` | Keyring trusting only `test-signing`. |
| `keys/keyring-retired.json`, `keys/keyring-revoked.json` | The same key retired (`not_after`) and revoked. |
| `policies/*.yaml`, `policies/*.sig` | Policies and envelopes for each case. |
| `policies/extends-child.resolved.json` | The resolved document whose canonical hash `extends-child.sig` covers. |
| `vectors.yaml` | The case manifest: policy, envelope, keyring, verifier clock, last-seen version, expected outcome. |

Envelopes were produced by computing the signing input with `scripts/canonical_json.py`
(RFC 8785 canonical form of the envelope without `signature`) and signing it with
`openssl pkeyutl -sign -rawin`. Re-verify any envelope by hand:

```bash
# signing input = canonical envelope without "signature"; signature = base64url(64 bytes)
python3 - <<'EOF'
import base64, json, subprocess, sys, tempfile
sys.path.insert(0, "scripts"); import canonical_json as c
env = json.load(open("fixtures/signing/policies/basic.sig"))
sig = base64.urlsafe_b64decode(env.pop("signature") + "==")
payload = c.jcs(env).encode()
pub = "".join(l for l in open("fixtures/signing/keys/test-signing.pub.pem") if not l.startswith("#"))
with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as k: k.write(pub)
with tempfile.NamedTemporaryFile("wb", delete=False) as s: s.write(sig)
# `-rawin` needs a seekable input, so the payload goes to a file rather than stdin.
with tempfile.NamedTemporaryFile("wb", delete=False) as m: m.write(payload)
print(subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",k.name,"-rawin",
                      "-sigfile",s.name,"-in",m.name], capture_output=True).stdout.decode().strip())
EOF
```

`h2h verify` walks these vectors too:

```bash
h2h verify fixtures/signing/policies/basic.yaml \
  --sig fixtures/signing/policies/basic.sig \
  --keyring fixtures/signing/keys/keyring.json \
  --now 2026-09-15T12:00:00.000Z
```

Expected outcomes and reason codes are defined in spec sections 6.2 and 6.4. Every SDK runs
these vectors in its own test suite, and `h2h verify` exercises the same cases; a divergence
between engines is a conformance failure.
