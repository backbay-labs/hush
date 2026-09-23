# Release-policy trust key

`hushspec-release-2026.pub.pem` is the dedicated Ed25519 public key provisioned
for HushSpec release-policy bundles on 2026-09-23. It is not a fixture key and
must not be replaced by a disposable rehearsal key.

SPKI SHA-256 key ID:
`sha256:19d582aef8ee788f6742b33c3723ced7f7feade9a73c6a4e8b86bd406bbf706d`

Custody: the Backbay repository maintainers administer the private key through
the `POLICY_SIGNING_KEY` GitHub Actions secret. An owner-only backup is retained
outside this repository on the provisioning host. The matching public key is
also configured as the `POLICY_SIGNING_PUBLIC_KEY` repository variable. Neither
the existence of this key nor a valid signature establishes independent review,
runtime enforcement or publication of a release.

Before trusting a downloaded bundle, obtain this public key through a separately
authenticated project channel and pin its key ID. A key supplied only beside an
untrusted bundle is not an independent trust anchor. Rehearsals use different,
disposable keys and do not establish production-key custody.

With a separately trusted copy of this key:

```sh
h2h bundle verify policy.bundle.json --key hushspec-release-2026.pub.pem
```

Keep the private key out of Git, CI artifacts and logs. Rotation requires a new
key ID, an explicit public trust update and retention of historical public keys
for verifying older releases. Do not overwrite this key to rotate silently.
