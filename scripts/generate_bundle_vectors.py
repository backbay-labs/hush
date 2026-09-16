#!/usr/bin/env python3
"""Derive the invalid policy-bundle vectors from the valid one.

`fixtures/bundle/bundles/valid.bundle.json`, `wrong-key.bundle.json`, and
`unsigned.bundle.json` are produced by `h2h bundle create` (see
fixtures/bundle/README.md). The three remaining cases cannot be: `tampered-payload`
keeps the valid signature over an edited payload, and the other two are
*correctly signed* over a statement that is wrong, which the CLI refuses to
produce by construction. This script builds them the way an attacker or a
broken bundler would -- by editing the statement and, where the case calls for
it, signing the result with the published test key -- so the vectors exercise
checks 1, 2 and 3 of bundle spec 5.2.

The signature is made with `openssl pkeyutl -sign -rawin` over the DSSE PAE,
independently of the Rust implementation, so the vectors cross-check it.

Usage:
    python3 scripts/generate_bundle_vectors.py [--check]
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import canonical_json as cj  # noqa: E402  (path set above)

BUNDLES = ROOT / "fixtures" / "bundle" / "bundles"
KEYS = ROOT / "fixtures" / "signing" / "keys"
SIGNING_KEY = KEYS / "test-signing.key.pem"

PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (bundle spec 3.1)."""
    type_bytes = payload_type.encode()
    header = b"DSSEv1 %d %s %d " % (len(type_bytes), type_bytes, len(payload))
    return header + payload


def strip_pem_preamble(path: Path) -> str:
    text = path.read_text()
    return text[text.index("-----BEGIN") :]


def sign(payload: bytes) -> bytes:
    """Ed25519 over the PAE, via OpenSSL rather than the Rust signer."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        key = tmp / "key.pem"
        key.write_text(strip_pem_preamble(SIGNING_KEY))
        message = tmp / "pae.bin"
        message.write_bytes(pae(PAYLOAD_TYPE, payload))
        out = tmp / "sig.bin"
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin",
                "-in", str(message), "-out", str(out),
            ],
            check=True,
            capture_output=True,
        )
        return out.read_bytes()


def key_id() -> str:
    """The signing key's key_id, read from the valid bundle it signed."""
    bundle = json.loads((BUNDLES / "valid.bundle.json").read_text())
    return bundle["signatures"][0]["keyid"]


def envelope(statement: dict) -> dict:
    """A correctly signed envelope over `statement`, however wrong it is."""
    payload = cj.jcs(statement).encode()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {"keyid": key_id(), "sig": base64.b64encode(sign(payload)).decode()}
        ],
    }


def valid_statement() -> dict:
    bundle = json.loads((BUNDLES / "valid.bundle.json").read_text())
    return json.loads(base64.b64decode(bundle["payload"]))


def tampered_payload() -> dict:
    """An edit in transit: the payload changed, the signature untouched.

    `created_at` is swapped for another timestamp of the same shape, so the
    statement still parses and still has a consistent subject digest. Only the
    signature is wrong, which is check 2.
    """
    bundle = json.loads((BUNDLES / "valid.bundle.json").read_text())
    payload = base64.b64decode(bundle["payload"]).decode()
    edited = payload.replace("2026-09-15T12:00:00.000Z", "2026-09-15T13:00:00.000Z")
    if edited == payload:
        raise SystemExit("the valid bundle no longer carries the pinned created_at")
    bundle["payload"] = base64.b64encode(edited.encode()).decode()
    return bundle


def subject_digest_mismatch() -> dict:
    """A bundler bug: the subject names a digest the payload does not have."""
    statement = valid_statement()
    statement["subject"][0]["digest"]["sha256"] = "0" * 64
    return envelope(statement)


def malformed_predicate_type() -> dict:
    """A predicate version this build does not know: closed by default."""
    statement = valid_statement()
    statement["predicateType"] = "https://hushspec.dev/attestation/policy-bundle/v0.2"
    return envelope(statement)


CASES = {
    "tampered-payload.bundle.json": tampered_payload,
    "subject-digest-mismatch.bundle.json": subject_digest_mismatch,
    "malformed-predicate-type.bundle.json": malformed_predicate_type,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if any derived vector is out of date",
    )
    args = parser.parse_args(argv)

    stale: list[str] = []
    for name, build in CASES.items():
        rendered = json.dumps(build(), indent=2) + "\n"
        path = BUNDLES / name
        current = path.read_text() if path.exists() else None
        if args.check:
            if current != rendered:
                stale.append(str(path.relative_to(ROOT)))
            continue
        path.write_text(rendered, newline="\n")

    if stale:
        for path in stale:
            print(f"{path} is out of date", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
