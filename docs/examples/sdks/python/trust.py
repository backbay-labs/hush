from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from hushspec import FileProvider, HushGuard, EvaluationAction
from hushspec.signing import Keyring, sign_policy, verify_policy


def check_trust(policy_path, resolved):
    # Ephemeral test key only. Never use example-generated keys as shared roots.
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    keyring = Keyring.from_public_key(public)
    envelope = sign_policy(resolved, private)
    assert verify_policy(resolved, envelope, keyring=keyring).valid
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert not verify_policy(resolved, envelope, keyring=Keyring.from_public_key(other)).valid
    with HushGuard.from_provider(FileProvider(policy_path)) as guard:
        assert not guard.check(EvaluationAction(type="tool_call", target="deploy"))
