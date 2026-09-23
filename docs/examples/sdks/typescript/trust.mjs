import assert from 'node:assert/strict';
import { FileProvider, HushGuard, generateKeypair, keyringFromPublicKey,
  signPolicy, verifyPolicy } from '@hushspec/core';

export async function checkTrust(policyPath, resolved) {
  // Ephemeral demonstration key. Production trust roots are operator inputs.
  const key = generateKeypair();
  const keyring = keyringFromPublicKey(key.publicKeyPem);
  const envelope = signPolicy(resolved, key.privateKeyPem);
  assert.equal(verifyPolicy(resolved, envelope, {keyring}).ok, true);
  const wrong = keyringFromPublicKey(generateKeypair().publicKeyPem);
  assert.equal(verifyPolicy(resolved, envelope, {keyring:wrong}).ok, false);
  const provider = new FileProvider(policyPath);
  try {
    const guard = await HushGuard.fromProvider(provider);
    assert.equal(guard.check({type:'tool_call', target:'deploy'}), false);
  } finally {
    provider.stop();
  }
}
