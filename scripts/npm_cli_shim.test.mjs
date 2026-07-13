import test from 'node:test';
import assert from 'node:assert/strict';
import { resolvePlatformPackage } from './npm-cli-shim.js';

test('maps platform/arch to package names', () => {
  assert.equal(resolvePlatformPackage('linux', 'x64'), '@hushspec/cli-linux-x64');
  assert.equal(resolvePlatformPackage('darwin', 'arm64'), '@hushspec/cli-darwin-arm64');
  assert.equal(resolvePlatformPackage('win32', 'x64'), '@hushspec/cli-win32-x64');
  assert.equal(resolvePlatformPackage('freebsd', 'x64'), null);
});
