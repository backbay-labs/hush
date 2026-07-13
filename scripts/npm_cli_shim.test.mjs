import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { resolvePlatformPackage, isEntryPoint } from './npm-cli-shim.js';

test('maps platform/arch to package names', () => {
  assert.equal(resolvePlatformPackage('linux', 'x64'), '@hushspec/cli-linux-x64');
  assert.equal(resolvePlatformPackage('darwin', 'arm64'), '@hushspec/cli-darwin-arm64');
  assert.equal(resolvePlatformPackage('win32', 'x64'), '@hushspec/cli-win32-x64');
  assert.equal(resolvePlatformPackage('freebsd', 'x64'), null);
});

test('isEntryPoint: direct path match (no symlink)', (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hushspec-shim-direct-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'h2h.js');
  writeFileSync(file, '// stub\n');

  // Real import.meta.url is derived from the fully-canonicalized module
  // path (that's *why* the symlink bug this fixes existed at all), and on
  // macOS os.tmpdir() itself sits behind a /var -> /private/var symlink --
  // so metaUrl must be built from the realpath, not the raw joined path,
  // to match what Node actually produces (and what isEntryPoint's own
  // default realpath(argv1) will independently compute).
  const metaUrl = pathToFileURL(realpathSync(file)).href;
  assert.equal(isEntryPoint(metaUrl, file), true);
});

test('isEntryPoint: symlinked path match (npm bin shape)', (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hushspec-shim-symlink-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, 'real', 'bin', 'h2h.js');
  const linkDir = path.join(dir, 'node_modules', '.bin');
  const link = path.join(linkDir, 'h2h');
  mkSubdirs(target, linkDir);
  writeFileSync(target, '// stub\n');
  symlinkSync(target, link);

  // Mirrors real Node behavior: import.meta.url resolves to the symlink's
  // TARGET (fully canonicalized -- see the realpath comment in the direct-
  // match test above), while argv[1] stays the symlink PATH as invoked.
  const metaUrl = pathToFileURL(realpathSync(target)).href;
  assert.equal(isEntryPoint(metaUrl, link), true);
});

test('isEntryPoint: space-containing path match', (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hushspec shim space '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'h2h.js');
  writeFileSync(file, '// stub\n');

  // pathToFileURL percent-encodes the space the same way import.meta.url
  // does, so building metaUrl the same way the real entry point would
  // (realpath first, same as the direct-match test above) is itself the
  // assertion that the two stay in sync for space-containing paths.
  const metaUrl = pathToFileURL(realpathSync(file)).href;
  assert.match(metaUrl, /%20/);
  assert.equal(isEntryPoint(metaUrl, file), true);
});

test('isEntryPoint: Windows-shaped inputs (exercised cross-platform, not strict-equality)', () => {
  // On a real Windows host, npm's generated .cmd wrapper invokes this
  // file's path directly (no symlink to resolve), and Node's
  // import.meta.url for that entry point comes out shaped like
  // 'file:///C:/x/bin/h2h.js' for an argv[1] of 'C:\\x\\bin\\h2h.js'.
  //
  // On *this* (POSIX) host, node:url's pathToFileURL resolves paths with
  // POSIX semantics: a backslash is not a path separator, so the whole
  // Windows-shaped string is treated as one relative path segment and
  // resolved against cwd, then percent-encoded -- it does NOT come out
  // equal to 'file:///C:/x/bin/h2h.js'. That is expected, not a bug: this
  // function only promises that Node's own import.meta.url and
  // pathToFileURL stay paired on whatever host actually runs it (verified
  // by the direct/symlink/space cases above using that same host's real
  // pathToFileURL). We can't assert real Windows equality from a POSIX
  // host, so instead we pin today's actual POSIX-host construction (the
  // percent-encoded backslash tail is host/cwd-independent) and confirm
  // the function still runs to completion and returns a boolean, rather
  // than skipping this input shape entirely.
  const metaUrl = 'file:///C:/x/bin/h2h.js';
  const argv1 = 'C:\\x\\bin\\h2h.js';
  const identity = (p) => p;

  const result = isEntryPoint(metaUrl, argv1, identity);
  assert.equal(typeof result, 'boolean');
  assert.equal(result, false);

  const computed = pathToFileURL(identity(argv1)).href;
  assert.ok(computed.startsWith('file://'));
  // Colon is left literal; backslashes (not a POSIX separator) are
  // percent-encoded as %5C -- pinned so a change in this encoding shows up
  // as a diff here.
  assert.ok(computed.endsWith('C:%5Cx%5Cbin%5Ch2h.js'), computed);
  assert.notEqual(computed, metaUrl);
});

test('isEntryPoint: metaUrl of a different module never matches (module-import case)', (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hushspec-shim-import-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const argv1 = path.join(dir, 'test-runner-entry.mjs');
  writeFileSync(argv1, '// stub -- stands in for e.g. node --test itself\n');

  // Models scripts/npm_cli_shim.test.mjs's own top-of-file
  // `import { ... } from './npm-cli-shim.js'` -- when the shim is imported
  // as a module rather than executed as the entry point, its
  // import.meta.url never matches process.argv[1] (the test runner's own
  // entry file), so main() must not fire.
  const shimMetaUrl = pathToFileURL(path.join(dir, 'npm-cli-shim.js')).href;
  assert.equal(isEntryPoint(shimMetaUrl, argv1), false);
});

test('isEntryPoint: missing argv[1] is false, not a throw', () => {
  assert.equal(isEntryPoint('file:///anything.js', undefined), false);
  assert.equal(isEntryPoint('file:///anything.js', ''), false);
});

test('isEntryPoint: nonexistent path is false, not a throw (realpath ENOENT)', () => {
  const bogus = path.join(tmpdir(), 'hushspec-shim-does-not-exist', 'h2h.js');
  assert.equal(isEntryPoint(pathToFileURL(bogus).href, bogus), false);
});

// Accepts a mix of file paths (creates the parent dir) and dir paths
// (creates the dir itself) -- distinguished by trailing path structure at
// each call site above (target is a file path, linkDir is a dir path).
function mkSubdirs(targetFilePath, dirPath) {
  mkdirSync(path.dirname(targetFilePath), { recursive: true });
  mkdirSync(dirPath, { recursive: true });
}
