#!/usr/bin/env node
// Locate the platform binary package and exec h2h with inherited stdio.
// This file is also copied verbatim into the generated @hushspec/cli
// package as bin/h2h.js by scripts/gen_npm_cli.mjs.
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const SUPPORTED = new Set([
  'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win32-x64',
]);

export function resolvePlatformPackage(platform, arch) {
  const key = `${platform}-${arch}`;
  return SUPPORTED.has(key) ? `@hushspec/cli-${key}` : null;
}

function main() {
  const pkg = resolvePlatformPackage(process.platform, process.arch);
  if (!pkg) {
    console.error(
      `@hushspec/cli: unsupported platform ${process.platform}-${process.arch}. ` +
      'Install from source instead: cargo install hushspec-cli',
    );
    process.exit(1);
  }
  const require = createRequire(import.meta.url);
  let binPath;
  try {
    const bin = process.platform === 'win32' ? 'h2h.exe' : 'h2h';
    binPath = require.resolve(`${pkg}/${bin}`);
  } catch {
    console.error(`@hushspec/cli: ${pkg} is not installed (optionalDependencies disabled?). Reinstall, or: cargo install hushspec-cli`);
    process.exit(1);
  }
  const r = spawnSync(binPath, process.argv.slice(2), { stdio: 'inherit' });
  if (r.error) {
    console.error(`@hushspec/cli: failed to execute ${binPath}: ${r.error.message}`);
  }
  process.exit(r.status ?? 1);
}

// Entry-point check, normalized through realpath and pathToFileURL. npm's bin
// mechanism always invokes this file through a symlink -- node_modules/.bin/h2h
// (local) and the global-install bin dir both point a symlink at
// .../@hushspec/cli/bin/h2h.js -- and Node resolves the *entry module's*
// import.meta.url to the symlink's TARGET while leaving process.argv[1] as the
// symlink PATH as invoked. Resolving argv[1] through fs.realpathSync before
// comparing fixes that; direct/no-symlink invocation (e.g. running this
// file's path straight, as in dev) is unaffected since realpathSync(path)
// === path when there's no symlink.
//
// The resolved path must then become a file:// URL via node:url's
// pathToFileURL rather than a hand-rolled `file://${path}` template, for two
// reasons this project actually hits:
//   - Windows: npm generates a .cmd wrapper that invokes this file's path
//     directly (no symlink to resolve), and Node's import.meta.url for that
//     entry point is a file:// URL shaped like `file:///C:/x/bin/h2h.js`
//     (forward slashes, extra slash before the drive letter) -- a naive
//     `file://${path}` template starting from a backslash-separated Windows
//     path never produces that shape.
//   - Spaces (any platform): import.meta.url percent-encodes characters
//     like spaces (` ` -> `%20`); a raw template concatenation does not, so
//     a path containing a space never compares equal even with no symlink
//     involved. pathToFileURL applies the same percent-encoding, so it
//     matches import.meta.url's format exactly.
export function isEntryPoint(metaUrl, argv1, realpath = realpathSync) {
  if (!argv1) return false;
  try {
    return metaUrl === pathToFileURL(realpath(argv1)).href;
  } catch {
    return false;
  }
}

if (isEntryPoint(import.meta.url, process.argv[1])) main();
