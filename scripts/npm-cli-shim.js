#!/usr/bin/env node
// Locate the platform binary package and exec h2h with inherited stdio.
// This file is also copied verbatim into the generated @hushspec/cli
// package as bin/h2h.js by scripts/gen_npm_cli.mjs.
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { realpathSync } from 'node:fs';

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
  process.exit(r.status ?? 1);
}

// Entry-point check, normalized through realpath. npm's bin mechanism always
// invokes this file through a symlink -- node_modules/.bin/h2h (local) and
// the global-install bin dir both point a symlink at .../@hushspec/cli/bin/h2h.js
// -- and Node resolves the *entry module's* import.meta.url to the symlink's
// TARGET while leaving process.argv[1] as the symlink PATH as invoked. A bare
// `import.meta.url === \`file://${process.argv[1]}\`` string comparison never
// matches in that case (verified empirically), so this shim would silently
// no-op on every real `h2h ...` invocation once installed. Resolving argv[1]
// through fs.realpathSync before comparing fixes it; direct/no-symlink
// invocation (e.g. running this file's path straight, as in dev) is
// unaffected since realpathSync(path) === path when there's no symlink.
function isEntryPoint() {
  try {
    return import.meta.url === `file://${realpathSync(process.argv[1])}`;
  } catch {
    return false;
  }
}

if (isEntryPoint()) main();
