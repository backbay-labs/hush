#!/usr/bin/env node
// Generate the six @hushspec/cli npm packages (one meta package + five
// per-platform binary carriers, esbuild-style optionalDependencies layout)
// from the release workflow's tarball artifacts.
//
// Usage: gen_npm_cli.mjs <tag> <artifact-dir> <out-dir>
//
//   <tag>          release tag, e.g. v1.2.3 (package versions = tag minus "v")
//   <artifact-dir> directory containing h2h-<tag>-<target>.tar.gz for each
//                  release target (as produced by release.yml's build job)
//   <out-dir>      directory to write the generated packages into (gitignored
//                  -- see /out/ in .gitignore; never committed)
//
// Prints the generated package directories to stdout, one per line, in
// publish order (platform packages first, meta package last) -- matching
// release.yml's npm-cli job publish loop.
import { execFileSync } from 'node:child_process';
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_URL = 'https://github.com/backbay-labs/hush';
// Same shape as release.yml's tag guard and render_formula.sh's tag validation.
const TAG_RE = /^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$/;

// Single source of truth mapping npm's (os, cpu) pairs to release.yml's Rust
// target triples. Keep the `suffix` values in lockstep with
// scripts/npm-cli-shim.js's SUPPORTED set -- both enumerate the same five
// platforms and must never drift apart.
const PLATFORMS = [
  { suffix: 'linux-x64', os: 'linux', cpu: 'x64', target: 'x86_64-unknown-linux-gnu' },
  { suffix: 'linux-arm64', os: 'linux', cpu: 'arm64', target: 'aarch64-unknown-linux-gnu' },
  { suffix: 'darwin-x64', os: 'darwin', cpu: 'x64', target: 'x86_64-apple-darwin' },
  { suffix: 'darwin-arm64', os: 'darwin', cpu: 'arm64', target: 'aarch64-apple-darwin' },
  { suffix: 'win32-x64', os: 'win32', cpu: 'x64', target: 'x86_64-pc-windows-msvc' },
];

function usage(msg) {
  if (msg) console.error(`error: ${msg}`);
  console.error('usage: gen_npm_cli.mjs <tag> <artifact-dir> <out-dir>');
  process.exit(2);
}

const [tag, artifactDir, outDir] = process.argv.slice(2);
if (!tag || !artifactDir || !outDir) usage();
if (!TAG_RE.test(tag)) usage(`invalid tag format: ${tag}`);
const version = tag.slice(1);

function binName(os) {
  return os === 'win32' ? 'h2h.exe' : 'h2h';
}

function writeJson(file, obj) {
  writeFileSync(file, `${JSON.stringify(obj, null, 2)}\n`);
}

/**
 * Build the @hushspec/cli-<suffix> package for one platform by extracting
 * its binary out of the matching release tarball. Returns the package dir,
 * or null (with a stderr warning) if that platform's tarball isn't present
 * in artifactDir -- tolerated so this script stays testable against a
 * partial/fake artifact set; release.yml's `needs: build` gating means all
 * five are always present in the real pipeline (see the fail-closed check
 * at the bottom of this file for that case).
 */
function generatePlatformPackage(p) {
  const bin = binName(p.os);
  const tarball = path.join(artifactDir, `h2h-${tag}-${p.target}.tar.gz`);
  if (!existsSync(tarball)) {
    console.error(
      `warning: missing artifact for ${p.target} (expected ${tarball}); ` +
      `skipping @hushspec/cli-${p.suffix}`,
    );
    return null;
  }

  const pkgDir = path.join(outDir, `cli-${p.suffix}`);
  mkdirSync(pkgDir, { recursive: true });

  // Release tarballs stage the binary inside a wrapper dir:
  // h2h-<tag>-<target>/{h2h(.exe),LICENSE,README.md}. Extract to a scratch
  // dir and copy just the binary up, rather than relying on tar flag
  // behavior (e.g. --strip-components) that differs subtly across the GNU
  // tar / bsdtar this script may run under.
  const scratch = mkdtempSync(path.join(tmpdir(), 'hushspec-npm-cli-'));
  try {
    execFileSync('tar', ['-xzf', path.resolve(tarball), '-C', scratch]);
    const extractedBin = path.join(scratch, `h2h-${tag}-${p.target}`, bin);
    if (!existsSync(extractedBin)) {
      throw new Error(`tarball ${tarball} did not contain expected member h2h-${tag}-${p.target}/${bin}`);
    }
    const destBin = path.join(pkgDir, bin);
    copyFileSync(extractedBin, destBin);
    if (p.os !== 'win32') chmodSync(destBin, 0o755);
  } catch (err) {
    // Unlike a missing tarball, a present-but-malformed tarball is a hard
    // failure -- fail-closed, don't ship a package with a wrong/missing
    // binary.
    console.error(`error: failed to extract binary from ${tarball}: ${err.message}`);
    process.exit(1);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  writeJson(path.join(pkgDir, 'package.json'), {
    name: `@hushspec/cli-${p.suffix}`,
    version,
    description: `h2h native binary for ${p.os}/${p.cpu} (published alongside @hushspec/cli; not for direct use)`,
    os: [p.os],
    cpu: [p.cpu],
    files: [bin],
    license: 'Apache-2.0',
    repository: { type: 'git', url: REPO_URL, directory: 'scripts' },
  });

  return pkgDir;
}

const README = `# @hushspec/cli

Command-line tool for [HushSpec](${REPO_URL}) policy documents: validate,
lint, test, diff, format, scaffold, sign.

This package is a thin Node shim (\`bin/h2h.js\`) that resolves and execs the
real \`h2h\` binary for your platform, installed automatically via
\`optionalDependencies\` -- the same per-platform-package pattern esbuild and
swc use. No Rust toolchain, no postinstall download.

## Install

\`\`\`bash
npm install -g @hushspec/cli
h2h --version
\`\`\`

## Or run without installing

\`\`\`bash
npx @hushspec/cli validate policy.yaml
\`\`\`

## Supported platforms

\`linux-x64\`, \`linux-arm64\`, \`darwin-x64\`, \`darwin-arm64\`, \`win32-x64\`, via
the optional \`@hushspec/cli-<platform>-<arch>\` packages. On any other
platform, or if npm's optional-dependency resolution is disabled, install
from source instead:

\`\`\`bash
cargo install hushspec-cli
\`\`\`

## Learn more

See the [HushSpec repository](${REPO_URL}) for the full CLI reference, the
spec, and the language SDKs.
`;

/** Build the @hushspec/cli meta package: shim + optionalDependencies + README. */
function generateMainPackage() {
  const pkgDir = path.join(outDir, 'cli');
  const binDir = path.join(pkgDir, 'bin');
  mkdirSync(binDir, { recursive: true });
  // Copy (not require/import) the shim -- it becomes this package's bin
  // entry verbatim. npm's installer chmods +x files listed in "bin" at
  // install time regardless, but set it here too so the generated tree is
  // correct on disk without depending on that (e.g. under `npm pack` +
  // manual extraction, or package managers with different fixup behavior).
  const shimDest = path.join(binDir, 'h2h.js');
  copyFileSync(path.join(SCRIPT_DIR, 'npm-cli-shim.js'), shimDest);
  chmodSync(shimDest, 0o755);

  const optionalDependencies = Object.fromEntries(
    PLATFORMS.map((p) => [`@hushspec/cli-${p.suffix}`, version]),
  );

  writeJson(path.join(pkgDir, 'package.json'), {
    name: '@hushspec/cli',
    version,
    description: 'Command-line tool for HushSpec policy documents (validate, lint, test, diff, format) -- native binary via optionalDependencies, no Rust toolchain required',
    type: 'module',
    bin: { h2h: 'bin/h2h.js' },
    files: ['bin'],
    license: 'Apache-2.0',
    repository: { type: 'git', url: REPO_URL, directory: 'scripts' },
    optionalDependencies,
    engines: { node: '>=18' },
    keywords: ['ai', 'security', 'policy', 'agent', 'hushspec', 'guardrails', 'cli'],
  });

  writeFileSync(path.join(pkgDir, 'README.md'), README);

  return pkgDir;
}

const generated = [];
for (const p of PLATFORMS) {
  const dir = generatePlatformPackage(p);
  if (dir) generated.push(dir);
}
const platformCount = generated.length;
generated.push(generateMainPackage());

for (const dir of generated) {
  console.log(path.relative(process.cwd(), dir));
}

const missing = PLATFORMS.length - platformCount;
if (missing > 0) {
  console.error(
    `error: ${missing} of ${PLATFORMS.length} platform artifact(s) missing -- ` +
    "@hushspec/cli's optionalDependencies references package(s) that were not generated. " +
    'Do not publish this output.',
  );
  process.exit(1);
}
