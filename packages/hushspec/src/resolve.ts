import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import type { HushSpec } from './schema.js';
import { merge } from './merge.js';
import { parse } from './parse.js';
import { loadBuiltin } from './builtin.js';

export interface LoadedSpec {
  source: string;
  spec: HushSpec;
}

export type ResolveResult =
  | { ok: true; value: HushSpec }
  | { ok: false; error: string };

export interface ResolveOptions {
  source?: string;
  load?: (reference: string, from?: string) => LoadedSpec;
}

/**
 * Maximum `extends` chain depth. Cycle detection only catches exact repeats, so
 * a long *acyclic* chain would otherwise recurse unbounded until a stack
 * overflow. 32 is far above any realistic composition (shipped policies are
 * depth <= 2); the cap fails closed with a clean error. Must match the other
 * SDK resolvers.
 */
const MAX_EXTENDS_DEPTH = 32;

export function resolve(spec: HushSpec, options: ResolveOptions = {}): ResolveResult {
  const stack = options.source ? [options.source] : [];
  const load = options.load ?? createCompositeLoader();
  return resolveInner(spec, options.source, load, stack, 0);
}

export function resolveFromFile(filePath: string): ResolveResult {
  const source = realpathSync(filePath);
  const parsed = parse(readFileSync(source, 'utf8'));
  if (!parsed.ok) {
    return {
      ok: false,
      error: `Failed to parse HushSpec at ${source}: ${parsed.error}`,
    };
  }
  return resolve(parsed.value, { source, load: createCompositeLoader() });
}

/**
 * Loader that serves `builtin:<name>` (and bare builtin names) from the
 * embedded rulesets and refuses everything else.
 *
 * This is the default for callers that have no filesystem root to resolve
 * relative references against -- `HushGuard.fromYaml()`, a provider that
 * hands back an already-parsed spec, a poller loader returning raw YAML.
 * Refusing (rather than guessing a root, or silently skipping the base) keeps
 * those paths fail-closed: a policy whose base cannot be loaded is never
 * evaluated as if the base said nothing.
 */
export function createBuiltinLoader(): (reference: string, from?: string) => LoadedSpec {
  return (reference: string): LoadedSpec => {
    const spec = loadBuiltin(reference);
    if (spec) {
      const source = reference.startsWith('builtin:') ? reference : `builtin:${reference}`;
      return { source, spec };
    }
    if (reference.startsWith('builtin:')) {
      throw new Error(`unknown builtin ruleset '${reference}'`);
    }
    throw new Error(
      `cannot resolve 'extends: ${reference}': this loader only serves builtin rulesets ` +
        `(${BUILTIN_REFERENCE_HINT})`,
    );
  };
}

const BUILTIN_REFERENCE_HINT =
  "pass a `baseDir` to resolve relative paths, or a custom `loader`";

export function createCompositeLoader(): (reference: string, from?: string) => LoadedSpec {
  return (reference: string, from?: string): LoadedSpec => {
    if (reference.startsWith('builtin:')) {
      return loadBuiltinOrThrow(reference);
    }

    if (reference.startsWith('https://') || reference.startsWith('http://')) {
      throw new Error(
        `HTTP-based policy loading is not supported in the synchronous loader; ` +
          `use createHttpLoader() for '${reference}'`,
      );
    }

    // Bare name without dots/slashes: try as builtin first
    if (!reference.includes('/') && !reference.includes('\\') && !reference.includes('.')) {
      const spec = loadBuiltin(reference);
      if (spec) {
        const source = `builtin:${reference}`;
        return { source, spec };
      }
    }

    return loadFromFilesystem(reference, from);
  };
}

function loadBuiltinOrThrow(reference: string): LoadedSpec {
  const spec = loadBuiltin(reference);
  if (!spec) {
    throw new Error(`unknown builtin ruleset '${reference}'`);
  }
  return { source: reference, spec };
}

function resolveInner(
  spec: HushSpec,
  source: string | undefined,
  load: (reference: string, from?: string) => LoadedSpec,
  stack: string[],
  depth: number,
): ResolveResult {
  if (!spec.extends) {
    return { ok: true, value: spec };
  }

  if (depth >= MAX_EXTENDS_DEPTH) {
    return {
      ok: false,
      error: `extends chain exceeds maximum depth of ${MAX_EXTENDS_DEPTH}`,
    };
  }

  let loaded: LoadedSpec;
  try {
    loaded = load(spec.extends, source);
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }

  const cycleIndex = stack.indexOf(loaded.source);
  if (cycleIndex >= 0) {
    return {
      ok: false,
      error: `circular extends detected: ${[...stack.slice(cycleIndex), loaded.source].join(' -> ')}`,
    };
  }

  stack.push(loaded.source);
  const parent = resolveInner(loaded.spec, loaded.source, load, stack, depth + 1);
  stack.pop();
  if (!parent.ok) {
    return parent;
  }

  return { ok: true, value: merge(parent.value, spec) };
}

function loadFromFilesystem(reference: string, from?: string): LoadedSpec {
  const resolvedPath = path.isAbsolute(reference)
    ? reference
    : from
      ? path.resolve(path.dirname(from), reference)
      : path.resolve(reference);
  const source = realpathSync(resolvedPath);
  const parsed = parse(readFileSync(source, 'utf8'));
  if (!parsed.ok) {
    throw new Error(`Failed to parse HushSpec at ${source}: ${parsed.error}`);
  }
  return { source, spec: parsed.value };
}
