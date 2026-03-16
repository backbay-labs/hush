import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import type { HushSpec } from './schema.js';
import { merge } from './merge.js';
import { parse } from './parse.js';

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

export function resolve(spec: HushSpec, options: ResolveOptions = {}): ResolveResult {
  const stack = options.source ? [options.source] : [];
  const load = options.load ?? loadFromFilesystem;
  return resolveInner(spec, options.source, load, stack);
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
  return resolve(parsed.value, { source, load: loadFromFilesystem });
}

function resolveInner(
  spec: HushSpec,
  source: string | undefined,
  load: (reference: string, from?: string) => LoadedSpec,
  stack: string[],
): ResolveResult {
  if (!spec.extends) {
    return { ok: true, value: spec };
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
  const parent = resolveInner(loaded.spec, loaded.source, load, stack);
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
