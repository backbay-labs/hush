import { createHash } from 'node:crypto';
import { parse } from './parse.js';
import type { ResolveOptions, Resolution } from './resolve.js';
import { createBuiltinLoader, resolveWithOptions } from './resolve.js';
import type { HushSpec } from './schema.js';

/**
 * Parse polled YAML, resolve its `extends` chain, and verify whatever the
 * options require.
 *
 * A polled document has no directory of its own, so only `builtin:` bases can
 * be resolved; anything else fails closed here instead of reaching the guard
 * as a leaf policy that silently drops every block its base declares. It has
 * no source either, so `requireSignature` on a raw-YAML poll refuses the load:
 * there is nowhere to look for the envelope. A caller that polls signed
 * policies should return a {@link PolicySnapshot} from a loader that verified
 * against the real source (`HttpProvider` does).
 */
function parseAndResolve(
  yaml: string,
  options: ResolveOptions,
): { ok: true; value: Resolution } | { ok: false; error: Error } {
  const parsed = parse(yaml);
  if (!parsed.ok) {
    return { ok: false, error: new Error(`Failed to parse policy: ${parsed.error}`) };
  }
  try {
    return {
      ok: true,
      value: resolveWithOptions(parsed.value, { loader: createBuiltinLoader(), options }),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error:
        parsed.value.extends == null
          ? new Error(`Failed to load policy: ${message}`)
          : new Error(`Failed to resolve policy 'extends: ${parsed.value.extends}': ${message}`),
    };
  }
}

export interface PolicySnapshot {
  spec: HushSpec;
  fingerprint?: string;
  /** The verified resolution behind `spec`, when the loader produced one. */
  resolution?: Resolution;
}

export interface PollerOptions {
  loader: () => Promise<string | PolicySnapshot>;
  intervalMs?: number;
  onChange: (spec: HushSpec, resolution?: Resolution) => void;
  onError?: (error: Error) => void;
  /** If set, `current()` throws when the last load exceeds this age. */
  maxStaleMs?: number;
  /** Verification policy for loaders that return raw YAML. */
  resolveOptions?: ResolveOptions;
}

export class PolicyPoller {
  private options: PollerOptions;
  private timer: ReturnType<typeof setInterval> | null = null;
  private currentSpec: HushSpec | null = null;
  private currentResolution: Resolution | null = null;
  private lastSuccessfulLoad: number = 0;
  private contentHash: string | null = null;
  private nextLoadId: number = 0;
  private latestAppliedLoadId: number = 0;

  constructor(options: PollerOptions) {
    this.options = options;
  }

  async start(): Promise<HushSpec> {
    const spec = await this.doLoad(true);

    const intervalMs = this.options.intervalMs ?? 60_000;
    this.timer = setInterval(() => {
      void this.doLoad(false);
    }, intervalMs);

    if (this.timer && typeof this.timer === 'object' && 'unref' in this.timer) {
      (this.timer as { unref(): void }).unref();
    }

    return spec;
  }

  stop(): void {
    if (this.timer != null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  current(): HushSpec | null {
    const maxStaleMs = this.options.maxStaleMs ?? Infinity;
    if (
      this.currentSpec != null &&
      maxStaleMs !== Infinity &&
      this.lastSuccessfulLoad > 0
    ) {
      const age = Date.now() - this.lastSuccessfulLoad;
      if (age > maxStaleMs) {
        throw new Error(
          `Policy is stale: last successful load was ${age}ms ago (max: ${maxStaleMs}ms)`,
        );
      }
    }
    return this.currentSpec;
  }

  async reload(): Promise<HushSpec> {
    return this.doLoad(true);
  }

  /** The chain and signature outcome behind the policy `current()` returns. */
  resolution(): Resolution | null {
    return this.currentResolution;
  }

  private async doLoad(throwOnError: boolean): Promise<HushSpec> {
    const loadId = ++this.nextLoadId;
    let loaded: string | PolicySnapshot;
    try {
      loaded = await this.options.loader();
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (throwOnError && this.currentSpec == null) {
        throw error;
      }
      if (loadId < this.latestAppliedLoadId) {
        return this.currentSpec!;
      }
      this.options.onError?.(error);
      return this.currentSpec!;
    }

    let spec: HushSpec;
    let resolution: Resolution | undefined;
    let fingerprintSource: string;

    if (typeof loaded === 'string') {
      fingerprintSource = loaded;
      const result = parseAndResolve(loaded, this.options.resolveOptions ?? {});
      if (!result.ok) {
        const error = result.error;
        if (throwOnError && this.currentSpec == null) {
          throw error;
        }
        if (loadId < this.latestAppliedLoadId) {
          return this.currentSpec!;
        }
        this.options.onError?.(error);
        return this.currentSpec!;
      }
      resolution = result.value;
      spec = resolution.spec;
    } else {
      spec = loaded.spec;
      resolution = loaded.resolution;
      fingerprintSource = loaded.fingerprint ?? JSON.stringify(loaded.spec);
    }

    if (loadId < this.latestAppliedLoadId) {
      return this.currentSpec ?? spec;
    }

    const hash = createHash('sha256').update(fingerprintSource).digest('hex');
    if (hash === this.contentHash) {
      this.latestAppliedLoadId = loadId;
      this.lastSuccessfulLoad = Date.now();
      return this.currentSpec!;
    }

    this.latestAppliedLoadId = loadId;
    this.currentSpec = spec;
    this.currentResolution = resolution ?? null;
    this.contentHash = hash;
    this.lastSuccessfulLoad = Date.now();
    this.options.onChange(spec, resolution);

    return spec;
  }
}
