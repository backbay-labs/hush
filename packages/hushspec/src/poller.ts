import { createHash } from 'node:crypto';
import { checkPanicSentinel } from './evaluate.js';
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
  /** Time the caller successfully loaded this snapshot, in milliseconds. */
  loadedAt?: number;
}

/** How often a {@link PolicyPoller} reloads, in milliseconds. */
export const DEFAULT_POLL_INTERVAL_MS = 60_000;

export interface PollerOptions {
  loader: () => Promise<string | PolicySnapshot>;
  /**
   * A policy the caller already loaded and verified before it began polling.
   * It becomes the baseline without being offered to `onChange` again.
   */
  initialSnapshot?: PolicySnapshot;
  /** Tick period in milliseconds. Default {@link DEFAULT_POLL_INTERVAL_MS}. */
  intervalMs?: number;
  onChange: (spec: HushSpec, resolution?: Resolution) => void;
  onError?: (error: Error) => void;
  /** If set, `current()` throws when the last load exceeds this age. */
  maxStaleMs?: number;
  /** Verification policy for loaders that return raw YAML. */
  resolveOptions?: ResolveOptions;
  /**
   * Sentinel file consulted on every tick, before the reload. The kill switch
   * has to be reachable from a running loop, so it is checked whether or not
   * the policy changed, and it fails closed: a sentinel whose absence cannot
   * be proven arms panic mode.
   */
  panicSentinel?: string;
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
  /** Invalidates an in-flight timer load when polling is stopped. */
  private lifecycle: number = 0;

  constructor(options: PollerOptions) {
    this.options = options;
    const initial = options.initialSnapshot;
    if (initial !== undefined) {
      // A provider may have loaded the policy before it starts watching. Keep
      // that accepted state rather than requiring a second successful remote
      // request merely to install the poll timer.
      this.currentSpec = initial.spec;
      this.currentResolution = initial.resolution ?? null;
      const fingerprintSource = initial.fingerprint ?? JSON.stringify(initial.spec);
      this.contentHash = createHash('sha256').update(fingerprintSource).digest('hex');
      this.lastSuccessfulLoad = initial.loadedAt ?? Date.now();
    }
  }

  async start(): Promise<HushSpec> {
    const lifecycle = this.lifecycle;
    try {
      const spec = this.currentSpec ?? await this.doLoad(true);
      if (lifecycle === this.lifecycle) this.startTimer();
      return spec;
    } catch (error) {
      // A first load can be transient. Keep the retry loop alive so the
      // provider can recover (and still check the panic sentinel) instead of
      // permanently stopping after the rejected start promise.
      if (lifecycle === this.lifecycle) this.startTimer();
      throw error;
    }
  }

  private startTimer(): void {
    if (this.timer != null) return;
    const intervalMs = this.options.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const lifecycle = this.lifecycle;
    this.timer = setInterval(() => {
      // A callback queued just before stop() must not begin a new reload after
      // polling has been stopped.
      if (lifecycle !== this.lifecycle) return;
      // A poll runs with nobody awaiting it, so a rejection here would be an
      // unhandled rejection rather than something a caller can catch. The
      // callbacks report their own failures, so anything reaching this point
      // is already past reporting.
      void this.doLoad(false).catch(() => {});
    }, intervalMs);

    if (this.timer && typeof this.timer === 'object' && 'unref' in this.timer) {
      (this.timer as { unref(): void }).unref();
    }
  }

  stop(): void {
    this.lifecycle += 1;
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

  /** When the policy currently served by this poller last loaded successfully. */
  lastSuccessfulLoadAt(): number {
    return this.lastSuccessfulLoad;
  }

  /**
   * Offer the new policy to `onChange`, returning the error it refused with or
   * `null` when it accepted.
   *
   * The callback belongs to the caller and runs on the poll timer, where an
   * escaping error is an unhandled rejection rather than something anyone can
   * catch -- and it would take the poll loop with it. A subscriber that throws
   * has rejected the reload, so the caller decides what to report and what to
   * keep serving.
   */
  private offerChange(spec: HushSpec, resolution?: Resolution): Error | null {
    try {
      this.options.onChange(spec, resolution);
      return null;
    } catch (err) {
      return err instanceof Error ? err : new Error(String(err));
    }
  }

  /**
   * Report a failed poll, tolerating a handler that throws. There is nowhere
   * left to report an `onError` that fails, so it is dropped rather than
   * allowed to stop the poll loop.
   */
  private notifyError(error: Error): void {
    try {
      this.options.onError?.(error);
    } catch {
      // Reporting the reporter has no destination.
    }
  }

  /** Arm the kill switch when the sentinel is there, on every tick. */
  private checkPanicSentinel(): void {
    if (this.options.panicSentinel !== undefined) {
      checkPanicSentinel(this.options.panicSentinel);
    }
  }

  private async doLoad(throwOnError: boolean): Promise<HushSpec> {
    const lifecycle = this.lifecycle;
    this.checkPanicSentinel();
    const loadId = ++this.nextLoadId;
    let loaded: string | PolicySnapshot;
    try {
      loaded = await this.options.loader();
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (lifecycle !== this.lifecycle) {
        if (this.currentSpec != null) return this.currentSpec;
        throw error;
      }
      if (throwOnError && this.currentSpec == null) {
        throw error;
      }
      if (loadId < this.latestAppliedLoadId) {
        return this.currentSpec!;
      }
      this.notifyError(error);
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
        this.notifyError(error);
        return this.currentSpec!;
      }
      resolution = result.value;
      spec = resolution.spec;
    } else {
      if (loaded.spec.extends != null) {
        // A loader that skipped resolution would otherwise have its leaf
        // served by `current()` with every block its base declares silently
        // dropped -- the same refusal the raw-YAML branch makes.
        const error = new Error(
          `Policy still declares 'extends: ${loaded.spec.extends}'; resolve it before returning a snapshot`,
        );
        if (throwOnError && this.currentSpec == null) {
          throw error;
        }
        if (loadId < this.latestAppliedLoadId) {
          return this.currentSpec!;
        }
        this.notifyError(error);
        return this.currentSpec!;
      }
      spec = loaded.spec;
      resolution = loaded.resolution;
      fingerprintSource = loaded.fingerprint ?? JSON.stringify(loaded.spec);
    }

    // stop() may run while the loader is doing I/O. Do not let that old tick
    // publish a policy or refresh staleness after polling was stopped.
    if (lifecycle !== this.lifecycle) return this.currentSpec ?? spec;

    if (loadId < this.latestAppliedLoadId) {
      return this.currentSpec ?? spec;
    }

    const hash = createHash('sha256').update(fingerprintSource).digest('hex');
    if (hash === this.contentHash) {
      this.latestAppliedLoadId = loadId;
      this.lastSuccessfulLoad = Date.now();
      return this.currentSpec!;
    }

    // The subscriber accepts the reload before any of it is committed: a
    // document the guard refuses must not become what `current()` serves, and
    // leaving the hash unrecorded is what makes the next poll offer the same
    // document again rather than skip it as already seen.
    const rejected = this.offerChange(spec, resolution);
    this.latestAppliedLoadId = loadId;
    if (rejected !== null) {
      if (throwOnError && this.currentSpec == null) {
        throw rejected;
      }
      this.notifyError(rejected);
      return this.currentSpec ?? spec;
    }

    this.currentSpec = spec;
    this.currentResolution = resolution ?? null;
    this.contentHash = hash;
    this.lastSuccessfulLoad = Date.now();

    return spec;
  }
}
