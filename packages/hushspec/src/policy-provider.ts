import type { HushSpec } from './schema.js';
import { checkPanicSentinel } from './evaluate.js';
import { PolicyWatcher, type WatcherOptions } from './watcher.js';
import { PolicyPoller, DEFAULT_POLL_INTERVAL_MS, type PollerOptions } from './poller.js';
import type { ResolveOptions, Resolution } from './resolve.js';
import {
  createBuiltinLoader,
  resolveFromFileWithOptions,
  resolveWithOptionsAsync,
} from './resolve.js';
import { createHttpLoader, httpSignatureLocator, type HttpLoaderConfig } from './http-loader.js';

export interface PolicyProvider {
  load(): Promise<HushSpec>;
  watch(
    onChange: (spec: HushSpec, resolution?: Resolution) => void,
    onError?: (error: Error) => void,
  ): void;
  stop(): void;
  current(): HushSpec | null;
  /**
   * The chain and signature outcome of the load that produced
   * {@link PolicyProvider.current}, when the provider verified one.
   *
   * `HushGuard.fromProvider()` adopts it rather than resolving again: by the
   * time a provider hands over a spec the `extends` chain is already merged
   * away and the source it was verified against is gone, so a second
   * resolution could not find the signatures the first one checked.
   */
  resolution?(): Resolution | null;
}

/** How often a watching {@link FileProvider} checks the panic sentinel. */
export const DEFAULT_WATCH_INTERVAL_MS = 1_000;

/** Verification options shared by the built-in providers. */
export interface ProviderResolveOptions {
  /** Verification policy applied on every load and reload. */
  resolveOptions?: ResolveOptions;
  /**
   * Sentinel file consulted on every tick while the provider is watching. The
   * kill switch has to be reachable from a running reload loop, so it is
   * checked whether or not the policy changed, and it fails closed: a sentinel
   * whose absence cannot be proven arms panic mode.
   */
  panicSentinel?: string;
}

export class FileProvider implements PolicyProvider {
  private path: string;
  private debounceMs: number;
  private watcher: PolicyWatcher | null = null;
  private currentSpec: HushSpec | null = null;
  private currentResolution: Resolution | null = null;
  private readonly resolveOptions: ResolveOptions;
  private readonly panicSentinel?: string;
  private readonly sentinelIntervalMs: number;
  private sentinelTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    path: string,
    options?: {
      debounceMs?: number;
      /** How often the panic sentinel is checked while watching. */
      sentinelIntervalMs?: number;
    } & ProviderResolveOptions,
  ) {
    this.path = path;
    this.debounceMs = options?.debounceMs ?? 300;
    this.resolveOptions = options?.resolveOptions ?? {};
    this.panicSentinel = options?.panicSentinel;
    this.sentinelIntervalMs = options?.sentinelIntervalMs ?? DEFAULT_WATCH_INTERVAL_MS;
  }

  async load(): Promise<HushSpec> {
    // Resolve here, not in the guard: a file policy's relative `extends`
    // references are only meaningful against this file's own directory, and
    // its detached signature is only findable next to the file itself.
    const resolution = resolveFromFileWithOptions(this.path, this.resolveOptions);
    this.currentResolution = resolution;
    this.currentSpec = resolution.spec;
    return resolution.spec;
  }

  watch(
    onChange: (spec: HushSpec, resolution?: Resolution) => void,
    onError?: (error: Error) => void,
  ): void {
    this.stop();

    const watcherOptions: WatcherOptions = {
      debounceMs: this.debounceMs,
      resolveOptions: this.resolveOptions,
      onChange: (spec: HushSpec, resolution?: Resolution) => {
        // The subscriber accepts the reload before the provider serves it: a
        // document it rejects must never be what `current()` answers with.
        onChange(spec, resolution);
        this.currentSpec = spec;
        this.currentResolution = resolution ?? null;
      },
      onError,
    };

    this.watcher = new PolicyWatcher(this.path, watcherOptions);
    const spec = this.watcher.start();
    this.currentSpec = spec;
    this.currentResolution = this.watcher.resolution();
    this.startSentinel();
  }

  /**
   * Check the kill switch on its own tick.
   *
   * A file watcher wakes on a change to the policy; the sentinel is a
   * different file, and the switch has to be reachable whether or not the
   * policy is changing.
   */
  private startSentinel(): void {
    if (this.panicSentinel === undefined) return;
    const sentinel = this.panicSentinel;
    checkPanicSentinel(sentinel);
    this.sentinelTimer = setInterval(() => {
      checkPanicSentinel(sentinel);
    }, this.sentinelIntervalMs);
    // A kill-switch check must never be the reason a process stays alive.
    this.sentinelTimer.unref?.();
  }

  stop(): void {
    if (this.sentinelTimer != null) {
      clearInterval(this.sentinelTimer);
      this.sentinelTimer = null;
    }
    if (this.watcher != null) {
      this.watcher.stop();
      this.watcher = null;
    }
  }

  current(): HushSpec | null {
    return this.currentSpec;
  }

  resolution(): Resolution | null {
    return this.currentResolution;
  }
}

export class HttpProvider implements PolicyProvider {
  private url: string;
  private intervalMs: number;
  private maxStaleMs: number;
  private poller: PolicyPoller | null = null;
  private currentSpec: HushSpec | null = null;
  private currentResolution: Resolution | null = null;
  private readonly resolveOptions: ResolveOptions;
  private readonly panicSentinel?: string;
  private readonly httpLoader: ReturnType<typeof createHttpLoader>;

  constructor(url: string, options?: {
    intervalMs?: number;
    maxStaleMs?: number;
  } & HttpLoaderConfig & ProviderResolveOptions) {
    this.url = url;
    this.intervalMs = options?.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.maxStaleMs = options?.maxStaleMs ?? Infinity;
    this.panicSentinel = options?.panicSentinel;
    // Every rule the HTTPS loader enforces (core spec 2.6.4) is configured
    // where the loader is, so a provider cannot quietly relax one.
    this.httpLoader = createHttpLoader(options);
    const resolveOptions = options?.resolveOptions ?? {};
    // The policy came over the network, so its sidecar has to as well, under
    // the same configuration: the resolver's default locator carries none, so
    // a TLS trust anchor, the loopback exemption or an authorization header
    // would be dropped for the `.sig` fetch and a signed policy could not load.
    this.resolveOptions =
      resolveOptions.signatureLocator === undefined
        ? { ...resolveOptions, signatureLocator: httpSignatureLocator(options) }
        : resolveOptions;
  }

  async load(): Promise<HushSpec> {
    const resolution = await this.loadRemoteSpec();
    this.currentResolution = resolution;
    this.currentSpec = resolution.spec;
    return resolution.spec;
  }

  watch(
    onChange: (spec: HushSpec, resolution?: Resolution) => void,
    onError?: (error: Error) => void,
  ): void {
    this.stop();

    const pollerOptions: PollerOptions = {
      loader: async () => {
        const resolution = await this.loadRemoteSpec();
        // `content_hash` is the canonical hash of the resolved policy, which
        // is exactly the "did it change" fingerprint the poller wants.
        return { spec: resolution.spec, resolution, fingerprint: resolution.content_hash };
      },
      intervalMs: this.intervalMs,
      onChange: (spec: HushSpec, resolution?: Resolution) => {
        // The subscriber accepts the reload before the provider serves it: a
        // document it rejects must never be what `current()` answers with.
        onChange(spec, resolution);
        this.currentSpec = spec;
        this.currentResolution = resolution ?? null;
      },
      onError,
      maxStaleMs: this.maxStaleMs,
      panicSentinel: this.panicSentinel,
    };

    this.poller = new PolicyPoller(pollerOptions);
    void this.poller.start().then((spec) => {
      this.currentSpec = spec;
    }).catch((err) => {
      if (onError) {
        onError(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  stop(): void {
    if (this.poller != null) {
      this.poller.stop();
      this.poller = null;
    }
  }

  current(): HushSpec | null {
    if (this.poller != null) {
      return this.poller.current();
    }
    return this.currentSpec;
  }

  resolution(): Resolution | null {
    return this.currentResolution;
  }

  private async loadRemoteSpec(): Promise<Resolution> {
    const loaded = await this.httpLoader(this.url);
    // A remote policy may only extend a builtin: a remote base
    // (`extends: https://...`) fails closed here with a clear message rather
    // than being evaluated without its base. `source` is the URL the policy
    // came from, so the locator set in the constructor looks for `<url>.sig`.
    try {
      return await resolveWithOptionsAsync(loaded.spec, {
        source: loaded.source,
        loader: createBuiltinLoader(),
        options: this.resolveOptions,
      });
    } catch (error) {
      if (loaded.spec.extends == null) throw error;
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Failed to resolve policy 'extends: ${loaded.spec.extends}' from ${this.url}: ${message}`,
      );
    }
  }
}
