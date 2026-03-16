import { readFileSync } from 'node:fs';
import type { HushSpec } from './schema.js';
import { PolicyWatcher, type WatcherOptions } from './watcher.js';
import { PolicyPoller, type PollerOptions } from './poller.js';
import { parse } from './parse.js';
import { computePolicyHash } from './receipt.js';
import { createHttpLoader } from './http-loader.js';

export interface PolicyProvider {
  load(): Promise<HushSpec>;
  watch(onChange: (spec: HushSpec) => void, onError?: (error: Error) => void): void;
  stop(): void;
  current(): HushSpec | null;
}

export class FileProvider implements PolicyProvider {
  private path: string;
  private debounceMs: number;
  private watcher: PolicyWatcher | null = null;
  private currentSpec: HushSpec | null = null;

  constructor(path: string, options?: { debounceMs?: number }) {
    this.path = path;
    this.debounceMs = options?.debounceMs ?? 300;
  }

  async load(): Promise<HushSpec> {
    const content = readFileSync(this.path, 'utf8');
    const result = parse(content);
    if (!result.ok) {
      throw new Error(`Failed to parse HushSpec at ${this.path}: ${result.error}`);
    }
    this.currentSpec = result.value;
    return result.value;
  }

  watch(onChange: (spec: HushSpec) => void, onError?: (error: Error) => void): void {
    this.stop();

    const watcherOptions: WatcherOptions = {
      debounceMs: this.debounceMs,
      onChange: (spec: HushSpec) => {
        this.currentSpec = spec;
        onChange(spec);
      },
      onError,
    };

    this.watcher = new PolicyWatcher(this.path, watcherOptions);
    const spec = this.watcher.start();
    this.currentSpec = spec;
  }

  stop(): void {
    if (this.watcher != null) {
      this.watcher.stop();
      this.watcher = null;
    }
  }

  current(): HushSpec | null {
    return this.currentSpec;
  }
}

export class HttpProvider implements PolicyProvider {
  private url: string;
  private intervalMs: number;
  private maxStaleMs: number;
  private poller: PolicyPoller | null = null;
  private currentSpec: HushSpec | null = null;
  private readonly httpLoader: ReturnType<typeof createHttpLoader>;

  constructor(url: string, options?: {
    intervalMs?: number;
    authHeader?: string;
    maxStaleMs?: number;
    timeoutMs?: number;
    maxSize?: number;
    cacheDir?: string;
  }) {
    this.url = url;
    this.intervalMs = options?.intervalMs ?? 60_000;
    this.maxStaleMs = options?.maxStaleMs ?? Infinity;
    this.httpLoader = createHttpLoader({
      authHeader: options?.authHeader,
      timeoutMs: options?.timeoutMs,
      maxSize: options?.maxSize,
      cacheDir: options?.cacheDir,
    });
  }

  async load(): Promise<HushSpec> {
    const spec = await this.loadRemoteSpec();
    this.currentSpec = spec;
    return spec;
  }

  watch(onChange: (spec: HushSpec) => void, onError?: (error: Error) => void): void {
    this.stop();

    const pollerOptions: PollerOptions = {
      loader: async () => {
        const spec = await this.loadRemoteSpec();
        return { spec, fingerprint: computePolicyHash(spec) };
      },
      intervalMs: this.intervalMs,
      onChange: (spec: HushSpec) => {
        this.currentSpec = spec;
        onChange(spec);
      },
      onError,
      maxStaleMs: this.maxStaleMs,
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

  private async loadRemoteSpec(): Promise<HushSpec> {
    const loaded = await this.httpLoader(this.url);
    return loaded.spec;
  }
}
