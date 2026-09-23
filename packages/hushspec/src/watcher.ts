import { watch } from 'node:fs';
import type { FSWatcher } from 'node:fs';
import type { ResolveOptions, Resolution } from './resolve.js';
import { resolveFromFileWithOptions } from './resolve.js';
import type { HushSpec } from './schema.js';

export interface WatcherOptions {
  debounceMs?: number;
  onChange: (spec: HushSpec, resolution?: Resolution) => void;
  onError?: (error: Error) => void;
  /**
   * Verification policy, applied on the initial load and on every reload. A
   * reload that fails verification goes to `onError` and leaves the previous
   * policy in force -- an unverified file must never become the policy in
   * effect just because it arrived second.
   */
  resolveOptions?: ResolveOptions;
}

export class PolicyWatcher {
  private path: string;
  private options: WatcherOptions;
  private watcher: FSWatcher | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private currentSpec: HushSpec | null = null;
  private currentResolution: Resolution | null = null;

  constructor(path: string, options: WatcherOptions) {
    this.path = path;
    this.options = options;
  }

  start(): HushSpec {
    const resolution = this.loadFromDisk();
    this.currentResolution = resolution;
    const spec = resolution.spec;
    this.currentSpec = spec;

    const debounceMs = this.options.debounceMs ?? 300;

    this.watcher = watch(this.path, () => {
      if (this.debounceTimer != null) {
        clearTimeout(this.debounceTimer);
      }

      this.debounceTimer = setTimeout(() => {
        this.debounceTimer = null;
        this.handleChange();
      }, debounceMs);
    });

    this.watcher.unref();

    return spec;
  }

  stop(): void {
    if (this.debounceTimer != null) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    if (this.watcher != null) {
      this.watcher.close();
      this.watcher = null;
    }
  }

  current(): HushSpec | null {
    return this.currentSpec;
  }

  /** The chain and signature outcome of the last successful load. */
  resolution(): Resolution | null {
    return this.currentResolution;
  }

  private loadFromDisk(): Resolution {
    // Reload resolves -- and verifies -- the `extends` chain the same way the
    // initial load does: a hot-swapped policy must never reach the guard as a
    // bare leaf, nor as one nobody checked.
    return resolveFromFileWithOptions(this.path, this.options.resolveOptions ?? {});
  }

  private handleChange(): void {
    try {
      const resolution = this.loadFromDisk();
      // The subscriber accepts the reload before it becomes what `current()`
      // serves: a document the guard refuses must not displace the one in
      // force, and the next change offers it again.
      this.options.onChange(resolution.spec, resolution);
      this.currentResolution = resolution;
      this.currentSpec = resolution.spec;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.options.onError?.(error);
    }
  }
}
