import { watch } from 'node:fs';
import type { FSWatcher } from 'node:fs';
import { resolveFromFile } from './resolve.js';
import type { HushSpec } from './schema.js';

export interface WatcherOptions {
  debounceMs?: number;
  onChange: (spec: HushSpec) => void;
  onError?: (error: Error) => void;
}

export class PolicyWatcher {
  private path: string;
  private options: WatcherOptions;
  private watcher: FSWatcher | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private currentSpec: HushSpec | null = null;

  constructor(path: string, options: WatcherOptions) {
    this.path = path;
    this.options = options;
  }

  start(): HushSpec {
    const spec = this.loadFromDisk();
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

  private loadFromDisk(): HushSpec {
    // Reload resolves the `extends` chain the same way the initial load does:
    // a hot-swapped policy must never reach the guard as a bare leaf.
    const result = resolveFromFile(this.path);
    if (!result.ok) {
      throw new Error(result.error);
    }
    return result.value;
  }

  private handleChange(): void {
    try {
      const newSpec = this.loadFromDisk();
      this.currentSpec = newSpec;
      this.options.onChange(newSpec);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.options.onError?.(error);
    }
  }
}
