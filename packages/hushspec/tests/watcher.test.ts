import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, afterEach, vi } from 'vitest';
import { PolicyWatcher } from '../src/watcher.js';
import { PolicyPoller } from '../src/poller.js';
import { FileProvider, HttpProvider } from '../src/policy-provider.js';

const VALID_POLICY = `
hushspec: "0.1.0"
name: test-policy
rules:
  tool_access:
    allow: [read_file]
    default: block
`;

const UPDATED_POLICY = `
hushspec: "0.1.0"
name: updated-policy
rules:
  tool_access:
    allow: [read_file, write_file]
    default: block
`;

const INVALID_POLICY = `
not_a_hushspec: true
`;

// ---------------------------------------------------------------------------
// PolicyWatcher
// ---------------------------------------------------------------------------

describe('PolicyWatcher', () => {
  let tmpDir: string;
  let watcher: PolicyWatcher | null = null;

  afterEach(() => {
    if (watcher) {
      watcher.stop();
      watcher = null;
    }
    if (tmpDir) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('loads initial policy from file', () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-watcher-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    watcher = new PolicyWatcher(filePath, {
      onChange: () => {},
    });

    const spec = watcher.start();
    expect(spec.name).toBe('test-policy');
    expect(spec.rules?.tool_access?.allow).toEqual(['read_file']);
    expect(watcher.current()).toEqual(spec);
  });

  it('detects file changes and calls onChange', async () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-watcher-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    const changed = new Promise<void>((resolve) => {
      watcher = new PolicyWatcher(filePath, {
        debounceMs: 50,
        onChange: (spec) => {
          if (spec.name === 'updated-policy') {
            resolve();
          }
        },
      });
      watcher.start();
    });

    // Write the updated policy after a short delay
    await new Promise((r) => setTimeout(r, 100));
    writeFileSync(filePath, UPDATED_POLICY);

    // Wait for the onChange callback (with timeout)
    await Promise.race([
      changed,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('onChange was not called within timeout')), 3000),
      ),
    ]);

    expect(watcher!.current()?.name).toBe('updated-policy');
    expect(watcher!.current()?.rules?.tool_access?.allow).toEqual([
      'read_file',
      'write_file',
    ]);
  });

  it('debounces rapid changes', async () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-watcher-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    const onChangeCalls: string[] = [];
    const settled = new Promise<void>((resolve) => {
      watcher = new PolicyWatcher(filePath, {
        debounceMs: 200,
        onChange: (spec) => {
          onChangeCalls.push(spec.name ?? 'unnamed');
          if (spec.name === 'updated-policy') {
            resolve();
          }
        },
      });
      watcher.start();
    });

    await new Promise((r) => setTimeout(r, 50));
    writeFileSync(filePath, VALID_POLICY.replace('test-policy', 'intermediate'));
    await new Promise((r) => setTimeout(r, 20));
    writeFileSync(filePath, UPDATED_POLICY);

    await Promise.race([
      settled,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('onChange was not called within timeout')), 3000),
      ),
    ]);

    expect(watcher!.current()?.name).toBe('updated-policy');
  });

  it('keeps old policy when new file is invalid', async () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-watcher-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    const errorReceived = new Promise<Error>((resolve) => {
      watcher = new PolicyWatcher(filePath, {
        debounceMs: 50,
        onChange: () => {},
        onError: (err) => {
          resolve(err);
        },
      });
      watcher.start();
    });

    // Write invalid content
    await new Promise((r) => setTimeout(r, 100));
    writeFileSync(filePath, INVALID_POLICY);

    const error = await Promise.race([
      errorReceived,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('onError was not called within timeout')), 3000),
      ),
    ]);

    expect(error).toBeInstanceOf(Error);
    expect(error.message).toContain('Failed to parse');
    expect(watcher!.current()?.name).toBe('test-policy');
  });

  it('stop() stops watching', () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-watcher-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    watcher = new PolicyWatcher(filePath, {
      onChange: () => {},
    });
    watcher.start();
    watcher.stop();

    expect(watcher.current()?.name).toBe('test-policy');
  });

  it('throws on initial load if file does not exist', () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-watcher-'));
    const filePath = path.join(tmpDir, 'nonexistent.yaml');

    watcher = new PolicyWatcher(filePath, {
      onChange: () => {},
    });

    expect(() => watcher!.start()).toThrow();
  });

  it('throws on initial load if file is invalid', () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-watcher-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, INVALID_POLICY);

    watcher = new PolicyWatcher(filePath, {
      onChange: () => {},
    });

    expect(() => watcher!.start()).toThrow('Failed to parse');
  });
});

// ---------------------------------------------------------------------------
// PolicyPoller
// ---------------------------------------------------------------------------

describe('PolicyPoller', () => {
  let poller: PolicyPoller | null = null;

  afterEach(() => {
    if (poller) {
      poller.stop();
      poller = null;
    }
  });

  it('loads initial policy on start', async () => {
    poller = new PolicyPoller({
      loader: async () => VALID_POLICY,
      onChange: () => {},
    });

    const spec = await poller.start();
    expect(spec.name).toBe('test-policy');
    expect(poller.current()?.name).toBe('test-policy');
  });

  it('calls onChange when content changes', async () => {
    let callCount = 0;
    let loadCount = 0;
    const policies = [VALID_POLICY, UPDATED_POLICY];

    const changed = new Promise<void>((resolve) => {
      poller = new PolicyPoller({
        loader: async () => {
          const idx = Math.min(loadCount, policies.length - 1);
          loadCount++;
          return policies[idx];
        },
        intervalMs: 50,
        onChange: (spec) => {
          callCount++;
          if (spec.name === 'updated-policy') {
            resolve();
          }
        },
      });
    });

    await poller!.start();

    await Promise.race([
      changed,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('onChange not called within timeout')), 3000),
      ),
    ]);

    expect(callCount).toBeGreaterThanOrEqual(2);
    expect(poller!.current()?.name).toBe('updated-policy');
  });

  it('does not call onChange when content is unchanged', async () => {
    let onChangeCalls = 0;
    let loadCount = 0;

    poller = new PolicyPoller({
      loader: async () => {
        loadCount++;
        return VALID_POLICY;
      },
      intervalMs: 50,
      onChange: () => {
        onChangeCalls++;
      },
    });

    await poller.start();

    await new Promise((r) => setTimeout(r, 300));
    poller.stop();

    expect(onChangeCalls).toBe(1);
    expect(loadCount).toBeGreaterThan(1);
  });

  it('handles loader errors gracefully', async () => {
    let loadCount = 0;
    const errors: Error[] = [];

    poller = new PolicyPoller({
      loader: async () => {
        loadCount++;
        if (loadCount > 1) {
          throw new Error('network failure');
        }
        return VALID_POLICY;
      },
      intervalMs: 50,
      onChange: () => {},
      onError: (err) => {
        errors.push(err);
      },
    });

    await poller.start();

    await new Promise((r) => setTimeout(r, 300));
    poller.stop();

    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].message).toBe('network failure');
    expect(poller.current()?.name).toBe('test-policy');
  });

  it('stop() stops polling', async () => {
    let loadCount = 0;

    poller = new PolicyPoller({
      loader: async () => {
        loadCount++;
        return VALID_POLICY;
      },
      intervalMs: 50,
      onChange: () => {},
    });

    await poller.start();
    poller.stop();
    const countAfterStop = loadCount;

    await new Promise((r) => setTimeout(r, 200));
    expect(loadCount).toBe(countAfterStop);
  });

  it('maxStaleMs enforcement', async () => {
    poller = new PolicyPoller({
      loader: async () => VALID_POLICY,
      onChange: () => {},
      maxStaleMs: 100,
    });

    await poller.start();
    poller.stop(); // Stop polling so time advances past the stale threshold

    expect(poller.current()?.name).toBe('test-policy');
    await new Promise((r) => setTimeout(r, 200));

    expect(() => poller!.current()).toThrow('Policy is stale');
  });

  it('ignores out-of-order reload completions', async () => {
    let loadCount = 0;
    const changes: string[] = [];

    poller = new PolicyPoller({
      intervalMs: 40,
      loader: async () => {
        loadCount++;
        if (loadCount === 1) return VALID_POLICY;
        if (loadCount === 2) {
          await new Promise((resolve) => setTimeout(resolve, 200));
          return VALID_POLICY.replace('test-policy', 'older-policy');
        }
        if (loadCount === 3) {
          await new Promise((resolve) => setTimeout(resolve, 10));
          return UPDATED_POLICY;
        }
        throw new Error('done');
      },
      onChange: (spec) => {
        changes.push(spec.name ?? 'unnamed');
      },
      onError: () => {},
    });

    await poller.start();
    await new Promise((resolve) => setTimeout(resolve, 320));
    poller.stop();

    expect(changes).toContain('updated-policy');
    expect(poller.current()?.name).toBe('updated-policy');
  });

  it('throws on initial load if loader fails and no fallback', async () => {
    poller = new PolicyPoller({
      loader: async () => {
        throw new Error('connection refused');
      },
      onChange: () => {},
    });

    await expect(poller.start()).rejects.toThrow('connection refused');
  });

  it('throws on initial load if content is invalid and no fallback', async () => {
    poller = new PolicyPoller({
      loader: async () => INVALID_POLICY,
      onChange: () => {},
    });

    await expect(poller.start()).rejects.toThrow('Failed to parse');
  });

  it('reload() forces an immediate load', async () => {
    let loadCount = 0;
    const policies = [VALID_POLICY, UPDATED_POLICY];

    poller = new PolicyPoller({
      loader: async () => {
        const idx = Math.min(loadCount, policies.length - 1);
        loadCount++;
        return policies[idx];
      },
      intervalMs: 60_000, // Long interval -- we don't want background polls
      onChange: () => {},
    });

    await poller.start();
    expect(poller.current()?.name).toBe('test-policy');

    const reloaded = await poller.reload();
    expect(reloaded.name).toBe('updated-policy');
    expect(poller.current()?.name).toBe('updated-policy');
  });
});

// ---------------------------------------------------------------------------
// FileProvider
// ---------------------------------------------------------------------------

describe('FileProvider', () => {
  let tmpDir: string;
  let provider: FileProvider | null = null;

  afterEach(() => {
    if (provider) {
      provider.stop();
      provider = null;
    }
    if (tmpDir) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('loads and watches a file', async () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-fileprovider-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    provider = new FileProvider(filePath, { debounceMs: 50 });

    const spec = await provider.load();
    expect(spec.name).toBe('test-policy');
    expect(provider.current()?.name).toBe('test-policy');
  });

  it('watch detects file changes via FileProvider', async () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-fileprovider-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    provider = new FileProvider(filePath, { debounceMs: 50 });

    const changed = new Promise<void>((resolve) => {
      provider!.watch(
        (spec) => {
          if (spec.name === 'updated-policy') {
            resolve();
          }
        },
      );
    });

    await new Promise((r) => setTimeout(r, 100));
    writeFileSync(filePath, UPDATED_POLICY);

    await Promise.race([
      changed,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('onChange not called within timeout')), 3000),
      ),
    ]);

    expect(provider.current()?.name).toBe('updated-policy');
  });

  it('current() returns null before load', () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-fileprovider-'));
    const filePath = path.join(tmpDir, 'policy.yaml');
    writeFileSync(filePath, VALID_POLICY);

    provider = new FileProvider(filePath);
    expect(provider.current()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// HttpProvider
// ---------------------------------------------------------------------------

describe('HttpProvider', () => {
  let provider: HttpProvider | null = null;

  afterEach(() => {
    if (provider) {
      provider.stop();
      provider = null;
    }
    vi.restoreAllMocks();
  });

  it('loads from a URL using fetch', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => VALID_POLICY,
    });
    vi.stubGlobal('fetch', mockFetch);

    provider = new HttpProvider('https://example.com/policy.yaml');
    const spec = await provider.load();

    expect(spec.name).toBe('test-policy');
    expect(provider.current()?.name).toBe('test-policy');
    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/policy.yaml',
      expect.objectContaining({ headers: {} }),
    );
  });

  it('passes auth header when configured', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => VALID_POLICY,
    });
    vi.stubGlobal('fetch', mockFetch);

    provider = new HttpProvider('https://example.com/policy.yaml', {
      authHeader: 'Bearer test-token',
    });
    await provider.load();

    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/policy.yaml',
      expect.objectContaining({
        headers: { Authorization: 'Bearer test-token' },
      }),
    );
  });

  it('throws on HTTP error', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      text: async () => 'Not Found',
    });
    vi.stubGlobal('fetch', mockFetch);

    provider = new HttpProvider('https://example.com/policy.yaml');
    await expect(provider.load()).rejects.toThrow('returned status 404');
  });

  it('rejects insecure HTTP URLs', async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);

    provider = new HttpProvider('http://127.0.0.1/policy.yaml');
    await expect(provider.load()).rejects.toThrow('only HTTPS URLs are allowed');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('current() returns null before load', () => {
    provider = new HttpProvider('https://example.com/policy.yaml');
    expect(provider.current()).toBeNull();
  });
});
