import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, afterEach, vi } from 'vitest';
import { HushGuard } from '../src/middleware.js';
import { PolicyWatcher } from '../src/watcher.js';
import { PolicyPoller } from '../src/poller.js';
import { FileProvider, HttpProvider } from '../src/policy-provider.js';
import { deactivatePanic, isPanicActive } from '../src/evaluate.js';
import { parseOrThrow } from '../src/parse.js';
import { resolutionFromResolved, type Resolution } from '../src/resolve.js';
import type { HttpLoaderConfig } from '../src/http-loader.js';
import { loadKeyring } from '../src/signing.js';
import { startTestServer, type Handler, type TestServer } from './helpers/https-server.js';
import { TEST_TLS_CERT } from './helpers/tls-cert.js';

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

const STRICTER_POLICY = `
hushspec: "0.1.0"
name: stricter-policy
rules:
  tool_access:
    allow: [read_file]
    default: block
`;

async function waitFor(check: () => boolean, message: string, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() >= deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

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

  it('arms the kill switch from the sentinel on every tick', async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), 'hushspec-panic-'));
    const sentinel = path.join(directory, '.hushspec_panic');
    deactivatePanic();
    try {
      poller = new PolicyPoller({
        loader: async () => VALID_POLICY,
        onChange: () => {},
        panicSentinel: sentinel,
      });
      await poller.start();
      expect(isPanicActive()).toBe(false);

      writeFileSync(sentinel, '');
      await poller.reload();
      expect(isPanicActive()).toBe(true);
    } finally {
      deactivatePanic();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('refuses a snapshot that still declares extends', async () => {
    const errors: Error[] = [];
    poller = new PolicyPoller({
      loader: async () => ({
        spec: parseOrThrow('hushspec: "0.1.0"\nname: leaf\nextends: "builtin:default"\n'),
      }),
      onChange: () => {},
      onError: (error) => errors.push(error),
    });

    await expect(poller.start()).rejects.toThrow(/still declares 'extends/);
    expect(poller.current()).toBeNull();
    expect(errors).toHaveLength(0);
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

  it('reports a throwing onChange through onError and keeps polling', async () => {
    const errors: Error[] = [];
    let loadCount = 0;

    poller = new PolicyPoller({
      loader: async () => {
        loadCount++;
        return loadCount === 1 ? VALID_POLICY : UPDATED_POLICY;
      },
      intervalMs: 50,
      onChange: (spec) => {
        if (spec.name !== 'test-policy') {
          throw new Error('subscriber blew up');
        }
      },
      onError: (error) => {
        errors.push(error);
      },
    });

    await poller.start();
    await new Promise((r) => setTimeout(r, 300));
    poller.stop();

    expect(errors.map((error) => error.message)).toContain('subscriber blew up');
    expect(loadCount).toBeGreaterThan(1);
  });

  it('keeps serving the accepted policy when the subscriber rejects a reload', async () => {
    const errors: Error[] = [];
    let loadCount = 0;

    poller = new PolicyPoller({
      loader: async () => {
        loadCount++;
        return loadCount === 1 ? VALID_POLICY : UPDATED_POLICY;
      },
      intervalMs: 20,
      onChange: (spec) => {
        if (spec.name !== 'test-policy') {
          throw new Error('the reloaded policy was refused');
        }
      },
      onError: (error) => {
        errors.push(error);
      },
    });

    const started = await poller.start();
    expect(started.name).toBe('test-policy');

    await new Promise((r) => setTimeout(r, 200));
    poller.stop();

    // The rejected snapshot never became what `current()` serves, and it is
    // offered again on every tick rather than skipped as already seen.
    expect(poller.current()?.name).toBe('test-policy');
    expect(errors.length).toBeGreaterThan(1);
  });

  it('refuses to start when the subscriber rejects the first load', async () => {
    poller = new PolicyPoller({
      loader: async () => VALID_POLICY,
      intervalMs: 50,
      onChange: () => {
        throw new Error('the first policy was refused');
      },
    });

    await expect(poller.start()).rejects.toThrow('the first policy was refused');
    expect(poller.current()).toBeNull();
  });

  it('survives an onError handler that throws', async () => {
    let loadCount = 0;

    poller = new PolicyPoller({
      loader: async () => {
        loadCount++;
        if (loadCount > 1) {
          throw new Error('network down');
        }
        return VALID_POLICY;
      },
      intervalMs: 50,
      onChange: () => {},
      onError: () => {
        throw new Error('handler blew up');
      },
    });

    await poller.start();
    await new Promise((r) => setTimeout(r, 300));
    poller.stop();

    expect(loadCount).toBeGreaterThan(2);
    expect(poller.current()?.name).toBe('test-policy');
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

  // Break caught: a failed initial start used to return before the interval
  // existed, leaving a transient outage with no retry path at all.
  it('keeps retrying after an initial load failure', async () => {
    let attempts = 0;
    poller = new PolicyPoller({
      intervalMs: 20,
      loader: async () => {
        attempts += 1;
        if (attempts === 1) throw new Error('connection refused');
        return VALID_POLICY;
      },
      onChange: () => {},
    });

    await expect(poller.start()).rejects.toThrow('connection refused');
    await waitFor(
      () => poller!.current()?.name === 'test-policy',
      'poller did not retry its failed initial load',
    );
    expect(attempts).toBeGreaterThanOrEqual(2);
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
  const servers: TestServer[] = [];

  afterEach(async () => {
    if (provider) {
      provider.stop();
      provider = null;
    }
    while (servers.length > 0) await servers.pop()!.close();
    vi.restoreAllMocks();
  });

  // A real `node:https` server, because the loader dials the address it checked
  // rather than going through a global `fetch` a test could stand in for. The
  // certificate is trusted through `tlsCa` -- verification stays on, so it is
  // still checked against `localhost` -- and `allowInsecureLoopback` is the
  // loader's documented test-only exemption for the address check.
  async function serve(handler: Handler): Promise<string> {
    const server = await startTestServer(handler);
    servers.push(server);
    return server.origin;
  }

  function options(extra?: HttpLoaderConfig): HttpLoaderConfig {
    return { allowInsecureLoopback: true, tlsCa: TEST_TLS_CERT, ...extra };
  }

  it('loads from a URL', async () => {
    const origin = await serve((_req, res) => res.end(VALID_POLICY));

    provider = new HttpProvider(`${origin}/policy.yaml`, options());
    const spec = await provider.load();

    expect(spec.name).toBe('test-policy');
    expect(provider.current()?.name).toBe('test-policy');
  });

  it('passes auth header when configured', async () => {
    let seen: string | undefined;
    const origin = await serve((req, res) => {
      seen = req.headers.authorization;
      res.end(VALID_POLICY);
    });

    provider = new HttpProvider(
      `${origin}/policy.yaml`,
      options({ authHeader: 'Bearer test-token' }),
    );
    await provider.load();

    expect(seen).toBe('Bearer test-token');
  });

  it('throws on HTTP error', async () => {
    const origin = await serve((_req, res) => {
      res.writeHead(404);
      res.end('Not Found');
    });

    provider = new HttpProvider(`${origin}/policy.yaml`, options());
    await expect(provider.load()).rejects.toThrow('returned status 404');
  });

  it('rejects insecure HTTP URLs', async () => {
    provider = new HttpProvider('http://127.0.0.1/policy.yaml');
    await expect(provider.load()).rejects.toThrow('only HTTPS URLs are allowed');
  });

  it('rejects a URL that resolves to a blocked address', async () => {
    provider = new HttpProvider('https://169.254.169.254/policy.yaml');
    await expect(provider.load()).rejects.toThrow('SSRF protection');
  });

  it('current() returns null before load', () => {
    provider = new HttpProvider('https://policies.example.com/policy.yaml');
    expect(provider.current()).toBeNull();
  });

  // Break caught: constructing a fresh poller after a successful provider
  // load discards that policy, so one transient bootstrap failure prevents all
  // later refreshes and sentinel checks.
  it.each(['enforce', 'monitor'] as const)(
    'keeps the loaded policy, recovers refreshes, and observes panic in %s mode',
    async (mode) => {
      const sentinelDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-http-panic-'));
      const sentinel = path.join(sentinelDir, '.hushspec_panic');
      let requests = 0;
      const errors: Error[] = [];
      const origin = await serve((_req, res) => {
        requests += 1;
        if (requests === 2 || requests >= 4) {
          res.writeHead(503);
          res.end('temporary outage');
          return;
        }
        res.end(requests >= 3 ? STRICTER_POLICY : VALID_POLICY);
      });

      deactivatePanic();
      try {
        provider = new HttpProvider(`${origin}/policy.yaml`, {
          ...options(),
          intervalMs: 25,
          maxStaleMs: 500,
          panicSentinel: sentinel,
        });
        const initial = await provider.load();
        const guard = new HushGuard(initial, {
          provider,
          enforcement: { mode },
          observer: { onEvent: () => {} },
        });
        provider.watch(
          (spec, resolution) => guard.swapPolicy(spec, resolution),
          (error) => errors.push(error),
        );

        await waitFor(
          () => requests >= 3 && provider!.resolution()?.spec.name === 'stricter-policy',
          'HTTP provider did not recover after its transient refresh failure',
        );
        expect(errors.some((error) => error.message.includes('returned status 503'))).toBe(true);

        const refreshed = guard.gate({ type: 'tool_call', target: 'write_file' });
        expect(refreshed.proceed).toBe(mode === 'monitor');
        expect(refreshed.enforcement).toEqual({
          mode,
          outcome: mode === 'monitor' ? 'would_block' : 'blocked',
        });

        writeFileSync(sentinel, 'panic\n');
        await waitFor(() => isPanicActive(), 'HTTP provider did not observe the panic sentinel');
        const panicked = guard.gate({ type: 'tool_call', target: 'read_file' });
        expect(panicked.proceed).toBe(false);
        expect(panicked.enforcement).toEqual({ mode: 'enforce', outcome: 'blocked' });

        rmSync(sentinel, { force: true });
        deactivatePanic();
        await waitFor(
          () =>
            guard.gate({ type: 'tool_call', target: 'read_file' }).result.matched_rule ===
            '__hushspec_policy_provider__',
          'HTTP provider did not fail closed after its refreshed policy became stale',
          5_000,
        );
        const stale = guard.gate({ type: 'tool_call', target: 'read_file' });
        expect(stale.result.matched_rule).toBe('__hushspec_policy_provider__');
        expect(stale.proceed).toBe(mode === 'monitor');

        provider.stop();
      } finally {
        deactivatePanic();
        rmSync(sentinelDir, { recursive: true, force: true });
      }
    },
  );

  // Break caught: retaining a stopped poller makes current() ignore a later
  // load, so a provider cannot be stopped, loaded, and watched again safely.
  it('uses a newly loaded policy after stop', async () => {
    let requests = 0;
    const origin = await serve((_req, res) => {
      requests += 1;
      res.end(requests === 1 ? VALID_POLICY : STRICTER_POLICY);
    });

    provider = new HttpProvider(`${origin}/policy.yaml`, {
      ...options(),
      intervalMs: 60_000,
    });
    expect((await provider.load()).name).toBe('test-policy');
    provider.watch(() => {});
    provider.stop();

    expect((await provider.load()).name).toBe('stricter-policy');
    expect(provider.current()?.name).toBe('stricter-policy');
    expect(provider.resolution()?.spec.name).toBe('stricter-policy');
  });

  // Break caught: rewatching a stale policy used to give its seeded poller a
  // fresh Date.now() timestamp, making the stale policy temporarily usable.
  it('does not reset policy staleness when watch restarts', async () => {
    vi.useFakeTimers();
    try {
      const resolution = resolutionFromResolved(
        parseOrThrow(VALID_POLICY),
        'https://policy.example.test',
      );
      provider = new HttpProvider('https://policy.example.test/policy.yaml', {
        intervalMs: 60_000,
        maxStaleMs: 10,
      });
      type ProviderInternals = { loadRemoteSpec: () => Promise<Resolution> };
      (provider as unknown as ProviderInternals).loadRemoteSpec = async () => resolution;

      await provider.load();
      await vi.advanceTimersByTimeAsync(11);
      provider.watch(() => {});
      expect(() => provider!.current()).toThrow('Policy is stale');

      provider.watch(() => {});
      expect(() => provider!.current()).toThrow('Policy is stale');
    } finally {
      vi.useRealTimers();
    }
  });

  // Break caught: unchanged successful polls refresh the poller's age, but a
  // rewatch used the provider's original load time and made that fresh policy
  // look stale again.
  it('keeps unchanged successful poll freshness across watch restart', async () => {
    vi.useFakeTimers();
    try {
      const resolution = resolutionFromResolved(
        parseOrThrow(VALID_POLICY),
        'https://policy.example.test',
      );
      provider = new HttpProvider('https://policy.example.test/policy.yaml', {
        intervalMs: 20,
        maxStaleMs: 50,
      });
      type ProviderInternals = { loadRemoteSpec: () => Promise<Resolution> };
      (provider as unknown as ProviderInternals).loadRemoteSpec = async () => resolution;

      await provider.load();
      provider.watch(() => {});
      await vi.advanceTimersByTimeAsync(100);
      expect(() => provider!.current()).not.toThrow();

      provider.watch(() => {});
      expect(() => provider!.current()).not.toThrow();
    } finally {
      vi.useRealTimers();
    }
  });

  // Break caught: a throwing startup onError handler escaped the detached
  // watch-start promise even though the poller treats reporter failures as
  // non-fatal and continues retrying.
  it('recovers when the initial watch error reporter throws', async () => {
    let attempts = 0;
    const resolution = resolutionFromResolved(
      parseOrThrow(VALID_POLICY),
      'https://policy.example.test',
    );
    provider = new HttpProvider('https://policy.example.test/policy.yaml', { intervalMs: 20 });
    type ProviderInternals = { loadRemoteSpec: () => Promise<Resolution> };
    (provider as unknown as ProviderInternals).loadRemoteSpec = async () => {
      attempts += 1;
      if (attempts === 1) throw new Error('initial outage');
      return resolution;
    };

    provider.watch(
      () => {},
      () => {
        throw new Error('reporter failed');
      },
    );

    await waitFor(
      () => provider!.current()?.name === 'test-policy',
      'HTTP provider did not retry after its startup error reporter failed',
    );
    expect(attempts).toBeGreaterThanOrEqual(2);
  });

  // Break caught: an initial watch load that completed after stop() used the
  // provider's unguarded start().then() continuation to resurrect a policy.
  it('does not publish a deferred watch load after stop or into a restart', async () => {
    let releaseStopped!: (value: Resolution) => void;
    const stoppedLoad = new Promise<Resolution>((resolve) => {
      releaseStopped = resolve;
    });
    const stoppedProvider = new HttpProvider('https://policy.example.test/policy.yaml');
    type ProviderInternals = { loadRemoteSpec: () => Promise<Resolution> };
    (stoppedProvider as unknown as ProviderInternals).loadRemoteSpec = () => stoppedLoad;
    stoppedProvider.watch(() => {});
    stoppedProvider.stop();
    releaseStopped(resolutionFromResolved(parseOrThrow(VALID_POLICY), 'https://policy.example.test'));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(stoppedProvider.current()).toBeNull();
    expect(stoppedProvider.resolution()).toBeNull();

    let releaseFirst!: (value: Resolution) => void;
    let releaseSecond!: (value: Resolution) => void;
    const first = new Promise<Resolution>((resolve) => {
      releaseFirst = resolve;
    });
    const second = new Promise<Resolution>((resolve) => {
      releaseSecond = resolve;
    });
    const snapshots = [first, second];
    let loads = 0;
    const changes: string[] = [];

    provider = new HttpProvider('https://policy.example.test/policy.yaml', { intervalMs: 60_000 });
    (provider as unknown as ProviderInternals).loadRemoteSpec = () => {
      const snapshot = snapshots[loads];
      loads += 1;
      if (snapshot === undefined) throw new Error('unexpected remote load');
      return snapshot;
    };

    provider.watch((spec) => changes.push(spec.name ?? 'unnamed'));
    expect(loads).toBe(1);
    provider.stop();
    provider.watch((spec) => changes.push(spec.name ?? 'unnamed'));
    expect(loads).toBe(2);

    releaseSecond(resolutionFromResolved(parseOrThrow(STRICTER_POLICY), 'https://policy.example.test'));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(provider.current()?.name).toBe('stricter-policy');
    expect(provider.resolution()?.spec.name).toBe('stricter-policy');

    releaseFirst(resolutionFromResolved(parseOrThrow(VALID_POLICY), 'https://policy.example.test'));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(provider.current()?.name).toBe('stricter-policy');
    expect(provider.resolution()?.spec.name).toBe('stricter-policy');
    expect(changes).toEqual(['stricter-policy']);

    provider.stop();
    expect(provider.current()?.name).toBe('stricter-policy');
    expect(provider.resolution()?.spec.name).toBe('stricter-policy');
  });

  // The published signing vectors, served over HTTPS: a signed remote policy
  // is a policy plus a `<url>.sig` sidecar, and the sidecar has to be fetched
  // under the provider's own HTTP configuration. With the resolver's
  // configuration-free default locator the TLS trust anchor and the loopback
  // exemption are dropped and the sidecar can never be read, so
  // `requireSignature` refuses a policy that is in fact correctly signed.
  const signingFixtures = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../../fixtures/signing',
  );
  const signedFixture = (relative: string): string =>
    readFileSync(path.join(signingFixtures, relative), 'utf8');

  /** The clock the signing vectors are pinned to. */
  const VECTOR_NOW = '2026-09-15T12:00:00.000Z';

  function signedPolicyOptions(extra?: HttpLoaderConfig) {
    return {
      ...options(extra),
      resolveOptions: {
        requireSignature: true,
        keyring: loadKeyring(signedFixture('keys/keyring.json')),
        verify: { now: VECTOR_NOW },
      },
    };
  }

  it('verifies a signed policy against its .sig sidecar', async () => {
    const paths: string[] = [];
    const origin = await serve((req, res) => {
      const url = req.url ?? '';
      paths.push(url);
      res.end(signedFixture(url.endsWith('.sig') ? 'policies/basic.sig' : 'policies/basic.yaml'));
    });

    provider = new HttpProvider(`${origin}/policy.yaml`, signedPolicyOptions());
    const spec = await provider.load();

    expect(spec.name).toBe('signed-basic');
    expect(paths).toEqual(['/policy.yaml', '/policy.yaml.sig']);
    expect(provider.resolution()?.signature?.verified).toBe(true);
  });

  it('sends the auth header when fetching the .sig sidecar', async () => {
    const authorized: string[] = [];
    const origin = await serve((req, res) => {
      const url = req.url ?? '';
      if (req.headers.authorization !== 'Bearer test-token') {
        res.writeHead(401);
        res.end('Unauthorized');
        return;
      }
      authorized.push(url);
      res.end(signedFixture(url.endsWith('.sig') ? 'policies/basic.sig' : 'policies/basic.yaml'));
    });

    provider = new HttpProvider(
      `${origin}/policy.yaml`,
      signedPolicyOptions({ authHeader: 'Bearer test-token' }),
    );
    await provider.load();

    expect(authorized).toEqual(['/policy.yaml', '/policy.yaml.sig']);
    expect(provider.resolution()?.signature?.verified).toBe(true);
  });

  it('keeps a signature locator the caller supplied', async () => {
    const origin = await serve((_req, res) => res.end(signedFixture('policies/basic.yaml')));
    const sources: string[] = [];

    provider = new HttpProvider(`${origin}/policy.yaml`, {
      ...signedPolicyOptions(),
      resolveOptions: {
        ...signedPolicyOptions().resolveOptions,
        signatureLocator: (source: string) => {
          sources.push(source);
          return signedFixture('policies/basic.sig');
        },
      },
    });
    await provider.load();

    expect(sources).toEqual([`${origin}/policy.yaml`]);
  });
});
