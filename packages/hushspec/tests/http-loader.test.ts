/**
 * HTTPS `extends` loading (`src/http-loader.ts`, core spec 2.6.4).
 *
 * Two halves, because they need different things to be true.
 *
 * The URL and address checks are pure: every rule the loader enforces before it
 * opens a socket is exercised directly, with no server involved. That is where
 * the server-side request forgery surface actually lives -- the loopback,
 * private, link-local, carrier-grade NAT, multicast, unspecified and
 * IPv4-in-IPv6 forms, the scheme check, the allowlist.
 *
 * The fetch, revalidation, redirect and size-cap paths run against a real
 * `node:https` server on the loopback address. The tests trust the server's certificate
 * through the loader's `tlsCa` option -- verification is never disabled, so the
 * certificate is still checked against `localhost`, the name the URL carries,
 * and not against the pinned address -- and pass the documented test-only
 * `allowInsecureLoopback` so the address check permits loopback. That the
 * option is *needed* -- that the loader refuses loopback without it -- is
 * itself asserted below.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import {
  CLOUD_METADATA_ADDRESSES,
  classifyStatus,
  createHttpLoader,
  createSyncHttpLoader,
  fetchSidecar,
  preferredSidecarUrl,
  fetchSignature,
  isBlockedAddress,
  MAX_PENDING_DNS_LOOKUPS,
  resolveTarget,
  stemSidecarUrl,
  type HttpLoaderConfig,
} from '../src/http-loader.js';
import { TEST_TLS_CERT } from './helpers/tls-cert.js';
import { startTestServer, type Handler, type TestServer } from './helpers/https-server.js';

// --------------------------------------------------------------------------
// Address classification
// --------------------------------------------------------------------------

describe('isBlockedAddress', () => {
  it('blocks every reserved IPv4 family', () => {
    for (const address of [
      '0.0.0.0',
      '0.1.2.3',
      '10.0.0.1',
      '100.64.0.1',
      '100.127.255.255',
      '127.0.0.1',
      '127.1.2.3',
      '169.254.1.1',
      '169.254.169.254',
      '172.16.0.1',
      '172.31.255.255',
      '192.0.0.1',
      '192.168.1.1',
      '198.18.0.1',
      '198.19.255.255',
      '224.0.0.1',
      '239.255.255.250',
      '240.0.0.1',
      '255.255.255.255',
    ]) {
      expect(isBlockedAddress(address), `${address} must not be reachable`).toBe(true);
    }
  });

  it('blocks every reserved IPv6 family', () => {
    for (const address of ['::', '::1', 'fc00::1', 'fd00::1', 'fd00:ec2::254', 'fe80::1', 'ff02::1']) {
      expect(isBlockedAddress(address), `${address} must not be reachable`).toBe(true);
    }
  });

  it('unwraps the IPv4-mapped form and judges the address inside', () => {
    for (const address of [
      '::ffff:127.0.0.1',
      '::ffff:10.0.0.1',
      '::ffff:169.254.169.254',
      '::ffff:7f00:1',
      '::ffff:a9fe:a9fe',
    ]) {
      expect(isBlockedAddress(address), `${address} must not be reachable`).toBe(true);
    }
  });

  it('unwraps the deprecated IPv4-compatible form and judges the address inside', () => {
    for (const address of ['::7f00:1', '::a9fe:a9fe', '::a00:1', '::127.0.0.1', '::10.0.0.1']) {
      expect(isBlockedAddress(address), `${address} must not be reachable`).toBe(true);
    }
  });

  it('blocks the cloud metadata endpoints', () => {
    for (const address of CLOUD_METADATA_ADDRESSES) {
      expect(isBlockedAddress(address), `${address} is reachable`).toBe(true);
    }
  });

  it('blocks an address it cannot parse', () => {
    for (const address of ['', 'not-an-address', '1.2.3', '1.2.3.4.5', '999.1.1.1', 'g::1']) {
      expect(isBlockedAddress(address), `${address} must not be reachable`).toBe(true);
    }
  });

  it('ignores a zone id, which never makes an address reachable', () => {
    expect(isBlockedAddress('fe80::1%eth0')).toBe(true);
  });

  it('leaves genuine public addresses reachable', () => {
    for (const address of [
      '8.8.8.8',
      '1.1.1.1',
      '93.184.216.34',
      '11.0.0.1',
      '172.32.0.1',
      '198.20.0.1',
      '223.255.255.255',
      '2606:4700:4700::1111',
      // An IPv4-compatible form wrapping a public address stays public.
      '::808:808',
    ]) {
      expect(isBlockedAddress(address), `${address} must be reachable`).toBe(false);
    }
  });
});

// --------------------------------------------------------------------------
// URL validation
// --------------------------------------------------------------------------

describe('resolveTarget', () => {
  it('accepts only https', async () => {
    for (const url of [
      'http://example.com/policy.yaml',
      'ftp://example.com/policy.yaml',
      'file:///etc/passwd',
    ]) {
      await expect(resolveTarget(url)).rejects.toThrow('only HTTPS URLs are allowed');
    }
  });

  it('refuses a blocked address without a lookup', async () => {
    for (const url of [
      'https://127.0.0.1/policy.yaml',
      'https://10.0.0.1/policy.yaml',
      'https://169.254.169.254/latest/meta-data/',
      'https://100.64.0.1/policy.yaml',
      'https://[::1]/policy.yaml',
      'https://[fc00::1]/policy.yaml',
      'https://[fe80::1]/policy.yaml',
      'https://[::ffff:127.0.0.1]/policy.yaml',
    ]) {
      await expect(resolveTarget(url)).rejects.toThrow('SSRF protection');
    }
  });

  it('checks the allowlist before DNS', async () => {
    const config: HttpLoaderConfig = { allowedHosts: ['Policies.Example.COM'] };
    // `.invalid` never resolves, so a lookup would fail with a different
    // message; the allowlist refusal is what must come back.
    await expect(resolveTarget('https://elsewhere.invalid/p.yaml', config)).rejects.toThrow(
      'is not in the allowlist',
    );
  });

  it('matches the allowlist case-insensitively and exactly', async () => {
    const config: HttpLoaderConfig = { allowedHosts: ['8.8.8.8'] };
    const target = await resolveTarget('https://8.8.8.8:8443/policy.yaml', config);
    expect(target.host).toBe('8.8.8.8');
    // A suffix of an allowed host is a different host.
    await expect(
      resolveTarget('https://evil-8.8.8.8.invalid/p.yaml', config),
    ).rejects.toThrow('is not in the allowlist');
  });

  it('carries the checked address forward as the one to dial', async () => {
    const target = await resolveTarget('https://8.8.8.8:8443/policy.yaml');
    expect(target.address).toBe('8.8.8.8');
    expect(target.port).toBe(8443);
    // The host is kept for SNI, certificate validation and the Host header.
    expect(target.host).toBe('8.8.8.8');
  });
});

describe('createSyncHttpLoader', () => {
  it('applies the same scheme and allowlist refusals', () => {
    const loader = createSyncHttpLoader({ allowedHosts: ['policies.example.com'] });
    expect(() => loader('http://policies.example.com/p.yaml')).toThrow(
      'only HTTPS URLs are allowed',
    );
    expect(() => loader('https://elsewhere.example.com/p.yaml')).toThrow(
      'is not in the allowlist',
    );
  });
});

// --------------------------------------------------------------------------
// Status classification
// --------------------------------------------------------------------------

describe('classifyStatus', () => {
  it('refuses every redirect rather than following it', () => {
    for (const status of [301, 302, 303, 307, 308]) {
      expect(classifyStatus(status, false)).toBe('redirect');
    }
  });

  it('covers the remaining cases', () => {
    expect(classifyStatus(200, false)).toBe('body');
    expect(classifyStatus(304, false)).toBe('not-modified');
    expect(classifyStatus(500, false)).toBe('failed');
    // Only a signature lookup reads 404 and 410 as "there is none".
    expect(classifyStatus(404, false)).toBe('failed');
    expect(classifyStatus(404, true)).toBe('missing');
    expect(classifyStatus(410, true)).toBe('missing');
  });
});

// --------------------------------------------------------------------------
// The transport, against a real HTTPS server
// --------------------------------------------------------------------------

const POLICY = 'hushspec: "0.2.0"\nname: remote-base\n';

const servers: TestServer[] = [];
const tempDirs: string[] = [];

afterEach(async () => {
  while (servers.length > 0) await servers.pop()!.close();
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

// The server is addressed as `localhost` on purpose: the certificate is
// checked against that name while the socket goes to the pinned address.
async function serve(handler: Handler): Promise<TestServer> {
  const server = await startTestServer(handler);
  servers.push(server);
  return server;
}

function tempCacheDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hushspec-http-'));
  tempDirs.push(dir);
  return dir;
}

function testConfig(extra?: HttpLoaderConfig): HttpLoaderConfig {
  return { allowInsecureLoopback: true, tlsCa: TEST_TLS_CERT, ...extra };
}

/** A real IPv4 listener that deliberately never completes TLS. */
async function startStalledTcpServer(): Promise<{ origin: string; close: () => Promise<void> }> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `https://localhost:${port}`,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

describe('http loader transport', () => {
  it('bounds a hung DNS lookup by the default connect budget', async () => {
    vi.useFakeTimers();
    try {
      let release!: (addresses: { address: string; family: number }[]) => void;
      const pending = resolveTarget('https://policy.example.test/policy.yaml', {
        allowedHosts: ['policy.example.test'],
        lookup: () => new Promise((resolve) => { release = resolve; }),
      });
      const rejected = expect(pending).rejects.toThrow(
        "connect to 'https://policy.example.test/policy.yaml' timed out after 10000 ms",
      );
      await vi.advanceTimersByTimeAsync(10_000);
      await rejected;
      release([{ address: '8.8.8.8', family: 4 }]);
      await vi.runAllTimersAsync();
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses an explicit connect budget for a hung DNS lookup without timeoutMs', async () => {
    vi.useFakeTimers();
    try {
      let release!: (addresses: { address: string; family: number }[]) => void;
      const pending = resolveTarget('https://policy.example.test/policy.yaml', {
        allowedHosts: ['policy.example.test'],
        connectTimeoutMs: 25,
        lookup: () => new Promise((resolve) => { release = resolve; }),
      });
      const rejected = expect(pending).rejects.toThrow('timed out after 25 ms');
      await vi.advanceTimersByTimeAsync(25);
      await rejected;
      release([{ address: '8.8.8.8', family: 4 }]);
      await vi.runAllTimersAsync();
    } finally {
      vi.useRealTimers();
    }
  });

  // Break caught: beginning the timeout only after DNS lets a resolver stall
  // forever even when the caller supplied timeoutMs for the request.
  it('bounds a DNS lookup by the request deadline', async () => {
    let release!: (addresses: { address: string; family: number }[]) => void;
    const loader = createHttpLoader({
      timeoutMs: 50,
      allowedHosts: ['policy.example.test'],
      lookup: () => new Promise((resolve) => { release = resolve; }),
    });
    const startedAt = Date.now();

    await expect(loader('https://policy.example.test/policy.yaml')).rejects.toThrow(
      'timed out after 50 ms',
    );
    expect(Date.now() - startedAt).toBeLessThan(500);
    release([{ address: '8.8.8.8', family: 4 }]);
    await new Promise((resolve) => setImmediate(resolve));
  });

  it('spends DNS time from the same connect budget used by the pinned socket', async () => {
    const server = await startStalledTcpServer();
    vi.useFakeTimers();
    try {
      let release!: (addresses: { address: string; family: number }[]) => void;
      const loader = createHttpLoader(testConfig({
        connectTimeoutMs: 50,
        lookup: () => new Promise((resolve) => { release = resolve; }),
      }));
      const pending = loader(`${server.origin}/policy.yaml`);

      await vi.advanceTimersByTimeAsync(30);
      release([{ address: '127.0.0.1', family: 4 }]);
      await Promise.resolve();

      const rejected = expect(pending).rejects.toThrow('timed out after 50 ms');
      await vi.advanceTimersByTimeAsync(20);
      await rejected;
    } finally {
      vi.useRealTimers();
      await server.close();
    }
  });

  it('does not open a socket when a DNS answer arrives after the connect deadline', async () => {
    const server = await serve((_req, res) => res.end(POLICY));
    vi.useFakeTimers();
    try {
      let release!: (addresses: { address: string; family: number }[]) => void;
      const loader = createHttpLoader(testConfig({
        connectTimeoutMs: 25,
        lookup: () => new Promise((resolve) => { release = resolve; }),
      }));
      const pending = loader(`${server.origin}/policy.yaml`);
      const rejected = expect(pending).rejects.toThrow('timed out after 25 ms');
      await vi.advanceTimersByTimeAsync(25);
      await rejected;

      release([{ address: '127.0.0.1', family: 4 }]);
      await vi.advanceTimersByTimeAsync(0);
      await Promise.resolve();
      expect(server.requests).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not open a socket when time expires between DNS approval and fetch admission', async () => {
    const server = await serve((_req, res) => res.end(POLICY));
    // The first three reads cover creation and DNS validation. The fourth is
    // fetchTarget's admission check, modelling synchronous cache work taking
    // the final millisecond of the connect budget.
    let clockReads = 0;
    const now = vi.spyOn(Date, 'now').mockImplementation(() => (++clockReads >= 4 ? 25 : 0));
    const request = vi.spyOn(https, 'request');
    try {
      const loader = createHttpLoader(testConfig({
        cacheDir: tempCacheDir(),
        connectTimeoutMs: 25,
        lookup: async () => [{ address: '127.0.0.1', family: 4 }],
      }));
      await expect(loader(`${server.origin}/policy.yaml`)).rejects.toThrow('timed out after 25 ms');
      expect(request).not.toHaveBeenCalled();
      expect(server.requests).toHaveLength(0);
    } finally {
      request.mockRestore();
      now.mockRestore();
    }
  });

  it('fails closed when unresolved DNS work is saturated, then releases a completed lookup', async () => {
    const releases: Array<(addresses: { address: string; family: number }[]) => void> = [];
    const pending = Array.from({ length: MAX_PENDING_DNS_LOOKUPS }, (_, index) =>
      resolveTarget(`https://pending-${index}.example.test/policy.yaml`, {
        connectTimeoutMs: 60_000,
        lookup: () => new Promise((resolve) => { releases.push(resolve); }),
      }),
    );

    await expect(
      resolveTarget('https://saturated.example.test/policy.yaml', {
        connectTimeoutMs: 60_000,
        lookup: async () => [{ address: '8.8.8.8', family: 4 }],
      }),
    ).rejects.toThrow(`DNS resolver saturated: ${MAX_PENDING_DNS_LOOKUPS}`);

    // Numeric targets bypass DNS and therefore do not consume the bounded resolver queue.
    await expect(resolveTarget('https://8.8.8.8/policy.yaml')).resolves.toMatchObject({
      address: '8.8.8.8',
    });

    releases[0]!([{ address: '8.8.8.8', family: 4 }]);
    await expect(pending[0]).resolves.toMatchObject({ address: '8.8.8.8' });

    let recover!: (addresses: { address: string; family: number }[]) => void;
    const recovered = resolveTarget('https://recovered.example.test/policy.yaml', {
      connectTimeoutMs: 60_000,
      lookup: () => new Promise((resolve) => { recover = resolve; }),
    });
    recover([{ address: '8.8.4.4', family: 4 }]);
    await expect(recovered).resolves.toMatchObject({ address: '8.8.4.4' });

    for (const release of releases.slice(1)) release([{ address: '8.8.8.8', family: 4 }]);
    await expect(Promise.all(pending.slice(1))).resolves.toHaveLength(MAX_PENDING_DNS_LOOKUPS - 1);
  });

  it('refuses loopback unless the test-only exemption is set', async () => {
    const server = await serve((_req, res) => res.end(POLICY));
    const loader = createHttpLoader({ tlsCa: TEST_TLS_CERT });
    await expect(loader(`${server.origin}/policy.yaml`)).rejects.toThrow('SSRF protection');
  });

  it('fetches a policy, keeping the hostname for the Host header', async () => {
    const server = await serve((_req, res) => {
      res.setHeader('content-type', 'application/yaml');
      res.end(POLICY);
    });
    const loader = createHttpLoader(testConfig());
    const loaded = await loader(`${server.origin}/policy.yaml`);
    expect(loaded.spec.name).toBe('remote-base');
    expect(loaded.source).toBe(`${server.origin}/policy.yaml`);
    // The socket went to the pinned loopback address, but the request still names the
    // host the URL did -- which is also the name the certificate was checked
    // against, since `tlsCa` trusts the certificate without disabling
    // verification.
    expect(server.requests[0]?.headers.host).toBe(new URL(server.origin).host);
  });

  it('refuses a redirect rather than following it', async () => {
    const server = await serve((_req, res) => {
      res.writeHead(302, { location: 'https://elsewhere.example.com/policy.yaml' });
      res.end();
    });
    const loader = createHttpLoader(testConfig());
    await expect(loader(`${server.origin}/policy.yaml`)).rejects.toThrow(
      'redirects are not followed',
    );
    expect(server.requests).toHaveLength(1);
  });

  it('refuses a body over the cap', async () => {
    const server = await serve((_req, res) => res.end('#'.repeat(4096)));
    const loader = createHttpLoader(testConfig({ maxSize: 1024 }));
    await expect(loader(`${server.origin}/policy.yaml`)).rejects.toThrow(
      'exceeds maximum size of 1024 bytes',
    );
  });

  it('accepts a body of exactly the cap', async () => {
    const server = await serve((_req, res) => res.end(POLICY));
    const loader = createHttpLoader(testConfig({ maxSize: Buffer.byteLength(POLICY) }));
    const loaded = await loader(`${server.origin}/policy.yaml`);
    expect(loaded.spec.name).toBe('remote-base');
  });

  it('turns a non-2xx into an error', async () => {
    const server = await serve((_req, res) => {
      res.writeHead(500);
      res.end('boom');
    });
    const loader = createHttpLoader(testConfig());
    await expect(loader(`${server.origin}/policy.yaml`)).rejects.toThrow('returned status 500');
  });

  it('revalidates with If-None-Match and serves the cached body on 304', async () => {
    const etag = '"v1"';
    const server = await serve((req, res) => {
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.setHeader('etag', etag);
      res.end(POLICY);
    });
    const loader = createHttpLoader(testConfig({ cacheDir: tempCacheDir() }));
    const url = `${server.origin}/policy.yaml`;

    const first = await loader(url);
    expect(first.spec.name).toBe('remote-base');

    const second = await loader(url);
    expect(second.spec.name).toBe('remote-base');

    // The server is always asked: a cached body is only ever returned on a 304.
    expect(server.requests).toHaveLength(2);
    expect(server.requests[1]?.headers['if-none-match']).toBe(etag);
  });

  it('refuses a 304 with no cached body to revalidate', async () => {
    const server = await serve((_req, res) => {
      res.writeHead(304);
      res.end();
    });
    const loader = createHttpLoader(testConfig());
    await expect(loader(`${server.origin}/policy.yaml`)).rejects.toThrow(
      'without a cached response to revalidate',
    );
  });

  it('sends an Authorization header when the server needs one', async () => {
    const server = await serve((_req, res) => res.end(POLICY));
    const loader = createHttpLoader(testConfig({ authHeader: 'Bearer token' }));
    await loader(`${server.origin}/policy.yaml`);
    expect(server.requests[0]?.headers.authorization).toBe('Bearer token');
  });

  it('gives up on a server that accepts and then stalls', async () => {
    const server = await serve(() => {
      // Never answer: the read budget is what ends this request.
    });
    const loader = createHttpLoader(testConfig({ readTimeoutMs: 150 }));
    await expect(loader(`${server.origin}/policy.yaml`)).rejects.toThrow('timed out');
  });
});

describe('fetchSignature', () => {
  it('fetches the sidecar beside a policy URL', async () => {
    const envelope = '{"format_version": "0.2"}';
    const server = await serve((_req, res) => res.end(envelope));
    const found = await fetchSignature(`${server.origin}/policy.yaml.sig`, testConfig());
    expect(found).toBe(envelope);
  });

  it('falls back to the stem sidecar of a 0.1 layout', async () => {
    const envelope = '{"format_version": "0.2"}';
    const server = await serve((req, res) => {
      if (req.url === '/policy.sig') {
        res.end(envelope);
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    expect(await fetchSidecar(`${server.origin}/policy.yaml`, testConfig())).toBe(envelope);
    expect(await fetchSidecar(`${server.origin}/absent.yaml`, testConfig())).toBeNull();
  });

  it('keeps a query after the preferred sidecar suffix', () => {
    expect(preferredSidecarUrl('https://policies.example/policy.yaml?v=2')).toBe(
      'https://policies.example/policy.yaml.sig?v=2',
    );
    expect(preferredSidecarUrl('https://policies.example/policy.yaml')).toBe(
      'https://policies.example/policy.yaml.sig',
    );
  });

  it('derives the stem sidecar from the last path segment only', () => {
    expect(stemSidecarUrl('https://policies.example/team/policy.yaml')).toBe(
      'https://policies.example/team/policy.sig',
    );
    expect(stemSidecarUrl('https://policies.example/policy.yaml?v=2')).toBe(
      'https://policies.example/policy.sig?v=2',
    );
    expect(stemSidecarUrl('https://policies.example/policy')).toBeNull();
    expect(stemSidecarUrl('https://policies.example')).toBeNull();
  });

  it('reads a missing sidecar as unsigned, not as a failure', async () => {
    for (const status of [404, 410]) {
      const server = await serve((_req, res) => {
        res.writeHead(status);
        res.end();
      });
      expect(await fetchSignature(`${server.origin}/policy.yaml.sig`, testConfig())).toBeNull();
    }
  });

  it('turns every other failure into an error', async () => {
    const server = await serve((_req, res) => {
      res.writeHead(500);
      res.end();
    });
    await expect(
      fetchSignature(`${server.origin}/policy.yaml.sig`, testConfig()),
    ).rejects.toThrow('returned status 500');
  });

  it('cannot reach somewhere the policy URL could not', async () => {
    await expect(fetchSignature('https://169.254.169.254/policy.yaml.sig')).rejects.toThrow(
      'SSRF protection',
    );
    await expect(fetchSignature('http://example.com/policy.yaml.sig')).rejects.toThrow(
      'only HTTPS URLs are allowed',
    );
  });
});
