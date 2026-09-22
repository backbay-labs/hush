/**
 * Loading an `extends` base over HTTPS (core spec 2.6.4).
 *
 * A policy may name its base by URL (`extends: "https://policies.example/base.yaml"`,
 * core spec 2.3). Fetching one is a request an attacker partly controls -- the
 * URL comes out of a document -- so this loader is the narrowest thing that can
 * still do the job:
 *
 * - **HTTPS only.** `http:` is refused outright. A base fetched in the clear is
 *   a base anyone on the path can rewrite, and the resolver would merge it.
 * - **No redirects.** A 3xx is an error, not a hop to follow: a redirect is the
 *   server asking to move the request somewhere the checks never saw.
 * - **The address is checked, then pinned.** The host is resolved first and
 *   every address it resolves to is checked against {@link isBlockedAddress};
 *   the connection then goes to the address that was checked, with the original
 *   hostname still used for SNI, certificate validation and the `Host` header.
 *   A name that re-resolves to `127.0.0.1` between the check and the connect --
 *   DNS rebinding -- reaches nothing.
 * - **Bounded.** A byte cap on the body, a connect timeout, and a read timeout.
 * - **Optionally allowlisted.** {@link HttpLoaderConfig.allowedHosts} narrows
 *   the reachable hosts to a fixed set, which is what a deployment that knows
 *   its policy server should do.
 *
 * Integrity is not this module's job and it does not pretend otherwise. A URL is
 * a location, never an identity: what makes a remote base trustworthy is the
 * `#sha256:` digest pin on the reference (core spec 2.3) or a detached
 * signature, both enforced by the resolver around this loader.
 * {@link fetchSignature} supplies the other half, fetching `<url>.sig` under the
 * same rules (signing spec 7.1).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import type { LookupAddress } from 'node:dns';
import type { IncomingMessage } from 'node:http';
import https from 'node:https';
import path from 'node:path';
import type { LoadedSpec } from './resolve.js';
import { parse } from './parse.js';

/** How long to wait for the TCP connection, in milliseconds. */
export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

/** How long to wait for response bytes once connected, in milliseconds. */
export const DEFAULT_READ_TIMEOUT_MS = 10_000;

/**
 * Largest response body accepted, in bytes. A policy is a small document; a
 * megabyte is already far beyond any real one, and the cap is what stops a
 * hostile server feeding the resolver until it runs out of memory.
 */
export const DEFAULT_MAX_SIZE = 1_048_576;

/**
 * The two well-known cloud instance-metadata endpoints, named so the intent is
 * readable even though the blocked networks already cover both
 * (`169.254.0.0/16` and `fc00::/7`). Reaching one from a URL an agent supplied
 * is the classic server-side request forgery credential theft.
 */
export const CLOUD_METADATA_ADDRESSES = ['169.254.169.254', 'fd00:ec2::254'] as const;

export interface HttpLoaderConfig {
  /** Milliseconds to wait for the TCP connection. */
  connectTimeoutMs?: number;
  /** Milliseconds to wait for response bytes once connected. */
  readTimeoutMs?: number;
  /** Sets both budgets at once, for callers that have only one number. */
  timeoutMs?: number;
  /** Largest response body accepted, in bytes. */
  maxSize?: number;
  /** Value of an `Authorization` header to send, when the server needs one. */
  authHeader?: string;
  /**
   * When set, the only hosts this loader will fetch from. A host outside it is
   * refused before DNS. Matching is exact and case-insensitive; it is a list of
   * host names, not a suffix rule, because `evil-example.com` ends in neither
   * `example.com` nor anything else a suffix test would be safe about.
   */
  allowedHosts?: string[];
  /** Where `ETag` revalidation state lives. Unset disables it. */
  cacheDir?: string;
  /**
   * **Test only.** Permit loopback addresses, which every other rule in this
   * module exists to forbid.
   *
   * A test server listens on `127.0.0.1`, so without this the fetch, ETag,
   * redirect and size-cap paths could not be exercised against a real server.
   * Setting it turns off the address check *for loopback only*: every other
   * blocked address is still refused, and the scheme is still `https:`. It is
   * never appropriate in a deployment.
   */
  allowInsecureLoopback?: boolean;
  /**
   * **Test only.** Extra certificate authorities to trust, for a test server
   * serving HTTPS from a certificate no public authority issued. Certificate
   * verification itself is never disabled: the certificate still has to be
   * valid for the hostname the policy named.
   */
  tlsCa?: string | string[];
}

interface Settings {
  connectTimeoutMs: number;
  readTimeoutMs: number;
  maxSize: number;
  authHeader?: string;
  allowedHosts?: string[];
  cacheDir?: string;
  allowInsecureLoopback: boolean;
  tlsCa?: string | string[];
}

function settingsFrom(config?: HttpLoaderConfig): Settings {
  return {
    connectTimeoutMs: config?.connectTimeoutMs ?? config?.timeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    readTimeoutMs: config?.readTimeoutMs ?? config?.timeoutMs ?? DEFAULT_READ_TIMEOUT_MS,
    maxSize: config?.maxSize ?? DEFAULT_MAX_SIZE,
    authHeader: config?.authHeader,
    allowedHosts: config?.allowedHosts,
    cacheDir: config?.cacheDir,
    allowInsecureLoopback: config?.allowInsecureLoopback ?? false,
    tlsCa: config?.tlsCa,
  };
}

// --------------------------------------------------------------------------
// Address classification
// --------------------------------------------------------------------------

/**
 * Every network a policy URL may not resolve to (core spec 2.6.4), as
 * `[network, prefix length]`. A host that resolves to any of these is refused
 * *after* DNS, because the danger is the address and not the name:
 * `internal.example.com` and a name that resolves to `10.0.0.5` are the same
 * request.
 */
const BLOCKED_IPV4_NETWORKS: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8], // "this network", and 0.0.0.0 itself
  ['10.0.0.0', 8], // RFC 1918
  ['100.64.0.0', 10], // RFC 6598 carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, including cloud metadata
  ['172.16.0.0', 12], // RFC 1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.168.0.0', 16], // RFC 1918
  ['198.18.0.0', 15], // benchmarking
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, including the 255.255.255.255 broadcast
];

const BLOCKED_IPV6_NETWORKS: ReadonlyArray<readonly [string, number]> = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['fc00::', 7], // unique local, including the IPv6 metadata endpoint
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];

/** The 32-bit value of a dotted-quad IPv4 address, or `null` when it is not one. */
function parseIpv4(text: string): number | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

/** The 128-bit value of an IPv6 address, or `null` when it is not one. */
function parseIpv6(text: string): bigint | null {
  if (!text.includes(':')) return null;

  let body = text;
  // A trailing dotted quad (`::ffff:127.0.0.1`) is the low 32 bits; rewriting
  // it as two hextets leaves one shape to parse.
  const lastColon = body.lastIndexOf(':');
  const trailer = body.slice(lastColon + 1);
  if (trailer.includes('.')) {
    const embedded = parseIpv4(trailer);
    if (embedded === null) return null;
    const high = ((embedded >>> 16) & 0xffff).toString(16);
    const low = (embedded & 0xffff).toString(16);
    body = `${body.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const doubleColon = body.indexOf('::');
  if (doubleColon !== -1 && body.indexOf('::', doubleColon + 1) !== -1) return null;

  const toGroups = (segment: string): bigint[] | null => {
    if (segment === '') return [];
    const groups: bigint[] = [];
    for (const group of segment.split(':')) {
      if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
      groups.push(BigInt(parseInt(group, 16)));
    }
    return groups;
  };

  let head: bigint[] | null;
  let rest: bigint[] | null;
  if (doubleColon === -1) {
    head = toGroups(body);
    rest = [];
    if (head === null || head.length !== 8) return null;
  } else {
    head = toGroups(body.slice(0, doubleColon));
    rest = toGroups(body.slice(doubleColon + 2));
    if (head === null || rest === null) return null;
    if (head.length + rest.length > 7) return null;
  }

  let value = 0n;
  for (const group of head) value = (value << 16n) | group;
  for (let index = head.length + rest.length; index < 8; index += 1) value <<= 16n;
  for (const group of rest) value = (value << 16n) | group;
  return value;
}

/**
 * The IPv4 address inside an IPv6 one, for both the IPv4-mapped
 * (`::ffff:a.b.c.d`) and the deprecated IPv4-compatible (`::a.b.c.d`) forms.
 * `null` when there is none, and for `::` and `::1`, which the IPv6 networks
 * already cover.
 */
function embeddedIpv4(value: bigint): number | null {
  const high = value >> 32n;
  const low = value & 0xffffffffn;
  if (high === 0xffffn) return Number(low); // IPv4-mapped
  if (high === 0n && low > 1n) return Number(low); // deprecated IPv4-compatible
  return null;
}

function inIpv4Network(address: number, network: string, prefix: number): boolean {
  const base = parseIpv4(network);
  if (base === null) return false;
  if (prefix === 0) return true;
  // `>>>` keeps the mask unsigned; a 32-bit shift is undefined in JavaScript,
  // so a /32 is compared whole.
  const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  return ((address & mask) >>> 0) === ((base & mask) >>> 0);
}

function inIpv6Network(address: bigint, network: string, prefix: number): boolean {
  const base = parseIpv6(network);
  if (base === null) return false;
  if (prefix === 0) return true;
  const mask = ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix);
  return (address & mask) === (base & mask);
}

/**
 * Whether `ip` is an address a policy URL may not reach (core spec 2.6.4).
 *
 * Blocks the unspecified address, loopback, the RFC 1918 private ranges,
 * link-local (which is where the cloud metadata endpoint lives), carrier-grade
 * NAT, the IETF protocol assignments, the benchmarking range, multicast, the
 * reserved range, and the IPv6 unique-local and link-local ranges.
 *
 * IPv6 forms that carry an IPv4 address in their low 32 bits are unwrapped
 * first and judged on the address inside. Both the IPv4-*mapped* form
 * (`::ffff:127.0.0.1`) and the deprecated IPv4-*compatible* form (`::7f00:1`,
 * which is `127.0.0.1`) would otherwise slip past a check that only looked at
 * IPv6 ranges.
 *
 * An address that cannot be parsed is blocked: a resolver that cannot tell what
 * it is about to connect to does not connect.
 */
export function isBlockedAddress(ip: string): boolean {
  const normalized = (ip.split('%')[0] ?? '').trim().toLowerCase();

  const ipv6 = parseIpv6(normalized);
  if (ipv6 !== null) {
    const embedded = embeddedIpv4(ipv6);
    if (embedded !== null) {
      return BLOCKED_IPV4_NETWORKS.some(([network, prefix]) =>
        inIpv4Network(embedded, network, prefix),
      );
    }
    return BLOCKED_IPV6_NETWORKS.some(([network, prefix]) =>
      inIpv6Network(ipv6, network, prefix),
    );
  }

  const ipv4 = parseIpv4(normalized);
  if (ipv4 !== null) {
    return BLOCKED_IPV4_NETWORKS.some(([network, prefix]) =>
      inIpv4Network(ipv4, network, prefix),
    );
  }

  return true;
}

function isLoopbackAddress(ip: string): boolean {
  const normalized = (ip.split('%')[0] ?? '').trim().toLowerCase();
  const ipv6 = parseIpv6(normalized);
  if (ipv6 !== null) {
    const embedded = embeddedIpv4(ipv6);
    if (embedded !== null) return inIpv4Network(embedded, '127.0.0.0', 8);
    return ipv6 === 1n;
  }
  const ipv4 = parseIpv4(normalized);
  return ipv4 !== null && inIpv4Network(ipv4, '127.0.0.0', 8);
}

// --------------------------------------------------------------------------
// URL validation
// --------------------------------------------------------------------------

/** A URL that passed every check, with the address the request will dial. */
export interface HttpTarget {
  /** The URL as the caller gave it. */
  url: string;
  /** The host as written, without IPv6 brackets. */
  host: string;
  port: number;
  /** Path and query, as the request line carries them. */
  requestPath: string;
  /** The address the socket goes to. */
  address: string;
  /** 4 or 6, as the socket needs it. */
  family: number;
}

/**
 * The checks that need no network: the scheme, the host, and the allowlist.
 * Split out so the synchronous cache-only loader applies exactly the same
 * refusals as the fetching one.
 */
function checkUrl(urlStr: string, settings: Settings): URL {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    throw new Error(`invalid URL '${urlStr}'`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`only HTTPS URLs are allowed, got '${url.protocol.replace(':', '')}'`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (host === '') {
    throw new Error(`URL '${urlStr}' has no host`);
  }
  if (settings.allowedHosts != null) {
    const allowed = settings.allowedHosts.some(
      (candidate) => candidate.toLowerCase() === host.toLowerCase(),
    );
    if (!allowed) {
      throw new Error(`host '${host}' is not in the allowlist of this loader`);
    }
  }
  return url;
}

/**
 * Check `urlStr` and resolve its host, or throw (core spec 2.6.4).
 *
 * The order matters: scheme, then host, then the allowlist, then DNS, then the
 * address check. Every address the name resolves to must be acceptable, not
 * merely the first -- a name with one public and one private address is a name
 * that reaches the private one. The address returned is the one the connection
 * is pinned to.
 */
export async function resolveTarget(urlStr: string, config?: HttpLoaderConfig): Promise<HttpTarget> {
  const settings = settingsFrom(config);
  const url = checkUrl(urlStr, settings);
  const host = url.hostname.replace(/^\[|\]$/g, '');

  let resolved: LookupAddress[];
  const literal = parseIpv6(host) !== null ? 6 : parseIpv4(host) !== null ? 4 : 0;
  if (literal !== 0) {
    // An IP literal is already an address; it never reaches the resolver.
    resolved = [{ address: host, family: literal }];
  } else {
    try {
      resolved = await dnsLookup(host, { all: true });
    } catch (err) {
      throw new Error(`failed to resolve host '${host}': ${err}`);
    }
  }
  if (resolved.length === 0) {
    throw new Error(`host '${host}' did not resolve to any addresses`);
  }

  // Outside the try: a refusal here is the answer, not a lookup failure to be
  // re-described as one.
  for (const entry of resolved) {
    if (!isBlockedAddress(entry.address)) continue;
    // The loopback exemption is deliberately the narrowest one that lets a test
    // server be reached: loopback and nothing else.
    if (settings.allowInsecureLoopback && isLoopbackAddress(entry.address)) continue;
    throw new Error(`SSRF protection: host '${host}' resolves to private IP ${entry.address}`);
  }

  const first = resolved[0]!;
  return {
    url: urlStr,
    host,
    port: url.port === '' ? 443 : Number(url.port),
    requestPath: `${url.pathname}${url.search}`,
    address: first.address,
    family: first.family,
  };
}

// --------------------------------------------------------------------------
// The transport
// --------------------------------------------------------------------------

/** What a response status means to this loader. */
type StatusOutcome = 'body' | 'not-modified' | 'missing' | 'redirect' | 'failed';

/**
 * Classify a response status (core spec 2.6.4).
 *
 * A 3xx is a refusal in its own right rather than a generic failure: a redirect
 * would reissue the request somewhere the scheme check, the allowlist and the
 * address check never saw, and even a same-host one moves the request to a
 * location the deployment never named.
 */
export function classifyStatus(status: number, missingIsNone: boolean): StatusOutcome {
  if (status === 304) return 'not-modified';
  if (status >= 300 && status < 400) return 'redirect';
  if (missingIsNone && (status === 404 || status === 410)) return 'missing';
  if (status >= 200 && status < 300) return 'body';
  return 'failed';
}

interface FetchResult {
  /** The body, empty on a revalidation or a miss. */
  body: string;
  /** The `ETag` the server returned, when it returned one. */
  etag: string | null;
  /** The server said the cached body is still current. */
  revalidated: boolean;
  /** There is nothing at this URL. */
  missing: boolean;
}

/**
 * Perform one GET of `target`.
 *
 * The request carries the original host, so the `Host` header, the SNI name and
 * the certificate check all use it; only the socket goes to the address
 * {@link resolveTarget} already approved. That is what closes DNS rebinding:
 * the name is resolved once, judged once, and connected to once. Node's HTTPS
 * client never follows a redirect, and a 3xx that comes back is refused here
 * rather than read as a document.
 */
function fetchTarget(
  target: HttpTarget,
  settings: Settings,
  etag: string | null,
  missingIsNone: boolean,
): Promise<FetchResult> {
  return new Promise<FetchResult>((resolve, reject) => {
    const headers: Record<string, string> = {
      Accept: 'application/yaml, text/yaml, */*',
    };
    if (settings.authHeader) headers['Authorization'] = settings.authHeader;
    if (etag) headers['If-None-Match'] = etag;

    const isLiteral = parseIpv4(target.host) !== null || parseIpv6(target.host) !== null;
    const request = https.request({
      hostname: target.host,
      port: target.port,
      path: target.requestPath,
      method: 'GET',
      headers,
      // SNI and certificate validation use the name the policy wrote, never
      // the pinned address; an IP literal has no name to send.
      ...(isLiteral ? {} : { servername: target.host }),
      ...(settings.tlsCa == null ? {} : { ca: settings.tlsCa }),
      agent: new https.Agent({ keepAlive: false, maxSockets: 1 }),
      lookup: (_hostname, options, callback) => {
        // Separate shapes: `net` asks for one address, `dns` for a list.
        if ((options as { all?: boolean }).all === true) {
          callback(null, [{ address: target.address, family: target.family }]);
        } else {
          callback(null, target.address, target.family);
        }
      },
    });

    // Separate budgets: getting connected is not the same wait as getting
    // bytes, and a server that accepts and then stalls must not inherit the
    // connect timeout's patience.
    let settled = false;
    let timer: NodeJS.Timeout = setTimeout(
      () => fail(`connect to '${target.url}' timed out after ${settings.connectTimeoutMs} ms`),
      settings.connectTimeoutMs,
    );

    function fail(message: string): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.destroy();
      reject(new Error(message));
    }

    function succeed(result: FetchResult): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    }

    request.on('socket', (socket) => {
      socket.on('secureConnect', () => {
        if (settled) return;
        clearTimeout(timer);
        timer = setTimeout(
          () => fail(`HTTP request to '${target.url}' timed out after ${settings.readTimeoutMs} ms`),
          settings.readTimeoutMs,
        );
      });
    });

    request.on('error', (err) => fail(`HTTP request to '${target.url}' failed: ${err}`));

    request.on('response', (response: IncomingMessage) => {
      const status = response.statusCode ?? 0;
      const outcome = classifyStatus(status, missingIsNone);

      if (outcome !== 'body') {
        response.resume();
        if (outcome === 'not-modified') {
          succeed({ body: '', etag, revalidated: true, missing: false });
        } else if (outcome === 'missing') {
          succeed({ body: '', etag: null, revalidated: false, missing: true });
        } else if (outcome === 'redirect') {
          const location = response.headers.location ?? '';
          fail(
            `HTTP request to '${target.url}' was redirected to '${location}'; ` +
              'redirects are not followed',
          );
        } else {
          fail(`HTTP request to '${target.url}' returned status ${status}`);
        }
        return;
      }

      const chunks: Buffer[] = [];
      let total = 0;
      response.on('data', (chunk: Buffer) => {
        total += chunk.byteLength;
        if (total > settings.maxSize) {
          response.destroy();
          fail(
            `response from '${target.url}' exceeds maximum size of ${settings.maxSize} bytes`,
          );
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', (err) => fail(`failed to read response from '${target.url}': ${err}`));
      response.on('end', () => {
        if (settled) return;
        let body: string;
        try {
          body = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
        } catch {
          fail(`response from '${target.url}' is not valid UTF-8`);
          return;
        }
        const responseEtag = response.headers.etag ?? null;
        succeed({ body, etag: responseEtag, revalidated: false, missing: false });
      });
    });

    request.end();
  });
}

// --------------------------------------------------------------------------
// Revalidation state
// --------------------------------------------------------------------------

function cacheKey(url: string): string {
  return createHash('sha256').update(url).digest('hex').slice(0, 32);
}

interface CacheMeta {
  etag: string;
  url: string;
}

function readCache(cacheDir: string, url: string): { etag: string; body: string } | null {
  const key = cacheKey(url);
  const metaPath = path.join(cacheDir, `${key}.meta.json`);
  const bodyPath = path.join(cacheDir, `${key}.yaml`);

  try {
    const meta = JSON.parse(readFileSync(metaPath, 'utf8')) as Partial<CacheMeta> | null;
    // A cache entry written by another version, or truncated: treat it as a
    // miss rather than revalidating against an etag that is not a string.
    if (meta == null || meta.url !== url || typeof meta.etag !== 'string') return null;
    const body = readFileSync(bodyPath, 'utf8');
    return { etag: meta.etag, body };
  } catch {
    return null;
  }
}

function writeCache(cacheDir: string, url: string, etag: string, body: string): void {
  try {
    if (!existsSync(cacheDir)) {
      mkdirSync(cacheDir, { recursive: true });
    }
    const key = cacheKey(url);
    const meta: CacheMeta = { etag, url };
    writeFileSync(path.join(cacheDir, `${key}.meta.json`), JSON.stringify(meta));
    writeFileSync(path.join(cacheDir, `${key}.yaml`), body);
  } catch {
    // Cache write failures are non-fatal
  }
}

// --------------------------------------------------------------------------
// Loaders
// --------------------------------------------------------------------------

/**
 * A loader that serves `https:` references and refuses everything else.
 *
 * The scheme, allowlist and address checks run before a socket is opened, the
 * connection is pinned to the address that was checked, redirects are refused,
 * the body is capped, and an `ETag` is revalidated with `If-None-Match` when
 * `cacheDir` is set. A 304 answered without a cached body to revalidate is a
 * failure, never an empty document.
 */
export function createHttpLoader(
  config?: HttpLoaderConfig,
): (reference: string, from?: string) => Promise<LoadedSpec> {
  const settings = settingsFrom(config);

  return async (reference: string, _from?: string): Promise<LoadedSpec> => {
    const target = await resolveTarget(reference, config);
    const cached = settings.cacheDir ? readCache(settings.cacheDir, reference) : null;
    const result = await fetchTarget(target, settings, cached?.etag ?? null, false);

    let body: string;
    if (result.revalidated) {
      if (cached == null) {
        throw new Error(
          `HTTP request to '${reference}' returned status 304 without a cached response to revalidate`,
        );
      }
      body = cached.body;
    } else {
      body = result.body;
      if (result.etag && settings.cacheDir) {
        writeCache(settings.cacheDir, reference, result.etag, body);
      }
    }

    const parsed = parse(body);
    if (!parsed.ok) {
      throw new Error(`failed to parse HushSpec at ${reference}: ${parsed.error}`);
    }
    return { source: reference, spec: parsed.value };
  };
}

/**
 * Sync variant: only works with a pre-cached response.
 * For production use, prefer the async createHttpLoader.
 */
export function createSyncHttpLoader(
  config?: HttpLoaderConfig,
): (reference: string, from?: string) => LoadedSpec {
  const settings = settingsFrom(config);

  return (reference: string, _from?: string): LoadedSpec => {
    checkUrl(reference, settings);

    if (settings.cacheDir) {
      const cached = readCache(settings.cacheDir, reference);
      if (cached) {
        const result = parse(cached.body);
        if (result.ok) {
          return { source: reference, spec: result.value };
        }
      }
    }

    throw new Error(
      `synchronous HTTP loading of '${reference}' is not supported without a cached response; ` +
        'use the async HTTP loader or pre-cache the policy',
    );
  };
}

/**
 * Fetch a detached signature envelope (signing spec 7.1) over HTTPS, under
 * exactly the rules the policy was fetched by: HTTPS only, the same allowlist,
 * the same address check and pinning, no redirects, the same caps. A `.sig` URL
 * must never be able to reach somewhere the policy URL could not.
 *
 * A missing sidecar is `null`, not an error: "this policy is unsigned" is a
 * fact the caller decides what to do with -- `requireSignature` turns it into
 * a refusal, opportunistic verification just records nothing. Every *other*
 * failure (a 500, a redirect, an oversized body) throws, because those say
 * nothing about whether a signature exists.
 */
/**
 * `source` split at its query or fragment, so a suffix is carried over rather
 * than having a sidecar name appended to it.
 */
function splitQuery(source: string): [string, string] {
  const cut = source.search(/[?#]/);
  return cut === -1 ? [source, ''] : [source.slice(0, cut), source.slice(cut)];
}

/**
 * The `<source>.sig` sidecar URL signing spec 7.1 prefers, with the `.sig` on
 * the path rather than on a query the URL may carry.
 */
export function preferredSidecarUrl(source: string): string {
  const [base, suffix] = splitQuery(source);
  return `${base}.sig${suffix}`;
}

/**
 * The `<stem>.sig` sidecar URL signing spec 7.1 also names, for a URL whose
 * last path segment carries an extension: `policy.yaml` beside `policy.sig`.
 * `null` when there is no extension to replace, since the candidate would
 * then be `<source>.sig` again.
 */
export function stemSidecarUrl(source: string): string | null {
  const [base, suffix] = splitQuery(source);
  const scheme = base.indexOf('://');
  if (scheme === -1) return null;
  const pathStart = base.indexOf('/', scheme + 3);
  if (pathStart === -1) return null;
  const segmentStart = base.lastIndexOf('/') + 1;
  const segment = base.slice(segmentStart);
  const dot = segment.lastIndexOf('.');
  if (dot <= 0) return null;
  return `${base.slice(0, segmentStart)}${segment.slice(0, dot)}.sig${suffix}`;
}

/**
 * Fetch the detached envelope beside a policy URL: `<source>.sig` first, then
 * the `<stem>.sig` sidecar of a 0.1 layout, the preference order signing spec
 * 7.1 makes normative. `null` when neither exists.
 */
export async function fetchSidecar(source: string, config?: HttpLoaderConfig): Promise<string | null> {
  const preferred = await fetchSignature(preferredSidecarUrl(source), config);
  if (preferred !== null) return preferred;
  const stem = stemSidecarUrl(source);
  return stem === null ? null : fetchSignature(stem, config);
}

export async function fetchSignature(
  url: string,
  config?: HttpLoaderConfig,
): Promise<string | null> {
  const settings = settingsFrom(config);
  const target = await resolveTarget(url, config);
  const result = await fetchTarget(target, settings, null, true);
  return result.missing ? null : result.body;
}

/**
 * A signature locator for URL sources: it looks for `<source>.sig` under
 * `config` and returns `null` when there is none, which the resolver reads as
 * `missing_signature`.
 *
 * A policy fetched over the network needs its sidecar fetched the same way and
 * under the same rules -- the TLS trust anchor, the loopback exemption and the
 * authorization header the policy was fetched with. The resolver's own default
 * locator carries no configuration, so a signed policy behind any of them
 * could not be verified without this.
 */
export function httpSignatureLocator(
  config?: HttpLoaderConfig,
): (source: string) => Promise<string | null> {
  return (source: string) => fetchSidecar(source, config);
}
