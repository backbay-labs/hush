import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import path from 'node:path';
import type { HushSpec } from './schema.js';
import type { LoadedSpec } from './resolve.js';
import { parse } from './parse.js';

export interface HttpLoaderConfig {
  timeoutMs?: number;
  maxSize?: number;
  authHeader?: string;
  cacheDir?: string;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_SIZE = 1_048_576; // 1 MB

/**
 * Extract the embedded IPv4 address from an IPv4-mapped (`::ffff:x`) or
 * IPv4-translated (`::ffff:0:x`) IPv6 address, in either dotted (`::ffff:127.0.0.1`)
 * or hextet (`::ffff:7f00:1`) form, returning it as a dotted string.
 */
function mappedIpv4Address(normalized: string): string | undefined {
  let rest: string;
  if (normalized.startsWith('::ffff:')) {
    rest = normalized.slice('::ffff:'.length);
  } else {
    return undefined;
  }
  // IPv4-translated form ::ffff:0:a.b.c.d
  if (rest.startsWith('0:')) {
    rest = rest.slice(2);
  }

  if (rest.includes('.')) {
    // Already dotted-quad IPv4.
    return rest;
  }

  // Trailing 32 bits encoded as one or two hextets, e.g. "7f00:1" or "a9fe:a9fe".
  const groups = rest.split(':');
  if (groups.length === 0 || groups.length > 2) {
    return undefined;
  }
  let value = 0;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) {
      return undefined;
    }
    value = value * 0x10000 + parseInt(group, 16);
  }
  const a = (value >>> 24) & 0xff;
  const b = (value >>> 16) & 0xff;
  const c = (value >>> 8) & 0xff;
  const d = value & 0xff;
  return `${a}.${b}.${c}.${d}`;
}

function isPrivateIp(ip: string): boolean {
  const normalized = ip.toLowerCase().split('%')[0];
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') {
    return true;
  }

  const mappedIpv4 = mappedIpv4Address(normalized);
  if (mappedIpv4 != null && isPrivateIp(mappedIpv4)) {
    return true;
  }

  if (normalized.includes(':')) {
    if (normalized === '::') {
      return true;
    }

    const firstSegment = normalized.split(':', 1)[0];
    const firstHextet = parseInt(firstSegment || '0', 16);
    if (!Number.isNaN(firstHextet)) {
      if ((firstHextet & 0xfe00) === 0xfc00) {
        return true;
      }
      if ((firstHextet & 0xffc0) === 0xfe80) {
        return true;
      }
    }

    return false;
  }

  const parts = normalized.split('.').map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p))) {
    const [a, b] = parts;
    // 127.0.0.0/8
    if (a === 127) return true;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 0.0.0.0
    if (a === 0 && b === 0 && parts[2] === 0 && parts[3] === 0) return true;
    // 169.254.0.0/16 link-local
    if (a === 169 && b === 254) return true;
  }

  return false;
}

function validateUrl(urlStr: string): URL {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    throw new Error(`invalid URL '${urlStr}'`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`only HTTPS URLs are allowed, got '${url.protocol.replace(':', '')}'`);
  }
  return url;
}

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
    const metaContent = readFileSync(metaPath, 'utf8');
    const meta: CacheMeta = JSON.parse(metaContent);
    if (meta.url !== url) return null;
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

async function readResponseText(
  response: Response,
  reference: string,
  maxSize: number,
): Promise<string> {
  if (response.body == null) {
    const body = await response.text();
    if (Buffer.byteLength(body) > maxSize) {
      throw new Error(`response from '${reference}' exceeds maximum size of ${maxSize} bytes`);
    }
    return body;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let body = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maxSize) {
      throw new Error(`response from '${reference}' exceeds maximum size of ${maxSize} bytes`);
    }
    body += decoder.decode(value, { stream: true });
  }

  body += decoder.decode();
  return body;
}

export function createHttpLoader(
  config?: HttpLoaderConfig,
): (reference: string, from?: string) => Promise<LoadedSpec> {
  const timeoutMs = config?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxSize = config?.maxSize ?? DEFAULT_MAX_SIZE;
  const authHeader = config?.authHeader;
  const cacheDir = config?.cacheDir;

  return async (reference: string, _from?: string): Promise<LoadedSpec> => {
    const url = validateUrl(reference);

    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    try {
      const resolved = await lookup(hostname, { all: true });
      for (const addr of resolved) {
        if (isPrivateIp(addr.address)) {
          throw new Error(
            `SSRF protection: host '${hostname}' resolves to private IP ${addr.address}`,
          );
        }
      }
    } catch (err) {
      if (err instanceof Error && err.message.includes('SSRF protection')) {
        throw err;
      }
      throw new Error(`failed to resolve host '${hostname}': ${err}`);
    }

    const cached = cacheDir ? readCache(cacheDir, reference) : null;

    const headers: Record<string, string> = {};
    if (authHeader) {
      headers['Authorization'] = authHeader;
    }
    if (cached) {
      headers['If-None-Match'] = cached.etag;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(reference, {
        headers,
        signal: controller.signal,
        redirect: 'error',
      });
    } catch (err) {
      throw new Error(`HTTP request to '${reference}' failed: ${err}`);
    } finally {
      clearTimeout(timeoutId);
    }

    if (response.status === 304 && cached) {
      const result = parse(cached.body);
      if (!result.ok) {
        throw new Error(`failed to parse cached HushSpec at ${reference}: ${result.error}`);
      }
      return { source: reference, spec: result.value };
    }

    if (!response.ok) {
      throw new Error(`HTTP request to '${reference}' returned status ${response.status}`);
    }

    const body = await readResponseText(response, reference, maxSize);

    const result = parse(body);
    if (!result.ok) {
      throw new Error(`failed to parse HushSpec at ${reference}: ${result.error}`);
    }

    const etag = response.headers?.get?.('etag') ?? null;
    if (etag && cacheDir) {
      writeCache(cacheDir, reference, etag, body);
    }

    return { source: reference, spec: result.value };
  };
}

/**
 * Sync variant: only works with a pre-cached response.
 * For production use, prefer the async createHttpLoader.
 */
export function createSyncHttpLoader(
  config?: HttpLoaderConfig,
): (reference: string, from?: string) => LoadedSpec {
  const cacheDir = config?.cacheDir;

  return (reference: string, _from?: string): LoadedSpec => {
    validateUrl(reference);

    if (cacheDir) {
      const cached = readCache(cacheDir, reference);
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
