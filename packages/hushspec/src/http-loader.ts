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

function isPrivateIp(ip: string): boolean {
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') {
    return true;
  }

  const parts = ip.split('.').map(Number);
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
