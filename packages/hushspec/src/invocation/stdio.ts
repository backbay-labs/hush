import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { TextDecoder } from 'node:util';
import { canonicalizeValue, type JsonValue } from '../canonical.js';
import { copyJson, jsonObject, snapshotJson } from './json.js';
import { closedObject } from './model.js';
import type { InvocationArguments } from './registry.js';

export const INVOCATION_MCP_VERSION = '2026-07-28';
interface Pending {
  resolve(value: Record<string, JsonValue>): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout>;
}
export interface OwnedMcpOptions { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number }

/** Operator-approved owned subprocess, not a sandbox for arbitrary server executables. */
export class OwnedMcpConnection {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #timeout: number;
  readonly #pending = new Map<number, Pending>();
  readonly #exited: Promise<void>;
  #next = 0;
  #buffer = Buffer.alloc(0);
  #outputBytes = 0;
  #stderrBytes = 0;
  #closed = false;
  #failure: Error | undefined;
  #exit = false;

  constructor(command: string, args: readonly string[], options: OwnedMcpOptions = {}) {
    this.#timeout = options.timeoutMs ?? 5000;
    if (!Number.isSafeInteger(this.#timeout) || this.#timeout < 1 || this.#timeout > 60_000) throw new Error('invalid MCP deadline');
    this.#child = spawn(command, [...args], { cwd: options.cwd, env: options.env,
      stdio: ['pipe', 'pipe', 'pipe'], shell: false, detached: process.platform !== 'win32' });
    this.#exited = new Promise(resolve => {
      this.#child.once('close', () => { this.#exit = true; this.#fail(new Error('MCP child exited')); resolve(); });
      this.#child.once('error', error => { this.#fail(error); resolve(); });
    });
    this.#child.stdin.on('error', error => this.#fail(error));
    this.#child.stdout.on('data', chunk => this.#read(Buffer.from(chunk)));
    this.#child.stdout.on('error', error => this.#fail(error));
    this.#child.stderr.on('data', chunk => {
      this.#stderrBytes += chunk.length;
      if (this.#stderrBytes > 16_384) this.#fail(new Error('MCP stderr limit exceeded'));
    });
  }

  async discover(): Promise<Record<string, JsonValue>> {
    const result = await this.#request('server/discover', {});
    if (result.resultType !== 'complete' || !Array.isArray(result.supportedVersions) ||
        !result.supportedVersions.includes(INVOCATION_MCP_VERSION) ||
        !result.capabilities || typeof result.capabilities !== 'object' || Array.isArray(result.capabilities)) {
      this.#fail(new Error('owned MCP protocol not supported')); throw this.#failure;
    }
    return result;
  }
  async listTools(): Promise<Record<string, JsonValue>> {
    const result = await this.#request('tools/list', {});
    if (result.resultType !== 'complete' || !Array.isArray(result.tools) || result.tools.length > 256) {
      this.#fail(new Error('malformed MCP tools list')); throw this.#failure;
    }
    return result;
  }
  async callTool(name: string, args: InvocationArguments, context: Readonly<{ callId: string }>): Promise<Record<string, JsonValue>> {
    if (typeof name !== 'string' || !name || Buffer.byteLength(name) > 128 ||
        typeof context.callId !== 'string' || !context.callId || Buffer.byteLength(context.callId) > 128) throw new Error('invalid MCP call identity');
    const captured = copyJson(args); jsonObject(captured);
    const result = await this.#request('tools/call', { name, arguments: captured }, context.callId);
    if (result.resultType !== 'complete' || !Array.isArray(result.content) ||
        (result.isError !== undefined && typeof result.isError !== 'boolean') ||
        (result.structuredContent !== undefined && (result.structuredContent === null ||
          typeof result.structuredContent !== 'object' || Array.isArray(result.structuredContent)))) {
      this.#fail(new Error('malformed MCP tool result')); throw this.#failure;
    }
    if (result.isError === true) throw new Error('MCP tool reported error; partial effect possible');
    return result;
  }

  #request(method: string, params: Record<string, JsonValue>, callId?: string): Promise<Record<string, JsonValue>> {
    if (this.#failure || this.#closed) return Promise.reject(new Error('MCP connection unavailable or closed'));
    if (this.#pending.size >= 16) return Promise.reject(new Error('MCP pending request limit'));
    if (this.#next >= 2000) return Promise.reject(new Error('MCP request lifetime limit'));
    const id = ++this.#next;
    const request = { jsonrpc: '2.0', id, method, params: { ...params, _meta: {
      'io.modelcontextprotocol/protocolVersion': INVOCATION_MCP_VERSION,
      'io.modelcontextprotocol/clientCapabilities': {},
      ...(callId === undefined ? {} : { 'dev.hushspec/callId': callId }),
    } } };
    const line = canonicalizeValue(request as JsonValue) + '\n';
    if (Buffer.byteLength(line) > 131_072) return Promise.reject(new Error('MCP request byte limit'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(new Error('MCP request deadline; execution outcome unknown')), this.#timeout);
      this.#pending.set(id, { resolve, reject, timer });
      this.#child.stdin.write(line, error => { if (error) this.#fail(error); });
    });
  }

  #read(chunk: Buffer): void {
    if (this.#closed || this.#failure) return;
    try {
      this.#outputBytes += chunk.length;
      if (this.#outputBytes > 8_388_608 || this.#buffer.length + chunk.length > 1_048_576) throw new Error('MCP output limit');
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      for (;;) {
        const end = this.#buffer.indexOf(10);
        if (end < 0) { if (this.#buffer.length > 524_288) throw new Error('MCP frame limit'); break; }
        if (end > 524_288) throw new Error('MCP frame limit');
        const line = new TextDecoder('utf-8', { fatal: true }).decode(this.#buffer.subarray(0, end));
        this.#buffer = this.#buffer.subarray(end + 1);
        const raw = jsonObject(snapshotJson(line, { maxBytes: 524_288, maxDepth: 28, maxNodes: 40_000 }));
        const isError = Object.hasOwn(raw, 'error');
        const message = closedObject(raw, ['jsonrpc', 'id', isError ? 'error' : 'result']);
        if (message.jsonrpc !== '2.0' || !Number.isSafeInteger(message.id)) throw new Error('malformed MCP response');
        const pending = this.#pending.get(message.id as number);
        if (!pending) throw new Error('foreign or duplicate MCP response ID');
        if (isError) {
          const error = closedObject(message.error, ['code', 'message'], ['data']);
          if (!Number.isInteger(error.code) || typeof error.message !== 'string') throw new Error('malformed MCP error');
          clearTimeout(pending.timer); this.#pending.delete(message.id as number);
          pending.reject(new Error(`MCP protocol error ${error.code}`));
        } else {
          const result = jsonObject(message.result);
          clearTimeout(pending.timer); this.#pending.delete(message.id as number);
          pending.resolve(result);
        }
      }
    } catch (error) { this.#fail(error instanceof Error ? error : new Error('MCP decoding failed')); }
  }
  #kill(signal: NodeJS.Signals): void {
    if (!this.#child.pid || this.#exit) return;
    try {
      if (process.platform === 'win32') this.#child.kill(signal);
      else process.kill(-this.#child.pid, signal);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
  }
  #fail(error: Error): void {
    if (!this.#failure) this.#failure = error;
    for (const pending of this.#pending.values()) { clearTimeout(pending.timer); pending.reject(this.#failure); }
    this.#pending.clear();
    if (!this.#exit) this.#kill('SIGKILL');
  }
  async close(): Promise<void> {
    if (this.#exit) return;
    this.#closed = true;
    for (const pending of this.#pending.values()) { clearTimeout(pending.timer); pending.reject(new Error('MCP connection closed')); }
    this.#pending.clear();
    this.#child.stdin.end();
    const timer = setTimeout(() => this.#kill('SIGKILL'), 300);
    try { await this.#exited; } finally { clearTimeout(timer); }
  }
}
