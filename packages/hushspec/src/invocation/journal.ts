import fs from 'node:fs';
import path from 'node:path';
import { canonicalizeValue, type JsonValue } from '../canonical.js';
import { uuidV7 } from '../receipt.js';
import { signContentHash } from '../signing.js';
import { copyJson, hashJson } from './json.js';
import { assertEvent, idField, type InvocationEvent, type InvocationEntryBody, type InvocationCheckpoint } from './model.js';

export type { InvocationEvent, InvocationCheckpoint, InvocationEntry, InvocationAttempt,
  InvocationDecision, TerminalDisposition, ConfirmationDisposition } from './model.js';
export interface InvocationAcknowledgment { sequence: number; entryHash: string }
export interface InvocationJournal {
  append(event: InvocationEvent): InvocationAcknowledgment;
  close(): InvocationCheckpoint;
}
export const JOURNAL_LIMITS = Object.freeze({ entryBytes: 2_097_152, streamBytes: 67_108_864, entries: 20_000 });

function syncDirectory(directory: string): void {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) {
    const written = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    if (written <= 0) throw new Error('journal write made no progress');
    offset += written;
  }
  fs.fsyncSync(fd);
}

/** Authoritative synchronous durability; unlike middleware sinks, errors never disappear. */
export class FileInvocationJournal implements InvocationJournal {
  readonly streamId: string;
  readonly directory: string;
  readonly #privateKeyPem: string;
  #fd: number | undefined;
  #sequence = 0;
  #head: string | null = null;
  #bytes = 0;
  #failed = false;
  #closed = false;
  #busy = false;
  readonly #pending = new Set<string>();

  constructor(directory: string, privateKeyPem: string, options: { streamId?: string } = {}) {
    this.streamId = options.streamId ?? uuidV7(); idField(this.streamId);
    this.directory = path.resolve(directory);
    this.#privateKeyPem = privateKeyPem;
    // Validate the key before leaving a partial journal directory.
    signContentHash(hashJson({ kind: 'hush.invocation.key-check' }), privateKeyPem);
    fs.mkdirSync(this.directory, { mode: 0o700 });
    try {
      this.#fd = fs.openSync(path.join(this.directory, 'entries.jsonl'), 'wx', 0o600);
      fs.fsyncSync(this.#fd);
      syncDirectory(this.directory);
      syncDirectory(path.dirname(this.directory));
    } catch (error) { this.dispose(); throw error; }
  }

  append(event: InvocationEvent): InvocationAcknowledgment {
    this.#assertOpen();
    if (this.#busy) { this.#failed = true; throw new Error('reentrant journal append'); }
    this.#busy = true;
    try {
      const captured = copyJson(event, { maxBytes: JOURNAL_LIMITS.entryBytes, maxDepth: 48, maxNodes: 150_000 });
      assertEvent(captured);
      const body: InvocationEntryBody = { kind: 'hush.invocation.entry', format_version: '0.1.0',
        stream_id: this.streamId, sequence: this.#sequence + 1, previous_hash: this.#head,
        timestamp: new Date().toISOString(), event: captured };
      const entryHash = hashJson(body);
      const signature = signContentHash(entryHash, this.#privateKeyPem, { signedAt: body.timestamp });
      const bytes = Buffer.from(canonicalizeValue({ ...body, entry_hash: entryHash, signature } as unknown as JsonValue) + '\n');
      if (bytes.length > JOURNAL_LIMITS.entryBytes || this.#bytes + bytes.length > JOURNAL_LIMITS.streamBytes ||
          this.#sequence >= JOURNAL_LIMITS.entries) throw new Error('journal resource limit');
      writeAll(this.#fd!, bytes);
      this.#sequence++; this.#head = entryHash; this.#bytes += bytes.length;
      if (captured.type === 'attempt') this.#pending.add(captured.call_id);
      if (captured.type === 'blocked' || captured.type === 'terminal') this.#pending.delete(captured.call_id);
      return Object.freeze({ sequence: this.#sequence, entryHash });
    } catch (error) { this.#failed = true; throw error; }
    finally { this.#busy = false; }
  }

  close(): InvocationCheckpoint {
    this.#assertOpen();
    if (this.#pending.size) throw new Error('journal has pending calls');
    if (this.#busy) throw new Error('journal append in progress');
    try {
      const body = { kind: 'hush.invocation.checkpoint' as const, format_version: '0.1.0' as const,
        stream_id: this.streamId, entry_count: this.#sequence, head_hash: this.#head,
        closed: true as const, timestamp: new Date().toISOString() };
      const checkpoint = { ...body, signature: signContentHash(hashJson(body), this.#privateKeyPem, { signedAt: body.timestamp }) };
      const fd = fs.openSync(path.join(this.directory, 'checkpoint.json'), 'wx', 0o600);
      try { writeAll(fd, Buffer.from(canonicalizeValue(checkpoint as unknown as JsonValue) + '\n')); }
      finally { fs.closeSync(fd); }
      syncDirectory(this.directory);
      fs.closeSync(this.#fd!); this.#fd = undefined; this.#closed = true;
      return copyJson(checkpoint);
    } catch (error) { this.#failed = true; throw error; }
  }

  /** Abandon an incomplete stream without fabricating a closing checkpoint. */
  dispose(): void {
    this.#failed = true;
    if (this.#fd !== undefined) { const fd = this.#fd; this.#fd = undefined; fs.closeSync(fd); }
  }
  #assertOpen(): void {
    if (this.#failed) throw new Error('journal failed');
    if (this.#closed || this.#fd === undefined) throw new Error('journal closed');
  }
}
