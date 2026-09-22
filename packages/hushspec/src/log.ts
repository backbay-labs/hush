import { createHash } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';
import { canonicalizeValue, type JsonValue } from './canonical.js';
import type { DecisionReceipt, EnforcementMode, PolicySummary } from './receipt.js';
import { RECEIPT_VERSION, formatTimestamp, parseReceipt } from './receipt.js';
import type { Envelope, Keyring, KeyringDocument, VerificationOutcome } from './signing.js';
import { signContentHash, verifyContentHash } from './signing.js';
import type { ReceiptSink } from './sinks.js';
import { HUSHSPEC_VERSION, SDK_NAME, SDK_VERSION } from './version.js';

/**
 * Hash-linked receipt log (spec/hushspec-log.md, format 0.1).
 *
 * A log is a JSON Lines file of {@link LogEntry} records. Each entry carries a
 * sequence number, the hash of the previous entry, its own hash over its
 * canonical form, and optionally an Ed25519 signature over that hash. A
 * verifier can therefore detect a line that was edited, deleted, inserted, or
 * reordered, without any other source of truth.
 *
 * Entries wrap a {@link DecisionReceipt} or a {@link PolicyEvent} (which
 * policy was loaded or swapped in, with its provenance) so the log proves not
 * only what was decided but what was in force when.
 *
 * Writers exclude each other through the `<path>.lock` sentinel of log spec 4
 * alone. The advisory `flock` the same section recommends underneath it has no
 * counterpart in Node's `fs` module, and a native addon bought to get one
 * would cost this package its dependency-free install. The sentinel is the
 * lock all four SDKs share, so it is the one that decides who may write.
 */

/** The log-entry format this module writes and verifies. */
export const LOG_VERSION = '0.1';

/** `prev_hash` of the first entry of a log that continues nothing. */
export const GENESIS_HASH = `sha256:${'0'.repeat(64)}`;

/** The break reported for an unsigned entry when signatures are required. */
export const REASON_UNSIGNED = 'entry_unsigned';

// --------------------------------------------------------------------------
// Wire types
// --------------------------------------------------------------------------

/** What an entry wraps. */
export type EntryType = 'receipt' | 'policy_loaded' | 'policy_swapped' | 'log_started';

/** The SDK that wrote an entry. */
export interface SdkInfo {
  name: string;
  version: string;
}

/** This package, as a log entry records it. */
export function thisSdk(): SdkInfo {
  return { name: SDK_NAME, version: SDK_VERSION };
}

export type PolicyEventKind = 'loaded' | 'swapped';

/**
 * A policy-in-effect record (log spec 6): what was enforced from this moment
 * on, with the same identity a receipt carries.
 */
export interface PolicyEvent {
  event: PolicyEventKind;
  /** RFC 3339 UTC, millisecond precision. */
  timestamp: string;
  policy: PolicySummary;
  enforcement_mode: EnforcementMode;
  sdk: SdkInfo;
  /** The HushSpec version the engine implements. */
  spec_version: string;
  /** For `swapped`: the content hash of the policy that was replaced. */
  previous_content_hash?: string;
}

/** A `loaded` event for `policy`, stamped `clock` (default now). */
export function policyLoadedEvent(
  policy: PolicySummary,
  enforcementMode: EnforcementMode = 'enforce',
  clock?: Date,
): PolicyEvent {
  return {
    event: 'loaded',
    timestamp: formatTimestamp(clock ?? new Date()),
    policy,
    enforcement_mode: enforcementMode,
    sdk: thisSdk(),
    spec_version: HUSHSPEC_VERSION,
  };
}

/** A `swapped` event: `policy` replaces the policy with `previousContentHash`. */
export function policySwappedEvent(
  policy: PolicySummary,
  enforcementMode: EnforcementMode = 'enforce',
  previousContentHash?: string,
  clock?: Date,
): PolicyEvent {
  return {
    ...policyLoadedEvent(policy, enforcementMode, clock),
    event: 'swapped',
    ...(previousContentHash === undefined
      ? {}
      : { previous_content_hash: previousContentHash }),
  };
}

/** The first entry of a rotated log file: where the chain came from. */
export interface LogStarted {
  timestamp: string;
  previous_file?: string;
  /** The previous file's last `entry_hash`; equals this entry's `prev_hash`. */
  previous_entry_hash?: string;
}

/**
 * An entry signature: the 0.2 signature envelope (signing spec 4) whose
 * `content_hash` is the entry's `entry_hash`.
 */
export type LogSignature = Envelope;

/** One line of a log. */
export interface LogEntry {
  log_version: string;
  /** Starts at 1 in every file and increases by exactly 1. */
  seq: number;
  /** `entry_hash` of the previous entry, or {@link GENESIS_HASH}. */
  prev_hash: string;
  entry_type: EntryType;
  receipt?: DecisionReceipt;
  policy_event?: PolicyEvent;
  log_started?: LogStarted;
  /**
   * `sha256:` over the canonical form of this entry without `entry_hash` and
   * `signature`.
   */
  entry_hash: string;
  signature?: LogSignature;
}

/** What an entry wraps, when appending. */
export type Payload =
  | { receipt: DecisionReceipt }
  | { policyEvent: PolicyEvent }
  | { logStarted: LogStarted };

const ENTRY_KEYS: ReadonlySet<string> = new Set([
  'log_version',
  'seq',
  'prev_hash',
  'entry_type',
  'receipt',
  'policy_event',
  'log_started',
  'entry_hash',
  'signature',
]);

const POLICY_EVENT_KEYS: ReadonlySet<string> = new Set([
  'event',
  'timestamp',
  'policy',
  'enforcement_mode',
  'sdk',
  'spec_version',
  'previous_content_hash',
]);

const LOG_STARTED_KEYS: ReadonlySet<string> = new Set([
  'timestamp',
  'previous_file',
  'previous_entry_hash',
]);

const SIGNATURE_KEYS: ReadonlySet<string> = new Set([
  'format_version',
  'algorithm',
  'key_id',
  'signed_at',
  'expires_at',
  'policy_version',
  'policy_name',
  'content_hash',
  'signer',
  'signature',
]);

const POLICY_SUMMARY_KEYS: ReadonlySet<string> = new Set([
  'name',
  'version',
  'spec_version',
  'content_hash',
  'extends_chain',
  'signature',
]);

const CHAIN_LINK_KEYS: ReadonlySet<string> = new Set(['source', 'content_hash']);

const SIGNATURE_STATUS_KEYS: ReadonlySet<string> = new Set([
  'verified',
  'key_id',
  'verified_at',
  'reason',
]);

const SDK_KEYS: ReadonlySet<string> = new Set(['name', 'version']);

/** The payload members an entry may carry, each a JSON object when present. */
const PAYLOAD_MEMBERS = ['receipt', 'policy_event', 'log_started', 'signature'] as const;

/**
 * The first unknown member of `value` against `allowed`, or `undefined`.
 * Unknown fields are a break (log spec 8, step 1): a verifier that ignored
 * them would not be hashing what it read.
 */
function unknownKey(value: unknown, allowed: ReadonlySet<string>): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) return key;
  }
  return undefined;
}

/**
 * The first unknown member anywhere inside a `policy_event`, or `undefined`.
 *
 * The log-entry schema closes every object it defines, not only the ones the
 * entry names directly, so the check has to reach the policy identity and the
 * SDK record too.
 */
function unknownPolicyEventKey(event: unknown): string | undefined {
  const top = unknownKey(event, POLICY_EVENT_KEYS);
  if (top !== undefined) return top;
  if (typeof event !== 'object' || event === null) return undefined;
  const { policy, sdk } = event as { policy?: unknown; sdk?: unknown };
  const inPolicy = unknownKey(policy, POLICY_SUMMARY_KEYS) ?? unknownSummaryKey(policy);
  return inPolicy ?? unknownKey(sdk, SDK_KEYS);
}

/** The first unknown member inside a policy summary's own objects. */
function unknownSummaryKey(policy: unknown): string | undefined {
  if (typeof policy !== 'object' || policy === null) return undefined;
  const { extends_chain: chain, signature } = policy as {
    extends_chain?: unknown;
    signature?: unknown;
  };
  if (Array.isArray(chain)) {
    for (const link of chain) {
      const unknown = unknownKey(link, CHAIN_LINK_KEYS);
      if (unknown !== undefined) return unknown;
    }
  }
  return unknownKey(signature, SIGNATURE_STATUS_KEYS);
}

/**
 * Why `value` is not a log entry, or `undefined`.
 *
 * The entry-level strictness of log spec 8, step 1: an unknown member anywhere
 * the log-entry schema closes an object, and a payload member that is not a
 * JSON object. An append runs it over the file's last line, so the tail this
 * SDK is willing to continue is exactly the tail a verifier is willing to
 * read.
 */
function logEntryProblem(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'expected a JSON object';
  }
  const entry = value as LogEntry;
  for (const member of PAYLOAD_MEMBERS) {
    const payload: unknown = entry[member];
    if (payload != null && (typeof payload !== 'object' || Array.isArray(payload))) {
      return `${member} is not a JSON object`;
    }
  }
  const unknown =
    unknownKey(entry, ENTRY_KEYS) ??
    unknownPolicyEventKey(entry.policy_event) ??
    unknownKey(entry.log_started, LOG_STARTED_KEYS) ??
    unknownKey(entry.signature, SIGNATURE_KEYS);
  return unknown === undefined ? undefined : `unknown field ${JSON.stringify(unknown)}`;
}

/**
 * Recompute the hash an entry should carry: `sha256:` over the RFC 8785
 * canonical form of the entry with `entry_hash` and `signature` removed.
 */
export function computeEntryHash(entry: Partial<LogEntry>): string {
  const { entry_hash: _hash, signature: _signature, ...rest } = entry;
  const canonical = canonicalizeValue(rest as unknown as JsonValue);
  return `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

/**
 * Whether exactly the payload named by `entry_type` is present.
 *
 * A member set to `null` counts as absent, as it does in every other SDK, so
 * an entry that names a payload it did not carry is a payload mismatch rather
 * than something a later step dereferences.
 */
export function payloadMatchesType(entry: LogEntry): boolean {
  const receipt = entry.receipt != null;
  const event = entry.policy_event != null;
  const started = entry.log_started != null;
  switch (entry.entry_type) {
    case 'receipt':
      return receipt && !event && !started;
    case 'policy_loaded':
      return !receipt && !started && entry.policy_event?.event === 'loaded';
    case 'policy_swapped':
      return !receipt && !started && entry.policy_event?.event === 'swapped';
    case 'log_started':
      return started && !receipt && !event;
    default:
      return false;
  }
}

function entryTypeOf(payload: Payload): EntryType {
  if ('receipt' in payload) return 'receipt';
  if ('logStarted' in payload) return 'log_started';
  return payload.policyEvent.event === 'loaded' ? 'policy_loaded' : 'policy_swapped';
}

// --------------------------------------------------------------------------
// Chained sink
// --------------------------------------------------------------------------

/** How long to wait for another writer's lock before failing. */
export const LOCK_TIMEOUT_MS = 5_000;

/** A log could not be continued or written consistently. */
export class LogChainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LogChainError';
  }
}

/**
 * Block for `ms` without a busy loop and without going async: appending is a
 * synchronous operation (a sink cannot make `gate()` return a promise), so
 * waiting for another writer's lock has to be synchronous too.
 */
function sleepSync(ms: number): void {
  const buffer = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(buffer, 0, 0, ms);
}

/**
 * Run `body` while holding `<path>.lock`, created atomically with `O_EXCL`.
 *
 * This is the lock every SDK takes (log spec 4), so writers in different
 * languages exclude each other. A stale lock -- one a writer that died left
 * behind -- times out rather than being bypassed: breaking a lock this process
 * cannot prove is stale would let two writers interleave chains and corrupt
 * both (log spec 9).
 */
function withFileLock<T>(target: string, body: () => T): T {
  const lockPath = `${target}.lock`;
  const started = Date.now();
  let fd: number;
  for (;;) {
    try {
      fd = openSync(lockPath, 'wx');
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        throw error;
      }
      if (Date.now() - started > LOCK_TIMEOUT_MS) {
        throw new LogChainError(`timed out waiting for ${lockPath}`);
      }
      sleepSync(5);
    }
  }
  try {
    return body();
  } finally {
    closeSync(fd);
    try {
      unlinkSync(lockPath);
    } catch {
      /* another writer already reclaimed it; nothing to undo */
    }
  }
}

/**
 * Appends hash-linked entries to a JSON Lines file, fsyncing each one.
 *
 * Opening an existing file continues its chain from the last entry. Appends
 * are serialized across processes by the `<path>.lock` sentinel every SDK
 * takes (log spec 4); a lock held longer than {@link LOCK_TIMEOUT_MS} is
 * reported as an error rather than bypassed. Each entry's `seq` and
 * `prev_hash` come from the file's current last entry, read while that lock is
 * held, so a second sink or process writing the same log extends the chain
 * instead of forking it.
 * {@link ChainedFileSink.rotate} carries the chain into a new file through a
 * `log_started` entry.
 */
export class ChainedFileSink implements ReceiptSink {
  private logPath: string;
  private seq: number;
  private prevHash: string;
  private clock?: Date;
  private signerKey?: string;

  private constructor(logPath: string, seq: number, prevHash: string) {
    this.logPath = logPath;
    this.seq = seq;
    this.prevHash = prevHash;
  }

  /**
   * Open (or create) the log at `filePath` and continue its chain.
   *
   * @throws {LogChainError} when the existing file's last line is not a log
   * entry -- continuing a file whose head cannot be read would start a second,
   * unlinked chain inside it.
   */
  static open(filePath: string): ChainedFileSink {
    const resolved = path.resolve(filePath);
    const last = lastEntry(resolved);
    return last === undefined
      ? new ChainedFileSink(resolved, 0, GENESIS_HASH)
      : new ChainedFileSink(resolved, last.seq, last.entry_hash);
  }

  /** Sign every entry with `privateKeyPem` (signing spec 4, over `entry_hash`). */
  withSigner(privateKeyPem: string): this {
    this.signerKey = privateKeyPem;
    return this;
  }

  /**
   * Use a fixed instant for `log_started` timestamps and signature
   * `signed_at`, so conformance vectors are byte-stable.
   */
  withClock(clock: Date): this {
    this.clock = clock;
    return this;
  }

  /** The file currently being written. */
  get path(): string {
    return this.logPath;
  }

  /** The last sequence number and entry hash written. */
  head(): { seq: number; entry_hash: string } {
    return { seq: this.seq, entry_hash: this.prevHash };
  }

  private now(): Date {
    return this.clock ?? new Date();
  }

  /**
   * Append one entry, fsynced before it is reported as written (log spec 3).
   *
   * The chain head is re-read from the file under the write lock, so an entry
   * continues what the file holds rather than what this sink last wrote. A
   * tail that cannot be parsed fails the append: continuing past it would
   * leave a second, unlinked chain in the file.
   *
   * @throws {LogChainError} when the lock cannot be taken or the file's last
   * line is not a log entry.
   */
  append(payload: Payload): LogEntry {
    const entry = this.appendTo(this.logPath, this.seq, this.prevHash, payload);
    this.seq = entry.seq;
    this.prevHash = entry.entry_hash;
    return entry;
  }

  /**
   * Write one entry to `target`, continuing from `cachedSeq` and
   * `cachedPrevHash` when the file holds no entry of its own, and return it
   * without touching the chain head.
   *
   * The caller commits the head, so an append that fails leaves the sink
   * describing the file it was describing before.
   */
  private appendTo(
    target: string,
    cachedSeq: number,
    cachedPrevHash: string,
    payload: Payload,
  ): LogEntry {
    // Before the lock: the lock file lives next to the log, so the directory
    // has to exist for the lock itself to be creatable.
    mkdirSync(path.dirname(target), { recursive: true });
    return withFileLock(target, () => {
      // A missing or empty file means a fresh log, or a rotation whose
      // `log_started` entry is about to seed the new file; both continue from
      // the head this sink carries.
      const head = lastEntry(target);
      const seq = head === undefined ? cachedSeq : head.seq;
      const prevHash = head === undefined ? cachedPrevHash : head.entry_hash;
      // Member order is fixed (log spec 4), so two writers appending the same
      // chain produce byte-identical files. The hash itself is over the
      // canonical form and does not depend on it.
      const written: LogEntry = {
        log_version: LOG_VERSION,
        seq: seq + 1,
        prev_hash: prevHash,
        entry_type: entryTypeOf(payload),
        ...('receipt' in payload ? { receipt: payload.receipt } : {}),
        ...('policyEvent' in payload ? { policy_event: payload.policyEvent } : {}),
        ...('logStarted' in payload ? { log_started: payload.logStarted } : {}),
        entry_hash: '',
      };
      written.entry_hash = computeEntryHash(written);
      // Signing belongs under the lock too: the signature covers `entry_hash`,
      // which depends on the `prev_hash` just read.
      if (this.signerKey !== undefined) {
        written.signature = signContentHash(written.entry_hash, this.signerKey, {
          signedAt: this.now(),
        });
      }

      const fd = openSync(target, 'a');
      try {
        writeSync(fd, `${JSON.stringify(written)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return written;
    });
  }

  /** {@link ReceiptSink.send}: append a receipt entry. */
  send(receipt: DecisionReceipt): void {
    this.append({ receipt });
  }

  /** Record a policy-in-effect event (log spec 6). */
  recordPolicyEvent(event: PolicyEvent): LogEntry {
    return this.append({ policyEvent: event });
  }

  /**
   * Start writing to `newPath`, whose first entry is a `log_started` record
   * naming the file this chain continues from and its last hash. Sequence
   * numbers restart at 1 in the new file; `prev_hash` carries over.
   *
   * The switch is committed only once that entry is on disk. A rotation that
   * cannot write it leaves the sink on the old file, still linked and still
   * verifiable, rather than on a new one whose first receipt would continue
   * nothing.
   *
   * @throws {LogChainError} when `newPath` already exists -- appending a
   * fresh chain onto an existing file would leave two unlinked chains in it.
   */
  rotate(newPath: string): LogEntry {
    const resolved = path.resolve(newPath);
    if (existsSync(resolved)) {
      throw new LogChainError(`cannot rotate into existing file ${resolved}`);
    }
    // Only the file name: logs are moved between hosts, and a path would leak
    // the writer's layout for no verification benefit.
    const previousFile = path.basename(this.logPath);
    const previousEntryHash = this.prevHash;
    const entry = this.appendTo(resolved, 0, previousEntryHash, {
      logStarted: {
        timestamp: formatTimestamp(this.now()),
        previous_file: previousFile,
        // Always recorded, the genesis value included (log spec 5): a verifier
        // given both files compares this against the previous file's last
        // hash, and an omitted member is not that hash.
        previous_entry_hash: previousEntryHash,
      },
    });
    this.logPath = resolved;
    this.seq = entry.seq;
    this.prevHash = entry.entry_hash;
    return entry;
  }
}

/** How much of the tail to read at a time when looking for the last line. */
const TAIL_CHUNK_BYTES = 8 * 1024;

/** The last non-empty line of `filePath` as an entry, or `undefined`. */
function lastEntry(filePath: string): LogEntry | undefined {
  const last = lastLine(filePath);
  if (last === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(last) as unknown;
  } catch (error) {
    throw new LogChainError(
      `last line of ${filePath} is not a log entry: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  // Reading the head loosely would seed the chain from a malformed tail: a
  // `seq` that is not an integer or an `entry_hash` that is not a string would
  // become the next entry's link and break the chain for every later verifier,
  // and an unknown member would make a line this SDK extended one no verifier
  // reads.
  const problem = logEntryProblem(parsed);
  if (problem !== undefined) {
    throw new LogChainError(`last line of ${filePath} is not a log entry: ${problem}`);
  }
  const { seq, entry_hash: entryHash } = parsed as Record<string, unknown>;
  if (typeof seq !== 'number' || !Number.isInteger(seq)) {
    throw new LogChainError(
      `last line of ${filePath} has a non-integer seq ${JSON.stringify(seq) ?? 'undefined'}`,
    );
  }
  if (typeof entryHash !== 'string') {
    throw new LogChainError(
      `last line of ${filePath} has a non-string entry_hash ` +
        `${JSON.stringify(entryHash) ?? 'undefined'}`,
    );
  }
  return parsed as LogEntry;
}

/**
 * The last non-empty line of `filePath`, read by seeking back from the end.
 *
 * Every append reads the head this way, so the cost has to be the size of one
 * entry rather than the size of the log.
 */
function lastLine(filePath: string): string | undefined {
  let fd: number;
  try {
    fd = openSync(filePath, 'r');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  try {
    let end = fstatSync(fd).size;
    let tail = Buffer.alloc(0);
    while (end > 0) {
      const start = Math.max(0, end - TAIL_CHUNK_BYTES);
      const chunk = Buffer.alloc(end - start);
      readSync(fd, chunk, 0, chunk.length, start);
      tail = Buffer.concat([chunk, tail]);
      end = start;
      const line = lastLineOf(tail, end === 0);
      if (line !== undefined) return line;
    }
    return undefined;
  } finally {
    closeSync(fd);
  }
}

/**
 * The last non-empty line inside `buffer`, or `undefined` when it may still
 * begin earlier in the file. `atStart` says `buffer` reaches the file's first
 * byte, so a line with no newline before it is already complete.
 */
function lastLineOf(buffer: Buffer, atStart: boolean): string | undefined {
  let end = buffer.length;
  while (end > 0 && isAsciiWhitespace(buffer[end - 1]!)) end -= 1;
  if (end === 0) return undefined;
  const newline = buffer.lastIndexOf(0x0a, end - 1);
  if (newline === -1 && !atStart) return undefined;
  return buffer.toString('utf8', newline + 1, end);
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x20 || (byte >= 0x09 && byte <= 0x0d);
}

// --------------------------------------------------------------------------
// Verification (log spec 8)
// --------------------------------------------------------------------------

/** What a verifier trusts and demands. */
export interface LogVerifyOptions {
  /** Every entry must carry a signature that verifies. */
  requireSignatures?: boolean;
  /**
   * Keys entry signatures are checked against. Without one, signed entries
   * are counted but not verified (an error under `requireSignatures`).
   */
  keyring?: Keyring | KeyringDocument | string;
  /** Clock parameters handed to the signature verifier. */
  verify?: { now?: Date | string; maxClockSkewSeconds?: number };
}

/** Where a chain first broke. */
export interface LogBreak {
  file: string;
  /** 1-based line number; `0` for a file-level problem. */
  line: number;
  message: string;
}

/** Summary of a verified log. */
export interface LogVerifyReport {
  /** False when {@link LogVerifyReport.break} names the first broken line. */
  ok: boolean;
  files: number;
  entries: number;
  receipts: number;
  policy_events: number;
  signed: number;
  verified_signatures: number;
  last_seq: number;
  last_entry_hash: string;
  break?: LogBreak;
}

/**
 * Verify one log file's text (log spec 8).
 *
 * Returns a report; `ok: false` carries the first break with the file and
 * 1-based line number that failed.
 */
export function verifyLog(
  name: string,
  text: string,
  options: LogVerifyOptions = {},
): LogVerifyReport {
  return verifyLogs([[name, text]], options);
}

/**
 * Verify a sequence of rotated log files in order: each file after the first
 * must start with a `log_started` entry whose `previous_entry_hash` is the
 * previous file's last hash (log spec 5).
 */
export function verifyLogs(
  files: ReadonlyArray<readonly [string, string]>,
  options: LogVerifyOptions = {},
): LogVerifyReport {
  const report: LogVerifyReport = {
    ok: true,
    files: 0,
    entries: 0,
    receipts: 0,
    policy_events: 0,
    signed: 0,
    verified_signatures: 0,
    last_seq: 0,
    last_entry_hash: GENESIS_HASH,
  };
  let carriedHash: string | undefined;

  for (let index = 0; index < files.length; index += 1) {
    const [name, text] = files[index]!;
    report.files += 1;
    let expectedSeq = 1;
    let prevHash = carriedHash ?? GENESIS_HASH;
    let any = false;

    const lines = text.split('\n');
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      const line = lines[lineIndex]!;
      const lineNo = lineIndex + 1;
      if (line.trim() === '') continue;
      const broke = (message: string): LogVerifyReport => {
        report.ok = false;
        report.break = { file: name, line: lineNo, message };
        return report;
      };

      let parsed: unknown;
      try {
        parsed = JSON.parse(line) as unknown;
      } catch (error) {
        return broke(
          `not a log entry: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return broke('not a log entry: expected a JSON object');
      }
      const unknown = unknownKey(parsed, ENTRY_KEYS);
      if (unknown !== undefined) {
        return broke(`not a log entry: unknown field ${JSON.stringify(unknown)}`);
      }
      const entry = parsed as LogEntry;

      // An entry's hash covers whatever JSON the line held, so a
      // hash-consistent line can still carry a member of the wrong shape.
      // Check the shapes before reading into them: a malformed log is a
      // verification failure, never an exception out of the verifier.
      for (const member of PAYLOAD_MEMBERS) {
        const value: unknown = entry[member];
        if (value != null && (typeof value !== 'object' || Array.isArray(value))) {
          return broke(`${member} is not a JSON object`);
        }
      }

      if (entry.log_version !== LOG_VERSION) {
        return broke(
          `unsupported log_version ${JSON.stringify(entry.log_version)}, ` +
            `expected ${JSON.stringify(LOG_VERSION)}`,
        );
      }
      if (entry.seq !== expectedSeq) {
        return broke(`sequence gap: expected seq ${expectedSeq}, found ${String(entry.seq)}`);
      }
      if (!payloadMatchesType(entry)) {
        return broke(`payload does not match entry_type ${JSON.stringify(entry.entry_type)}`);
      }
      const nestedUnknown =
        unknownPolicyEventKey(entry.policy_event) ??
        unknownKey(entry.log_started, LOG_STARTED_KEYS) ??
        unknownKey(entry.signature, SIGNATURE_KEYS);
      if (nestedUnknown !== undefined) {
        return broke(`not a log entry: unknown field ${JSON.stringify(nestedUnknown)}`);
      }

      if (expectedSeq === 1 && index > 0) {
        const started = entry.log_started;
        if (started === undefined) {
          return broke('a continued file must start with a log_started entry');
        }
        if (started.previous_entry_hash !== carriedHash) {
          return broke(
            "log_started.previous_entry_hash does not match the previous file's last hash",
          );
        }
      }
      if (expectedSeq === 1 && index === 0 && entry.log_started?.previous_entry_hash != null) {
        // The first file of a set may itself continue an earlier file the
        // verifier was not given; its prev_hash must then be that file's last
        // hash. The chain before it is not vouched for (log spec 5).
        prevHash = entry.log_started.previous_entry_hash;
      }
      if (entry.prev_hash !== prevHash) {
        return broke(
          `prev_hash ${String(entry.prev_hash)} does not link to the previous entry ${prevHash}`,
        );
      }

      let recomputed: string;
      try {
        recomputed = computeEntryHash(entry);
      } catch (error) {
        return broke(
          `cannot canonicalize entry: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (recomputed !== entry.entry_hash) {
        return broke(
          `entry_hash ${String(entry.entry_hash)} does not match the entry's ` +
            `canonical form (${recomputed})`,
        );
      }

      if (entry.receipt != null) {
        if (entry.receipt.receipt_version !== RECEIPT_VERSION) {
          return broke(
            `receipt_version ${JSON.stringify(entry.receipt.receipt_version)} is not ` +
              `${JSON.stringify(RECEIPT_VERSION)}`,
          );
        }
        // The entry hash covers whatever JSON the line held, so a
        // hash-consistent line can still carry something that is not a
        // receipt. Log spec 8, step 8 requires the payload to validate.
        try {
          parseReceipt(entry.receipt);
        } catch (error) {
          return broke(
            'receipt does not validate against the 0.2 receipt schema: ' +
              `${error instanceof Error ? error.message : String(error)}`,
          );
        }
        report.receipts += 1;
      }
      if (entry.policy_event != null) {
        report.policy_events += 1;
      }

      const signature = entry.signature;
      if (signature == null) {
        if (options.requireSignatures === true) {
          return broke(`${REASON_UNSIGNED}: signatures are required`);
        }
      } else {
        report.signed += 1;
        if (signature.content_hash !== entry.entry_hash) {
          return broke("signature.content_hash does not name this entry's entry_hash");
        }
        if (options.keyring !== undefined) {
          const outcome: VerificationOutcome = verifyContentHash(signature, entry.entry_hash, {
            keyring: options.keyring,
            ...(options.verify?.now === undefined ? {} : { now: options.verify.now }),
            ...(options.verify?.maxClockSkewSeconds === undefined
              ? {}
              : { maxClockSkewSeconds: options.verify.maxClockSkewSeconds }),
          });
          if (!outcome.ok) {
            return broke(`signature: ${outcome.reason}: ${outcome.detail}`);
          }
          report.verified_signatures += 1;
        } else if (options.requireSignatures === true) {
          return broke('no_keyring: cannot verify a required signature');
        }
      }

      prevHash = entry.entry_hash;
      expectedSeq += 1;
      any = true;
      report.entries += 1;
      report.last_seq = entry.seq;
      report.last_entry_hash = entry.entry_hash;
    }

    if (!any && index > 0) {
      report.ok = false;
      report.break = { file: name, line: 0, message: 'continued file is empty' };
      return report;
    }
    carriedHash = prevHash;
  }
  return report;
}

/** Verify the log files at `paths`, in order. */
export function verifyLogFiles(
  paths: readonly string[],
  options: LogVerifyOptions = {},
): LogVerifyReport {
  const files: [string, string][] = [];
  for (const filePath of paths) {
    try {
      files.push([filePath, readFileSync(filePath, 'utf8')]);
    } catch (error) {
      return {
        ok: false,
        files: files.length,
        entries: 0,
        receipts: 0,
        policy_events: 0,
        signed: 0,
        verified_signatures: 0,
        last_seq: 0,
        last_entry_hash: GENESIS_HASH,
        break: {
          file: filePath,
          line: 0,
          message: `cannot read: ${error instanceof Error ? error.message : String(error)}`,
        },
      };
    }
  }
  return verifyLogs(files, options);
}
