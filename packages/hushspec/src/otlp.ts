import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { RequestOptions } from 'node:http';
import { canonicalizeValue, type JsonValue } from './canonical.js';
import type { PolicyEvent } from './log.js';
import type { DecisionReceipt } from './receipt.js';
import { canonicalJson, receiptHash } from './receipt.js';
import type { ReceiptSink } from './sinks.js';
import { HUSHSPEC_VERSION, SDK_NAME, SDK_VERSION } from './version.js';

/**
 * OTLP/HTTP receipt sink.
 *
 * Exports decision receipts and policy-in-effect events to an OpenTelemetry
 * collector as OTLP/HTTP **logs** in JSON encoding (`POST <endpoint>/v1/logs`),
 * using only `node:http` / `node:https` -- the SDK takes no OpenTelemetry
 * dependency, and an application that already runs the OTel SDK is unaffected.
 *
 * The wire mapping is the one every HushSpec SDK emits, so a collector cannot
 * tell which produced an entry:
 *
 * - one `logRecord` per receipt or policy event;
 * - `timeUnixNano` from the entry's own timestamp, and
 *   `observedTimeUnixNano` from the moment the sink took it;
 * - `severityText` and `severityNumber` of `INFO`/9 for `allow`, `WARN`/13 for
 *   `warn` and `ERROR`/17 for `deny`, and `INFO`/9 for a policy event;
 * - `body.stringValue` is the entry's RFC 8785 canonical JSON, byte for byte
 *   the form its hash covers, so a collector-side consumer can re-hash it;
 * - attributes `hushspec.entry_type`, `hushspec.receipt_version`,
 *   `hushspec.decision`, `hushspec.action_type`, `hushspec.matched_rule`,
 *   `hushspec.policy.content_hash`, `hushspec.receipt_hash`,
 *   `hushspec.enforcement.mode`, `hushspec.enforcement.outcome` (each omitted
 *   where it does not apply -- a policy event has no decision);
 * - resource attributes `service.name`, `hushspec.sdk`, `hushspec.sdk.version`,
 *   `hushspec.spec_version`.
 *
 * Export never blocks {@link OtlpReceiptSink.send}: entries land in a bounded
 * queue and are flushed by size or by timer on a background chain. A full
 * queue drops the incoming entry, counts it ({@link OtlpReceiptSink.dropped})
 * and reports it through `onError` -- evidence is never traded for latency in
 * the evaluation path, and a silent loss is never acceptable either.
 */

// --------------------------------------------------------------------------
// Wire types (OTLP/HTTP JSON, logs)
// --------------------------------------------------------------------------

/** An OTLP `AnyValue`, in the only shape this sink emits. */
export interface OtlpStringValue {
  stringValue: string;
}

/** An OTLP `KeyValue`. */
export interface OtlpAttribute {
  key: string;
  value: OtlpStringValue;
}

/** An OTLP `LogRecord`, JSON encoding. */
export interface OtlpLogRecord {
  timeUnixNano: string;
  observedTimeUnixNano: string;
  severityNumber: number;
  severityText: string;
  body: OtlpStringValue;
  attributes: OtlpAttribute[];
}

/** An OTLP `ExportLogsServiceRequest`, JSON encoding. */
export interface OtlpLogsPayload {
  resourceLogs: [
    {
      resource: { attributes: OtlpAttribute[] };
      scopeLogs: [{ scope: { name: string; version: string }; logRecords: OtlpLogRecord[] }];
    },
  ];
}

/** What a queued entry carries. */
export type OtlpEntry =
  | { kind: 'receipt'; receipt: DecisionReceipt; observedUnixNano: string }
  | { kind: 'policy_event'; event: PolicyEvent; observedUnixNano: string };

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

export interface OtlpReceiptSinkOptions {
  /**
   * Collector base URL, e.g. `http://localhost:4318`. `/v1/logs` is appended
   * unless the URL already ends with it.
   */
  endpoint: string;
  /** Extra request headers (authorization, tenant routing). */
  headers?: Record<string, string>;
  /** `service.name` resource attribute. Default `hushspec`. */
  serviceName?: string;
  /** Entries per export request. Default 32. */
  batchSize?: number;
  /** Idle flush period in milliseconds. Default 5000; 0 disables the timer. */
  flushIntervalMs?: number;
  /** Per-request timeout in milliseconds. Default 10000. */
  timeoutMs?: number;
  /** Bounded queue depth. Default 2048. */
  maxQueue?: number;
  /** Retries after the first attempt, for 5xx/429/network failures. Default 3. */
  maxRetries?: number;
  /** First backoff delay in milliseconds; doubles per attempt. Default 200. */
  retryBackoffMs?: number;
  /** Export failures and queue overflow are reported here, never thrown. */
  onError?: (error: Error) => void;
}

const DEFAULT_SERVICE_NAME = 'hushspec';
const DEFAULT_BATCH_SIZE = 32;
const DEFAULT_FLUSH_INTERVAL_MS = 5_000;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_QUEUE = 2_048;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BACKOFF_MS = 200;

/** Severity numbers from the OpenTelemetry log data model. */
const SEVERITY_INFO = 9;
const SEVERITY_WARN = 13;
const SEVERITY_ERROR = 17;

/** Reported through `onError` when a full queue drops an entry. */
export class OtlpQueueOverflowError extends Error {
  /** Entries dropped by this sink so far, this one included. */
  readonly dropped: number;

  constructor(dropped: number, maxQueue: number) {
    super(`OTLP receipt sink queue is full (${maxQueue}); dropped ${dropped} entries`);
    this.name = 'OtlpQueueOverflowError';
    this.dropped = dropped;
  }
}

/** Reported through `onError` when an export gives up. */
export class OtlpExportError extends Error {
  /** Entries in the batch that was lost. */
  readonly entries: number;

  constructor(message: string, entries: number, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'OtlpExportError';
    this.entries = entries;
  }
}

// --------------------------------------------------------------------------
// Wire construction
// --------------------------------------------------------------------------

function attribute(key: string, value: string | undefined): OtlpAttribute[] {
  return value === undefined ? [] : [{ key, value: { stringValue: value } }];
}

function unixNanoFrom(timestamp: string, fallback: string): string {
  const millis = Date.parse(timestamp);
  if (Number.isNaN(millis)) return fallback;
  return (BigInt(millis) * 1_000_000n).toString();
}

/** `Date.now()` as an OTLP nanosecond string. */
export function nowUnixNano(millis: number = Date.now()): string {
  return (BigInt(Math.trunc(millis)) * 1_000_000n).toString();
}

function severityFor(decision: string): { text: string; number: number } {
  switch (decision) {
    case 'allow':
      return { text: 'INFO', number: SEVERITY_INFO };
    case 'warn':
      return { text: 'WARN', number: SEVERITY_WARN };
    case 'deny':
      return { text: 'ERROR', number: SEVERITY_ERROR };
    default:
      // Fail-closed: a decision this build does not know is not an "INFO".
      return { text: 'ERROR', number: SEVERITY_ERROR };
  }
}

/** The `logRecord` for one receipt. */
export function receiptLogRecord(
  receipt: DecisionReceipt,
  observedUnixNano: string,
): OtlpLogRecord {
  const severity = severityFor(receipt.decision);
  return {
    timeUnixNano: unixNanoFrom(receipt.timestamp, observedUnixNano),
    observedTimeUnixNano: observedUnixNano,
    severityNumber: severity.number,
    severityText: severity.text,
    body: { stringValue: canonicalJson(receipt) },
    attributes: [
      ...attribute('hushspec.entry_type', 'receipt'),
      ...attribute('hushspec.receipt_version', receipt.receipt_version),
      ...attribute('hushspec.decision', receipt.decision),
      ...attribute('hushspec.action_type', receipt.action.type),
      ...attribute('hushspec.matched_rule', receipt.matched_rule),
      ...attribute('hushspec.policy.content_hash', receipt.policy.content_hash),
      ...attribute('hushspec.receipt_hash', receiptHash(receipt)),
      ...attribute('hushspec.enforcement.mode', receipt.enforcement.mode),
      ...attribute('hushspec.enforcement.outcome', receipt.enforcement.outcome),
    ],
  };
}

/** The `logRecord` for one policy-in-effect event. */
export function policyEventLogRecord(
  event: PolicyEvent,
  observedUnixNano: string,
): OtlpLogRecord {
  return {
    timeUnixNano: unixNanoFrom(event.timestamp, observedUnixNano),
    observedTimeUnixNano: observedUnixNano,
    severityNumber: SEVERITY_INFO,
    severityText: 'INFO',
    body: { stringValue: canonicalizeValue(event as unknown as JsonValue) },
    attributes: [
      ...attribute(
        'hushspec.entry_type',
        event.event === 'swapped' ? 'policy_swapped' : 'policy_loaded',
      ),
      ...attribute('hushspec.policy.content_hash', event.policy.content_hash),
      ...attribute('hushspec.enforcement.mode', event.enforcement_mode),
    ],
  };
}

/** The OTLP request body for `entries`, as the collector receives it. */
export function otlpLogsPayload(
  records: OtlpLogRecord[],
  serviceName: string = DEFAULT_SERVICE_NAME,
): OtlpLogsPayload {
  return {
    resourceLogs: [
      {
        resource: {
          attributes: [
            ...attribute('service.name', serviceName),
            ...attribute('hushspec.sdk', SDK_NAME),
            ...attribute('hushspec.sdk.version', SDK_VERSION),
            ...attribute('hushspec.spec_version', HUSHSPEC_VERSION),
          ],
        },
        scopeLogs: [
          {
            scope: { name: SDK_NAME, version: SDK_VERSION },
            logRecords: records,
          },
        ],
      },
    ],
  };
}

/** `<endpoint>/v1/logs`, without doubling a path the caller already gave. */
export function logsEndpoint(endpoint: string): string {
  const trimmed = endpoint.replace(/\/+$/, '');
  return trimmed.endsWith('/v1/logs') ? trimmed : `${trimmed}/v1/logs`;
}

// --------------------------------------------------------------------------
// The sink
// --------------------------------------------------------------------------

interface PostResult {
  status: number;
  body: string;
}

/** Statuses worth another attempt: the collector is busy, not unhappy. */
function retryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

export class OtlpReceiptSink implements ReceiptSink {
  private readonly url: URL;
  private readonly headers: Record<string, string>;
  private readonly serviceName: string;
  private readonly batchSize: number;
  private readonly flushIntervalMs: number;
  private readonly timeoutMs: number;
  private readonly maxQueue: number;
  private readonly maxRetries: number;
  private readonly retryBackoffMs: number;
  private readonly onError?: (error: Error) => void;

  private queue: OtlpEntry[] = [];
  /** Serializes exports so batches reach the collector in order. */
  private chain: Promise<void> = Promise.resolve();
  private timer: ReturnType<typeof setInterval> | null = null;
  private closed = false;
  private droppedCount = 0;

  constructor(options: OtlpReceiptSinkOptions) {
    this.url = new URL(logsEndpoint(options.endpoint));
    if (this.url.protocol !== 'http:' && this.url.protocol !== 'https:') {
      throw new Error(`OTLP endpoint must be http or https, got '${this.url.protocol}'`);
    }
    this.headers = { ...(options.headers ?? {}) };
    this.serviceName = options.serviceName ?? DEFAULT_SERVICE_NAME;
    this.batchSize = Math.max(1, options.batchSize ?? DEFAULT_BATCH_SIZE);
    this.flushIntervalMs = options.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxQueue = Math.max(1, options.maxQueue ?? DEFAULT_MAX_QUEUE);
    this.maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES);
    this.retryBackoffMs = Math.max(0, options.retryBackoffMs ?? DEFAULT_RETRY_BACKOFF_MS);
    this.onError = options.onError;

    if (this.flushIntervalMs > 0) {
      this.timer = setInterval(() => {
        if (this.queue.length > 0) void this.drain();
      }, this.flushIntervalMs);
      // A pending export must never be the reason a process stays alive.
      this.timer.unref?.();
    }
  }

  /** Entries dropped because the queue was full or the sink was closed. */
  get dropped(): number {
    return this.droppedCount;
  }

  /** Entries waiting to be exported. */
  get queued(): number {
    return this.queue.length;
  }

  send(receipt: DecisionReceipt): void {
    this.enqueue({ kind: 'receipt', receipt, observedUnixNano: nowUnixNano() });
  }

  recordPolicyEvent(event: PolicyEvent): void {
    this.enqueue({ kind: 'policy_event', event, observedUnixNano: nowUnixNano() });
  }

  /** Export everything queued now, and everything queued before it settles. */
  flush(): Promise<void> {
    return this.drain();
  }

  /** Stop the timer, export what is queued, and refuse further entries. */
  async close(): Promise<void> {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    // Closed before the final drain, so an entry racing close() is counted as
    // dropped rather than left in a queue nothing will ever flush.
    this.closed = true;
    await this.drain();
  }

  private enqueue(entry: OtlpEntry): void {
    if (this.closed) {
      this.droppedCount += 1;
      this.report(new OtlpExportError('OTLP receipt sink is closed; entry dropped', 1));
      return;
    }
    if (this.queue.length >= this.maxQueue) {
      // Drop the newcomer, not the backlog: the queue holds the older
      // evidence, and evicting it would lose the entries most likely to be
      // the start of an incident.
      this.droppedCount += 1;
      this.report(new OtlpQueueOverflowError(this.droppedCount, this.maxQueue));
      return;
    }
    this.queue.push(entry);
    if (this.queue.length >= this.batchSize) {
      void this.drain();
    }
  }

  private drain(): Promise<void> {
    const next = this.chain.then(() => this.drainQueue());
    // Keep the chain resolvable: a failed export is reported, not propagated.
    this.chain = next.catch(() => {});
    return this.chain;
  }

  private async drainQueue(): Promise<void> {
    while (this.queue.length > 0) {
      const batch = this.queue.splice(0, this.batchSize);
      await this.exportBatch(batch);
    }
  }

  private async exportBatch(batch: OtlpEntry[]): Promise<void> {
    let body: string;
    try {
      body = JSON.stringify(otlpLogsPayload(this.records(batch), this.serviceName));
    } catch (error) {
      this.report(
        new OtlpExportError(
          `OTLP receipt sink could not encode ${batch.length} entries`,
          batch.length,
          error,
        ),
      );
      return;
    }

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      if (attempt > 0) {
        await delay(this.retryBackoffMs * 2 ** (attempt - 1));
      }
      try {
        const result = await this.post(body);
        if (result.status >= 200 && result.status < 300) return;
        lastError = new Error(
          `collector returned ${result.status}${result.body ? `: ${truncate(result.body)}` : ''}`,
        );
        if (!retryableStatus(result.status)) break;
      } catch (error) {
        lastError = error;
      }
    }

    this.report(
      new OtlpExportError(
        `OTLP export of ${batch.length} entries failed: ${errorMessage(lastError)}`,
        batch.length,
        lastError,
      ),
    );
  }

  /** Records for a batch; an entry that cannot be canonicalized is reported. */
  private records(batch: OtlpEntry[]): OtlpLogRecord[] {
    const records: OtlpLogRecord[] = [];
    for (const entry of batch) {
      try {
        records.push(
          entry.kind === 'receipt'
            ? receiptLogRecord(entry.receipt, entry.observedUnixNano)
            : policyEventLogRecord(entry.event, entry.observedUnixNano),
        );
      } catch (error) {
        this.droppedCount += 1;
        this.report(
          new OtlpExportError(
            `OTLP receipt sink could not canonicalize a ${entry.kind} entry`,
            1,
            error,
          ),
        );
      }
    }
    return records;
  }

  private post(body: string): Promise<PostResult> {
    return new Promise<PostResult>((resolve, reject) => {
      const payload = Buffer.from(body, 'utf8');
      const options: RequestOptions = {
        protocol: this.url.protocol,
        hostname: this.url.hostname,
        port: this.url.port || (this.url.protocol === 'https:' ? 443 : 80),
        path: `${this.url.pathname}${this.url.search}`,
        method: 'POST',
        headers: {
          ...this.headers,
          'content-type': 'application/json',
          'content-length': String(payload.byteLength),
        },
        timeout: this.timeoutMs,
      };

      const send = this.url.protocol === 'https:' ? httpsRequest : httpRequest;
      const req = send(options, res => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
        res.on('error', reject);
      });
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error(`request timed out after ${this.timeoutMs}ms`));
      });
      req.end(payload);
    });
  }

  private report(error: Error): void {
    if (this.onError === undefined) return;
    try {
      this.onError(error);
    } catch {
      // An error handler must not break the sink that called it.
    }
  }
}

/**
 * Not unref'd: a retry backoff is bounded, and `close()` awaiting one must
 * not be cut short by an event loop that considers itself idle.
 */
function delay(millis: number): Promise<void> {
  if (millis <= 0) return Promise.resolve();
  return new Promise<void>(resolve => {
    setTimeout(resolve, millis);
  });
}

function truncate(text: string, max = 200): string {
  return text.length <= max ? text : `${text.slice(0, max)}...`;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}
