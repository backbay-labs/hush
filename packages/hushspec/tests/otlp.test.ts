import { describe, expect, it } from 'vitest';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { canonicalizeValue, type JsonValue } from '../src/canonical.js';
import type { PolicyEvent } from '../src/log.js';
import type { DecisionReceipt } from '../src/receipt.js';
import { canonicalJson, receiptHash } from '../src/receipt.js';
import {
  OtlpExportError,
  OtlpQueueOverflowError,
  OtlpReceiptSink,
  logsEndpoint,
  type OtlpAttribute,
  type OtlpLogRecord,
  type OtlpLogsPayload,
} from '../src/otlp.js';
import { HUSHSPEC_VERSION, SDK_NAME, SDK_VERSION } from '../src/version.js';

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

function makeReceipt(decision: 'allow' | 'warn' | 'deny'): DecisionReceipt {
  return {
    receipt_version: '0.2',
    receipt_id: '01994b7e-2c1a-7c3e-8f4a-0123456789ab',
    timestamp: '2026-03-15T00:00:00.000Z',
    time_source: 'system',
    policy: {
      name: 'test-policy',
      spec_version: '0.2.0',
      content_hash: `sha256:${'ab'.repeat(32)}`,
    },
    action: { type: 'egress', target: 'api.example.com' },
    decision,
    matched_rule: 'rules.egress.allow',
    reason: 'host is allowed',
    rule_trace: [
      {
        rule_block: 'egress',
        rule_path: 'rules.egress.allow',
        outcome: decision === 'allow' ? 'allow' : 'deny',
        evaluated: true,
      },
    ],
    enforcement: { mode: 'enforce', outcome: decision === 'allow' ? 'allowed' : 'blocked' },
  };
}

function makePolicyEvent(kind: 'loaded' | 'swapped'): PolicyEvent {
  return {
    event: kind,
    timestamp: '2026-03-15T00:00:01.000Z',
    policy: {
      name: 'test-policy',
      spec_version: '0.2.0',
      content_hash: `sha256:${'cd'.repeat(32)}`,
    },
    enforcement_mode: 'enforce',
    sdk: { name: SDK_NAME, version: SDK_VERSION },
    spec_version: HUSHSPEC_VERSION,
    ...(kind === 'swapped' ? { previous_content_hash: `sha256:${'ab'.repeat(32)}` } : {}),
  };
}

interface Capture {
  url: string;
  headers: IncomingHttpHeaders;
  payload: OtlpLogsPayload;
}

interface Collector {
  endpoint: string;
  captures: Capture[];
  close(): Promise<void>;
}

/** A collector stand-in. `reply` decides the status per request (1-based). */
async function startCollector(
  reply: (requestNumber: number) => { status: number; body?: string } = () => ({ status: 200 }),
): Promise<Collector> {
  const captures: Capture[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      captures.push({
        url: req.url ?? '',
        headers: req.headers,
        payload: JSON.parse(text) as OtlpLogsPayload,
      });
      const { status, body } = reply(captures.length);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(body ?? '{}');
    });
  });

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  return {
    endpoint: `http://127.0.0.1:${port}`,
    captures,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close(error => (error ? reject(error) : resolve()));
      }),
  };
}

function attributes(record: { attributes: OtlpAttribute[] }): Record<string, string> {
  return Object.fromEntries(record.attributes.map(a => [a.key, a.value.stringValue]));
}

function records(payload: OtlpLogsPayload): OtlpLogRecord[] {
  return payload.resourceLogs[0].scopeLogs[0].logRecords;
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for condition');
    await new Promise<void>(resolve => setTimeout(resolve, 10));
  }
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

describe('logsEndpoint', () => {
  it('appends /v1/logs to a base endpoint', () => {
    expect(logsEndpoint('http://localhost:4318')).toBe('http://localhost:4318/v1/logs');
    expect(logsEndpoint('http://localhost:4318/')).toBe('http://localhost:4318/v1/logs');
  });

  it('does not double a signal path the caller already gave', () => {
    expect(logsEndpoint('http://localhost:4318/v1/logs')).toBe('http://localhost:4318/v1/logs');
  });

  it('rejects a non-http endpoint', () => {
    expect(() => new OtlpReceiptSink({ endpoint: 'ftp://collector' })).toThrow(/http or https/);
  });
});

// ---------------------------------------------------------------------------
// Wire shape
// ---------------------------------------------------------------------------

describe('OtlpReceiptSink wire format', () => {
  it('posts one logRecord per receipt to <endpoint>/v1/logs', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      flushIntervalMs: 0,
      headers: { authorization: 'Bearer token' },
    });
    const receipt = makeReceipt('allow');

    sink.send(receipt);
    await sink.flush();

    expect(collector.captures).toHaveLength(1);
    const capture = collector.captures[0];
    expect(capture.url).toBe('/v1/logs');
    expect(capture.headers['content-type']).toBe('application/json');
    expect(capture.headers['authorization']).toBe('Bearer token');

    const resource = attributes(capture.payload.resourceLogs[0].resource);
    expect(resource).toEqual({
      'service.name': 'hushspec',
      'hushspec.sdk': SDK_NAME,
      'hushspec.sdk.version': SDK_VERSION,
      'hushspec.spec_version': HUSHSPEC_VERSION,
    });

    const logRecords = records(capture.payload);
    expect(logRecords).toHaveLength(1);
    const record = logRecords[0];
    expect(record.timeUnixNano).toBe(String(BigInt(Date.parse(receipt.timestamp)) * 1_000_000n));
    expect(record.severityText).toBe('INFO');
    expect(record.body.stringValue).toBe(canonicalJson(receipt));
    expect(attributes(record)).toEqual({
      'hushspec.entry_type': 'receipt',
      'hushspec.receipt_version': '0.2',
      'hushspec.decision': 'allow',
      'hushspec.action_type': 'egress',
      'hushspec.matched_rule': 'rules.egress.allow',
      'hushspec.policy.content_hash': receipt.policy.content_hash,
      'hushspec.receipt_hash': receiptHash(receipt),
      'hushspec.enforcement.mode': 'enforce',
      'hushspec.enforcement.outcome': 'allowed',
    });

    await sink.close();
    await collector.close();
  });

  it('maps decisions onto severities', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({ endpoint: collector.endpoint, flushIntervalMs: 0 });

    sink.send(makeReceipt('allow'));
    sink.send(makeReceipt('warn'));
    sink.send(makeReceipt('deny'));
    await sink.flush();

    const logRecords = records(collector.captures[0].payload);
    expect(logRecords.map(r => r.severityText)).toEqual(['INFO', 'WARN', 'ERROR']);
    expect(logRecords.map(r => r.severityNumber)).toEqual([9, 13, 17]);

    await sink.close();
    await collector.close();
  });

  it('carries a service name override', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      serviceName: 'deploy-bot',
      flushIntervalMs: 0,
    });

    sink.send(makeReceipt('deny'));
    await sink.flush();

    const resource = attributes(collector.captures[0].payload.resourceLogs[0].resource);
    expect(resource['service.name']).toBe('deploy-bot');

    await sink.close();
    await collector.close();
  });

  it('exports policy events as INFO records with their own entry type', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({ endpoint: collector.endpoint, flushIntervalMs: 0 });
    const loaded = makePolicyEvent('loaded');
    const swapped = makePolicyEvent('swapped');

    sink.recordPolicyEvent(loaded);
    sink.recordPolicyEvent(swapped);
    await sink.flush();

    const logRecords = records(collector.captures[0].payload);
    expect(logRecords).toHaveLength(2);
    expect(logRecords[0].severityText).toBe('INFO');
    expect(logRecords[0].body.stringValue).toBe(canonicalizeValue(loaded as unknown as JsonValue));
    expect(attributes(logRecords[0])).toEqual({
      'hushspec.entry_type': 'policy_loaded',
      'hushspec.policy.content_hash': loaded.policy.content_hash,
      'hushspec.enforcement.mode': 'enforce',
    });
    expect(attributes(logRecords[1])['hushspec.entry_type']).toBe('policy_swapped');
    expect(logRecords[1].timeUnixNano).toBe(
      String(BigInt(Date.parse(swapped.timestamp)) * 1_000_000n),
    );

    await sink.close();
    await collector.close();
  });
});

// ---------------------------------------------------------------------------
// Batching
// ---------------------------------------------------------------------------

describe('OtlpReceiptSink batching', () => {
  it('exports a full batch without being flushed', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      batchSize: 2,
      flushIntervalMs: 0,
    });

    sink.send(makeReceipt('allow'));
    sink.send(makeReceipt('deny'));
    await waitFor(() => collector.captures.length === 1);

    expect(records(collector.captures[0].payload)).toHaveLength(2);

    await sink.close();
    await collector.close();
  });

  it('splits a backlog into batch-sized requests', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      batchSize: 2,
      flushIntervalMs: 0,
    });

    for (let index = 0; index < 5; index += 1) sink.send(makeReceipt('allow'));
    await sink.flush();

    expect(collector.captures.map(c => records(c.payload).length)).toEqual([2, 2, 1]);

    await sink.close();
    await collector.close();
  });

  it('send() does not block on the export', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      batchSize: 1,
      flushIntervalMs: 0,
    });

    sink.send(makeReceipt('allow'));
    // Synchronously after send(), nothing has left the process yet.
    expect(collector.captures).toHaveLength(0);
    await sink.flush();
    expect(collector.captures).toHaveLength(1);

    await sink.close();
    await collector.close();
  });

  it('flushes on the timer without an explicit flush()', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      batchSize: 100,
      flushIntervalMs: 10,
    });

    // The batch is nowhere near `batchSize`, so only the timer can export it.
    sink.send(makeReceipt('warn'));
    await waitFor(() => collector.captures.length === 1);

    const exported = records(collector.captures[0].payload);
    expect(exported).toHaveLength(1);
    expect(exported[0].severityText).toBe('WARN');
    expect(sink.queued).toBe(0);

    await sink.close();
    await collector.close();
  });

  it('close() exports the backlog and refuses later entries', async () => {
    const collector = await startCollector();
    const errors: Error[] = [];
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      batchSize: 100,
      flushIntervalMs: 0,
      onError: error => errors.push(error),
    });

    sink.send(makeReceipt('allow'));
    await sink.close();
    expect(collector.captures).toHaveLength(1);

    sink.send(makeReceipt('deny'));
    await sink.flush();
    expect(collector.captures).toHaveLength(1);
    expect(sink.dropped).toBe(1);
    expect(errors.some(error => /closed/.test(error.message))).toBe(true);

    await collector.close();
  });
});

// ---------------------------------------------------------------------------
// Retries
// ---------------------------------------------------------------------------

describe('OtlpReceiptSink retries', () => {
  it('retries a 5xx with backoff and succeeds', async () => {
    const collector = await startCollector(n => ({ status: n < 3 ? 503 : 200 }));
    const errors: Error[] = [];
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      flushIntervalMs: 0,
      retryBackoffMs: 1,
      onError: error => errors.push(error),
    });

    sink.send(makeReceipt('deny'));
    await sink.flush();

    expect(collector.captures).toHaveLength(3);
    expect(errors).toEqual([]);

    await sink.close();
    await collector.close();
  });

  it('gives up after maxRetries and reports the failure', async () => {
    const collector = await startCollector(() => ({ status: 500, body: 'boom' }));
    const errors: Error[] = [];
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      flushIntervalMs: 0,
      maxRetries: 2,
      retryBackoffMs: 1,
      onError: error => errors.push(error),
    });

    sink.send(makeReceipt('deny'));
    await sink.flush();

    expect(collector.captures).toHaveLength(3); // first attempt + 2 retries
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(OtlpExportError);
    expect((errors[0] as OtlpExportError).entries).toBe(1);
    expect(errors[0].message).toContain('500');

    await sink.close();
    await collector.close();
  });

  it('does not retry a 4xx', async () => {
    const collector = await startCollector(() => ({ status: 400, body: 'bad request' }));
    const errors: Error[] = [];
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      flushIntervalMs: 0,
      retryBackoffMs: 1,
      onError: error => errors.push(error),
    });

    sink.send(makeReceipt('allow'));
    await sink.flush();

    expect(collector.captures).toHaveLength(1);
    expect(errors).toHaveLength(1);
    expect(errors[0].message).toContain('400');

    await sink.close();
    await collector.close();
  });

  it('reports a network failure without throwing into send()', async () => {
    const collector = await startCollector();
    const endpoint = collector.endpoint;
    await collector.close();

    const errors: Error[] = [];
    const sink = new OtlpReceiptSink({
      endpoint,
      flushIntervalMs: 0,
      maxRetries: 1,
      retryBackoffMs: 1,
      onError: error => errors.push(error),
    });

    expect(() => sink.send(makeReceipt('deny'))).not.toThrow();
    await sink.flush();

    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(OtlpExportError);

    await sink.close();
  });
});

// ---------------------------------------------------------------------------
// Bounded queue
// ---------------------------------------------------------------------------

describe('OtlpReceiptSink overflow', () => {
  it('drops entries past maxQueue, counts them, and reports each drop', () => {
    const errors: Error[] = [];
    const sink = new OtlpReceiptSink({
      // Nothing is exported in this test: batchSize exceeds maxQueue, so the
      // queue fills without a drain ever being triggered.
      endpoint: 'http://127.0.0.1:1',
      batchSize: 100,
      maxQueue: 2,
      flushIntervalMs: 0,
      onError: error => errors.push(error),
    });

    for (let index = 0; index < 5; index += 1) sink.send(makeReceipt('allow'));

    expect(sink.queued).toBe(2);
    expect(sink.dropped).toBe(3);
    expect(errors).toHaveLength(3);
    expect(errors[0]).toBeInstanceOf(OtlpQueueOverflowError);
    expect((errors[2] as OtlpQueueOverflowError).dropped).toBe(3);
    expect(errors[0].message).toContain('queue is full');
  });

  it('keeps the oldest entries when the queue overflows', async () => {
    const collector = await startCollector();
    const sink = new OtlpReceiptSink({
      endpoint: collector.endpoint,
      batchSize: 100,
      maxQueue: 1,
      flushIntervalMs: 0,
    });

    const kept = makeReceipt('deny');
    sink.send(kept);
    sink.send({ ...makeReceipt('allow'), receipt_id: '01994b7e-2c1a-7c3e-8f4a-ffffffffffff' });
    await sink.flush();

    const logRecords = records(collector.captures[0].payload);
    expect(logRecords).toHaveLength(1);
    expect(logRecords[0].body.stringValue).toBe(canonicalJson(kept));
    expect(sink.dropped).toBe(1);

    await sink.close();
    await collector.close();
  });

  it('survives an onError handler that throws', () => {
    const sink = new OtlpReceiptSink({
      endpoint: 'http://127.0.0.1:1',
      batchSize: 100,
      maxQueue: 1,
      flushIntervalMs: 0,
      onError: () => {
        throw new Error('handler exploded');
      },
    });

    sink.send(makeReceipt('allow'));
    expect(() => sink.send(makeReceipt('allow'))).not.toThrow();
    expect(sink.dropped).toBe(1);
  });
});
