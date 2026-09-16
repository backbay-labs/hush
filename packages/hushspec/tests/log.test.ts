import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadBuiltin } from '../src/builtin.js';
import { resolutionFromResolved } from '../src/resolve.js';
import type { EvaluationAction } from '../src/evaluate.js';
import {
  ChainedFileSink,
  GENESIS_HASH,
  LOG_VERSION,
  LogChainError,
  computeEntryHash,
  policyLoadedEvent,
  policySwappedEvent,
  thisSdk,
  verifyLog,
  verifyLogFiles,
  verifyLogs,
} from '../src/log.js';
import type { LogEntry, LogVerifyOptions, PolicyEvent } from '../src/log.js';
import {
  deterministicUuidV7,
  evaluateAudited,
  policySummary,
} from '../src/receipt.js';
import type { AuditConfig, AuditContext } from '../src/receipt.js';
import { loadKeyring } from '../src/signing.js';
import { SDK_NAME, SDK_VERSION } from '../src/version.js';
import { schemaErrors, type SchemaDocument } from './helpers/json-schema.js';

/**
 * The hash-linked receipt log (spec/hushspec-log.md, format 0.1): the chained
 * sink, rotation, signing, verification, and the normative vectors under
 * `fixtures/log/`.
 *
 * The vectors are built from the fixed inputs of
 * `fixtures/receipts/expected/README.md`. Every `valid/` file must verify,
 * every `invalid/` one must be rejected at the line its name ends with, and
 * -- because the entry hash is over the canonical form -- writing the same
 * chain here must reproduce it byte for byte.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const vectorsDir = path.join(repoRoot, 'fixtures/log');
const keysDir = path.join(repoRoot, 'fixtures/signing/keys');

const CLOCK_MILLIS = 1_789_473_600_000; // 2026-09-15T12:00:00.000Z
const clock = () => new Date(CLOCK_MILLIS);

const CONFIG: AuditConfig = { enabled: true, includeRuleTrace: true, recordDuration: false };

function ctx(index: number): AuditContext {
  return {
    actor: {
      agent_id: 'fixture-agent',
      session_id: 'fixture-session',
      principal: 'fixture@hushspec.dev',
      runtime: 'hushspec-conformance/0.2',
    },
    timeSource: 'trusted',
    clock: clock(),
    receiptId: deterministicUuidV7(CLOCK_MILLIS, index),
  };
}

function resolution() {
  return resolutionFromResolved(loadBuiltin('default')!, 'builtin:default');
}

/** The `policy_loaded` event the committed vectors were generated with. */
function fixtureLoadedEvent(): PolicyEvent {
  return {
    event: 'loaded',
    timestamp: '2026-09-15T12:00:00.000Z',
    policy: policySummary(resolution()),
    enforcement_mode: 'enforce',
    sdk: { name: 'hushspec-conformance', version: '0.2' },
    spec_version: '0.2.0',
  };
}

function actions(): EvaluationAction[] {
  return [
    { type: 'tool_call', target: 'read_file' },
    { type: 'egress', target: 'api.github.com' },
    { type: 'file_read', target: '/home/me/.ssh/id_rsa' },
  ];
}

function testKey(): string {
  return readFileSync(path.join(keysDir, 'test-signing.key.pem'), 'utf8');
}

function keyring() {
  return loadKeyring(readFileSync(path.join(keysDir, 'keyring.json'), 'utf8'));
}

function verifyOptions(): LogVerifyOptions {
  return { keyring: keyring(), verify: { now: clock(), maxClockSkewSeconds: 300 } };
}

/** Write a chain of policy_loaded + three receipts into `file`. */
function writeBasic(file: string, signed: boolean): ChainedFileSink {
  const resolved = resolution();
  let sink = ChainedFileSink.open(file).withClock(clock());
  if (signed) sink = sink.withSigner(testKey());
  sink.recordPolicyEvent(fixtureLoadedEvent());
  actions().forEach((action, index) => {
    sink.send(evaluateAudited(resolved, action, CONFIG, ctx(index)));
  });
  return sink;
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'hushspec-log-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------- behavior --

describe('ChainedFileSink', () => {
  it('links entries and verifies', () => {
    const file = path.join(dir, 'log.jsonl');
    const sink = writeBasic(file, false);
    expect(sink.head().seq).toBe(4);

    const text = readFileSync(file, 'utf8');
    const entries = text
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as LogEntry);

    expect(entries).toHaveLength(4);
    expect(entries[0].log_version).toBe(LOG_VERSION);
    expect(entries[0].seq).toBe(1);
    expect(entries[0].prev_hash).toBe(GENESIS_HASH);
    expect(entries[0].entry_type).toBe('policy_loaded');
    expect(entries[0].policy_event).toBeDefined();
    for (let index = 1; index < entries.length; index += 1) {
      expect(entries[index].prev_hash).toBe(entries[index - 1].entry_hash);
      expect(entries[index].seq).toBe(entries[index - 1].seq + 1);
    }
    for (const entry of entries) {
      expect(computeEntryHash(entry)).toBe(entry.entry_hash);
    }

    const report = verifyLog('log.jsonl', text);
    expect(report.ok).toBe(true);
    expect(report.entries).toBe(4);
    expect(report.receipts).toBe(3);
    expect(report.policy_events).toBe(1);
    expect(report.last_seq).toBe(4);
    expect(report.last_entry_hash).toBe(entries[3].entry_hash);
  });

  it('fsyncs and reports the head after every append', () => {
    const file = path.join(dir, 'log.jsonl');
    const sink = ChainedFileSink.open(file).withClock(clock());
    expect(sink.head()).toEqual({ seq: 0, entry_hash: GENESIS_HASH });
    const entry = sink.recordPolicyEvent(fixtureLoadedEvent());
    expect(sink.head()).toEqual({ seq: 1, entry_hash: entry.entry_hash });
    expect(readFileSync(file, 'utf8').endsWith('\n')).toBe(true);
  });

  it('continues the chain when the file is reopened', () => {
    const file = path.join(dir, 'log.jsonl');
    const head = writeBasic(file, false).head();

    const reopened = ChainedFileSink.open(file).withClock(clock());
    expect(reopened.head()).toEqual(head);
    reopened.send(evaluateAudited(resolution(), actions()[0], CONFIG, ctx(9)));

    const report = verifyLog('log.jsonl', readFileSync(file, 'utf8'));
    expect(report.ok).toBe(true);
    expect(report.entries).toBe(5);
  });

  it('extends one chain when two sinks share a file', () => {
    const file = path.join(dir, 'log.jsonl');
    const resolved = resolution();
    const first = ChainedFileSink.open(file).withClock(clock());
    const second = ChainedFileSink.open(file).withClock(clock());

    first.recordPolicyEvent(fixtureLoadedEvent());
    actions().forEach((action, index) => {
      const sink = index % 2 === 0 ? second : first;
      sink.send(evaluateAudited(resolved, action, CONFIG, ctx(index)));
    });

    const text = readFileSync(file, 'utf8');
    const entries = text
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as LogEntry);
    expect(entries.map((entry) => entry.seq)).toEqual([1, 2, 3, 4]);

    const report = verifyLog('log.jsonl', text);
    expect(report.ok).toBe(true);
    expect(report.entries).toBe(4);
    expect(report.last_seq).toBe(4);
    expect(second.head()).toEqual({ seq: 4, entry_hash: entries[3].entry_hash });
  });

  it('creates the log directory on demand', () => {
    const file = path.join(dir, 'nested', 'deeper', 'log.jsonl');
    ChainedFileSink.open(file).withClock(clock()).recordPolicyEvent(fixtureLoadedEvent());
    expect(existsSync(file)).toBe(true);
  });

  it('releases the lock file after each append', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    expect(existsSync(`${file}.lock`)).toBe(false);
  });

  it('records swapped events naming the policy they replaced', () => {
    const file = path.join(dir, 'log.jsonl');
    const sink = ChainedFileSink.open(file).withClock(clock());
    const summary = policySummary(resolution());
    sink.recordPolicyEvent(policyLoadedEvent(summary, 'enforce', clock()));
    const entry = sink.recordPolicyEvent(
      policySwappedEvent(summary, 'monitor', `sha256:${'11'.repeat(32)}`, clock()),
    );
    expect(entry.entry_type).toBe('policy_swapped');
    expect(entry.policy_event!.previous_content_hash).toBe(`sha256:${'11'.repeat(32)}`);
    expect(entry.policy_event!.enforcement_mode).toBe('monitor');
    expect(entry.policy_event!.sdk).toEqual({ name: SDK_NAME, version: SDK_VERSION });
    expect(thisSdk()).toEqual({ name: '@hushspec/core', version: SDK_VERSION });

    const report = verifyLog('log.jsonl', readFileSync(file, 'utf8'));
    expect(report.ok).toBe(true);
    expect(report.policy_events).toBe(2);
  });

  it('signs every entry when given a key', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, true);
    const text = readFileSync(file, 'utf8');

    const report = verifyLog('log.jsonl', text, {
      ...verifyOptions(),
      requireSignatures: true,
    });
    expect(report.ok).toBe(true);
    expect(report.signed).toBe(4);
    expect(report.verified_signatures).toBe(4);

    const noKeyring = verifyLog('log.jsonl', text, { requireSignatures: true });
    expect(noKeyring.ok).toBe(false);
    expect(noKeyring.break!.message).toContain('no_keyring');

    const untrusted = verifyLog('log.jsonl', text, {
      requireSignatures: true,
      keyring: loadKeyring(readFileSync(path.join(keysDir, 'keyring-revoked.json'), 'utf8')),
      verify: { now: clock() },
    });
    expect(untrusted.ok).toBe(false);
    expect(untrusted.break!.line).toBe(1);
    expect(untrusted.break!.message).toContain('signature');
  });

  it('rejects unsigned entries when signatures are required', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const report = verifyLog('log.jsonl', readFileSync(file, 'utf8'), {
      ...verifyOptions(),
      requireSignatures: true,
    });
    expect(report.ok).toBe(false);
    expect(report.break!.line).toBe(1);
    expect(report.break!.message).toContain('entry_unsigned');
  });

  it('carries the chain into the next file on rotation', () => {
    const first = path.join(dir, 'log-1.jsonl');
    const second = path.join(dir, 'log-2.jsonl');
    const sink = writeBasic(first, false);
    const lastHash = sink.head().entry_hash;

    const started = sink.rotate(second);
    expect(started.seq).toBe(1);
    expect(started.prev_hash).toBe(lastHash);
    expect(started.log_started!.previous_entry_hash).toBe(lastHash);
    expect(started.log_started!.previous_file).toBe('log-1.jsonl');
    expect(sink.path).toBe(second);
    sink.send(evaluateAudited(resolution(), actions()[1], CONFIG, ctx(7)));

    const both = verifyLogFiles([first, second]);
    expect(both.ok).toBe(true);
    expect(both.files).toBe(2);
    expect(both.entries).toBe(6);

    // The second file alone verifies from its log_started link.
    const alone = verifyLog('log-2.jsonl', readFileSync(second, 'utf8'));
    expect(alone.ok).toBe(true);
    expect(alone.entries).toBe(2);

    // Given out of order, the link breaks on the first line of the second file.
    const reversed = verifyLogFiles([second, first]);
    expect(reversed.ok).toBe(false);
    expect(reversed.break!.line).toBe(1);
  });

  it('carries the genesis hash into a file rotated before anything was written', () => {
    const first = path.join(dir, 'log-1.jsonl');
    const second = path.join(dir, 'log-2.jsonl');
    writeFileSync(first, '');
    const sink = ChainedFileSink.open(first).withClock(clock());

    const started = sink.rotate(second);
    expect(started.prev_hash).toBe(GENESIS_HASH);
    // Recorded even at genesis: a verifier compares it against the previous
    // file's last hash, and an omitted member is not that hash.
    expect(started.log_started!.previous_entry_hash).toBe(GENESIS_HASH);
    sink.send(evaluateAudited(resolution(), actions()[0], CONFIG, ctx(0)));

    const both = verifyLogFiles([first, second]);
    expect(both.ok, JSON.stringify(both.break)).toBe(true);
    expect(both.files).toBe(2);
    expect(both.entries).toBe(2);
  });

  it('refuses to rotate into a file that already exists', () => {
    const first = path.join(dir, 'log-1.jsonl');
    const second = path.join(dir, 'log-2.jsonl');
    writeBasic(first, false);
    writeBasic(second, false);
    expect(() => ChainedFileSink.open(first).rotate(second)).toThrow(LogChainError);
  });

  it('refuses to continue a file whose tail has no usable chain head', () => {
    // A tail read loosely would seed the next entry from a `seq` that is not a
    // number or an `entry_hash` that is not a string, forking the chain.
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const text = readFileSync(file, 'utf8');
    for (const tail of ['{"seq":"5","entry_hash":"sha256:00"}', '{"seq":5}', '[]']) {
      writeFileSync(file, `${text}${tail}\n`);
      expect(() => ChainedFileSink.open(file)).toThrow(LogChainError);
    }
  });

  it('refuses to continue a file whose last line is not an entry', () => {
    // Fail closed: continuing a file whose head cannot be read would start a
    // second, unlinked chain inside it.
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    writeFileSync(file, `${readFileSync(file, 'utf8')}not json\n`);
    expect(() => ChainedFileSink.open(file)).toThrow(LogChainError);
  });
});

describe('verifyLog', () => {
  it('reports a null payload member instead of dereferencing it', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line !== '');

    // A receipt entry that carries no receipt is a payload mismatch, the break
    // the other three SDKs report for it.
    const withoutReceipt = { ...(JSON.parse(lines[1]!) as object), receipt: null };
    const broken = verifyLog('t', [lines[0], JSON.stringify(withoutReceipt)].join('\n'));
    expect(broken.ok).toBe(false);
    expect(broken.break!.line).toBe(2);
    expect(broken.break!.message).toContain('payload');

    // `signature` is outside the entry hash, so a null one is simply an
    // unsigned entry.
    const unsigned = lines.map((line) => JSON.stringify({ ...(JSON.parse(line) as object), signature: null }));
    const report = verifyLog('t', unsigned.join('\n'));
    expect(report.ok, JSON.stringify(report.break)).toBe(true);
    expect(report.signed).toBe(0);
  });

  it('rejects an unknown field inside a policy event', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const first = readFileSync(file, 'utf8').split('\n')[0]!;
    const entry = JSON.parse(first) as { policy_event: { policy: Record<string, unknown> } };
    entry.policy_event.policy.rogue = 1;
    const report = verifyLog('t', JSON.stringify(entry));
    expect(report.ok).toBe(false);
    expect(report.break!.message).toContain('rogue');
  });

  it('detects tampering, deletion and reordering at the first broken line', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line !== '');

    const tampered = [lines[0], lines[1], lines[2]!.replace('"allow"', '"deny"'), lines[3]].join(
      '\n',
    );
    const tamperedReport = verifyLog('t', tampered);
    expect(tamperedReport.ok).toBe(false);
    expect(tamperedReport.break!.line).toBe(3);
    expect(tamperedReport.break!.message).toContain('entry_hash');

    const deleted = [lines[0], lines[2], lines[3]].join('\n');
    const deletedReport = verifyLog('t', deleted);
    expect(deletedReport.ok).toBe(false);
    expect(deletedReport.break!.line).toBe(2);
    expect(deletedReport.break!.message).toContain('sequence gap');

    const reordered = [lines[0], lines[2], lines[1], lines[3]].join('\n');
    const reorderedReport = verifyLog('t', reordered);
    expect(reorderedReport.ok).toBe(false);
    expect(reorderedReport.break!.line).toBe(2);

    // Truncation is not detectable from the file alone (log spec 9).
    expect(verifyLog('t', [lines[0], lines[1]].join('\n')).ok).toBe(true);
  });

  it('rejects an unknown log_version', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line !== '');
    const entry = JSON.parse(lines[0]!) as LogEntry;
    entry.log_version = '0.2';
    const report = verifyLog('t', JSON.stringify(entry));
    expect(report.ok).toBe(false);
    expect(report.break!.message).toContain('unsupported log_version');
  });

  it('rejects an unknown field', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line !== '');
    const entry = JSON.parse(lines[0]!) as Record<string, unknown>;
    entry['note'] = 'added later';
    const report = verifyLog('t', JSON.stringify(entry));
    expect(report.ok).toBe(false);
    expect(report.break!.message).toContain('unknown field');
  });

  it('rejects a payload that does not match entry_type', () => {
    const file = path.join(dir, 'log.jsonl');
    const sink = writeBasic(file, false);
    const entry = sink.recordPolicyEvent(fixtureLoadedEvent());
    const mislabeled = { ...entry, entry_type: 'receipt' };
    const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line !== '');
    lines[lines.length - 1] = JSON.stringify(mislabeled);
    const report = verifyLog('t', lines.join('\n'));
    expect(report.ok).toBe(false);
    expect(report.break!.line).toBe(5);
    expect(report.break!.message).toContain('payload');
  });

  it('rejects a receipt that is not format 0.2', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line !== '');
    const entry = JSON.parse(lines[1]!) as LogEntry;
    entry.receipt!.receipt_version = '0.1';
    entry.entry_hash = computeEntryHash(entry);
    const report = verifyLog('t', [lines[0], JSON.stringify(entry)].join('\n'));
    expect(report.ok).toBe(false);
    expect(report.break!.message).toContain('receipt_version');
  });

  it('rejects a signature that names another entry', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, true);
    const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line !== '');
    const entry = JSON.parse(lines[0]!) as LogEntry;
    entry.signature!.content_hash = `sha256:${'00'.repeat(32)}`;
    const report = verifyLog('t', JSON.stringify(entry));
    expect(report.ok).toBe(false);
    expect(report.break!.message).toContain('content_hash');
  });

  it('reports a file it cannot read', () => {
    const report = verifyLogFiles([path.join(dir, 'missing.jsonl')]);
    expect(report.ok).toBe(false);
    expect(report.break!.line).toBe(0);
    expect(report.break!.message).toContain('cannot read');
  });

  it('ignores blank lines', () => {
    const file = path.join(dir, 'log.jsonl');
    writeBasic(file, false);
    const text = readFileSync(file, 'utf8').replace(/\n/g, '\n\n');
    expect(verifyLog('t', text).ok).toBe(true);
  });
});

// ----------------------------------------------------------------- vectors --

const logEntrySchema = JSON.parse(
  readFileSync(path.join(repoRoot, 'schemas/hushspec-log-entry.v1.schema.json'), 'utf8'),
) as SchemaDocument;

/** `invalid/<what>-line-<n>.jsonl` names the line the break must be found on. */
function expectedBreakLine(name: string): number {
  const match = /-(\d+)\.jsonl$/.exec(name);
  expect(match, `${name} must end with the breaking line number`).not.toBeNull();
  return Number(match![1]);
}

describe('log vectors', () => {
  const validDir = path.join(vectorsDir, 'valid');
  const invalidDir = path.join(vectorsDir, 'invalid');

  for (const name of readdirSync(validDir).sort()) {
    it(`verifies valid/${name}`, () => {
      const text = readFileSync(path.join(validDir, name), 'utf8');
      const report = verifyLog(name, text, verifyOptions());
      expect(report.break).toBeUndefined();
      expect(report.ok).toBe(true);
      expect(report.entries).toBeGreaterThan(0);
      for (const line of text.split('\n')) {
        if (line.trim() === '') continue;
        expect(schemaErrors(logEntrySchema, JSON.parse(line) as unknown)).toEqual([]);
      }
    });
  }

  it('verifies the rotated pair in order', () => {
    const first = readFileSync(path.join(validDir, 'rotated-1.jsonl'), 'utf8');
    const second = readFileSync(path.join(validDir, 'rotated-2.jsonl'), 'utf8');
    const report = verifyLogs(
      [
        ['rotated-1', first],
        ['rotated-2', second],
      ],
      verifyOptions(),
    );
    expect(report.ok).toBe(true);
    expect(report.files).toBe(2);
    expect(report.entries).toBe(6);
  });

  for (const name of readdirSync(invalidDir).sort()) {
    it(`rejects invalid/${name} at the line its name names`, () => {
      const text = readFileSync(path.join(invalidDir, name), 'utf8');
      const report = verifyLog(name, text, verifyOptions());
      expect(report.ok, `${name} must be rejected`).toBe(false);
      expect(report.break!.line).toBe(expectedBreakLine(name));
    });
  }

  it('walks both directories', () => {
    expect(readdirSync(validDir)).toHaveLength(4);
    expect(readdirSync(invalidDir).length).toBeGreaterThanOrEqual(5);
  });

  it('reproduces the committed chain: same entry hashes, written by this SDK', () => {
    // The entry hash is over the canonical form, so an SDK that builds the
    // same receipts and links them the same way lands on the same hashes --
    // which is what makes a log portable between implementations.
    const file = path.join(dir, 'basic.jsonl');
    writeBasic(file, false);
    const mine = readFileSync(file, 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as LogEntry);
    const theirs = readFileSync(path.join(validDir, 'basic.jsonl'), 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as LogEntry);

    expect(mine.map((entry) => entry.entry_hash)).toEqual(
      theirs.map((entry) => entry.entry_hash),
    );
  });

  it('reproduces the committed signatures too', () => {
    // Ed25519 is deterministic and the signing input is canonical, so the
    // same key over the same entry hash yields the same bytes.
    const file = path.join(dir, 'signed.jsonl');
    writeBasic(file, true);
    const mine = readFileSync(file, 'utf8');
    const theirs = readFileSync(path.join(validDir, 'signed.jsonl'), 'utf8');
    const signatures = (text: string) =>
      text
        .split('\n')
        .filter((line) => line.trim() !== '')
        .map((line) => (JSON.parse(line) as LogEntry).signature!.signature);
    expect(signatures(mine)).toEqual(signatures(theirs));
  });
});
