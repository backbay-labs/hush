#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distEntry = path.join(root, 'packages', 'hushspec', 'dist', 'index.js');
const {
  parse,
  validate,
  resolve,
  evaluateTraced,
  evaluateAuditedSpec,
  contentHash,
  policySummary,
  resolutionFromResolved,
  receiptHash,
  impliedEnforcement,
  deterministicUuidV7,
  RECEIPT_VERSION,
  formatTimestamp,
} = await import(distEntry);

if (process.argv.length !== 3) {
  console.error('usage: diffeval_ts.mjs <bundle.json>');
  process.exit(2);
}

const bundle = JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (bundle.hushspec_diff !== '0.1.0') {
  console.error(`unsupported hushspec_diff version: ${bundle.hushspec_diff}`);
  process.exit(2);
}

/**
 * The audited inputs every SDK replays so the receipts they record for a case
 * are byte-identical (fixtures/receipts/expected/README.md). A bundle written
 * before the `audit` block existed replays these same defaults.
 */
const DEFAULT_AUDIT = {
  clock: '2026-09-15T12:00:00.000Z',
  time_source: 'trusted',
  enforcement_mode: 'enforce',
  actor: {
    agent_id: 'fixture-agent',
    session_id: 'fixture-session',
    principal: 'fixture@hushspec.dev',
    runtime: 'hushspec-conformance/0.2',
  },
  index_base: 0,
  emit_receipts: false,
};
const audit = { ...DEFAULT_AUDIT, ...(bundle.audit ?? {}) };
const clockMillis = Date.parse(audit.clock);
if (Number.isNaN(clockMillis)) {
  // Fail closed: a clock we cannot read has no reproducible receipts, and
  // falling back to "now" would make this harness disagree with every other
  // one while still looking like it answered.
  console.error(`unreadable audit.clock: ${audit.clock}`);
  process.exit(2);
}
const clock = new Date(clockMillis);

/** Record the trace but never the duration: a receipt's bytes must not depend on the machine. */
const AUDIT_CONFIG = { enabled: true, includeRuleTrace: true, recordDuration: false };

/** The audit context of the case at `position` in the bundle. */
function auditContext(position) {
  return {
    actor: audit.actor,
    enforcementMode: audit.enforcement_mode,
    timeSource: audit.time_source,
    clock,
    receiptId: deterministicUuidV7(clockMillis, audit.index_base + position),
  };
}

/**
 * The group-level `receipt_hash`: a receipt carrying this policy's summary and
 * nothing else that varies (fixed id, the bundle's clock, a reserved action, a
 * deny with an empty trace). Hashed with this SDK's own receipt canonicalizer,
 * so a disagreement means the policy identity our receipts would record --
 * name, version, spec_version, content_hash, extends_chain, signature --
 * differs from the reference's, independently of any one action.
 */
function policyIdentityHash(spec) {
  return receiptHash({
    receipt_version: RECEIPT_VERSION,
    receipt_id: '00000000-0000-7000-8000-000000000000',
    timestamp: formatTimestamp(clock),
    time_source: audit.time_source,
    policy: policySummary(resolutionFromResolved(spec)),
    action: { type: '__hushspec_policy_identity__' },
    decision: 'deny',
    rule_trace: [],
    enforcement: impliedEnforcement('deny', audit.enforcement_mode),
  });
}

const results = {};
// Canonical content hash per group (spec/hushspec-canonical.md section 5),
// keyed by group id alongside the per-action `results`. Only groups whose
// policy survived parse -> resolve -> validate have one: the canonical form is
// defined for resolved, valid documents only, and the reference has nothing to
// compare against for a rejected policy.
const groups = {};
// Position of the next case in the bundle, counting every action of every
// group in order (rejected policies included). `index_base + position` seeds
// that case's receipt id in every SDK, so the counter must advance even when
// there is no receipt to record.
let position = 0;
for (const group of bundle.groups) {
  let spec = null;
  let rejection = null;
  const parsed = parse(YAML.stringify(group.policy));
  if (!parsed.ok) {
    rejection = { status: 'rejected', phase: 'parse', message: parsed.error };
  } else {
    // parse -> resolve -> validate -> evaluate, the same order the reference
    // uses. The generator only emits `builtin:` references, which the default
    // composite loader serves from the SDK's own embedded rulesets.
    let candidate = parsed.value;
    if (candidate.extends != null) {
      const resolved = resolve(candidate);
      if (!resolved.ok) {
        rejection = { status: 'rejected', phase: 'resolve', message: resolved.error };
      } else {
        candidate = resolved.value;
      }
    }
    if (rejection == null) {
      const validation = validate(candidate);
      if (!validation.valid) {
        rejection = {
          status: 'rejected',
          phase: 'validate',
          message: validation.errors[0]?.message ?? 'invalid HushSpec document',
        };
      } else {
        spec = candidate;
      }
    }
  }

  if (spec != null) {
    const entry = {};
    try {
      const hash = contentHash(spec);
      // A canonicalization failure is a divergence to report, not a silently
      // missing key: the reference hashes every accepted policy.
      if (typeof hash === 'string' && hash.startsWith('sha256:')) entry.content_hash = hash;
    } catch {
      /* leave content_hash absent: reported as a divergence */
    }
    try {
      entry.receipt_hash = policyIdentityHash(spec);
    } catch {
      /* leave receipt_hash absent: reported as a divergence */
    }
    groups[group.id] = entry;
  } else {
    groups[group.id] = {};
  }

  for (const caseAction of group.actions) {
    const key = `${group.id}/${caseAction.id}`;
    const caseIndex = position;
    position += 1;
    if (rejection) {
      results[key] = rejection;
      continue;
    }
    try {
      // The audited path is the one an enforcement point runs: it routes
      // through the detection pipeline and records the evidence, so the
      // verdict reported here is read back out of the receipt.
      //
      // The base evaluator's trace comes from an explicit `evaluateTraced`
      // call over the same inputs -- the receipt's own `rule_trace` is the
      // receipt spelling (engine-stage ids, `rule_path`), this one is the
      // evaluator's. Detection never re-runs the rule blocks, so the two
      // agree by construction.
      const traced = evaluateTraced(spec, caseAction.action);
      const receipt = evaluateAuditedSpec(
        spec,
        caseAction.action,
        AUDIT_CONFIG,
        auditContext(caseIndex),
      );
      const normalized = { decision: receipt.decision };
      if (receipt.matched_rule != null) normalized.matched_rule = receipt.matched_rule;
      if (receipt.reason != null) normalized.reason = receipt.reason;
      if (receipt.origin_profile != null) normalized.origin_profile = receipt.origin_profile;
      if (receipt.posture != null) {
        normalized.posture = { current: receipt.posture.current, next: receipt.posture.next };
      }
      if (traced.trace.length > 0) {
        normalized.rule_trace = traced.trace.map(entry => {
          const normalizedEntry = {
            rule_block: entry.rule_block,
            outcome: entry.outcome,
            evaluated: entry.evaluated,
          };
          if (entry.matched_rule != null) normalizedEntry.matched_rule = entry.matched_rule;
          if (entry.reason != null) normalizedEntry.reason = entry.reason;
          return normalizedEntry;
        });
      }
      normalized.receipt_hash = receiptHash(receipt);
      if (audit.emit_receipts) normalized.receipt = receipt;
      results[key] = { status: 'ok', result: normalized };
    } catch (error) {
      results[key] = {
        status: 'error',
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

process.stdout.write(
  // Difftest contract: per-group data lives under `groups`; a rejected policy
  // reports neither hash.
  `${JSON.stringify({ sdk: 'typescript', results, groups })}\n`,
);
