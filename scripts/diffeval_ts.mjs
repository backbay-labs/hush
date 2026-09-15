#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distEntry = path.join(root, 'packages', 'hushspec', 'dist', 'index.js');
const { parse, validate, resolve, evaluateTraced, evaluateWithDetection, contentHash } =
  await import(distEntry);

if (process.argv.length !== 3) {
  console.error('usage: diffeval_ts.mjs <bundle.json>');
  process.exit(2);
}

const bundle = JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (bundle.hushspec_diff !== '0.1.0') {
  console.error(`unsupported hushspec_diff version: ${bundle.hushspec_diff}`);
  process.exit(2);
}

const results = {};
// Canonical content hash per group (spec/hushspec-canonical.md section 5),
// keyed by group id alongside the per-action `results`. Only groups whose
// policy survived parse -> resolve -> validate have one: the canonical form is
// defined for resolved, valid documents only, and the oracle has nothing to
// compare against for a rejected policy.
const contentHashes = {};
for (const group of bundle.groups) {
  let spec = null;
  let rejection = null;
  const parsed = parse(YAML.stringify(group.policy));
  if (!parsed.ok) {
    rejection = { status: 'rejected', phase: 'parse', message: parsed.error };
  } else {
    // parse -> resolve -> validate -> evaluate, the same order the Rust oracle
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
    try {
      contentHashes[group.id] = contentHash(spec);
    } catch (error) {
      // A canonicalization failure is a divergence to report, not a silently
      // missing key: the oracle hashes every accepted policy.
      contentHashes[group.id] = `error: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  for (const caseAction of group.actions) {
    const key = `${group.id}/${caseAction.id}`;
    if (rejection) {
      results[key] = rejection;
      continue;
    }
    try {
      // Detection-aware result plus the base evaluator's trace. Detection
      // never re-runs the rule blocks, so the trace of the plain traced
      // evaluation is the trace behind the detection-aware verdict.
      const traced = evaluateTraced(spec, caseAction.action);
      const result = evaluateWithDetection(spec, caseAction.action).evaluation;
      const normalized = { decision: result.decision };
      if (result.matched_rule != null) normalized.matched_rule = result.matched_rule;
      if (result.reason != null) normalized.reason = result.reason;
      if (result.origin_profile != null) normalized.origin_profile = result.origin_profile;
      if (result.posture != null) {
        normalized.posture = { current: result.posture.current, next: result.posture.next };
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
  `${JSON.stringify({ sdk: 'typescript', results, content_hash: contentHashes })}\n`,
);
