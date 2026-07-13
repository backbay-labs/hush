#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distEntry = path.join(root, 'packages', 'hushspec', 'dist', 'index.js');
const { parse, validate, evaluate } = await import(distEntry);

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
for (const group of bundle.groups) {
  let spec = null;
  let rejection = null;
  const parsed = parse(YAML.stringify(group.policy));
  if (!parsed.ok) {
    rejection = { status: 'rejected', phase: 'parse', message: parsed.error };
  } else {
    const validation = validate(parsed.value);
    if (!validation.valid) {
      rejection = {
        status: 'rejected',
        phase: 'validate',
        message: validation.errors[0]?.message ?? 'invalid HushSpec document',
      };
    } else {
      spec = parsed.value;
    }
  }

  for (const caseAction of group.actions) {
    const key = `${group.id}/${caseAction.id}`;
    if (rejection) {
      results[key] = rejection;
      continue;
    }
    try {
      const result = evaluate(spec, caseAction.action);
      const normalized = { decision: result.decision };
      if (result.matched_rule != null) normalized.matched_rule = result.matched_rule;
      if (result.reason != null) normalized.reason = result.reason;
      if (result.origin_profile != null) normalized.origin_profile = result.origin_profile;
      if (result.posture != null) {
        normalized.posture = { current: result.posture.current, next: result.posture.next };
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

process.stdout.write(`${JSON.stringify({ sdk: 'typescript', results })}\n`);
