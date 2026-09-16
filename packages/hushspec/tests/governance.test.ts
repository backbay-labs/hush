import { describe, it, expect } from 'vitest';
import { parse } from '../src/parse.js';
import { validate } from '../src/validate.js';

/**
 * Governance metadata parity (core spec 2.5). Every warning and error asserted
 * here is produced verbatim by the Rust, Python and Go validators too -- the
 * wording is the contract, not an implementation detail.
 */

const RULES = 'rules:\n  egress:\n    allow: ["api.example.com"]\n    default: block\n';

/**
 * A document is rejected either at parse (structural problems the raw pass
 * catches) or by `validate`; callers here only care that it *is* rejected, so
 * both paths collapse into one result.
 */
function check(metadata: string): { valid: boolean; warnings: string[]; errors: { code: string; message: string }[] } {
  const parsed = parse(`hushspec: "0.2.0"\nname: governed\nmetadata:\n${metadata}${RULES}`);
  if (!parsed.ok) {
    return { valid: false, warnings: [], errors: [{ code: 'parse_error', message: parsed.error }] };
  }
  const result = validate(parsed.value);
  return { valid: result.valid, warnings: result.warnings, errors: result.errors };
}

describe('governance metadata', () => {
  it('warns when the author approved their own policy', () => {
    const result = check('  author: "security@example.com"\n  approved_by: "  Security@Example.com "\n  approval_date: "2024-03-15"\n');
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain(
      "author and approved_by are the same identity 'security@example.com': separation of duties requires a different approver",
    );
  });

  it('does not warn when the approver differs from the author', () => {
    const result = check('  author: "security@example.com"\n  approved_by: "ciso@example.com"\n  approval_date: "2024-03-15"\n');
    expect(result.warnings).toEqual([]);
  });

  it('warns when an approved policy has no approver', () => {
    const result = check('  lifecycle_state: approved\n');
    expect(result.warnings).toContain("lifecycle_state is 'approved' but no approved_by is set");
  });

  it('warns when the next review date has passed', () => {
    const result = check('  next_review_date: "2020-01-01"\n');
    expect(result.warnings).toContain("policy next_review_date '2020-01-01' is in the past");
  });

  it('warns when the changelog is not newest-first', () => {
    const result = check(
      '  changelog:\n' +
        '    - version: "1"\n      date: "2024-01-01"\n      summary: "first"\n' +
        '    - version: "2"\n      date: "2024-07-01"\n      summary: "second"\n',
    );
    expect(result.warnings).toContain(
      'changelog entries are not in descending version/date order at entry 1',
    );
  });

  it('accepts a newest-first changelog', () => {
    const result = check(
      '  changelog:\n' +
        '    - version: "2"\n      date: "2024-07-01"\n      summary: "second"\n' +
        '    - version: "1"\n      date: "2024-01-01"\n      summary: "first"\n',
    );
    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('rejects a date that is not a real calendar day', () => {
    for (const value of ['2026-13-45', '2023-02-29', '2024-1-01', '01/02/2026']) {
      const result = check(`  expiry_date: "${value}"\n`);
      expect(result.valid, value).toBe(false);
      expect(result.errors.map(e => e.message).join('\n'), value).toContain('is not an ISO 8601 date');
    }
  });

  it('accepts a leap day in a leap year', () => {
    expect(check('  expiry_date: "2024-02-29"\n').valid).toBe(true);
  });

  it('rejects a policy that supersedes its own version', () => {
    const result = check('  policy_version: 4\n  supersedes: "4"\n');
    expect(result.valid).toBe(false);
    expect(result.errors.map(e => e.message).join('\n')).toContain(
      "metadata.supersedes '4' is the policy's own policy_version",
    );
  });

  it('accepts a policy that supersedes the previous version', () => {
    expect(check('  policy_version: 4\n  supersedes: "3"\n').valid).toBe(true);
  });

  it('rejects an unknown key inside a changelog entry', () => {
    const result = check(
      '  changelog:\n    - version: "1"\n      date: "2024-01-01"\n      summary: "first"\n      reason: "nope"\n',
    );
    expect(result.valid).toBe(false);
  });

  it('rejects a changelog entry missing its required fields', () => {
    const result = check('  changelog:\n    - version: "1"\n');
    expect(result.valid).toBe(false);
    expect(result.valid).toBe(false);
    expect(result.errors.map(e => e.message).join('\n')).toContain(
      'metadata.changelog[0].date is required',
    );
  });

  it('accepts owner, reviewers and supersedes', () => {
    const result = check(
      '  owner: "platform-security@example.com"\n  reviewers:\n    - "appsec@example.com"\n  supersedes: "3"\n',
    );
    expect(result.valid).toBe(true);
  });
});
