import { describe, it, expect } from 'vitest';
import {
  evaluateCondition,
  timezoneIsKnown,
  validateCondition,
  validateConditions,
  type Condition,
  type RuntimeContext,
} from '../src/conditions.js';
import { evaluateWithContext } from '../src/evaluate.js';
import type { HushSpec } from '../src/schema.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ctxWithEnv(env: string): RuntimeContext {
  return { environment: env };
}

function ctxWithTime(time: string): RuntimeContext {
  return { current_time: time };
}

function ctxWithUserRole(role: string): RuntimeContext {
  return { user: { role } };
}

function makeEgressSpec(): HushSpec {
  return {
    hushspec: '0.1.0',
    name: 'conditional-test',
    rules: {
      egress: {
        enabled: true,
        allow: ['api.openai.com'],
        default: 'block',
      },
    },
  };
}

function makeToolAccessSpec(): HushSpec {
  return {
    hushspec: '0.1.0',
    name: 'conditional-tool-test',
    rules: {
      tool_access: {
        enabled: true,
        allow: ['deploy'],
        block: ['danger_tool'],
        default: 'block',
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Context conditions
// ---------------------------------------------------------------------------

describe('evaluateCondition', () => {
  describe('context conditions', () => {
    it('matches environment', () => {
      const cond: Condition = {
        context: { environment: 'production' },
      };
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(true);
    });

    it('rejects mismatch', () => {
      const cond: Condition = {
        context: { environment: 'production' },
      };
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(false);
    });

    it('missing context field fails closed', () => {
      const cond: Condition = {
        context: { 'user.role': 'admin' },
      };
      expect(evaluateCondition(cond, {})).toBe(false);
    });

    it('matches user role', () => {
      const cond: Condition = {
        context: { 'user.role': 'admin' },
      };
      expect(evaluateCondition(cond, ctxWithUserRole('admin'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithUserRole('viewer'))).toBe(false);
    });

    it('array of expected values (OR within a key)', () => {
      const cond: Condition = {
        context: { environment: ['production', 'staging'] },
      };
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('development'))).toBe(false);
    });

    it('scalar expected vs array actual (membership check)', () => {
      const ctx: RuntimeContext = {
        user: { groups: ['engineering', 'ml-team'] },
      };
      const cond: Condition = {
        context: { 'user.groups': 'ml-team' },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);
    });

    // An array expected value against an array actual value matches when the
    // sets intersect, not when they are equal (core spec 3.13).
    it('array expected vs array actual matches when the sets intersect', () => {
      const ctx: RuntimeContext = {
        user: { groups: ['engineering', 'ml-team'] },
      };
      const cond: Condition = {
        context: { 'user.groups': ['ml-team', 'sre'] },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);
    });

    it('array expected vs array actual does not match when the sets are disjoint', () => {
      const ctx: RuntimeContext = {
        user: { groups: ['engineering', 'ml-team'] },
      };
      const cond: Condition = {
        context: { 'user.groups': ['sre', 'finance'] },
      };
      expect(evaluateCondition(cond, ctx)).toBe(false);
    });

    // An array expected value against a scalar actual value matches when the
    // scalar is a member of the array, for numbers and booleans as well as
    // strings (core spec 3.13).
    it('array of expected numbers matches a scalar actual number (membership)', () => {
      const ctx: RuntimeContext = {
        session: { action_count: 2 },
      };
      const cond: Condition = {
        context: { 'session.action_count': [1, 2, 3] },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);
    });

    it('array of expected numbers rejects a scalar actual number outside the set', () => {
      const ctx: RuntimeContext = {
        session: { action_count: 9 },
      };
      const cond: Condition = {
        context: { 'session.action_count': [1, 2, 3] },
      };
      expect(evaluateCondition(cond, ctx)).toBe(false);
    });

    it('array of expected booleans matches a scalar actual boolean (membership)', () => {
      const ctx: RuntimeContext = {
        request: { interactive: true },
      };
      const cond: Condition = {
        context: { 'request.interactive': [true] },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);
    });

    it('array of expected booleans rejects a scalar actual boolean outside the set', () => {
      const ctx: RuntimeContext = {
        request: { interactive: false },
      };
      const cond: Condition = {
        context: { 'request.interactive': [true] },
      };
      expect(evaluateCondition(cond, ctx)).toBe(false);
    });

    it('numbers compare exactly, with no tolerance', () => {
      const cond: Condition = {
        context: { 'custom.ratio': 0.3 },
      };
      expect(evaluateCondition(cond, { custom: { ratio: 0.3 } })).toBe(true);
      expect(evaluateCondition(cond, { custom: { ratio: 0.30000000000000004 } })).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Time window conditions
  // -----------------------------------------------------------------------

  describe('time window conditions', () => {
    it('matches during business hours', () => {
      const ctx = ctxWithTime('2026-01-14T10:30:00Z');
      const cond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);
    });

    it('rejects outside hours', () => {
      const ctx = ctxWithTime('2026-01-14T20:00:00Z');
      const cond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(cond, ctx)).toBe(false);
    });

    it('filters by day of week', () => {
      // 2026-01-14 is a Wednesday
      const ctx = ctxWithTime('2026-01-14T10:00:00Z');

      const weekdayCond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
          days: ['mon', 'tue', 'wed', 'thu', 'fri'],
        },
      };
      expect(evaluateCondition(weekdayCond, ctx)).toBe(true);

      const weekendCond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
          days: ['sat', 'sun'],
        },
      };
      expect(evaluateCondition(weekendCond, ctx)).toBe(false);
    });

    it('wraps midnight', () => {
      const condNight: Condition = {
        time_window: {
          start: '22:00',
          end: '06:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(condNight, ctxWithTime('2026-01-14T23:00:00Z'))).toBe(true);
      expect(evaluateCondition(condNight, ctxWithTime('2026-01-14T03:00:00Z'))).toBe(true);
      expect(evaluateCondition(condNight, ctxWithTime('2026-01-14T10:00:00Z'))).toBe(false);
    });

    it('same start and end means all day', () => {
      const cond: Condition = {
        time_window: {
          start: '12:00',
          end: '12:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(cond, ctxWithTime('2026-01-14T03:00:00Z'))).toBe(true);
    });

    it('supports minute offsets in numeric timezones', () => {
      const cond: Condition = {
        time_window: {
          start: '05:30',
          end: '06:30',
          timezone: '+05:30',
        },
      };
      expect(evaluateCondition(cond, ctxWithTime('2026-01-14T00:15:00Z'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithTime('2026-01-14T01:15:00Z'))).toBe(false);
    });

    it('uses real IANA timezone offsets including dst', () => {
      const cond: Condition = {
        time_window: {
          start: '08:30',
          end: '09:30',
          timezone: 'America/New_York',
        },
      };
      expect(evaluateCondition(cond, ctxWithTime('2026-01-14T13:45:00Z'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithTime('2026-07-14T12:45:00Z'))).toBe(true);
    });

    it('keeps the prior day for post-midnight portions of a wrapped window', () => {
      const cond: Condition = {
        time_window: {
          start: '22:00',
          end: '06:00',
          timezone: 'UTC',
          days: ['fri'],
        },
      };
      expect(evaluateCondition(cond, ctxWithTime('2026-01-17T03:00:00Z'))).toBe(true);
    });

    it('keeps the block active when the timezone cannot be resolved', () => {
      // Core spec 3.13: a window the engine cannot evaluate must not switch a
      // control off, so an unresolvable zone leaves the rule block ACTIVE.
      const cond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'America/NeYork',
        },
      };
      expect(evaluateCondition(cond, ctxWithTime('2026-01-14T13:30:00Z'))).toBe(true);
    });

    it('keeps the block active when current_time cannot be parsed', () => {
      const cond: Condition = {
        time_window: { start: '09:00', end: '17:00', timezone: 'UTC' },
      };
      expect(evaluateCondition(cond, { current_time: 'not-a-timestamp' })).toBe(true);
    });

    it('keeps the block active for a malformed HH:MM that escaped validation', () => {
      const cond: Condition = {
        time_window: { start: '25:00', end: '17:00', timezone: 'UTC' },
      };
      expect(evaluateCondition(cond, ctxWithTime('2026-01-14T13:30:00Z'))).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Compound conditions
  // -----------------------------------------------------------------------

  describe('compound conditions', () => {
    it('all_of requires all conditions', () => {
      const cond: Condition = {
        all_of: [
          { context: { environment: 'production' } },
          { context: { 'user.role': 'admin' } },
        ],
      };

      const fullCtx: RuntimeContext = {
        environment: 'production',
        user: { role: 'admin' },
      };
      expect(evaluateCondition(cond, fullCtx)).toBe(true);

      // Only env matches
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(false);
    });

    it('any_of requires any condition', () => {
      const cond: Condition = {
        any_of: [
          { context: { environment: 'production' } },
          { context: { environment: 'staging' } },
        ],
      };

      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('development'))).toBe(false);
    });

    it('treats empty any_of as unset', () => {
      const cond: Condition = {
        any_of: [],
      };

      expect(evaluateCondition(cond, ctxWithEnv('development'))).toBe(true);
    });

    it('not negates condition', () => {
      const cond: Condition = {
        not: { context: { environment: 'production' } },
      };

      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(false);
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(true);
    });

    it('nested compound conditions', () => {
      // Business hours AND production AND (admin OR sre)
      const cond: Condition = {
        all_of: [
          {
            time_window: {
              start: '09:00',
              end: '17:00',
              timezone: 'UTC',
            },
          },
          { context: { environment: 'production' } },
          {
            any_of: [
              { context: { 'user.role': 'admin' } },
              { context: { 'user.role': 'sre' } },
            ],
          },
        ],
      };

      const ctx: RuntimeContext = {
        environment: 'production',
        current_time: '2026-01-14T10:00:00Z',
        user: { role: 'admin' },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);

      const ctxViewer: RuntimeContext = {
        ...ctx,
        user: { role: 'viewer' },
      };
      expect(evaluateCondition(cond, ctxViewer)).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('empty condition is always true', () => {
      expect(evaluateCondition({}, {})).toBe(true);
    });

    it('keeps the block active past the nesting cap', () => {
      // Validation rejects this at parse time; at evaluation time a condition
      // the engine cannot evaluate must leave the block ACTIVE (core spec 3.13).
      let cond: Condition = { context: { environment: 'nowhere' } };
      for (let i = 0; i < 12; i++) {
        cond = { all_of: [cond] };
      }
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// evaluateWithContext
// ---------------------------------------------------------------------------

describe('evaluateWithContext', () => {
  it('passes when condition is met', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'api.openai.com' };
    const ctx: RuntimeContext = { environment: 'production' };
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('allow');
  });

  it('skips rule when condition fails', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const ctx: RuntimeContext = { environment: 'staging' };
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('allow');
  });

  it('enforces rule when condition is met', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const ctx: RuntimeContext = { environment: 'production' };
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('deny');
  });

  it('no conditions behaves like evaluate', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const ctx: RuntimeContext = {};
    const conditions: Record<string, Condition> = {};

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('deny');
  });

  // The target is on the block list, so the window decides the outcome: an
  // allowlisted target would answer `allow` whether or not the condition was
  // applied at all.
  it('tool access with time window condition', () => {
    const spec = makeToolAccessSpec();
    const action = { type: 'tool_call', target: 'danger_tool' };
    const conditions: Record<string, Condition> = {
      tool_access: {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
        },
      },
    };

    const ctxInside: RuntimeContext = { current_time: '2026-01-14T10:00:00Z' };
    const resultInside = evaluateWithContext(spec, action, ctxInside, conditions);
    expect(resultInside.decision).toBe('deny');

    const ctxOutside: RuntimeContext = { current_time: '2026-01-14T20:00:00Z' };
    const resultOutside = evaluateWithContext(spec, action, ctxOutside, conditions);
    expect(resultOutside.decision).toBe('allow');
  });

  // A context field the engine did not supply makes the predicate false, so
  // the block is inert and the blocked target is not denied. The supplied
  // context is asserted beside it, because a target the policy allows anyway
  // would answer `allow` either way.
  it('missing context fails closed', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const missing = evaluateWithContext(spec, action, {}, conditions);
    expect(missing.decision).toBe('allow');

    const supplied = evaluateWithContext(
      spec,
      action,
      { environment: 'production' },
      conditions,
    );
    expect(supplied.decision).toBe('deny');
  });

  it('compound condition', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const conditions: Record<string, Condition> = {
      egress: {
        all_of: [
          { context: { environment: 'production' } },
          { context: { 'user.role': 'admin' } },
        ],
      },
    };

    const fullCtx: RuntimeContext = {
      environment: 'production',
      user: { role: 'admin' },
    };
    const result = evaluateWithContext(spec, action, fullCtx, conditions);
    expect(result.decision).toBe('deny');

    const partialCtx: RuntimeContext = { environment: 'production' };
    const result2 = evaluateWithContext(spec, action, partialCtx, conditions);
    expect(result2.decision).toBe('allow');
  });
});

// ---------------------------------------------------------------------------
// Parse-time validation (core spec 3.13)
// ---------------------------------------------------------------------------

describe('validateCondition', () => {
  it('accepts every well-formed condition form', () => {
    const condition: Condition = {
      time_window: {
        start: '22:00',
        end: '06:00',
        timezone: 'America/New_York',
        days: ['mon', 'TUE', 'wed'],
      },
      any_of: [
        { context: { 'user.role': 'contractor' } },
        { all_of: [{ context: { 'deployment.region': 'eu-west-1' } }, { not: { context: { 'agent.type': 'batch' } } }] },
      ],
    };
    expect(validateCondition(condition, 'rules.egress.when')).toEqual([]);
  });

  it('rejects an out-of-range HH:MM time', () => {
    const errors = validateCondition(
      { time_window: { start: '25:00', end: '06:00' } },
      'rules.shell_commands.when',
    );
    expect(errors).toEqual([
      'rules.shell_commands.when.time_window.start: "25:00" is not a valid HH:MM time',
    ]);
  });

  it('rejects an unknown timezone but accepts a fixed offset', () => {
    expect(
      validateCondition(
        { time_window: { start: '09:00', end: '17:00', timezone: 'Mars/Olympus_Mons' } },
        'rules.egress.when',
      ),
    ).toEqual([
      'rules.egress.when.time_window.timezone: "Mars/Olympus_Mons" is neither an IANA time zone nor a fixed offset',
    ]);
    expect(
      validateCondition(
        { time_window: { start: '09:00', end: '17:00', timezone: '+05:30' } },
        'rules.egress.when',
      ),
    ).toEqual([]);
  });

  it('rejects a day outside mon..sun', () => {
    const errors = validateCondition(
      { time_window: { start: '09:00', end: '17:00', days: ['mon', 'funday'] } },
      'rules.egress.when',
    );
    expect(errors).toEqual([
      'rules.egress.when.time_window.days: "funday" is not one of mon, tue, wed, thu, fri, sat, sun',
    ]);
  });

  it('rejects nesting deeper than eight levels', () => {
    let condition: Condition = { context: { environment: 'production' } };
    for (let i = 0; i < 9; i++) {
      condition = { not: condition };
    }
    const errors = validateCondition(condition, 'rules.shell_commands.when');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('conditions nest deeper than the maximum of 8 levels');
  });

  it('accepts nesting at exactly the cap', () => {
    let condition: Condition = { context: { environment: 'production' } };
    for (let i = 0; i < 8; i++) {
      condition = { not: condition };
    }
    expect(validateCondition(condition, 'rules.shell_commands.when')).toEqual([]);
  });
});

describe('validateConditions', () => {
  it('reports each offending rule block by path', () => {
    const errors = validateConditions({
      egress: { when: { time_window: { start: '09:00', end: '99:00' } } },
      shell_commands: { when: { time_window: { start: '09:00', end: '17:00', days: ['xyz'] } } },
      tool_access: { when: { context: { environment: 'production' } } },
    });
    expect(errors).toHaveLength(2);
    expect(errors[0]).toContain('rules.egress.when.time_window.end');
    expect(errors[1]).toContain('rules.shell_commands.when.time_window.days');
  });
});

describe('timezoneIsKnown', () => {
  it('accepts IANA zones, UTC aliases and fixed offsets', () => {
    for (const zone of ['UTC', 'GMT', 'Etc/UTC', 'America/New_York', 'Europe/London', '+05:30', '-08:00', 'IST']) {
      expect(timezoneIsKnown(zone), zone).toBe(true);
    }
  });

  it('rejects identifiers no engine can resolve', () => {
    for (const zone of ['Mars/Olympus_Mons', 'Not/AZone', '+99:00', '']) {
      expect(timezoneIsKnown(zone), zone).toBe(false);
    }
  });
});

describe('fixed-offset timezone grammar', () => {
  it('accepts two-digit hour and minute fields', () => {
    for (const zone of ['+05:30', '-08:00', '+05', '-08', '+00:00']) {
      expect(timezoneIsKnown(zone), zone).toBe(true);
    }
  });

  // A zone the engine cannot resolve leaves the rule block active (core spec
  // 3.13), so an offset another engine refuses must not resolve here either.
  it('rejects one-digit fields, a missing colon and a doubled sign', () => {
    for (const zone of ['+5', '+0530', '+5:0', '++5', '+05:3', '+ 5:30', '+05:30 ']) {
      expect(timezoneIsKnown(zone), zone).toBe(false);
    }
  });
});

describe('rate predicate', () => {
  const gte: Condition = {
    rate: { counter: 'shell_commands', threshold: 5, comparison: 'gte' },
  };

  it('compares at the threshold', () => {
    expect(evaluateCondition(gte, { counters: { shell_commands: 4 } })).toBe(false);
    expect(evaluateCondition(gte, { counters: { shell_commands: 5 } })).toBe(true);
    expect(evaluateCondition(gte, { counters: { shell_commands: 6 } })).toBe(true);
  });

  it('holds when the engine supplied no such counter', () => {
    expect(evaluateCondition(gte, {})).toBe(true);
    expect(evaluateCondition(gte, { counters: { egress_calls: 9 } })).toBe(true);
  });

  // A counter is a non-negative integer (core spec 3.13). Anything else is not
  // a counter the engine supplied, so the predicate is unevaluable and the
  // block stays active rather than being switched off by a malformed value.
  it('holds when the counter is not a non-negative integer', () => {
    const malformed: unknown[] = [
      5.5,
      -1,
      -0.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      '6',
      true,
      null,
    ];
    for (const value of malformed) {
      const context = { counters: { shell_commands: value } } as unknown as RuntimeContext;
      expect(evaluateCondition(gte, context), String(value)).toBe(true);
    }
  });
});
