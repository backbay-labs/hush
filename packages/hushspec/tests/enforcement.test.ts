import { describe, it, expect } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import { evaluateAudited, DEFAULT_AUDIT_CONFIG } from '../src/receipt.js';
import type { EnforcementSummary } from '../src/receipt.js';
import { ObservableEvaluator } from '../src/observer.js';
import type { EvaluationCompletedEvent, ObserverEvent } from '../src/observer.js';
import type { EvaluationResult } from '../src/evaluate.js';

const POLICY = `
hushspec: "0.1.0"
name: enforcement-fixture
rules:
  tool_access:
    block: ["dangerous_tool"]
    default: allow
`;

describe('receipt enforcement summary', () => {
  it('evaluateAudited never sets enforcement', () => {
    const spec = parseOrThrow(POLICY);
    const receipt = evaluateAudited(
      spec,
      { type: 'tool_call', target: 'dangerous_tool' },
      DEFAULT_AUDIT_CONFIG,
    );
    expect(receipt.decision).toBe('deny');
    expect(receipt.enforcement).toBeUndefined();
  });

  it('serializes enforcement when set by an enforcement point', () => {
    const spec = parseOrThrow(POLICY);
    const receipt = evaluateAudited(
      spec,
      { type: 'tool_call', target: 'dangerous_tool' },
      DEFAULT_AUDIT_CONFIG,
    );
    const summary: EnforcementSummary = { mode: 'monitor', outcome: 'would_block' };
    receipt.enforcement = summary;

    const json = JSON.parse(JSON.stringify(receipt));
    expect(json.enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
    expect(json.decision).toBe('deny');
  });
});

describe('observer enforcement tagging', () => {
  it('notifyEvaluationCompleted emits one tagged evaluation.completed event', () => {
    const events: ObserverEvent[] = [];
    const evaluator = new ObservableEvaluator();
    evaluator.addObserver({ onEvent: (e) => events.push(e) });

    const result: EvaluationResult = {
      decision: 'deny',
      matched_rule: 'rules.tool_access.block',
      reason: 'tool is explicitly blocked',
    };
    evaluator.notifyEvaluationCompleted(
      { type: 'tool_call', target: 'dangerous_tool' },
      result,
      42,
      { mode: 'monitor', outcome: 'would_block' },
    );

    expect(events).toHaveLength(1);
    const event = events[0] as EvaluationCompletedEvent;
    expect(event.type).toBe('evaluation.completed');
    expect(event.duration_us).toBe(42);
    expect(event.result.decision).toBe('deny');
    expect(event.enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
    expect(event.receipt).toBeUndefined();
  });
});
