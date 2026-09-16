import { describe, it, expect } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import { evaluateAuditedSpec, DEFAULT_AUDIT_CONFIG } from '../src/receipt.js';
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
  it('records the disposition a decision implies when there is no enforcement point', () => {
    const spec = parseOrThrow(POLICY);
    const receipt = evaluateAuditedSpec(
      spec,
      { type: 'tool_call', target: 'dangerous_tool' },
      DEFAULT_AUDIT_CONFIG,
    );
    expect(receipt.decision).toBe('deny');
    // Required in 0.2, never absent: a warn or deny with no confirmation
    // channel blocks (core spec 6, receipt spec 4.7).
    expect(receipt.enforcement).toEqual({ mode: 'enforce', outcome: 'blocked' });
  });

  it('serializes enforcement supplied by an enforcement point', () => {
    const spec = parseOrThrow(POLICY);
    const summary: EnforcementSummary = { mode: 'monitor', outcome: 'would_block' };
    const receipt = evaluateAuditedSpec(
      spec,
      { type: 'tool_call', target: 'dangerous_tool' },
      DEFAULT_AUDIT_CONFIG,
      { enforcement: summary },
    );

    const json = JSON.parse(JSON.stringify(receipt));
    expect(json.enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
    expect(json.decision).toBe('deny');
  });

  it('monitor mode turns a block into would_block without an explicit summary', () => {
    const spec = parseOrThrow(POLICY);
    const receipt = evaluateAuditedSpec(
      spec,
      { type: 'tool_call', target: 'dangerous_tool' },
      DEFAULT_AUDIT_CONFIG,
      { enforcementMode: 'monitor' },
    );
    expect(receipt.enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
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
