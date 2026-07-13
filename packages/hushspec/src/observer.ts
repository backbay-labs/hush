import type { EvaluationAction, EvaluationResult, Decision } from './evaluate.js';
import type { DecisionReceipt, EnforcementSummary } from './receipt.js';
import type { HushSpec } from './schema.js';
import { evaluate } from './evaluate.js';
import { computePolicyHash } from './receipt.js';

export interface EvaluationEvent {
  type: 'evaluation.completed' | 'policy.loaded' | 'policy.load_failed' | 'policy.reloaded';
  timestamp: string;
}

export interface EvaluationCompletedEvent extends EvaluationEvent {
  type: 'evaluation.completed';
  action: EvaluationAction;
  result: EvaluationResult;
  duration_us: number;
  receipt?: DecisionReceipt;
  enforcement?: EnforcementSummary;
}

export interface PolicyLoadedEvent extends EvaluationEvent {
  type: 'policy.loaded';
  policy_name?: string;
  content_hash: string;
}

export interface PolicyLoadFailedEvent extends EvaluationEvent {
  type: 'policy.load_failed';
  error: string;
  source?: string;
}

export interface PolicyReloadedEvent extends EvaluationEvent {
  type: 'policy.reloaded';
  policy_name?: string;
  content_hash: string;
  previous_hash?: string;
}

export type ObserverEvent =
  | EvaluationCompletedEvent
  | PolicyLoadedEvent
  | PolicyLoadFailedEvent
  | PolicyReloadedEvent;

export interface EvaluationObserver {
  onEvent(event: ObserverEvent): void;
}

export class JsonLineObserver implements EvaluationObserver {
  constructor(private stream: NodeJS.WritableStream) {}

  onEvent(event: ObserverEvent): void {
    this.stream.write(JSON.stringify(event) + '\n');
  }
}

export class ConsoleObserver implements EvaluationObserver {
  constructor(private level: 'all' | 'deny_only' = 'all') {}

  onEvent(event: ObserverEvent): void {
    if (this.level === 'deny_only' && event.type === 'evaluation.completed') {
      const e = event as EvaluationCompletedEvent;
      if (e.result.decision !== 'deny') return;
    }
    console.error(`[hushspec] ${event.type} at ${event.timestamp}`, event);
  }
}

export class MetricsCollector implements EvaluationObserver {
  private counts: Map<string, number> = new Map();
  private durations: number[] = [];

  onEvent(event: ObserverEvent): void {
    if (event.type === 'evaluation.completed') {
      const e = event as EvaluationCompletedEvent;
      const key = `evaluate.${e.result.decision}`;
      this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
      this.durations.push(e.duration_us);
    }
    this.counts.set(event.type, (this.counts.get(event.type) ?? 0) + 1);
  }

  getCount(key: string): number {
    return this.counts.get(key) ?? 0;
  }

  getTotalEvaluations(): number {
    return this.durations.length;
  }

  getAverageDurationUs(): number {
    if (this.durations.length === 0) return 0;
    return this.durations.reduce((a, b) => a + b, 0) / this.durations.length;
  }

  getP99DurationUs(): number {
    if (this.durations.length === 0) return 0;
    const sorted = [...this.durations].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length * 0.99)] ?? sorted[sorted.length - 1];
  }

  toPrometheus(): string {
    const lines: string[] = [];
    for (const [key, value] of this.counts) {
      lines.push(`hushspec_${key.replace(/\./g, '_')}_total ${value}`);
    }
    if (this.durations.length > 0) {
      lines.push(`hushspec_evaluate_duration_us_avg ${this.getAverageDurationUs()}`);
      lines.push(`hushspec_evaluate_duration_us_p99 ${this.getP99DurationUs()}`);
    }
    return lines.join('\n');
  }

  reset(): void {
    this.counts.clear();
    this.durations = [];
  }
}

export class ObservableEvaluator {
  private observers: EvaluationObserver[] = [];

  addObserver(observer: EvaluationObserver): void {
    this.observers.push(observer);
  }

  removeObserver(observer: EvaluationObserver): void {
    this.observers = this.observers.filter(o => o !== observer);
  }

  evaluate(spec: HushSpec, action: EvaluationAction): EvaluationResult {
    const start = performance.now();
    const result = evaluate(spec, action);
    const duration_us = Math.round((performance.now() - start) * 1000);
    this.emit({
      type: 'evaluation.completed',
      timestamp: new Date().toISOString(),
      action,
      result,
      duration_us,
    });
    return result;
  }

  notifyEvaluationCompleted(
    action: EvaluationAction,
    result: EvaluationResult,
    durationUs: number,
    enforcement?: EnforcementSummary,
    receipt?: DecisionReceipt,
  ): void {
    this.emit({
      type: 'evaluation.completed',
      timestamp: new Date().toISOString(),
      action,
      result,
      duration_us: durationUs,
      enforcement,
      receipt,
    });
  }

  notifyPolicyLoaded(name?: string, hash?: string): void {
    this.emit({
      type: 'policy.loaded',
      timestamp: new Date().toISOString(),
      policy_name: name,
      content_hash: hash ?? '',
    });
  }

  notifyPolicyLoadFailed(error: string, source?: string): void {
    this.emit({
      type: 'policy.load_failed',
      timestamp: new Date().toISOString(),
      error,
      source,
    });
  }

  notifyPolicyReloaded(name?: string, hash?: string, previousHash?: string): void {
    this.emit({
      type: 'policy.reloaded',
      timestamp: new Date().toISOString(),
      policy_name: name,
      content_hash: hash ?? '',
      previous_hash: previousHash,
    });
  }

  private emit(event: ObserverEvent): void {
    for (const observer of this.observers) {
      try {
        observer.onEvent(event);
      } catch {
        /* observers must not crash the evaluator */
      }
    }
  }
}
