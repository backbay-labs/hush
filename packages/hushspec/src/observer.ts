import type { EvaluationAction, EvaluationResult, Decision } from './evaluate.js';
import type { DecisionReceipt, EnforcementSummary } from './receipt.js';
import type { HushSpec } from './schema.js';
import { evaluateWithDetection } from './detection.js';

export interface EvaluationEvent {
  type:
    | 'evaluation.completed'
    | 'policy.loaded'
    | 'policy.load_failed'
    | 'policy.reloaded'
    | 'sink.error'
    | 'error';
  timestamp: string;
}

export interface EvaluationCompletedEvent extends EvaluationEvent {
  type: 'evaluation.completed';
  /** The action with `content` stripped (receipt spec 4.4). */
  action: EvaluationAction;
  /**
   * True when `action.content` was present and removed. The flag sits on the
   * event rather than on the action because `EvaluationAction` is a closed
   * wire type -- an SDK reading the event back rejects a member it does not
   * declare.
   */
  content_redacted?: boolean;
  result: EvaluationResult;
  duration_us: number;
  receipt?: DecisionReceipt;
  enforcement?: EnforcementSummary;
}

export interface PolicyLoadedEvent extends EvaluationEvent {
  type: 'policy.loaded';
  policy_name?: string;
  /**
   * The canonical content hash of the resolved policy (`sha256:` + hex), the
   * same value a receipt's `policy.content_hash` carries. Empty only when the
   * emitter had no policy to hash.
   */
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
  /** @see {@link PolicyLoadedEvent.content_hash} */
  content_hash: string;
  previous_hash?: string;
}

/**
 * A receipt sink refused what it was handed. The decision it belonged to
 * stands: a sink is evidence, never enforcement.
 */
export interface SinkErrorEvent extends EvaluationEvent {
  type: 'sink.error';
  error: string;
  /** The sink that refused, by name. */
  source?: string;
}

/**
 * A failure the guard absorbed that is neither a policy load nor a sink: an
 * observer that threw, say. The evaluation that produced the event stands --
 * an observer is a bystander, never enforcement.
 */
export interface ObserverErrorEvent extends EvaluationEvent {
  type: 'error';
  error: string;
  /** What failed, when the emitter can name it. */
  source?: string;
}

export type ObserverEvent =
  | EvaluationCompletedEvent
  | PolicyLoadedEvent
  | PolicyLoadFailedEvent
  | PolicyReloadedEvent
  | SinkErrorEvent
  | ObserverErrorEvent;

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
    if (
      this.level === 'deny_only' &&
      event.type === 'evaluation.completed' &&
      event.result.decision !== 'deny'
    ) {
      return;
    }
    console.error(`[hushspec] ${event.type} at ${event.timestamp}`, event);
  }
}

/**
 * Upper bounds of the latency histogram, in microseconds. The last bucket is
 * `+Inf`, which the exposition adds.
 */
export const DURATION_BUCKETS_US: readonly number[] = [
  10, 25, 50, 100, 250, 500, 1_000, 5_000, 10_000,
];

/**
 * How many recent durations a {@link MetricsCollector} keeps for its
 * percentile. A collector lives as long as the process, so the window is
 * bounded; the counters and the histogram it reports are exact regardless.
 */
export const DURATION_WINDOW = 10_000;

/** One action type's latency histogram. */
interface Histogram {
  /** Cumulative counts, aligned with {@link DURATION_BUCKETS_US}. */
  buckets: number[];
  sum: number;
  count: number;
}

/**
 * Counters and a latency histogram over the evaluation stream, rendered as
 * Prometheus text.
 *
 * The exposed series are the ones the observability specification names, so a
 * dashboard or a recording rule works against any SDK unchanged:
 *
 * | Series | Type | Labels |
 * |---|---|---|
 * | `hushspec_evaluate_total` | counter | `decision`, `action_type` |
 * | `hushspec_evaluate_duration_us` | histogram | `action_type` |
 * | `hushspec_rule_match_total` | counter | `rule_block`, `decision` |
 * | `hushspec_policy_load_total` | counter | `status` |
 */
export class MetricsCollector implements EvaluationObserver {
  private counts: Map<string, number> = new Map();
  /** `decision` and `action_type` -> count. */
  private evaluations: Map<string, number> = new Map();
  /** `rule_block` and `decision` -> count. */
  private ruleMatches: Map<string, number> = new Map();
  /** `success` / `failure` -> count. */
  private policyLoads: Map<string, number> = new Map();
  /** `action_type` -> histogram. */
  private histograms: Map<string, Histogram> = new Map();
  /** A bounded window of recent samples, for the percentile. */
  private durations: number[] = [];
  private durationsAt = 0;
  private evaluationCount = 0;

  constructor(private readonly durationWindow: number = DURATION_WINDOW) {}

  onEvent(event: ObserverEvent): void {
    if (event.type === 'evaluation.completed') {
      this.recordEvaluation(event);
    } else if (event.type === 'policy.loaded' || event.type === 'policy.reloaded') {
      increment(this.policyLoads, 'success');
    } else if (event.type === 'policy.load_failed') {
      increment(this.policyLoads, 'failure');
    }
    increment(this.counts, event.type);
  }

  private recordEvaluation(event: EvaluationCompletedEvent): void {
    const decision = event.result.decision;
    const actionType = event.action.type;
    increment(this.counts, `evaluate.${decision}`);
    increment(this.evaluations, labelKey(decision, actionType));

    const ruleBlock = ruleBlockOf(event.result.matched_rule);
    if (ruleBlock !== undefined) {
      increment(this.ruleMatches, labelKey(ruleBlock, decision));
    }

    const durationUs = Math.max(0, event.duration_us);
    let histogram = this.histograms.get(actionType);
    if (histogram === undefined) {
      histogram = { buckets: DURATION_BUCKETS_US.map(() => 0), sum: 0, count: 0 };
      this.histograms.set(actionType, histogram);
    }
    histogram.count += 1;
    histogram.sum += durationUs;
    DURATION_BUCKETS_US.forEach((bound, index) => {
      if (durationUs <= bound) histogram.buckets[index] += 1;
    });

    this.evaluationCount += 1;
    this.recordSample(durationUs);
  }

  /** Keep the newest `durationWindow` samples, overwriting the oldest. */
  private recordSample(durationUs: number): void {
    if (this.durationWindow < 1) return;
    if (this.durations.length < this.durationWindow) {
      this.durations.push(durationUs);
      return;
    }
    this.durations[this.durationsAt] = durationUs;
    this.durationsAt = (this.durationsAt + 1) % this.durationWindow;
  }

  getCount(key: string): number {
    return this.counts.get(key) ?? 0;
  }

  getTotalEvaluations(): number {
    return this.evaluationCount;
  }

  /** Mean latency over the sample window, in microseconds. */
  getAverageDurationUs(): number {
    if (this.durations.length === 0) return 0;
    return this.durations.reduce((a, b) => a + b, 0) / this.durations.length;
  }

  /** 99th percentile latency over the sample window, in microseconds. */
  getP99DurationUs(): number {
    if (this.durations.length === 0) return 0;
    const sorted = [...this.durations].sort((a, b) => a - b);
    // `floor(n * 0.99) < n` for every n >= 1, so the index is always in range.
    return sorted[Math.floor(sorted.length * 0.99)];
  }

  /** Prometheus text exposition (version 0.0.4) of every series. */
  toPrometheus(): string {
    const lines: string[] = [];

    lines.push('# HELP hushspec_evaluate_total Total HushSpec evaluations');
    lines.push('# TYPE hushspec_evaluate_total counter');
    for (const [pair, count] of sortedEntries(this.evaluations)) {
      const [decision, actionType] = splitKey(pair);
      lines.push(
        `hushspec_evaluate_total{decision="${decision}",action_type="${escapeLabel(actionType)}"} ${count}`,
      );
    }

    lines.push('# HELP hushspec_evaluate_duration_us Evaluation duration in microseconds');
    lines.push('# TYPE hushspec_evaluate_duration_us histogram');
    for (const [actionType, histogram] of [...this.histograms].sort(byKey)) {
      const label = escapeLabel(actionType);
      DURATION_BUCKETS_US.forEach((bound, index) => {
        lines.push(
          `hushspec_evaluate_duration_us_bucket{action_type="${label}",le="${bound}"} ${histogram.buckets[index]}`,
        );
      });
      lines.push(
        `hushspec_evaluate_duration_us_bucket{action_type="${label}",le="+Inf"} ${histogram.count}`,
      );
      lines.push(`hushspec_evaluate_duration_us_sum{action_type="${label}"} ${histogram.sum}`);
      lines.push(`hushspec_evaluate_duration_us_count{action_type="${label}"} ${histogram.count}`);
    }

    lines.push('# HELP hushspec_rule_match_total Rule block match counts');
    lines.push('# TYPE hushspec_rule_match_total counter');
    for (const [pair, count] of sortedEntries(this.ruleMatches)) {
      const [ruleBlock, decision] = splitKey(pair);
      lines.push(
        `hushspec_rule_match_total{rule_block="${escapeLabel(ruleBlock)}",decision="${decision}"} ${count}`,
      );
    }

    lines.push('# HELP hushspec_policy_load_total Policy load operations');
    lines.push('# TYPE hushspec_policy_load_total counter');
    for (const [status, count] of sortedEntries(this.policyLoads)) {
      lines.push(`hushspec_policy_load_total{status="${status}"} ${count}`);
    }

    return lines.join('\n') + '\n';
  }

  reset(): void {
    this.counts.clear();
    this.evaluations.clear();
    this.ruleMatches.clear();
    this.policyLoads.clear();
    this.histograms.clear();
    this.durations = [];
    this.durationsAt = 0;
    this.evaluationCount = 0;
  }
}

/** Two label values as one map key; NUL cannot occur in either. */
function labelKey(first: string, second: string): string {
  return `${first}\0${second}`;
}

function splitKey(pair: string): [string, string] {
  const index = pair.indexOf('\0');
  return [pair.slice(0, index), pair.slice(index + 1)];
}

function increment(counts: Map<string, number>, at: string): void {
  counts.set(at, (counts.get(at) ?? 0) + 1);
}

function byKey(left: [string, unknown], right: [string, unknown]): number {
  return left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : 0;
}

function sortedEntries(counts: Map<string, number>): [string, number][] {
  return [...counts].sort(byKey);
}

function escapeLabel(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

/**
 * The rule block a `matched_rule` belongs to, for the
 * `hushspec_rule_match_total` label.
 *
 * `rules.egress.default` -> `egress`; `extensions.posture.budgets` ->
 * `posture`; the bare `detection` the detection pipeline emits -> `detection`;
 * a reserved `__hushspec_x__` id -> `hushspec_x`. `undefined` for an
 * evaluation no rule decided (a default allow).
 */
export function ruleBlockOf(matchedRule?: string): string | undefined {
  if (matchedRule === undefined || matchedRule === '') return undefined;
  if (matchedRule.startsWith('__')) return matchedRule.replace(/^_+|_+$/g, '');
  if (matchedRule.startsWith('rules.')) return firstSegment(matchedRule.slice('rules.'.length));
  if (matchedRule.startsWith('extensions.')) {
    return firstSegment(matchedRule.slice('extensions.'.length));
  }
  return firstSegment(matchedRule);
}

function firstSegment(path: string): string {
  const index = path.search(/[.[]/);
  return index < 0 ? path : path.slice(0, index);
}

export class ObservableEvaluator {
  private observers: EvaluationObserver[] = [];

  addObserver(observer: EvaluationObserver): void {
    this.observers.push(observer);
  }

  removeObserver(observer: EvaluationObserver): void {
    this.observers = this.observers.filter(o => o !== observer);
  }

  /**
   * Evaluate `action` against `spec`, time it, and announce the outcome.
   *
   * Routes through the detection pipeline, as every other evaluation surface
   * does: for a policy carrying an `extensions.detection` block an escalated
   * decision must not come back as an allow simply because the caller went
   * through an observer (detection spec section 4).
   */
  evaluate(spec: HushSpec, action: EvaluationAction): EvaluationResult {
    const start = performance.now();
    const result = evaluateWithDetection(spec, action).evaluation;
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

  notifySinkError(error: string, source?: string): void {
    this.emit({
      type: 'sink.error',
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

  /** Announce a failure the guard absorbed that is neither a load nor a sink. */
  notifyError(error: string, source?: string): void {
    this.emit({
      type: 'error',
      timestamp: new Date().toISOString(),
      error,
      source,
    });
  }

  /**
   * Fan one event out, absorbing a throw.
   *
   * An observer is a bystander: it never decides whether an action proceeds,
   * so a throw in one must stop neither the evaluation that produced the event
   * nor the rest of the fan-out. The failure is handed back to the same
   * observer as an `error` event, because a failure nobody is told about is
   * the one that goes unnoticed; an observer that throws reporting its own
   * throw is dropped rather than retried.
   *
   * An `evaluation.completed` event is redacted here, so no path to an
   * observer can carry an action's `content` (receipt spec 4.4).
   */
  private emit(event: ObserverEvent): void {
    if (event.type === 'evaluation.completed') {
      event = redactCompleted(event);
    }
    for (const observer of this.observers) {
      try {
        observer.onEvent(event);
      } catch (thrown) {
        if (event.type === 'error') continue;
        const message = thrown instanceof Error ? thrown.message : String(thrown);
        try {
          observer.onEvent({
            type: 'error',
            timestamp: new Date().toISOString(),
            error: `observer threw: ${message}`,
          });
        } catch {
          /* best-effort: an observer that cannot be told is left alone */
        }
      }
    }
  }
}

/**
 * The event with `action.content` stripped, flagged on the event itself.
 *
 * Evidence records an action's content by hash and size, never by its bytes
 * (receipt spec 4.4), and an observer stream is held to the same rule.
 */
function redactCompleted(event: EvaluationCompletedEvent): EvaluationCompletedEvent {
  if (event.action.content == null) return event;
  const { content: _content, ...action } = event.action;
  return { ...event, action, content_redacted: true };
}
