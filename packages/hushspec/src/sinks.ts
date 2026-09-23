import type { DecisionReceipt } from './receipt.js';
import type { PolicyEvent } from './log.js';
import { appendFileSync } from 'node:fs';

export interface ReceiptSink {
  send(receipt: DecisionReceipt): void;

  /**
   * Record a policy-in-effect event (log spec 6). Sinks that only carry
   * receipts leave it unimplemented; the hash-linked log writes it as an
   * entry (`ChainedFileSink`).
   */
  recordPolicyEvent?(event: PolicyEvent): unknown;
}

export class FileReceiptSink implements ReceiptSink {
  constructor(private path: string) {}

  send(receipt: DecisionReceipt): void {
    appendFileSync(this.path, JSON.stringify(receipt) + '\n');
  }
}

export class ConsoleReceiptSink implements ReceiptSink {
  send(receipt: DecisionReceipt): void {
    console.error('[hushspec]', JSON.stringify(receipt));
  }
}

/**
 * The name every HushSpec SDK gives this sink, as an alias for the same class:
 * receipts go to stderr, so a receipt stream and a program's own stdout never
 * interleave.
 */
export const StderrReceiptSink = ConsoleReceiptSink;
/** @see {@link StderrReceiptSink} */
export type StderrReceiptSink = ConsoleReceiptSink;

export class FilteredSink implements ReceiptSink {
  constructor(
    private inner: ReceiptSink,
    private decisions: string[],
  ) {}

  static denyOnly(sink: ReceiptSink): FilteredSink {
    return new FilteredSink(sink, ['deny']);
  }

  send(receipt: DecisionReceipt): void {
    if (this.decisions.includes(receipt.decision)) {
      this.inner.send(receipt);
    }
  }

  /**
   * Policy events are never filtered by decision: a reader maps a receipt to
   * the policy in force by walking back to the nearest policy event, so
   * dropping one would orphan every receipt after it.
   */
  recordPolicyEvent(event: PolicyEvent): void {
    this.inner.recordPolicyEvent?.(event);
  }
}

/**
 * Fans out to several sinks.
 *
 * Every sink is attempted whatever the ones before it did -- one destination
 * refusing a receipt must not cost the others theirs -- and the first failure
 * is then thrown, naming the sink that refused, so a guard raises a
 * `sink.error` observer event for it rather than losing the evidence quietly.
 */
export class MultiSink implements ReceiptSink {
  constructor(private sinks: ReceiptSink[]) {}

  send(receipt: DecisionReceipt): void {
    this.fanOut(sink => sink.send(receipt));
  }

  recordPolicyEvent(event: PolicyEvent): void {
    this.fanOut(sink => sink.recordPolicyEvent?.(event));
  }

  private fanOut(deliver: (sink: ReceiptSink) => void): void {
    let firstFailure: Error | undefined;
    for (const sink of this.sinks) {
      try {
        deliver(sink);
      } catch (error) {
        firstFailure ??= sinkFailure(sink, error);
      }
    }
    if (firstFailure !== undefined) throw firstFailure;
  }
}

/** A child sink's failure, named by the sink that refused. */
function sinkFailure(sink: ReceiptSink, error: unknown): Error {
  const name = sink.constructor?.name ?? 'sink';
  const message = error instanceof Error ? error.message : String(error);
  return new Error(`sink ${name}: ${message}`, { cause: error });
}

export class CallbackSink implements ReceiptSink {
  constructor(private callback: (receipt: DecisionReceipt) => void) {}

  send(receipt: DecisionReceipt): void {
    this.callback(receipt);
  }
}

export class NullSink implements ReceiptSink {
  send(): void {}
}
