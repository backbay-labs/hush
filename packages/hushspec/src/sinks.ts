import type { DecisionReceipt } from './receipt.js';
import type { PolicyEvent } from './log.js';
import { appendFileSync } from 'node:fs';

export interface ReceiptSink {
  send(receipt: DecisionReceipt): void;

  /**
   * Record a policy-in-effect event (RFC 09 P2-10). Sinks that only carry
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

export class MultiSink implements ReceiptSink {
  constructor(private sinks: ReceiptSink[]) {}

  send(receipt: DecisionReceipt): void {
    for (const sink of this.sinks) {
      try {
        sink.send(receipt);
      } catch {
        // Sinks must not crash the application.
      }
    }
  }

  recordPolicyEvent(event: PolicyEvent): void {
    for (const sink of this.sinks) {
      try {
        sink.recordPolicyEvent?.(event);
      } catch {
        // Sinks must not crash the application.
      }
    }
  }
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
