import type { JsonValue } from '../canonical.js';
import type { EvaluationAction } from '../evaluate.js';
import { assertUnicode } from './json.js';

export type InvocationArguments = Readonly<Record<string, JsonValue>>;
export interface InvocationBinding {
  readonly connectionId: string;
  readonly toolName: string;
  readonly extract: (args: InvocationArguments) => readonly EvaluationAction[];
  readonly dispatch: (args: InvocationArguments, context: Readonly<{ callId: string }>) => unknown;
}

export function qualifiedToolTarget(connectionId: string, toolName: string): string {
  if (typeof connectionId !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/.test(connectionId)) {
    throw new Error('invalid host connection identity');
  }
  if (typeof toolName !== 'string' || !toolName || toolName.normalize('NFC') !== toolName ||
      /[\u0000-\u001f\u007f-\u009f]/.test(toolName) || Buffer.byteLength(toolName) > 128) {
    throw new Error('invalid tool identity');
  }
  assertUnicode(toolName);
  return `mcp:${connectionId}/${encodeURIComponent(toolName)}`;
}

/** Constructed by the trusted host, never populated from server discovery metadata. */
export class InvocationRegistry {
  readonly #bindings = new Map<string, InvocationBinding>();

  constructor(bindings: readonly InvocationBinding[]) {
    if (!Array.isArray(bindings) || bindings.length === 0 || bindings.length > 256) {
      throw new Error('invalid registry size');
    }
    for (const binding of bindings) {
      const target = qualifiedToolTarget(binding.connectionId, binding.toolName);
      if (this.#bindings.has(target)) throw new Error('duplicate registry identity');
      if (typeof binding.extract !== 'function' || typeof binding.dispatch !== 'function') {
        throw new Error('registry requires trusted extractor and dispatch handle');
      }
      this.#bindings.set(target, Object.freeze({ connectionId: binding.connectionId,
        toolName: binding.toolName, extract: binding.extract, dispatch: binding.dispatch }));
    }
    Object.freeze(this);
  }

  get(connectionId: string, toolName: string): InvocationBinding {
    const binding = this.#bindings.get(qualifiedToolTarget(connectionId, toolName));
    if (!binding) throw new Error('unregistered tool identity');
    return binding;
  }
}
