import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';
import { mapWellKnownTool } from './tool-mapping.js';

/**
 * Vercel AI SDK adapter.
 *
 * Structural typing only: nothing here imports `ai`, so the adapter costs no
 * dependency and works across the AI SDK 4 (`args`) and 5 (`input`) tool-call
 * shapes. A tool set is wrapped by replacing each tool's `execute` with one
 * that gates the call through a {@link HushGuard} first -- a denial throws
 * `HushSpecDenied` before the side effect happens, and a warn decision is put
 * to the guard's own `onWarn` handler (fail-closed: no handler means deny).
 */

/** A tool call as `onToolCall` / `toolCalls` hands it over. */
export interface VercelToolCall {
  toolName: string;
  /** AI SDK 4 spelling of the arguments. */
  args?: unknown;
  /** AI SDK 5 spelling of the arguments. */
  input?: unknown;
  toolCallId?: string;
}

/** The only member of a tool this adapter touches. */
export interface VercelTool {
  execute?: (...args: never[]) => unknown;
}

/** What {@link createVercelGuard} returns. */
export interface VercelGuard {
  /**
   * A copy of `tools` whose every executable tool is gated. The tool set keeps
   * its own type: only `execute` is replaced, by a function of the same shape.
   */
  wrapTools<T extends object>(tools: T): T;
  /** One gated tool, for a tool set assembled by hand. */
  wrapTool<T extends object>(toolName: string, tool: T): T;
  /** Evaluate a tool call without executing anything. */
  evaluate(toolCall: VercelToolCall): EvaluationResult;
}

/**
 * Map an AI SDK tool call onto an {@link EvaluationAction}.
 *
 * Recognized names (`readFile`, `writeFile`, `bash`, `fetch`, ...) map onto
 * `file_read`, `file_write`, `shell_command` and `egress`; everything else is
 * a `tool_call` targeting the tool name. Every action records `args_size`, so
 * a receipt carries the payload's size without the payload.
 */
export function mapVercelToolCall(toolCall: VercelToolCall): EvaluationAction {
  return mapWellKnownTool(toolCall.toolName, toolCall.args ?? toolCall.input);
}

function executeOf(tool: object): ((...args: never[]) => unknown) | undefined {
  const candidate = (tool as VercelTool).execute;
  return typeof candidate === 'function' ? candidate : undefined;
}

/**
 * Gate a tool set with `guard`.
 *
 * ```typescript
 * const { wrapTools } = createVercelGuard(HushGuard.fromFile('./policy.yaml'));
 * const result = await generateText({ model, tools: wrapTools(tools), prompt });
 * ```
 *
 * A wrapped `execute` runs the guard before the tool body and throws
 * `HushSpecDenied` when the action is refused, so the model sees a tool error
 * instead of a side effect. Tools without an `execute` (provider-executed, or
 * resolved on the client) are returned untouched: there is no call for this
 * adapter to intercept.
 */
export function createVercelGuard(guard: HushGuard): VercelGuard {
  function wrapTool<T extends object>(toolName: string, tool: T): T {
    const execute = executeOf(tool);
    if (execute === undefined) return tool;
    const gated = async (...args: never[]): Promise<unknown> => {
      guard.enforce(mapVercelToolCall({ toolName, args: args[0] }));
      return await (execute.apply(tool, args) as Promise<unknown>);
    };
    return { ...tool, execute: gated };
  }

  return {
    wrapTool,
    wrapTools<T extends object>(tools: T): T {
      const wrapped: Record<string, unknown> = {};
      for (const [toolName, tool] of Object.entries(tools)) {
        wrapped[toolName] =
          typeof tool === 'object' && tool !== null ? wrapTool(toolName, tool) : tool;
      }
      return wrapped as T;
    },
    evaluate(toolCall: VercelToolCall): EvaluationResult {
      return guard.evaluate(mapVercelToolCall(toolCall));
    },
  };
}
