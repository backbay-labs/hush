import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';
import { argsSize } from './tool-mapping.js';

/**
 * Map an OpenAI tool call onto an {@link EvaluationAction}.
 *
 * The call is always a `tool_call` against the function's own name: the API
 * declares no action semantics, and guessing one would consult the wrong rule
 * block. `args_size` records the payload's size without the payload -- for a
 * string it is the arguments exactly as the model emitted them, which is what
 * a `max_args_size` limit is about.
 *
 * The arguments are never parsed. A model can emit a truncated or malformed
 * JSON string, and an enforcement point that threw on one would fail open:
 * the call would be gated by whatever the caller does with the exception
 * rather than by the policy.
 */
export function mapOpenAIToolCall(
  functionName: string,
  functionArgs: string | Record<string, unknown>,
): EvaluationAction {
  return {
    type: 'tool_call',
    target: functionName,
    args_size: argsSize(functionArgs),
  };
}

export function createOpenAIGuard(
  guard: HushGuard,
): (functionName: string, functionArgs: string | Record<string, unknown>) => EvaluationResult {
  return (
    functionName: string,
    functionArgs: string | Record<string, unknown>,
  ): EvaluationResult => {
    const action = mapOpenAIToolCall(functionName, functionArgs);
    return guard.evaluate(action);
  };
}
