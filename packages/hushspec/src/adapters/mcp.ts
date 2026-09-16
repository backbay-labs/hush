import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';
import { hostOf, mapWellKnownTool } from './tool-mapping.js';

/**
 * Map an MCP `tools/call` onto the action a policy evaluates.
 *
 * MCP fixes no action semantics, so the recognized names come from the shared
 * table in `tool-mapping.ts` -- the same one the Vercel AI SDK and LangChain
 * adapters use, so `readFile` cannot mean `file_read` under one enforcement
 * point and an opaque `tool_call` under another. Everything else is a
 * `tool_call` against the tool's own name.
 */
export function mapMCPToolCall(
  toolName: string,
  args?: Record<string, unknown>,
): EvaluationAction {
  return mapWellKnownTool(toolName, args);
}

export function extractDomain(url: string): string {
  return hostOf(url);
}

export function createMCPGuard(
  guard: HushGuard,
): (toolName: string, args?: Record<string, unknown>) => EvaluationResult {
  return (
    toolName: string,
    args?: Record<string, unknown>,
  ): EvaluationResult => {
    const action = mapMCPToolCall(toolName, args);
    return guard.evaluate(action);
  };
}
