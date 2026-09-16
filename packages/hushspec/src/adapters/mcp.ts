import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';
import { argsSize, hostOf } from './tool-mapping.js';

export function mapMCPToolCall(
  toolName: string,
  args?: Record<string, unknown>,
): EvaluationAction {
  const mappings: Record<
    string,
    (a?: Record<string, unknown>) => EvaluationAction
  > = {
    read_file: (a) => ({
      type: 'file_read',
      target: (a?.path as string) ?? '',
    }),
    write_file: (a) => ({
      type: 'file_write',
      target: (a?.path as string) ?? '',
      content: a?.content as string,
    }),
    list_directory: (a) => ({
      type: 'file_read',
      target: (a?.path as string) ?? '',
    }),
    run_command: (a) => ({
      type: 'shell_command',
      target: (a?.command as string) ?? '',
    }),
    execute: (a) => ({
      type: 'shell_command',
      target: (a?.command as string) ?? '',
    }),
    fetch: (a) => ({
      type: 'egress',
      target: extractDomain((a?.url as string) ?? ''),
    }),
    http_request: (a) => ({
      type: 'egress',
      target: extractDomain((a?.url as string) ?? ''),
    }),
  };

  const mapper = mappings[toolName];
  if (mapper) return mapper(args);

  return {
    type: 'tool_call',
    target: toolName,
    args_size: args ? argsSize(args) : undefined,
  };
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
