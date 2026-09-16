import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';
import { argsSize, hostOf } from './tool-mapping.js';

/**
 * Anthropic versions its built-in server tools with a date suffix
 * (`text_editor_20250429`). The suffix names a revision of the same tool, so it
 * is stripped before matching -- a tool released next quarter maps the same way
 * instead of silently falling back to an opaque `tool_call`.
 */
const DATED_TOOL_SUFFIX = /_20\d{6}$/;

function stringField(input: Record<string, unknown>, key: string): string {
  const value = input[key];
  return typeof value === 'string' ? value : '';
}

function optionalStringField(
  input: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = input[key];
  return typeof value === 'string' ? value : undefined;
}

/**
 * Map one Claude `tool_use` block onto the action a policy evaluates.
 *
 * Claude's built-in tools are not opaque tool calls: `bash` and `terminal` are
 * shell commands, the text editor is a file read or a file write, `computer` is
 * computer use, and `web_fetch` / `fetch` is egress to the URL's host. An
 * `mcp__<server>__<tool>` name is evaluated under the inner tool name, so a
 * policy names the tool rather than the transport. Everything else is a
 * `tool_call` carrying the size of its input, which is the fail-safe reading:
 * an unrecognized tool is still gated, just by the rules that apply to every
 * tool.
 */
export function mapClaudeToolToAction(
  toolName: string,
  toolInput: Record<string, unknown>,
): EvaluationAction {
  switch (toolName.replace(DATED_TOOL_SUFFIX, '')) {
    case 'bash':
    case 'terminal':
      return { type: 'shell_command', target: stringField(toolInput, 'command') };

    case 'str_replace_editor':
    case 'str_replace_based_edit_tool':
    case 'text_editor': {
      const path = stringField(toolInput, 'path');
      if (stringField(toolInput, 'command') === 'view') {
        return { type: 'file_read', target: path };
      }
      // `create` carries the whole file under `file_text`; an edit carries the
      // replacement under `new_str`. Either way the payload goes through as
      // content, so `secret_patterns` and the detection pipeline see what is
      // about to be written.
      const content =
        optionalStringField(toolInput, 'new_str') ??
        optionalStringField(toolInput, 'file_text');
      return {
        type: 'file_write',
        target: path,
        ...(content === undefined ? {} : { content }),
      };
    }

    case 'computer':
      return { type: 'computer_use', target: stringField(toolInput, 'action') };

    case 'web_fetch':
    case 'fetch':
      return { type: 'egress', target: hostOf(stringField(toolInput, 'url')) };
  }

  let target = toolName;
  if (toolName.startsWith('mcp__')) {
    const parts = toolName.split('__');
    if (parts.length >= 3) target = parts.slice(2).join('__');
  }
  return { type: 'tool_call', target, args_size: argsSize(toolInput) };
}

export function createSecureToolHandler(
  guard: HushGuard,
): (toolName: string, toolInput: Record<string, unknown>) => EvaluationResult {
  return (toolName: string, toolInput: Record<string, unknown>): EvaluationResult => {
    const action = mapClaudeToolToAction(toolName, toolInput);
    return guard.evaluate(action);
  };
}
