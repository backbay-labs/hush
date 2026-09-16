import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';
import { argsSize } from './tool-mapping.js';

export function mapClaudeToolToAction(
  toolName: string,
  toolInput: Record<string, unknown>,
): EvaluationAction {
  switch (toolName) {
    case 'bash':
    case 'terminal':
      return {
        type: 'shell_command',
        target: (toolInput.command as string) ?? '',
      };

    case 'str_replace_editor':
    case 'text_editor_20250124':
    case 'text_editor_20250429': {
      const cmd = toolInput.command as string;
      if (cmd === 'view') {
        return { type: 'file_read', target: (toolInput.path as string) ?? '' };
      }
      return {
        type: 'file_write',
        target: (toolInput.path as string) ?? '',
        content: toolInput.new_str as string,
      };
    }

    case 'computer':
      return {
        type: 'computer_use',
        target: (toolInput.action as string) ?? '',
      };

    default:
      if (toolName.startsWith('mcp__')) {
        const parts = toolName.split('__');
        const innerTool = parts.length >= 3 ? parts.slice(2).join('__') : toolName;
        return {
          type: 'tool_call',
          target: innerTool,
          args_size: argsSize(toolInput),
        };
      }
      return {
        type: 'tool_call',
        target: toolName,
        args_size: argsSize(toolInput),
      };
  }
}

export function createSecureToolHandler(
  guard: HushGuard,
): (toolName: string, toolInput: Record<string, unknown>) => EvaluationResult {
  return (toolName: string, toolInput: Record<string, unknown>): EvaluationResult => {
    const action = mapClaudeToolToAction(toolName, toolInput);
    return guard.evaluate(action);
  };
}
