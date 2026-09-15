import type { EvaluationAction } from '../evaluate.js';

/**
 * Shared tool-name mapping for the framework adapters.
 *
 * The Vercel AI SDK and LangChain.js both hand an enforcement point a tool
 * name and a bag of arguments, with no declared action semantics. This module
 * is the one table that turns the handful of unambiguous names into reference
 * action types, so the two adapters cannot drift apart on what `readFile`
 * means. Anything not in the table is a `tool_call` against the tool's own
 * name: guessing wrong would consult the wrong rule block, which is worse than
 * not guessing at all.
 */

type ArgRecord = Record<string, unknown>;

const FILE_READ_TOOLS: ReadonlySet<string> = new Set([
  'readfile', 'read', 'cat', 'view', 'viewfile', 'listdirectory', 'listdir', 'ls',
]);
const FILE_WRITE_TOOLS: ReadonlySet<string> = new Set([
  'writefile', 'write', 'createfile', 'editfile', 'edit', 'appendfile', 'strreplace',
]);
const SHELL_TOOLS: ReadonlySet<string> = new Set([
  'bash', 'sh', 'shell', 'exec', 'execute', 'executecommand', 'runcommand', 'terminal',
]);
const EGRESS_TOOLS: ReadonlySet<string> = new Set([
  'fetch', 'webfetch', 'http', 'httprequest', 'httpfetch', 'request', 'apicall',
]);

const PATH_KEYS = ['path', 'filePath', 'file_path', 'file', 'filename', 'directory'] as const;
const CONTENT_KEYS = ['content', 'contents', 'text', 'data', 'new_str', 'newStr'] as const;
const COMMAND_KEYS = ['command', 'cmd', 'script'] as const;
const URL_KEYS = ['url', 'endpoint', 'uri', 'href'] as const;

/** Lowercase alphanumerics: `read_file`, `readFile` and `ReadFile` are one key. */
export function normalizeToolName(toolName: string): string {
  return toolName.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** The arguments as an object, parsing a JSON string argument. */
export function argRecord(value: unknown): ArgRecord | undefined {
  if (typeof value === 'string') {
    try {
      const parsed: unknown = JSON.parse(value);
      return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
        ? (parsed as ArgRecord)
        : undefined;
    } catch {
      return undefined;
    }
  }
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as ArgRecord;
  }
  return undefined;
}

function firstString(args: ArgRecord | undefined, keys: readonly string[]): string | undefined {
  if (args === undefined) return undefined;
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'string') return value;
  }
  return undefined;
}

/** Content-free size signal: the JSON length of the arguments as supplied. */
export function argsSize(raw: unknown): number | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw === 'string') return raw.length;
  try {
    const encoded = JSON.stringify(raw);
    return encoded === undefined ? undefined : encoded.length;
  } catch {
    return undefined;
  }
}

/** The hostname of a URL, or the string itself when it does not parse. */
export function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/**
 * Map `toolName` plus its raw arguments onto an action.
 *
 * `raw` may be an object, a JSON string, or -- as LangChain's single-input
 * tools pass it -- a bare string, which is then taken as the target itself
 * (the path a `readFile` reads, the command a `bash` runs).
 */
export function mapWellKnownTool(toolName: string, raw: unknown): EvaluationAction {
  const args = argRecord(raw);
  const bare = args === undefined && typeof raw === 'string' ? raw : undefined;
  const name = normalizeToolName(toolName);
  const size = argsSize(raw);

  let action: EvaluationAction;
  if (FILE_READ_TOOLS.has(name)) {
    action = { type: 'file_read', target: firstString(args, PATH_KEYS) ?? bare ?? '' };
  } else if (FILE_WRITE_TOOLS.has(name)) {
    const content = firstString(args, CONTENT_KEYS);
    action = {
      type: 'file_write',
      target: firstString(args, PATH_KEYS) ?? bare ?? '',
      ...(content === undefined ? {} : { content }),
    };
  } else if (SHELL_TOOLS.has(name)) {
    action = { type: 'shell_command', target: firstString(args, COMMAND_KEYS) ?? bare ?? '' };
  } else if (EGRESS_TOOLS.has(name)) {
    const url = firstString(args, URL_KEYS) ?? bare;
    action = { type: 'egress', target: url === undefined ? '' : hostOf(url) };
  } else {
    action = { type: 'tool_call', target: toolName };
  }

  return size === undefined ? action : { ...action, args_size: size };
}
