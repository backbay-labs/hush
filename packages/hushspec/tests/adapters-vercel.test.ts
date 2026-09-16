import { describe, expect, it } from 'vitest';
import { canonicalizeValue } from '../src/canonical.js';
import { HushGuard, HushSpecDenied } from '../src/middleware.js';
import { utf8ByteLength } from '../src/utf8.js';
import { createVercelGuard, mapVercelToolCall } from '../src/adapters/vercel.js';

const POLICY = `
hushspec: "0.2.0"
name: vercel-adapter-policy
rules:
  tool_access:
    allow: ["safe_tool", "search"]
    block: ["dangerous_tool"]
    require_confirmation: ["risky_tool"]
    default: block
  shell_commands:
    forbidden_patterns:
      - "rm -rf"
  egress:
    allow: ["api.example.com"]
    default: block
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
`;

function guard(options?: { onWarn?: () => boolean }): HushGuard {
  return HushGuard.fromYaml(POLICY, options?.onWarn ? { onWarn: options.onWarn } : undefined);
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

describe('mapVercelToolCall', () => {
  it('maps readFile onto file_read', () => {
    const action = mapVercelToolCall({ toolName: 'readFile', args: { path: '/etc/hosts' } });
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('/etc/hosts');
    expect(action.args_size).toBe(utf8ByteLength(canonicalizeValue({ path: '/etc/hosts' })));
  });

  it('normalizes tool-name spelling', () => {
    for (const toolName of ['read_file', 'ReadFile', 'read-file']) {
      expect(mapVercelToolCall({ toolName, args: { path: '/a' } }).type).toBe('file_read');
    }
  });

  it('maps writeFile onto file_write with its content', () => {
    const action = mapVercelToolCall({
      toolName: 'writeFile',
      args: { path: '/tmp/out.txt', content: 'hello' },
    });
    expect(action.type).toBe('file_write');
    expect(action.target).toBe('/tmp/out.txt');
    expect(action.content).toBe('hello');
  });

  it('maps bash onto shell_command', () => {
    const action = mapVercelToolCall({ toolName: 'bash', args: { command: 'ls -la' } });
    expect(action.type).toBe('shell_command');
    expect(action.target).toBe('ls -la');
  });

  it('maps fetch onto egress, targeting the host', () => {
    const action = mapVercelToolCall({
      toolName: 'fetch',
      args: { url: 'https://api.example.com/v1/items?q=1' },
    });
    expect(action.type).toBe('egress');
    expect(action.target).toBe('api.example.com');
  });

  it('keeps an unparseable URL as the target', () => {
    const action = mapVercelToolCall({ toolName: 'fetch', args: { url: 'not a url' } });
    expect(action.type).toBe('egress');
    expect(action.target).toBe('not a url');
  });

  it('maps an unrecognized tool onto tool_call with its args size', () => {
    const args = { query: 'weather in NYC' };
    const action = mapVercelToolCall({ toolName: 'search', args });
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('search');
    expect(action.args_size).toBe(utf8ByteLength(canonicalizeValue(args)));
  });

  it('accepts the AI SDK 5 `input` spelling', () => {
    const action = mapVercelToolCall({ toolName: 'bash', input: { command: 'whoami' } });
    expect(action.type).toBe('shell_command');
    expect(action.target).toBe('whoami');
  });

  it('parses JSON string arguments and sizes them as the bytes supplied', () => {
    const raw = '{"path":   "/tmp/a.txt"}';
    const action = mapVercelToolCall({ toolName: 'readFile', args: raw });
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('/tmp/a.txt');
    expect(action.args_size).toBe(utf8ByteLength(raw));
  });

  it('tolerates missing arguments', () => {
    const action = mapVercelToolCall({ toolName: 'readFile' });
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('');
    expect(action.args_size).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// wrapTools
// ---------------------------------------------------------------------------

interface FakeTool {
  description: string;
  calls: unknown[];
  execute?: (args: unknown, options?: unknown) => Promise<string>;
}

function fakeTool(): FakeTool {
  const tool: FakeTool = {
    description: 'a fake tool',
    calls: [],
    execute: async (args: unknown, options?: unknown) => {
      tool.calls.push({ args, options });
      return 'executed';
    },
  };
  return tool;
}

describe('createVercelGuard', () => {
  it('runs an allowed tool and passes its arguments through', async () => {
    const tool = fakeTool();
    const { wrapTools } = createVercelGuard(guard());
    const tools = wrapTools({ bash: tool });

    await expect(tools.bash.execute?.({ command: 'ls -la' }, { toolCallId: 'x' })).resolves.toBe(
      'executed',
    );
    expect(tool.calls).toEqual([{ args: { command: 'ls -la' }, options: { toolCallId: 'x' } }]);
  });

  it('throws HushSpecDenied before a denied tool body runs', async () => {
    const tool = fakeTool();
    const { wrapTools } = createVercelGuard(guard());
    const tools = wrapTools({ bash: tool });

    await expect(tools.bash.execute?.({ command: 'rm -rf /' })).rejects.toBeInstanceOf(
      HushSpecDenied,
    );
    expect(tool.calls).toEqual([]);
  });

  it('denies an unlisted tool under a default-block policy', async () => {
    const tool = fakeTool();
    const { wrapTools } = createVercelGuard(guard());
    const tools = wrapTools({ dangerous_tool: tool });

    await expect(tools.dangerous_tool.execute?.({})).rejects.toBeInstanceOf(HushSpecDenied);
    expect(tool.calls).toEqual([]);
  });

  it('denies egress to a host the policy does not allow', async () => {
    const tool = fakeTool();
    const { wrapTools } = createVercelGuard(guard());
    const tools = wrapTools({ fetch: tool });

    await expect(
      tools.fetch.execute?.({ url: 'https://evil.example.org/exfil' }),
    ).rejects.toBeInstanceOf(HushSpecDenied);
    await expect(tools.fetch.execute?.({ url: 'https://api.example.com/ok' })).resolves.toBe(
      'executed',
    );
  });

  it('puts a warn decision to the guard onWarn handler', async () => {
    const confirmed = fakeTool();
    const refused = fakeTool();

    const allowing = createVercelGuard(guard({ onWarn: () => true }));
    await expect(allowing.wrapTools({ risky_tool: confirmed }).risky_tool.execute?.({})).resolves.toBe(
      'executed',
    );

    // Fail-closed: the default handler refuses, so a warn is a denial.
    const refusing = createVercelGuard(guard());
    await expect(
      refusing.wrapTools({ risky_tool: refused }).risky_tool.execute?.({}),
    ).rejects.toBeInstanceOf(HushSpecDenied);
    expect(refused.calls).toEqual([]);
  });

  it('keeps every other member of a tool', () => {
    const tool = fakeTool();
    const wrapped = createVercelGuard(guard()).wrapTools({ bash: tool });
    expect(wrapped.bash.description).toBe('a fake tool');
    expect(wrapped.bash.execute).not.toBe(tool.execute);
  });

  it('leaves a tool without execute untouched', () => {
    const providerExecuted = { description: 'runs on the provider' };
    const wrapped = createVercelGuard(guard()).wrapTools({ web_search: providerExecuted });
    expect(wrapped.web_search).toBe(providerExecuted);
  });

  it('evaluates a tool call without executing it', () => {
    const tool = fakeTool();
    const vercel = createVercelGuard(guard());
    vercel.wrapTools({ bash: tool });

    expect(vercel.evaluate({ toolName: 'safe_tool', args: {} }).decision).toBe('allow');
    expect(vercel.evaluate({ toolName: 'dangerous_tool', args: {} }).decision).toBe('deny');
    expect(tool.calls).toEqual([]);
  });

  it('wraps a single tool for a hand-assembled tool set', async () => {
    const tool = fakeTool();
    const wrapped = createVercelGuard(guard()).wrapTool('bash', tool);
    await expect(wrapped.execute?.({ command: 'rm -rf /tmp' })).rejects.toBeInstanceOf(
      HushSpecDenied,
    );
  });
});
