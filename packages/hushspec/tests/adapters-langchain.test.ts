import { describe, expect, it } from 'vitest';
import { canonicalizeValue } from '../src/canonical.js';
import { HushGuard, HushSpecDenied } from '../src/middleware.js';
import { utf8ByteLength } from '../src/utf8.js';
import {
  createLangChainCallbackHandler,
  createLangChainGuard,
  mapLangChainToolCall,
  wrapLangChainTool,
} from '../src/adapters/langchain.js';

const POLICY = `
hushspec: "0.2.0"
name: langchain-adapter-policy
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

function guard(onWarn?: () => boolean): HushGuard {
  return HushGuard.fromYaml(POLICY, onWarn ? { onWarn } : undefined);
}

// ---------------------------------------------------------------------------
// Fakes: LangChain tools are class instances with prototype methods.
// ---------------------------------------------------------------------------

class FakeTool {
  readonly name: string;
  readonly description = 'a fake LangChain tool';
  readonly calls: unknown[] = [];

  constructor(name: string) {
    this.name = name;
  }

  async invoke(input: unknown, config?: unknown): Promise<string> {
    this.calls.push({ input, config });
    return `ran ${this.name}`;
  }

  describeSelf(): string {
    return this.name;
  }
}

class FakeDynamicTool {
  readonly name = 'bash';
  readonly calls: unknown[] = [];

  func = async (input: unknown): Promise<string> => {
    this.calls.push(input);
    return 'ran func';
  };
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

describe('mapLangChainToolCall', () => {
  it('takes a single-input tool\'s bare string as the target', () => {
    expect(mapLangChainToolCall('read_file', '/etc/hosts')).toEqual({
      type: 'file_read',
      target: '/etc/hosts',
      args_size: utf8ByteLength('/etc/hosts'),
    });
    expect(mapLangChainToolCall('bash', 'ls -la').target).toBe('ls -la');
    expect(mapLangChainToolCall('fetch', 'https://api.example.com/x').target).toBe(
      'api.example.com',
    );
  });

  it('maps structured input', () => {
    const action = mapLangChainToolCall('write_file', {
      path: '/tmp/out.txt',
      text: 'hello',
    });
    expect(action.type).toBe('file_write');
    expect(action.target).toBe('/tmp/out.txt');
    expect(action.content).toBe('hello');
  });

  it('maps an unrecognized tool onto tool_call', () => {
    const action = mapLangChainToolCall('search', { query: 'weather' });
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('search');
    expect(action.args_size).toBe(utf8ByteLength(canonicalizeValue({ query: 'weather' })));
  });
});

// ---------------------------------------------------------------------------
// wrapLangChainTool
// ---------------------------------------------------------------------------

describe('wrapLangChainTool', () => {
  it('runs an allowed invocation and passes the input through', async () => {
    const tool = new FakeTool('bash');
    const wrapped = wrapLangChainTool(tool, guard());

    await expect(wrapped.invoke('ls -la', { runId: '1' })).resolves.toBe('ran bash');
    expect(tool.calls).toEqual([{ input: 'ls -la', config: { runId: '1' } }]);
  });

  it('rejects a denied invocation before the tool body runs', async () => {
    const tool = new FakeTool('bash');
    const wrapped = wrapLangChainTool(tool, guard());

    await expect(wrapped.invoke('rm -rf /')).rejects.toBeInstanceOf(HushSpecDenied);
    expect(tool.calls).toEqual([]);
  });

  it('denies an unlisted tool under a default-block policy', async () => {
    const tool = new FakeTool('dangerous_tool');
    await expect(wrapLangChainTool(tool, guard()).invoke({})).rejects.toBeInstanceOf(
      HushSpecDenied,
    );
  });

  it('gates a DynamicTool func', async () => {
    const tool = new FakeDynamicTool();
    const wrapped = wrapLangChainTool(tool, guard());

    await expect(wrapped.func('rm -rf /var')).rejects.toBeInstanceOf(HushSpecDenied);
    await expect(wrapped.func('ls')).resolves.toBe('ran func');
    expect(tool.calls).toEqual(['ls']);
  });

  it('keeps the tool\'s identity, fields and other methods', () => {
    const tool = new FakeTool('safe_tool');
    const wrapped = wrapLangChainTool(tool, guard());

    expect(wrapped).toBeInstanceOf(FakeTool);
    expect(wrapped.name).toBe('safe_tool');
    expect(wrapped.description).toBe('a fake LangChain tool');
    expect(wrapped.describeSelf()).toBe('safe_tool');
  });

  it('returns a stable gated function', () => {
    const wrapped = wrapLangChainTool(new FakeTool('safe_tool'), guard());
    expect(wrapped.invoke).toBe(wrapped.invoke);
  });

  it('accepts a tool-name override', async () => {
    const tool = new FakeTool('unnamed');
    const wrapped = wrapLangChainTool(tool, guard(), 'dangerous_tool');
    await expect(wrapped.invoke({})).rejects.toBeInstanceOf(HushSpecDenied);
  });

  it('puts a warn decision to the guard onWarn handler', async () => {
    const confirmed = new FakeTool('risky_tool');
    await expect(wrapLangChainTool(confirmed, guard(() => true)).invoke({})).resolves.toBe(
      'ran risky_tool',
    );

    const refused = new FakeTool('risky_tool');
    await expect(wrapLangChainTool(refused, guard()).invoke({})).rejects.toBeInstanceOf(
      HushSpecDenied,
    );
    expect(refused.calls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// createLangChainCallbackHandler
// ---------------------------------------------------------------------------

describe('createLangChainCallbackHandler', () => {
  it('asks to be awaited and to have its errors raised', () => {
    const handler = createLangChainCallbackHandler(guard());
    expect(handler.name).toBe('hushspec');
    expect(handler.raiseError).toBe(true);
    expect(handler.awaitHandlers).toBe(true);
  });

  it('throws on a denied tool start', () => {
    const handler = createLangChainCallbackHandler(guard());
    expect(() => handler.handleToolStart({ name: 'bash' }, 'rm -rf /')).toThrow(HushSpecDenied);
  });

  it('allows a permitted tool start', () => {
    const handler = createLangChainCallbackHandler(guard());
    expect(() => handler.handleToolStart({ name: 'bash' }, 'ls -la')).not.toThrow();
    expect(() => handler.handleToolStart({ name: 'safe_tool' }, '{}')).not.toThrow();
  });

  it('falls back to the run name when the serialized tool has none', () => {
    const handler = createLangChainCallbackHandler(guard());
    expect(() =>
      handler.handleToolStart(
        { id: ['langchain', 'tools', 'DynamicTool'] },
        '{}',
        'run-1',
        undefined,
        undefined,
        undefined,
        'dangerous_tool',
      ),
    ).toThrow(HushSpecDenied);
  });

  it('falls back to the serialized id tail when there is no run name', () => {
    const handler = createLangChainCallbackHandler(guard());
    expect(() =>
      handler.handleToolStart({ id: ['langchain', 'tools', 'dangerous_tool'] }, '{}'),
    ).toThrow(HushSpecDenied);
  });

  it('denies an unnamed tool under a default-block policy', () => {
    const handler = createLangChainCallbackHandler(guard());
    expect(() => handler.handleToolStart({}, '{}')).toThrow(HushSpecDenied);
  });
});

// ---------------------------------------------------------------------------
// createLangChainGuard
// ---------------------------------------------------------------------------

describe('createLangChainGuard', () => {
  it('evaluates without executing', () => {
    const evaluate = createLangChainGuard(guard());
    expect(evaluate('safe_tool', {}).decision).toBe('allow');
    expect(evaluate('bash', 'rm -rf /').decision).toBe('deny');
  });
});
