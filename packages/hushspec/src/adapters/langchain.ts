import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';
import { mapWellKnownTool } from './tool-mapping.js';

/**
 * LangChain.js adapter.
 *
 * Structural typing only: nothing here imports `@langchain/core`, so the
 * adapter costs no dependency and survives the framework's class hierarchy
 * changing shape. Two entry points, because LangChain offers two places to
 * stand:
 *
 * - {@link wrapLangChainTool} gates one tool at the tool boundary, where the
 *   side effect is, and therefore holds however the tool is invoked (`invoke`,
 *   `call`, or a `DynamicTool`'s `func`);
 * - {@link createLangChainCallbackHandler} gates every tool an agent runs
 *   through one handler, for an executor whose tool list is not yours to wrap.
 *
 * Both throw `HushSpecDenied` on a deny, and put a warn to the guard's own
 * `onWarn` handler (fail-closed: no handler means deny).
 */

/** The members of a LangChain tool this adapter touches. */
export interface LangChainToolLike {
  name?: string;
  invoke?: (...args: never[]) => unknown;
  call?: (...args: never[]) => unknown;
  /** `DynamicTool` / `DynamicStructuredTool`'s underlying function. */
  func?: (...args: never[]) => unknown;
}

/** The `Serialized` first argument of `handleToolStart`. */
export interface LangChainSerializedTool {
  name?: string;
  /** Serializable id path; its last element is the class or tool name. */
  id?: string[];
}

/** What {@link createLangChainCallbackHandler} returns. */
export interface LangChainCallbackHandler {
  name: string;
  /**
   * Errors thrown by a callback are swallowed unless the handler asks for
   * them to be raised, and a denial that only logs is a fail-open.
   */
  raiseError: boolean;
  /** Run the handler inline, so the throw reaches the caller. */
  awaitHandlers: boolean;
  handleToolStart(
    tool: LangChainSerializedTool,
    input: unknown,
    runId?: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
    runName?: string,
  ): void;
}

/** The methods a wrapped tool has gated, in the order they are consulted. */
const GATED_METHODS = ['invoke', 'call', 'func'] as const;

/**
 * Map a LangChain tool invocation onto an {@link EvaluationAction}.
 *
 * Recognized names (`read_file`, `write_file`, `bash`, `fetch`, ...) map onto
 * `file_read`, `file_write`, `shell_command` and `egress`; everything else is
 * a `tool_call` targeting the tool name. A single-input tool's bare string
 * input becomes the target itself.
 */
export function mapLangChainToolCall(toolName: string, input: unknown): EvaluationAction {
  return mapWellKnownTool(toolName, input);
}

function toolNameOf(tool: object, fallback = 'unknown_tool'): string {
  const named = tool as LangChainToolLike;
  if (typeof named.name === 'string' && named.name.length > 0) return named.name;
  return fallback;
}

/**
 * Gate one LangChain tool with `guard`.
 *
 * The result is a proxy: the tool keeps its prototype, its fields, and its
 * `instanceof`, and every call still runs against the original instance --
 * only `invoke`, `call` and `func` are intercepted, so a denial throws
 * `HushSpecDenied` before the tool body runs.
 *
 * ```typescript
 * const safeTool = wrapLangChainTool(readFileTool, guard);
 * const agent = createReactAgent({ llm, tools: [safeTool] });
 * ```
 */
export function wrapLangChainTool<T extends object>(
  tool: T,
  guard: HushGuard,
  toolName?: string,
): T {
  const name = toolName ?? toolNameOf(tool);
  const gated = new Map<string | symbol, (...args: never[]) => Promise<unknown>>();

  return new Proxy(tool, {
    get(target, property, receiver): unknown {
      if (!(GATED_METHODS as readonly (string | symbol)[]).includes(property)) {
        return Reflect.get(target, property, receiver);
      }
      const original = Reflect.get(target, property, target) as unknown;
      if (typeof original !== 'function') return original;

      const cached = gated.get(property);
      if (cached !== undefined) return cached;

      const call = original as (...a: never[]) => unknown;
      const wrapper = async (...args: never[]): Promise<unknown> => {
        guard.enforce(mapLangChainToolCall(name, args[0]));
        return await Reflect.apply(call, target, args);
      };
      gated.set(property, wrapper);
      return wrapper;
    },
  });
}

/**
 * A callback handler that gates every tool an agent starts.
 *
 * ```typescript
 * await executor.invoke({ input }, { callbacks: [createLangChainCallbackHandler(guard)] });
 * ```
 *
 * `handleToolStart` fires before the tool runs, so throwing there stops the
 * call. It is the coarser of the two options -- a callback sees the tool's
 * serialized name and its input, not the tool object -- and the one to reach
 * for when the tool list is assembled somewhere you do not control.
 */
export function createLangChainCallbackHandler(guard: HushGuard): LangChainCallbackHandler {
  return {
    name: 'hushspec',
    raiseError: true,
    awaitHandlers: true,
    handleToolStart(
      tool: LangChainSerializedTool,
      input: unknown,
      _runId?: string,
      _parentRunId?: string,
      _tags?: string[],
      _metadata?: Record<string, unknown>,
      runName?: string,
    ): void {
      // `tool.name` when the framework serialized one; otherwise the run name
      // (which an executor sets to the tool's name), and only then the tail of
      // the serializable id -- which is the *class* name, not the tool's.
      const idName =
        Array.isArray(tool?.id) && tool.id.length > 0 ? tool.id[tool.id.length - 1] : undefined;
      const name =
        (typeof tool?.name === 'string' && tool.name.length > 0 ? tool.name : undefined) ??
        runName ??
        idName ??
        'unknown_tool';
      guard.enforce(mapLangChainToolCall(name, input));
    },
  };
}

/** Evaluate a tool invocation without running it. */
export function createLangChainGuard(
  guard: HushGuard,
): (toolName: string, input: unknown) => EvaluationResult {
  return (toolName: string, input: unknown): EvaluationResult =>
    guard.evaluate(mapLangChainToolCall(toolName, input));
}
