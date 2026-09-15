import type { HushSpec } from './schema.js';
import { compiledFor } from './compiled.js';
import type {
  EvaluationAction,
  EvaluationResult,
  Decision,
  TracedEvaluation,
} from './evaluate.js';
import type { Condition, RuntimeContext } from './conditions.js';
import type { DetectionExtension, DetectionLevel } from './extensions.js';
import { compileProfileRegex } from './regex.js';

export type DetectionCategory = 'prompt_injection' | 'jailbreak' | 'data_exfiltration';

export interface MatchedPattern {
  name: string;
  weight: number;
  matched_text?: string;
}

export interface DetectionResult {
  detector_name: string;
  category: DetectionCategory;
  score: number;
  matched_patterns: MatchedPattern[];
  explanation?: string;
}

export interface Detector {
  name: string;
  category: DetectionCategory;
  detect(input: string): DetectionResult;
}

export class DetectorRegistry {
  private detectors: Detector[] = [];

  register(detector: Detector): void {
    this.detectors.push(detector);
  }

  static withDefaults(): DetectorRegistry {
    const registry = new DetectorRegistry();
    registry.register(new RegexInjectionDetector());
    registry.register(new HeuristicInjectionDetector());
    registry.register(new RegexJailbreakDetector());
    registry.register(new RegexExfiltrationDetector());
    return registry;
  }

  detectAll(input: string): DetectionResult[] {
    return this.detectors.map((d) => d.detect(input));
  }
}

interface DetectionPattern {
  name: string;
  regex: RegExp;
  weight: number;
}

export class RegexInjectionDetector implements Detector {
  readonly name = 'regex_injection';
  readonly category: DetectionCategory = 'prompt_injection';

  private patterns: DetectionPattern[];

  constructor() {
    this.patterns = [
      {
        name: 'ignore_instructions',
        // Character classes spelled out explicitly ([ \t\n\r\f] / [0-9] /
        // [A-Za-z0-9_]) instead of \s/\d/\w: those shorthands are
        // Unicode-aware in Rust `regex`/Python `re` but ASCII-only in Go
        // RE2/JS `RegExp`, which made Go/JS miss NBSP-obfuscated injection
        // content that Rust/Python caught. Spelling them out keeps all four
        // SDKs consistently ASCII-whitespace-only, restoring cross-SDK parity.
        regex: /ignore[ \t\n\r\f]+(all[ \t\n\r\f]+)?(previous|prior|above)[ \t\n\r\f]+(instructions|rules|prompts)/i,
        weight: 0.4,
      },
      {
        name: 'new_instructions',
        regex: /(new|updated|revised)[ \t\n\r\f]+instructions?[ \t\n\r\f]*:/i,
        weight: 0.3,
      },
      {
        name: 'system_prompt_extract',
        regex: /(reveal|show|display|print|output)[ \t\n\r\f]+(your|the)[ \t\n\r\f]+(system[ \t\n\r\f]+)?(prompt|instructions|rules)/i,
        weight: 0.4,
      },
      {
        name: 'role_override',
        regex: /you[ \t\n\r\f]+are[ \t\n\r\f]+now[ \t\n\r\f]+(a|an|the)[ \t\n\r\f]+/i,
        weight: 0.3,
      },
      {
        name: 'pretend_mode',
        regex: /(pretend|imagine|act[ \t\n\r\f]+as[ \t\n\r\f]+if|suppose)[ \t\n\r\f]+(you|that|we)/i,
        weight: 0.2,
      },
      {
        name: 'delimiter_injection',
        regex: /(---+|===+|```)[ \t\n\r\f]*(system|assistant|user)[ \t\n\r\f]*[:\n]/i,
        weight: 0.4,
      },
      {
        name: 'encoding_evasion',
        regex: /(base64|rot13|hex|url.?encod|unicode)[ \t\n\r\f]*(decod|encod|convert)/i,
        weight: 0.1,
      },
    ];
  }

  detect(input: string): DetectionResult {
    const matchedPatterns: MatchedPattern[] = [];
    let totalWeight = 0;

    for (const pattern of this.patterns) {
      const m = pattern.regex.exec(input);
      if (m) {
        totalWeight += pattern.weight;
        matchedPatterns.push({
          name: pattern.name,
          weight: pattern.weight,
          matched_text: m[0],
        });
      }
    }

    const score = Math.min(totalWeight, 1.0);

    const explanation =
      matchedPatterns.length === 0
        ? undefined
        : `matched ${matchedPatterns.length} injection pattern(s): ${matchedPatterns.map((p) => p.name).join(', ')}`;

    return {
      detector_name: this.name,
      category: this.category,
      score,
      matched_patterns: matchedPatterns,
      explanation,
    };
  }
}

/**
 * Name of the normative heuristic detector (`heuristic_injection@1` once the
 * id version suffix is appended).
 */
export const HEURISTIC_DETECTOR_NAME = 'heuristic_injection';

/**
 * The signal families of `heuristic_injection@1`, verbatim from detection
 * spec 3.5: `[family, weight, patterns]`. Patterns are written in the
 * HushSpec regex profile (ASCII classes, no lookaround) and matched against
 * the NFC-normalized, ASCII-case-folded input, so they are lowercase. A
 * family contributes its weight at most once; the sum is clamped to 100.
 */
export const HEURISTIC_FAMILIES: ReadonlyArray<readonly [string, number, readonly string[]]> = [
  [
    'instruction_override',
    40,
    [
      'ignore (all |any |the |every |your )?(previous|prior|above|earlier|preceding) (instructions?|prompts?|rules|guidance)',
      'disregard (all |any |the |your )?(system|previous|prior|earlier|above) (prompts?|instructions?|rules)',
      'forget (all |everything )?(you were told|your instructions|the instructions|previous instructions|prior instructions)',
      '(new|updated|revised|override) instructions?[ \\t]*:',
    ],
  ],
  [
    'role_switch',
    30,
    [
      'you are now (a|an|the|my|in) ',
      'act as (a|an|the|my|if you were) ',
      'pretend (to be|you are|that you are|you have) ',
      'from now on,? you (are|will|must|should)',
      'developer mode',
      'do anything now',
      'dan mode',
    ],
  ],
  [
    'delimiter_smuggling',
    30,
    [
      '<\\|(im_start|im_end|system|endoftext)\\|>',
      '\\[/?inst\\]',
      '##+[ \\t]*(system|assistant|instructions)',
      '(begin|end) (system|hidden|secret) (prompt|instructions)',
      '<(system|assistant)>',
      '(---+|===+|```)[ \\t]*(system|assistant|user)[ \\t]*[:\\n]',
    ],
  ],
  [
    'exfiltration_coercion',
    35,
    [
      '(reveal|print|show|output|repeat|display|dump|leak|expose) (me )?(all )?(of )?(the |your )?(hidden |initial |original |secret |system |confidential |full )?(system prompt|prompt|instructions|rules|configuration|guidelines)',
      '(send|post|upload|exfiltrate|forward) [^\\n]{0,40} (to|at) https?://',
      'what (is|are|were) your (system prompt|initial instructions|hidden instructions|original instructions)',
    ],
  ],
  [
    'encoded_payload',
    15,
    ['[a-z0-9+/]{40,}={0,2}', '(\\\\u[0-9a-f]{4}){4,}', '(%[0-9a-f]{2}){8,}'],
  ],
  ['structural_punctuation', 10, ['[!?]{4,}']],
];

/**
 * The computed `structural_uppercase` family (detection spec 3.5): weight 10
 * when the NFC text has at least 40 ASCII letters and at least 60% of them are
 * uppercase. Measured before case folding, since folding erases it.
 */
export const HEURISTIC_UPPERCASE_WEIGHT = 10;
/** @see {@link HEURISTIC_UPPERCASE_WEIGHT} */
export const HEURISTIC_UPPERCASE_MIN_LETTERS = 40;
/** @see {@link HEURISTIC_UPPERCASE_WEIGHT} */
export const HEURISTIC_UPPERCASE_MIN_PERCENT = 60;

interface HeuristicFamily {
  name: string;
  weight: number;
  patterns: RegExp[];
}

/** `structural_uppercase`: at least 40 ASCII letters, at least 60% uppercase. */
function uppercaseSignal(text: string): boolean {
  let letters = 0;
  let upper = 0;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    const isUpper = code >= 65 && code <= 90;
    if (isUpper || (code >= 97 && code <= 122)) {
      letters += 1;
      if (isUpper) upper += 1;
    }
  }
  if (letters < HEURISTIC_UPPERCASE_MIN_LETTERS) return false;
  return upper * 100 >= letters * HEURISTIC_UPPERCASE_MIN_PERCENT;
}

/**
 * Fold `A-Z` and nothing else. `String.prototype.toLowerCase` is
 * Unicode-aware -- it maps the Kelvin sign to `k` and `I` with a dot above to
 * `i` plus a combining dot -- where the reference engine's
 * `to_ascii_lowercase` touches only ASCII, so spelling it out is what keeps
 * the score identical across SDKs.
 */
function asciiFold(text: string): string {
  return text.replace(/[A-Z]/g, ch => String.fromCharCode(ch.charCodeAt(0) + 32));
}

/**
 * The normative heuristic prompt-injection detector (detection spec 3.5).
 *
 * Integer arithmetic over a fixed signal table so every conformant engine
 * reproduces the score exactly: the input (already truncated to the policy's
 * `max_scan_bytes`) is NFC-normalized, the uppercase signal is measured, the
 * text is ASCII-case-folded, and each family whose pattern matches adds its
 * weight once. The receipt carries `score / 100`.
 */
export class HeuristicInjectionDetector implements Detector {
  readonly name = HEURISTIC_DETECTOR_NAME;
  readonly category: DetectionCategory = 'prompt_injection';

  private readonly families: HeuristicFamily[];

  constructor() {
    this.families = HEURISTIC_FAMILIES.map(([name, weight, patterns]) => ({
      name,
      weight,
      patterns: patterns.map(pattern => {
        try {
          return compileProfileRegex(pattern).regex;
        } catch (error) {
          throw new Error(
            `heuristic family ${name} pattern ${JSON.stringify(pattern)}: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }
      }),
    }));
  }

  /** The spec's integer score in `0..=100` and the families that fired. */
  integerScore(input: string): { score: number; matched: MatchedPattern[] } {
    const normalized = input.normalize('NFC');
    let total = 0;
    const matched: MatchedPattern[] = [];

    if (uppercaseSignal(normalized)) {
      total += HEURISTIC_UPPERCASE_WEIGHT;
      matched.push({ name: 'structural_uppercase', weight: HEURISTIC_UPPERCASE_WEIGHT / 100 });
    }

    const folded = asciiFold(normalized);
    for (const family of this.families) {
      for (const pattern of family.patterns) {
        const found = pattern.exec(folded);
        if (found == null) continue;
        total += family.weight;
        matched.push({
          name: family.name,
          weight: family.weight / 100,
          matched_text: found[0],
        });
        break;
      }
    }

    return { score: Math.min(total, 100), matched };
  }

  detect(input: string): DetectionResult {
    const { score, matched } = this.integerScore(input);
    const explanation = matched.length === 0
      ? undefined
      : `heuristic score ${score}/100 from ${matched.length} signal famil${
        matched.length === 1 ? 'y' : 'ies'
      }: ${matched.map(entry => entry.name).join(', ')}`;
    return {
      detector_name: this.name,
      category: this.category,
      score: score / 100,
      matched_patterns: matched,
      explanation,
    };
  }
}

export class RegexJailbreakDetector implements Detector {
  readonly name = 'regex_jailbreak';
  readonly category: DetectionCategory = 'jailbreak';

  private patterns: DetectionPattern[];

  constructor() {
    this.patterns = [
      {
        name: 'jailbreak_dan',
        // See RegexInjectionDetector for why \s is spelled out as
        // [ \t\n\r\f] here (Go RE2 / JS RegExp vs. Rust regex / Python re
        // Unicode-vs-ASCII parity).
        regex: /(DAN|do[ \t\n\r\f]+anything[ \t\n\r\f]+now|developer[ \t\n\r\f]+mode|jailbreak)/i,
        weight: 0.5,
      },
    ];
  }

  detect(input: string): DetectionResult {
    const matchedPatterns: MatchedPattern[] = [];
    let totalWeight = 0;

    for (const pattern of this.patterns) {
      const m = pattern.regex.exec(input);
      if (m) {
        totalWeight += pattern.weight;
        matchedPatterns.push({
          name: pattern.name,
          weight: pattern.weight,
          matched_text: m[0],
        });
      }
    }

    const score = Math.min(totalWeight, 1.0);

    const explanation =
      matchedPatterns.length === 0
        ? undefined
        : `matched ${matchedPatterns.length} jailbreak pattern(s): ${matchedPatterns.map((p) => p.name).join(', ')}`;

    return {
      detector_name: this.name,
      category: this.category,
      score,
      matched_patterns: matchedPatterns,
      explanation,
    };
  }
}

export class RegexExfiltrationDetector implements Detector {
  readonly name = 'regex_exfiltration';
  readonly category: DetectionCategory = 'data_exfiltration';

  private patterns: DetectionPattern[];

  constructor() {
    this.patterns = [
      {
        name: 'ssn',
        // Explicit ASCII non-digit boundary instead of `\b`: `\b` is
        // Unicode-aware in Rust `regex`/Python `re` (a letter like "é" or
        // "中" is `\w`, so no boundary forms before the digits) but
        // ASCII-only in Go RE2/JS `RegExp`. This keeps all four SDKs in
        // agreement -- e.g. "café123-45-6789" and "中123-45-6789" now match
        // identically everywhere. The body also spells out [0-9] instead of
        // \d: \d is Unicode-aware in Rust/Python (matching fullwidth digits
        // like "１２３-４５-６７８９") but ASCII-only in Go RE2/JS, so
        // spelling it out keeps all four SDKs ASCII-digit-only too.
        regex: /(?:^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?:[^0-9]|$)/,
        weight: 0.8,
      },
      {
        name: 'credit_card',
        regex: /(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)/,
        weight: 0.8,
      },
      {
        name: 'email_address',
        // Explicit ASCII boundaries instead of \b, for the same reason as
        // ssn above: \b is a Unicode word boundary in Rust/Python but
        // ASCII-only in Go RE2/JS. Spelling it out as an explicit
        // non-member-character boundary keeps the pattern text (and
        // matching behavior) identical across all four SDKs instead of
        // relying on each engine's own definition of "word".
        regex: /(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[^A-Za-z0-9.-]|$)/,
        weight: 0.3,
      },
      {
        name: 'api_key_pattern',
        // \s -> [ \t\n\r\f], \S -> [^ \t\n\r\f]: see RegexInjectionDetector.
        regex: /(api[_\-]?key|secret[_\-]?key|access[_\-]?token)[ \t\n\r\f]*[:=][ \t\n\r\f]*[^ \t\n\r\f]+/i,
        weight: 0.6,
      },
      {
        name: 'private_key',
        regex: /-----BEGIN[ \t\n\r\f]+(RSA[ \t\n\r\f]+)?PRIVATE[ \t\n\r\f]+KEY-----/,
        weight: 0.9,
      },
    ];
  }

  detect(input: string): DetectionResult {
    const matchedPatterns: MatchedPattern[] = [];
    let totalWeight = 0;

    for (const pattern of this.patterns) {
      const m = pattern.regex.exec(input);
      if (m) {
        totalWeight += pattern.weight;
        matchedPatterns.push({
          name: pattern.name,
          weight: pattern.weight,
          matched_text: m[0],
        });
      }
    }

    const score = Math.min(totalWeight, 1.0);

    const explanation =
      matchedPatterns.length === 0
        ? undefined
        : `matched ${matchedPatterns.length} exfiltration pattern(s): ${matchedPatterns.map((p) => p.name).join(', ')}`;

    return {
      detector_name: this.name,
      category: this.category,
      score,
      matched_patterns: matchedPatterns,
      explanation,
    };
  }
}

export interface EvaluationWithDetection {
  evaluation: EvaluationResult;
  detections: DetectionResult[];
  detectionDecision?: Decision;
}

/**
 * The level a normalized detector score maps to in a receipt's
 * `detection_trace` (Receipt specification section 4.6).
 *
 * `none` is a zero score, `low` a non-zero score below every policy threshold
 * floor, and the rest follow the prompt-injection level floors (0.25 / 0.5 /
 * 0.75) applied to every detector's normalized 0-1 score.
 */
export type DetectorLevel = 'none' | 'low' | 'suspicious' | 'high' | 'critical';

/** One detector's contribution, recorded as it ran (receipt spec 4.6). */
export interface DetectorEvaluation {
  /** Stable identifier with a version suffix, e.g. `regex_injection@1`. */
  detector_id: string;
  category: DetectionCategory;
  /** Normalized score in [0, 1]. */
  score: number;
  level: DetectorLevel;
  /** True when the finding met the policy's warn or block threshold. */
  matched: boolean;
}

/** Version suffix appended to a built-in detector's name to form its id. */
const DETECTOR_ID_VERSION = '@1';

/** Map a normalized score to its {@link DetectorLevel}. */
export function detectorLevel(score: number): DetectorLevel {
  if (score <= 0) return 'none';
  if (score < LEVEL_FLOORS.suspicious) return 'low';
  if (score < LEVEL_FLOORS.high) return 'suspicious';
  if (score < LEVEL_FLOORS.critical) return 'high';
  return 'critical';
}

/** A traced evaluation with the detection pipeline folded in. */
export interface TracedEvaluationWithDetection {
  /** The rule-block evaluation and its recorded trace, before detection. */
  traced: TracedEvaluation;
  /** The final decision callers act on. */
  evaluation: EvaluationResult;
  detections: DetectionResult[];
  detectionDecision?: Decision;
  /**
   * Per-detector receipt entries, in run order. `undefined` when the pipeline
   * did not run (no `detection:` extension); an empty array when it ran and no
   * detector was enabled or there was nothing to scan.
   */
  detectorTrace?: DetectorEvaluation[];
}

/**
 * Default byte budget for one detection scan when the policy sets none.
 * Applies to prompt_injection `max_scan_bytes` and jailbreak `max_input_bytes`.
 */
const DEFAULT_SCAN_BYTES = 200_000;

const LEVEL_FLOORS: Record<DetectionLevel, number> = {
  safe: 0.0,
  suspicious: 0.25,
  high: 0.5,
  critical: 0.75,
};

/**
 * The heuristic detector's integer score recovered from its normalized
 * `score / 100` form (exact: the normalized value is always `n / 100`).
 */
function heuristicInteger(score: number): number {
  return Math.max(Math.round(score * 100), 0);
}

const DECISION_RANK: Record<Decision, number> = { allow: 0, warn: 1, deny: 2 };

function decisionRank(decision: Decision | undefined): number {
  return decision == null ? -1 : DECISION_RANK[decision];
}

/** `deny > warn > allow`; `undefined` (no detector contribution) ranks lowest. */
function stricterDecision(base: Decision, candidate: Decision | undefined): Decision {
  return candidate != null && decisionRank(candidate) > decisionRank(base) ? candidate : base;
}

/**
 * Truncate `input` to at most `maxBytes` UTF-8 bytes without splitting a
 * multi-byte character. JS strings are UTF-16, but `max_scan_bytes` /
 * `max_input_bytes` are byte counts shared with the Rust/Python/Go SDKs
 * (whose native string types are UTF-8 byte sequences), so the limit is
 * applied against the UTF-8 encoding rather than `string.length`.
 */
function truncateUtf8(input: string, maxBytes: number): string {
  const bytes = Buffer.from(input, 'utf8');
  if (bytes.length <= maxBytes) {
    return input;
  }
  let end = maxBytes;
  // Back off while the next byte is a UTF-8 continuation byte (`10xxxxxx`),
  // so the cut point never splits a multi-byte character.
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) {
    end -= 1;
  }
  return bytes.toString('utf8', 0, end);
}

// Singletons: the spec-driven path only ever drives these built-in detectors
// (see evaluateWithDetection's threat_intel note below), so there is no need
// to pay DetectorRegistry.withDefaults()'s per-call allocation.
const INJECTION_DETECTOR = new RegexInjectionDetector();
const HEURISTIC_DETECTOR = new HeuristicInjectionDetector();
const JAILBREAK_DETECTOR = new RegexJailbreakDetector();

/**
 * Every prompt-injection detector, in registration order (detection spec
 * 3.5): the engine's regex detector and the normative heuristic one. Each is
 * scored against the same byte budget and level floors and records its own
 * `detection_trace` entry.
 */
const PROMPT_INJECTION_DETECTORS: readonly Detector[] = [INJECTION_DETECTOR, HEURISTIC_DETECTOR];

/**
 * Spec-driven detection entry point.
 *
 * `base = evaluate(spec, action)`, then the detectors configured under
 * `spec.extensions.detection` are run against `action.content` and folded
 * into `base` with a strictest-of merge (`deny > warn > allow`): detection
 * can escalate a policy allow/warn, but a policy deny is never weakened or
 * relabeled, and a tie (e.g. policy warn + detection warn) keeps the
 * policy's own `matched_rule`.
 *
 * Exact no-op -- returns `{ evaluation: base, detections: [], detectionDecision:
 * undefined }` -- when there is no `detection` extension or `action.content`
 * is empty/absent, so every existing (non-detection) evaluation fixture and
 * policy is unaffected.
 */
export function evaluateWithDetection(
  spec: HushSpec,
  action: EvaluationAction,
): EvaluationWithDetection {
  return compiledFor(spec).evaluateWithDetection(action);
}

/**
 * {@link evaluateWithDetection} with the evaluator's recorded rule trace and
 * the per-detector receipt entries (Receipt specification section 4.6).
 *
 * This is what receipts are built from: `detectorTrace` is present whenever
 * the pipeline ran -- even with nothing to scan -- so a receipt can say
 * "detection ran and found nothing" as distinct from "detection never ran".
 */
export function evaluateWithDetectionTraced(
  spec: HushSpec,
  action: EvaluationAction,
  context?: RuntimeContext,
  conditions: Record<string, Condition> = {},
): TracedEvaluationWithDetection {
  return compiledFor(spec).evaluateWithDetectionTraced(action, context, conditions);
}

/**
 * The detection extension, compiled: thresholds resolved to the floors the
 * pipeline compares against, so a scan reads no policy fields at all.
 *
 * `undefined` means the document has no `detection:` extension and the
 * pipeline does not run; a present-but-empty configuration still runs (and
 * reports an empty `detection_trace`), which is what distinguishes "detection
 * found nothing" from "detection never ran".
 */
export interface CompiledDetection {
  promptInjection?: CompiledPromptInjection;
  jailbreak?: CompiledJailbreak;
}

/** Prompt-injection detection with its level floors resolved. */
export interface CompiledPromptInjection {
  scanBytes: number;
  blockFloor: number;
  warnFloor: number;
  /** `heuristics.enabled` (detection spec 3.5.1), default `true`. */
  heuristicsEnabled: boolean;
  /** `heuristics.min_score` (detection spec 3.5.1), default `0`. */
  heuristicsMinScore: number;
}

/** Jailbreak detection with its 0-100 thresholds resolved. */
export interface CompiledJailbreak {
  scanBytes: number;
  blockThreshold: number;
  warnThreshold: number;
}

/** Compile the `detection:` extension (a no-op when the policy has none). */
export function compileDetection(
  detection: DetectionExtension | undefined,
): CompiledDetection | undefined {
  if (detection == null) return undefined;

  const compiled: CompiledDetection = {};

  const promptInjection = detection.prompt_injection;
  if (promptInjection != null && promptInjection.enabled !== false) {
    compiled.promptInjection = {
      scanBytes: promptInjection.max_scan_bytes ?? DEFAULT_SCAN_BYTES,
      blockFloor: LEVEL_FLOORS[promptInjection.block_at_or_above ?? 'high'],
      warnFloor: LEVEL_FLOORS[promptInjection.warn_at_or_above ?? 'suspicious'],
      heuristicsEnabled: promptInjection.heuristics?.enabled !== false,
      heuristicsMinScore: promptInjection.heuristics?.min_score ?? 0,
    };
  }

  const jailbreak = detection.jailbreak;
  if (jailbreak != null && jailbreak.enabled !== false) {
    compiled.jailbreak = {
      scanBytes: jailbreak.max_input_bytes ?? DEFAULT_SCAN_BYTES,
      blockThreshold: jailbreak.block_threshold ?? 80,
      warnThreshold: jailbreak.warn_threshold ?? 50,
    };
  }

  // threat_intel is NOT auto-wired: the built-in engine has only regex
  // detectors, no pattern-db / similarity model to satisfy it. Serving it
  // requires a custom Detector registered through DetectorRegistry.

  return compiled;
}

/**
 * Run the compiled detection pipeline over an evaluation that has already
 * happened, folding the detectors' verdict into it with a strictest-of merge
 * (`deny > warn > allow`): detection can escalate a policy allow/warn, but a
 * policy deny is never weakened or relabeled, and a tie (e.g. policy warn +
 * detection warn) keeps the policy's own `matched_rule`.
 *
 * An exact no-op -- the base evaluation, no detections, no `detection_trace`
 * -- when the policy has no `detection:` extension, so every existing
 * (non-detection) evaluation fixture and policy is unaffected.
 */
export function runDetection(
  detection: CompiledDetection | undefined,
  traced: TracedEvaluation,
  action: EvaluationAction,
): TracedEvaluationWithDetection {
  const base = traced.result;
  if (detection == null) {
    return { traced, evaluation: base, detections: [] };
  }

  const content = action.content ?? '';
  if (content.length === 0) {
    return { traced, evaluation: base, detections: [], detectorTrace: [] };
  }

  const detections: DetectionResult[] = [];
  const detectorTrace: DetectorEvaluation[] = [];
  // (category, contribution) for each detector that raised a warn/deny.
  const contributions: [DetectionCategory, Decision][] = [];

  const promptInjection = detection.promptInjection;
  if (promptInjection != null) {
    const scan = truncateUtf8(content, promptInjection.scanBytes);
    for (const detector of PROMPT_INJECTION_DETECTORS) {
      const isHeuristic = detector.name === HEURISTIC_DETECTOR_NAME;
      if (isHeuristic && !promptInjection.heuristicsEnabled) continue;
      const result = detector.detect(scan);
      if (isHeuristic && heuristicInteger(result.score) < promptInjection.heuristicsMinScore) {
        // Below the policy's floor the heuristic reports no signal
        // (detection spec 3.5.4).
        result.score = 0;
        result.matched_patterns = [];
        result.explanation = undefined;
      }

      let matched = false;
      if (result.score >= promptInjection.blockFloor) {
        contributions.push(['prompt_injection', 'deny']);
        matched = true;
      } else if (result.score >= promptInjection.warnFloor) {
        contributions.push(['prompt_injection', 'warn']);
        matched = true;
      }
      detectorTrace.push({
        detector_id: `${result.detector_name}${DETECTOR_ID_VERSION}`,
        category: 'prompt_injection',
        score: result.score,
        level: detectorLevel(result.score),
        matched,
      });
      detections.push(result);
    }
  }

  const jailbreak = detection.jailbreak;
  if (jailbreak != null) {
    const scan = truncateUtf8(content, jailbreak.scanBytes);
    const result = JAILBREAK_DETECTOR.detect(scan);

    // Compare directly against the 0-100 thresholds -- no rounding.
    const scaled = result.score * 100.0;
    let matched = false;
    if (scaled >= jailbreak.blockThreshold) {
      contributions.push(['jailbreak', 'deny']);
      matched = true;
    } else if (scaled >= jailbreak.warnThreshold) {
      contributions.push(['jailbreak', 'warn']);
      matched = true;
    }
    detectorTrace.push({
      detector_id: `${result.detector_name}${DETECTOR_ID_VERSION}`,
      category: 'jailbreak',
      score: result.score,
      level: detectorLevel(result.score),
      matched,
    });
    detections.push(result);
  }

  let detectionDecision: Decision | undefined;
  for (const [, decision] of contributions) {
    if (decisionRank(decision) > decisionRank(detectionDecision)) {
      detectionDecision = decision;
    }
  }

  const finalDecision = stricterDecision(base.decision, detectionDecision);
  if (finalDecision === base.decision) {
    // No escalation: return the base evaluation untouched so a policy deny
    // keeps its own matched_rule and detection never weakens a decision.
    return { traced, evaluation: base, detections, detectionDecision, detectorTrace };
  }

  // Detection escalated. Attribute it to the first detector whose
  // contribution reached the strictest detection decision.
  const escalationCategory =
    contributions.find(([, decision]) => decision === detectionDecision)?.[0] ?? 'prompt_injection';

  return {
    traced,
    evaluation: {
      decision: finalDecision,
      matched_rule: 'detection',
      reason: `content flagged by ${escalationCategory} detection`,
      origin_profile: base.origin_profile,
      posture: base.posture,
    },
    detections,
    detectionDecision,
    detectorTrace,
  };
}
