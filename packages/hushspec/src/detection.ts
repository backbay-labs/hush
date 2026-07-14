import type { HushSpec } from './schema.js';
import { evaluate } from './evaluate.js';
import type { EvaluationAction, EvaluationResult, Decision } from './evaluate.js';
import type { DetectionLevel } from './extensions.js';

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
        regex: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)/i,
        weight: 0.4,
      },
      {
        name: 'new_instructions',
        regex: /(new|updated|revised)\s+instructions?\s*:/i,
        weight: 0.3,
      },
      {
        name: 'system_prompt_extract',
        regex: /(reveal|show|display|print|output)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)/i,
        weight: 0.4,
      },
      {
        name: 'role_override',
        regex: /you\s+are\s+now\s+(a|an|the)\s+/i,
        weight: 0.3,
      },
      {
        name: 'pretend_mode',
        regex: /(pretend|imagine|act\s+as\s+if|suppose)\s+(you|that|we)/i,
        weight: 0.2,
      },
      {
        name: 'delimiter_injection',
        regex: /(---+|===+|```)\s*(system|assistant|user)\s*[:\n]/i,
        weight: 0.4,
      },
      {
        name: 'encoding_evasion',
        regex: /(base64|rot13|hex|url.?encod|unicode)\s*(decod|encod|convert)/i,
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

export class RegexJailbreakDetector implements Detector {
  readonly name = 'regex_jailbreak';
  readonly category: DetectionCategory = 'jailbreak';

  private patterns: DetectionPattern[];

  constructor() {
    this.patterns = [
      {
        name: 'jailbreak_dan',
        regex: /(DAN|do\s+anything\s+now|developer\s+mode|jailbreak)/i,
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
        // identically everywhere.
        regex: /(?:^|[^0-9])\d{3}-\d{2}-\d{4}(?:[^0-9]|$)/,
        weight: 0.8,
      },
      {
        name: 'credit_card',
        regex: /(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)/,
        weight: 0.8,
      },
      {
        name: 'email_address',
        regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
        weight: 0.3,
      },
      {
        name: 'api_key_pattern',
        regex: /(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*\S+/i,
        weight: 0.6,
      },
      {
        name: 'private_key',
        regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
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

const LEVEL_FLOORS: Record<DetectionLevel, number> = {
  safe: 0.0,
  suspicious: 0.25,
  high: 0.5,
  critical: 0.75,
};

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

// Singletons: the spec-driven path only ever drives these two built-in
// detectors (see evaluateWithDetection's threat_intel note below), so there
// is no need to pay DetectorRegistry.withDefaults()'s per-call allocation.
const INJECTION_DETECTOR = new RegexInjectionDetector();
const JAILBREAK_DETECTOR = new RegexJailbreakDetector();

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
  const base = evaluate(spec, action);

  const det = spec.extensions?.detection;
  if (det == null) {
    return { evaluation: base, detections: [], detectionDecision: undefined };
  }

  const content = action.content ?? '';
  if (content.length === 0) {
    return { evaluation: base, detections: [], detectionDecision: undefined };
  }

  const detections: DetectionResult[] = [];
  let detectionDecision: Decision | undefined;
  let escalationCategory: DetectionCategory | undefined;

  const promptInjection = det.prompt_injection;
  if (promptInjection != null && promptInjection.enabled !== false) {
    const scan = truncateUtf8(content, promptInjection.max_scan_bytes ?? 200_000);
    const result = INJECTION_DETECTOR.detect(scan);
    detections.push(result);

    const blockFloor = LEVEL_FLOORS[promptInjection.block_at_or_above ?? 'high'];
    const warnFloor = LEVEL_FLOORS[promptInjection.warn_at_or_above ?? 'suspicious'];
    const contribution: Decision | undefined =
      result.score >= blockFloor ? 'deny' : result.score >= warnFloor ? 'warn' : undefined;

    if (contribution != null && decisionRank(contribution) > decisionRank(detectionDecision)) {
      detectionDecision = contribution;
      escalationCategory = 'prompt_injection';
    }
  }

  const jailbreak = det.jailbreak;
  if (jailbreak != null && jailbreak.enabled !== false) {
    const scan = truncateUtf8(content, jailbreak.max_input_bytes ?? 200_000);
    const result = JAILBREAK_DETECTOR.detect(scan);
    detections.push(result);

    // Compare directly against the 0-100 thresholds -- no rounding.
    const scaled = result.score * 100.0;
    const blockThreshold = jailbreak.block_threshold ?? 80;
    const warnThreshold = jailbreak.warn_threshold ?? 50;
    const contribution: Decision | undefined =
      scaled >= blockThreshold ? 'deny' : scaled >= warnThreshold ? 'warn' : undefined;

    if (contribution != null && decisionRank(contribution) > decisionRank(detectionDecision)) {
      detectionDecision = contribution;
      escalationCategory = 'jailbreak';
    }
  }

  // threat_intel is NOT auto-wired: the built-in engine has only regex
  // detectors, no pattern-db / similarity model to satisfy it. Serving it
  // requires a custom Detector registered through DetectorRegistry.

  const finalDecision = stricterDecision(base.decision, detectionDecision);
  if (finalDecision === base.decision) {
    return { evaluation: base, detections, detectionDecision };
  }

  return {
    evaluation: {
      decision: finalDecision,
      matched_rule: 'detection',
      reason: `content flagged by ${escalationCategory} detection`,
      origin_profile: base.origin_profile,
      posture: base.posture,
    },
    detections,
    detectionDecision,
  };
}
