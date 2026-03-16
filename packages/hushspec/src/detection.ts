import type { HushSpec } from './schema.js';
import { evaluate } from './evaluate.js';
import type { EvaluationAction, EvaluationResult, Decision } from './evaluate.js';

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
        regex: /\b\d{3}-\d{2}-\d{4}\b/,
        weight: 0.8,
      },
      {
        name: 'credit_card',
        regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/,
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

export interface DetectionConfig {
  enabled: boolean;
  prompt_injection_threshold: number;
  jailbreak_threshold: number;
  exfiltration_threshold: number;
}

export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
  enabled: true,
  prompt_injection_threshold: 0.5,
  jailbreak_threshold: 0.5,
  exfiltration_threshold: 0.5,
};

export interface EvaluationWithDetection {
  evaluation: EvaluationResult;
  detections: DetectionResult[];
  detection_decision?: Decision;
}

function checkThresholds(
  detections: DetectionResult[],
  config: DetectionConfig,
): Decision | undefined {
  const exceeded = detections.some((result) => {
    let threshold: number;
    switch (result.category) {
      case 'prompt_injection':
        threshold = config.prompt_injection_threshold;
        break;
      case 'jailbreak':
        threshold = config.jailbreak_threshold;
        break;
      case 'data_exfiltration':
        threshold = config.exfiltration_threshold;
        break;
    }
    return result.score >= threshold;
  });

  return exceeded ? 'deny' : undefined;
}

/**
 * Detection deny overrides policy allow/warn but never weakens a policy deny.
 */
export function evaluateWithDetection(
  spec: HushSpec,
  action: EvaluationAction,
  registry: DetectorRegistry,
  config: DetectionConfig = DEFAULT_DETECTION_CONFIG,
): EvaluationWithDetection {
  const evaluation = evaluate(spec, action);

  if (!config.enabled) {
    return {
      evaluation,
      detections: [],
      detection_decision: undefined,
    };
  }

  const content = action.content ?? '';
  if (content.length === 0) {
    return {
      evaluation,
      detections: [],
      detection_decision: undefined,
    };
  }

  const detections = registry.detectAll(content);
  const detectionDecision = checkThresholds(detections, config);

  const finalEval: EvaluationResult =
    detectionDecision === 'deny' && evaluation.decision !== 'deny'
      ? {
          decision: 'deny',
          matched_rule: 'detection',
          reason: 'content exceeded detection threshold',
          origin_profile: evaluation.origin_profile,
          posture: evaluation.posture,
        }
      : evaluation;

  return {
    evaluation: finalEval,
    detections,
    detection_decision: detectionDecision,
  };
}
