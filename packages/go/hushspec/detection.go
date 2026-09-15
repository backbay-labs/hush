package hushspec

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

type DetectionCategory string

const (
	DetectionCategoryPromptInjection DetectionCategory = "prompt_injection"
	DetectionCategoryJailbreak       DetectionCategory = "jailbreak"
	DetectionCategoryDataExfil       DetectionCategory = "data_exfiltration"
)

type MatchedPattern struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	MatchedText string  `json:"matched_text,omitempty"`
}

type DetectionResult struct {
	DetectorName    string            `json:"detector_name"`
	Category        DetectionCategory `json:"category"`
	Score           float64           `json:"score"`
	MatchedPatterns []MatchedPattern  `json:"matched_patterns"`
	Explanation     string            `json:"explanation,omitempty"`
}

// Detector scans input text for a specific threat category.
type Detector interface {
	Name() string
	Category() DetectionCategory
	Detect(input string) DetectionResult
}

// DetectorRegistry runs a set of detectors against input.
type DetectorRegistry struct {
	detectors []Detector
}

func NewDetectorRegistry() *DetectorRegistry {
	return &DetectorRegistry{}
}

func (r *DetectorRegistry) Register(detector Detector) {
	r.detectors = append(r.detectors, detector)
}

// WithDefaultDetectors returns a registry pre-loaded with the built-in
// regex-based injection, jailbreak, and exfiltration detectors.
func WithDefaultDetectors() *DetectorRegistry {
	r := NewDetectorRegistry()
	r.Register(NewRegexInjectionDetector())
	r.Register(NewRegexJailbreakDetector())
	r.Register(NewRegexExfiltrationDetector())
	return r
}

func (r *DetectorRegistry) DetectAll(input string) []DetectionResult {
	results := make([]DetectionResult, 0, len(r.detectors))
	for _, d := range r.detectors {
		results = append(results, d.Detect(input))
	}
	return results
}

type detectionPattern struct {
	name     string
	regex    *regexp.Regexp
	weight   float64
	category DetectionCategory
}

// RegexInjectionDetector scores prompt injection attempts using a fixed
// set of compiled regex patterns.
type RegexInjectionDetector struct {
	patterns []detectionPattern
}

func NewRegexInjectionDetector() *RegexInjectionDetector {
	return &RegexInjectionDetector{
		patterns: []detectionPattern{
			{
				// Character classes below are explicit ASCII ([ \t\n\r\f],
				// [0-9], [A-Za-z0-9_]) instead of \s/\d/\w: those shorthands
				// are Unicode-aware in Rust `regex` & Python `re` but
				// ASCII-only in Go RE2 & JS RegExp, so a pattern using \s+
				// let Rust/Python match NBSP-obfuscated injection content
				// that Go/JS missed. Must stay byte-for-byte identical to
				// the Rust/TS/Python patterns.
				name:     "ignore_instructions",
				regex:    regexp.MustCompile(`(?i)ignore[ \t\n\r\f]+(all[ \t\n\r\f]+)?(previous|prior|above)[ \t\n\r\f]+(instructions|rules|prompts)`),
				weight:   0.4,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "new_instructions",
				regex:    regexp.MustCompile(`(?i)(new|updated|revised)[ \t\n\r\f]+instructions?[ \t\n\r\f]*:`),
				weight:   0.3,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "system_prompt_extract",
				regex:    regexp.MustCompile(`(?i)(reveal|show|display|print|output)[ \t\n\r\f]+(your|the)[ \t\n\r\f]+(system[ \t\n\r\f]+)?(prompt|instructions|rules)`),
				weight:   0.4,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "role_override",
				regex:    regexp.MustCompile(`(?i)you[ \t\n\r\f]+are[ \t\n\r\f]+now[ \t\n\r\f]+(a|an|the)[ \t\n\r\f]+`),
				weight:   0.3,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "pretend_mode",
				regex:    regexp.MustCompile(`(?i)(pretend|imagine|act[ \t\n\r\f]+as[ \t\n\r\f]+if|suppose)[ \t\n\r\f]+(you|that|we)`),
				weight:   0.2,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "delimiter_injection",
				regex:    regexp.MustCompile(`(?i)(---+|===+|` + "```" + `)[ \t\n\r\f]*(system|assistant|user)[ \t\n\r\f]*[:\n]`),
				weight:   0.4,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "encoding_evasion",
				regex:    regexp.MustCompile(`(?i)(base64|rot13|hex|url.?encod|unicode)[ \t\n\r\f]*(decod|encod|convert)`),
				weight:   0.1,
				category: DetectionCategoryPromptInjection,
			},
		},
	}
}

func (d *RegexInjectionDetector) Name() string { return "regex_injection" }

func (d *RegexInjectionDetector) Category() DetectionCategory {
	return DetectionCategoryPromptInjection
}

func (d *RegexInjectionDetector) Detect(input string) DetectionResult {
	var matchedPatterns []MatchedPattern
	totalWeight := 0.0

	for _, p := range d.patterns {
		loc := p.regex.FindStringIndex(input)
		if loc != nil {
			totalWeight += p.weight
			matchedPatterns = append(matchedPatterns, MatchedPattern{
				Name:        p.name,
				Weight:      p.weight,
				MatchedText: input[loc[0]:loc[1]],
			})
		}
	}

	score := totalWeight
	if score > 1.0 {
		score = 1.0
	}

	var explanation string
	if len(matchedPatterns) > 0 {
		names := make([]string, len(matchedPatterns))
		for i, p := range matchedPatterns {
			names[i] = p.Name
		}
		explanation = fmt.Sprintf(
			"matched %d injection pattern(s): %s",
			len(matchedPatterns), strings.Join(names, ", "),
		)
	}

	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matchedPatterns,
		Explanation:     explanation,
	}
}

// RegexJailbreakDetector scores jailbreak attempts using a fixed set of
// compiled regex patterns.
type RegexJailbreakDetector struct {
	patterns []detectionPattern
}

func NewRegexJailbreakDetector() *RegexJailbreakDetector {
	return &RegexJailbreakDetector{
		patterns: []detectionPattern{
			{
				// See the ignore_instructions comment above: explicit ASCII
				// class instead of \s for cross-SDK parity.
				name:     "jailbreak_dan",
				regex:    regexp.MustCompile(`(?i)(DAN|do[ \t\n\r\f]+anything[ \t\n\r\f]+now|developer[ \t\n\r\f]+mode|jailbreak)`),
				weight:   0.5,
				category: DetectionCategoryJailbreak,
			},
		},
	}
}

func (d *RegexJailbreakDetector) Name() string { return "regex_jailbreak" }

func (d *RegexJailbreakDetector) Category() DetectionCategory {
	return DetectionCategoryJailbreak
}

func (d *RegexJailbreakDetector) Detect(input string) DetectionResult {
	var matchedPatterns []MatchedPattern
	totalWeight := 0.0

	for _, p := range d.patterns {
		loc := p.regex.FindStringIndex(input)
		if loc != nil {
			totalWeight += p.weight
			matchedPatterns = append(matchedPatterns, MatchedPattern{
				Name:        p.name,
				Weight:      p.weight,
				MatchedText: input[loc[0]:loc[1]],
			})
		}
	}

	score := totalWeight
	if score > 1.0 {
		score = 1.0
	}

	var explanation string
	if len(matchedPatterns) > 0 {
		names := make([]string, len(matchedPatterns))
		for i, p := range matchedPatterns {
			names[i] = p.Name
		}
		explanation = fmt.Sprintf(
			"matched %d jailbreak pattern(s): %s",
			len(matchedPatterns), strings.Join(names, ", "),
		)
	}

	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matchedPatterns,
		Explanation:     explanation,
	}
}

// RegexExfiltrationDetector scores data exfiltration risk by matching
// PII, credentials, and sensitive data patterns.
type RegexExfiltrationDetector struct {
	patterns []detectionPattern
}

func NewRegexExfiltrationDetector() *RegexExfiltrationDetector {
	return &RegexExfiltrationDetector{
		patterns: []detectionPattern{
			{
				// Explicit ASCII non-digit boundaries instead of \b AND an
				// explicit [0-9] body instead of \d: Go RE2's \b and \d are
				// already ASCII-only, but Rust `regex` and Python `re` treat
				// \b as a Unicode word boundary and \d as a Unicode digit
				// class, so a run of digits preceded/followed by a non-ASCII
				// letter (e.g. "café123-45-6789") or a fullwidth-digit SSN
				// matched there but not here. The explicit (?:^|[^0-9]) /
				// (?:[^0-9]|$) boundaries and [0-9] body make the ASCII-vs-
				// Unicode distinction irrelevant -- only "is this an ASCII
				// digit" matters -- so all four SDKs agree. Must stay
				// byte-for-byte identical to the Rust/TS/Python patterns.
				name:     "ssn",
				regex:    regexp.MustCompile(`(?:^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?:[^0-9]|$)`),
				weight:   0.8,
				category: DetectionCategoryDataExfil,
			},
			{
				// Same ASCII-boundary fix as ssn above.
				name:     "credit_card",
				regex:    regexp.MustCompile(`(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)`),
				weight:   0.8,
				category: DetectionCategoryDataExfil,
			},
			{
				// Explicit ASCII boundaries instead of \b: Rust `regex` and
				// Python `re` treat \b as a Unicode word boundary while Go RE2
				// and JS RegExp treat it as ASCII, so an address adjacent to a
				// non-ASCII letter diverged. The explicit
				// (?:^|[^A-Za-z0-9._%+-]) / (?:[^A-Za-z0-9.-]|$) boundaries make
				// all four agree. Must stay byte-for-byte identical to the
				// Rust/TS/Python patterns.
				name:     "email_address",
				regex:    regexp.MustCompile(`(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[^A-Za-z0-9.-]|$)`),
				weight:   0.3,
				category: DetectionCategoryDataExfil,
			},
			{
				// See the ignore_instructions comment above: explicit ASCII
				// classes instead of \s/\S for cross-SDK parity.
				name:     "api_key_pattern",
				regex:    regexp.MustCompile(`(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)[ \t\n\r\f]*[:=][ \t\n\r\f]*[^ \t\n\r\f]+`),
				weight:   0.6,
				category: DetectionCategoryDataExfil,
			},
			{
				name:     "private_key",
				regex:    regexp.MustCompile(`-----BEGIN[ \t\n\r\f]+(RSA[ \t\n\r\f]+)?PRIVATE[ \t\n\r\f]+KEY-----`),
				weight:   0.9,
				category: DetectionCategoryDataExfil,
			},
		},
	}
}

func (d *RegexExfiltrationDetector) Name() string { return "regex_exfiltration" }

func (d *RegexExfiltrationDetector) Category() DetectionCategory {
	return DetectionCategoryDataExfil
}

func (d *RegexExfiltrationDetector) Detect(input string) DetectionResult {
	var matchedPatterns []MatchedPattern
	totalWeight := 0.0

	for _, p := range d.patterns {
		loc := p.regex.FindStringIndex(input)
		if loc != nil {
			totalWeight += p.weight
			matchedPatterns = append(matchedPatterns, MatchedPattern{
				Name:        p.name,
				Weight:      p.weight,
				MatchedText: input[loc[0]:loc[1]],
			})
		}
	}

	score := totalWeight
	if score > 1.0 {
		score = 1.0
	}

	var explanation string
	if len(matchedPatterns) > 0 {
		names := make([]string, len(matchedPatterns))
		for i, p := range matchedPatterns {
			names[i] = p.Name
		}
		explanation = fmt.Sprintf(
			"matched %d exfiltration pattern(s): %s",
			len(matchedPatterns), strings.Join(names, ", "),
		)
	}

	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matchedPatterns,
		Explanation:     explanation,
	}
}

// EvaluationWithDetection combines a policy evaluation with the detection
// signal folded into it. DetectionDecision is "" (none) when no configured
// detector's contribution reached its warn threshold, otherwise DecisionWarn
// or DecisionDeny -- the strictest contribution across the detectors that ran.
type EvaluationWithDetection struct {
	Evaluation        EvaluationResult
	Detections        []DetectionResult
	DetectionDecision Decision
}

// DetectorLevel is the level a normalized detector score maps to in a
// receipt's `detection_trace` (receipt spec 4.6).
//
// none is a zero score, low is a non-zero score below every policy threshold
// floor, and the rest follow the DetectionLevel floors of the prompt-injection
// thresholds (0.25 / 0.5 / 0.75) applied to every detector's normalized score.
type DetectorLevel string

const (
	DetectorLevelNone       DetectorLevel = "none"
	DetectorLevelLow        DetectorLevel = "low"
	DetectorLevelSuspicious DetectorLevel = "suspicious"
	DetectorLevelHigh       DetectorLevel = "high"
	DetectorLevelCritical   DetectorLevel = "critical"
)

// DetectorLevelFromScore maps a normalized score in [0, 1] to its level.
func DetectorLevelFromScore(score float64) DetectorLevel {
	switch {
	case score <= 0:
		return DetectorLevelNone
	case score < detectionLevelFloor(DetectionLevelSuspicious):
		return DetectorLevelLow
	case score < detectionLevelFloor(DetectionLevelHigh):
		return DetectorLevelSuspicious
	case score < detectionLevelFloor(DetectionLevelCritical):
		return DetectorLevelHigh
	default:
		return DetectorLevelCritical
	}
}

// DetectorIDVersion is the version suffix appended to a built-in detector's
// name to form the stable `detector_id` a receipt records.
const DetectorIDVersion = "@1"

// DetectorEvaluation is one detector's contribution, recorded as it ran
// (receipt spec 4.6).
type DetectorEvaluation struct {
	// DetectorID is the stable detector identifier with a version suffix,
	// e.g. "regex_injection@1".
	DetectorID string            `json:"detector_id"`
	Category   DetectionCategory `json:"category"`
	// Score is the detector's normalized score in [0, 1].
	Score float64       `json:"score"`
	Level DetectorLevel `json:"level"`
	// Matched is true when the finding met the policy's warn or block
	// threshold and so contributed to the decision.
	Matched bool `json:"matched"`
}

// TracedEvaluationWithDetection is an [EvaluationWithDetection] with the
// evaluator's recorded rule trace and the per-detector receipt entries.
//
// DetectorTrace is nil when the pipeline did not run (the policy has no
// `detection:` extension) and a pointer to an empty slice when it ran but no
// detector was enabled or there was no content to scan -- the distinction the
// receipt schema draws between an absent and an empty `detection_trace`.
type TracedEvaluationWithDetection struct {
	// Traced is the rule-block evaluation and its recorded trace, before
	// detection.
	Traced TracedEvaluation
	// Evaluation is the final decision callers act on (the base evaluation,
	// possibly escalated by detection).
	Evaluation        EvaluationResult
	Detections        []DetectionResult
	DetectionDecision Decision
	DetectorTrace     *[]DetectorEvaluation
}

// defaultInjectionDetector and defaultJailbreakDetector are process-wide
// singletons. The built-in pattern sets are static, so EvaluateWithDetection
// reuses one compiled instance of each rather than recompiling every regex
// on every call.
var (
	defaultInjectionDetector = NewRegexInjectionDetector()
	defaultJailbreakDetector = NewRegexJailbreakDetector()
)

// detectionLevelFloor maps a DetectionLevel to the score floor a detector's
// score must meet or exceed to be considered "at or above" that level:
// safe=0.0, suspicious=0.25, high=0.5, critical=0.75. Reuses detectionRank
// (validate.go) -- the single source of truth for DetectionLevel ordering --
// so the level-to-floor mapping can never drift from the level-ordering
// warning validateDetection already relies on.
func detectionLevelFloor(level DetectionLevel) float64 {
	return float64(detectionRank(level)) * 0.25
}

// truncateToBytes returns the longest prefix of s that is at most maxBytes
// bytes long without splitting a multi-byte UTF-8 rune.
func truncateToBytes(s string, maxBytes int) string {
	if maxBytes < 0 || len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

// mergeDetectionDecision keeps the strictest (highest-rank) of the current
// and new contributions. Ties keep the current (earlier-evaluated) one, so
// "category" ends up naming the first detector that forced the escalation
// to the final level, per spec.
func mergeDetectionDecision(
	curDecision Decision, curCategory DetectionCategory,
	newDecision Decision, newCategory DetectionCategory,
) (Decision, DetectionCategory) {
	if decisionRank(newDecision) > decisionRank(curDecision) {
		return newDecision, newCategory
	}
	return curDecision, curCategory
}

// EvaluateWithDetection runs the reference policy evaluator and, when the
// spec declares a `detection` extension, scans action.Content with the
// built-in regex detectors and folds their signal into the decision.
//
// It is an EXACT no-op -- the returned Evaluation is `base` unchanged, with
// no Detections and an empty DetectionDecision -- whenever
// spec.Extensions.Detection is absent or action.Content is empty. Every
// pre-existing evaluation fixture has no detection extension, so this keeps
// them byte-for-byte unaffected.
//
// prompt_injection and jailbreak are wired to the built-in regex detectors
// (RegexInjectionDetector / RegexJailbreakDetector), each gated on being
// present in the extension AND not explicitly disabled (enabled != false;
// default enabled). threat_intel is intentionally NOT auto-wired: the
// built-in engine ships regex detectors only, with no pattern-db /
// similarity model to back a threat_intel signal -- a caller that needs one
// must register a custom Detector via DetectorRegistry and run it itself.
//
// The two wired detectors run in a fixed order (prompt_injection, then
// jailbreak); detection_decision is the strictest of their contributions.
// The final decision is the strictest of the base policy decision and
// detection_decision (deny > warn > allow). Detection only ever escalates:
// if it doesn't strictly exceed the base decision's rank, `base` is
// returned unchanged -- a policy warn/deny keeps its own matched_rule and is
// never weakened or relabeled. If it does escalate, the returned evaluation
// gets matched_rule "detection" and a reason naming the category (the first
// detector that forced the escalation to the final level).
func EvaluateWithDetection(spec *HushSpec, action *EvaluationAction) EvaluationWithDetection {
	traced := EvaluateWithDetectionTraced(spec, action, nil, nil)
	return EvaluationWithDetection{
		Evaluation:        traced.Evaluation,
		Detections:        traced.Detections,
		DetectionDecision: traced.DetectionDecision,
	}
}

// EvaluateWithDetectionTraced is [EvaluateWithDetection] with the evaluator's
// recorded rule trace and the per-detector entries a receipt records. The
// explicit context replaces action.Context and out-of-band conditions keyed by
// rule-block name are ANDed with each block's own `when` (core spec 3.13).
//
// It is the call receipts are built from, so the decision an enforcement point
// acts on and the evidence recorded for it can never disagree.
func EvaluateWithDetectionTraced(
	spec *HushSpec,
	action *EvaluationAction,
	context *RuntimeContext,
	conditions map[string]*Condition,
) TracedEvaluationWithDetection {
	traced := EvaluateTraced(spec, action, context, conditions)
	base := traced.Result

	if spec == nil || spec.Extensions == nil || spec.Extensions.Detection == nil {
		return TracedEvaluationWithDetection{Traced: traced, Evaluation: base}
	}
	// Detection is emptiness-gated, not presence-gated: Rust reads
	// `content.unwrap_or_default()` and returns the base evaluation when the
	// result is empty, so an explicitly empty payload is a no-op here (unlike
	// secret_patterns, where presence alone makes the block applicable). The
	// pipeline still counts as having run, so the trace is empty, not absent.
	if action.ContentOrEmpty() == "" {
		empty := []DetectorEvaluation{}
		return TracedEvaluationWithDetection{
			Traced: traced, Evaluation: base, DetectorTrace: &empty,
		}
	}
	det := spec.Extensions.Detection

	var detections []DetectionResult
	detectorTrace := []DetectorEvaluation{}
	decision := Decision("")
	category := DetectionCategory("")

	if pi := det.PromptInjection; pi != nil && (pi.Enabled == nil || *pi.Enabled) {
		maxBytes := 200000
		if pi.MaxScanBytes != nil {
			maxBytes = *pi.MaxScanBytes
		}
		result := defaultInjectionDetector.Detect(truncateToBytes(action.ContentOrEmpty(), maxBytes))
		detections = append(detections, result)

		blockLevel := DetectionLevelHigh
		if pi.BlockAtOrAbove != nil {
			blockLevel = *pi.BlockAtOrAbove
		}
		warnLevel := DetectionLevelSuspicious
		if pi.WarnAtOrAbove != nil {
			warnLevel = *pi.WarnAtOrAbove
		}

		matched := true
		switch {
		case result.Score >= detectionLevelFloor(blockLevel):
			decision, category = mergeDetectionDecision(decision, category, DecisionDeny, DetectionCategoryPromptInjection)
		case result.Score >= detectionLevelFloor(warnLevel):
			decision, category = mergeDetectionDecision(decision, category, DecisionWarn, DetectionCategoryPromptInjection)
		default:
			matched = false
		}
		detectorTrace = append(detectorTrace, DetectorEvaluation{
			DetectorID: result.DetectorName + DetectorIDVersion,
			Category:   DetectionCategoryPromptInjection,
			Score:      result.Score,
			Level:      DetectorLevelFromScore(result.Score),
			Matched:    matched,
		})
	}

	if jb := det.Jailbreak; jb != nil && (jb.Enabled == nil || *jb.Enabled) {
		maxBytes := 200000
		if jb.MaxInputBytes != nil {
			maxBytes = *jb.MaxInputBytes
		}
		result := defaultJailbreakDetector.Detect(truncateToBytes(action.ContentOrEmpty(), maxBytes))
		detections = append(detections, result)

		blockThreshold := 80.0
		if jb.BlockThreshold != nil {
			blockThreshold = float64(*jb.BlockThreshold)
		}
		warnThreshold := 50.0
		if jb.WarnThreshold != nil {
			warnThreshold = float64(*jb.WarnThreshold)
		}

		scaled := result.Score * 100.0
		matched := true
		switch {
		case scaled >= blockThreshold:
			decision, category = mergeDetectionDecision(decision, category, DecisionDeny, DetectionCategoryJailbreak)
		case scaled >= warnThreshold:
			decision, category = mergeDetectionDecision(decision, category, DecisionWarn, DetectionCategoryJailbreak)
		default:
			matched = false
		}
		detectorTrace = append(detectorTrace, DetectorEvaluation{
			DetectorID: result.DetectorName + DetectorIDVersion,
			Category:   DetectionCategoryJailbreak,
			Score:      result.Score,
			Level:      DetectorLevelFromScore(result.Score),
			Matched:    matched,
		})
	}

	// threat_intel: intentionally not auto-wired -- see doc comment above.
	// No detector runs for it; det.ThreatIntel is unused here on purpose.

	final := base
	if decisionRank(decision) > decisionRank(base.Decision) {
		final = EvaluationResult{
			Decision:      decision,
			MatchedRule:   "detection",
			Reason:        fmt.Sprintf("content flagged by %s detection", category),
			OriginProfile: base.OriginProfile,
			Posture:       base.Posture,
		}
	}

	return TracedEvaluationWithDetection{
		Traced:            traced,
		Evaluation:        final,
		Detections:        detections,
		DetectionDecision: decision,
		DetectorTrace:     &detectorTrace,
	}
}
