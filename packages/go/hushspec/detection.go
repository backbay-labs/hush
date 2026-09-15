package hushspec

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
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
// detectors, in registration order: the regex-based prompt-injection detector,
// the normative `heuristic_injection@1` detector (detection spec 3.5), then
// the jailbreak and exfiltration detectors.
func WithDefaultDetectors() *DetectorRegistry {
	r := NewDetectorRegistry()
	r.Register(NewRegexInjectionDetector())
	r.Register(NewHeuristicInjectionDetector())
	r.Register(NewRegexJailbreakDetector())
	r.Register(NewRegexExfiltrationDetector())
	return r
}

// NewDefaultDetectorRegistry is an alias for [WithDefaultDetectors].
func NewDefaultDetectorRegistry() *DetectorRegistry { return WithDefaultDetectors() }

// DetectorsFor returns every registered detector of category, in registration
// order. The prompt-injection pipeline runs all of them -- the regex detector
// and the normative heuristic detector -- each against the category's byte
// budget and thresholds.
func (r *DetectorRegistry) DetectorsFor(category DetectionCategory) []Detector {
	var out []Detector
	for _, detector := range r.detectors {
		if detector.Category() == category {
			out = append(out, detector)
		}
	}
	return out
}

// DetectorFor returns the first registered detector whose category matches, or
// nil.
func (r *DetectorRegistry) DetectorFor(category DetectionCategory) Detector {
	for _, detector := range r.detectors {
		if detector.Category() == category {
			return detector
		}
	}
	return nil
}

func (r *DetectorRegistry) DetectAll(input string) []DetectionResult {
	results := make([]DetectionResult, 0, len(r.detectors))
	for _, d := range r.detectors {
		results = append(results, d.Detect(input))
	}
	return results
}

// scorePatterns is the shared body of the three fixed-pattern detectors: every
// pattern that matches contributes its weight once, the total is clamped to 1,
// and the explanation names the patterns that fired. label is the word the
// explanation uses for this detector's pattern set.
func scorePatterns(patterns []detectionPattern, input, label string) (float64, []MatchedPattern, string) {
	var matched []MatchedPattern
	total := 0.0
	for index := range patterns {
		pattern := &patterns[index]
		loc := pattern.regex.FindStringIndex(input)
		if loc == nil {
			continue
		}
		total += pattern.weight
		matched = append(matched, MatchedPattern{
			Name:        pattern.name,
			Weight:      pattern.weight,
			MatchedText: input[loc[0]:loc[1]],
		})
	}
	if total > 1.0 {
		total = 1.0
	}
	if len(matched) == 0 {
		return total, nil, ""
	}
	names := make([]string, len(matched))
	for index, pattern := range matched {
		names[index] = pattern.Name
	}
	explanation := fmt.Sprintf(
		"matched %d %s pattern(s): %s", len(matched), label, strings.Join(names, ", "))
	return total, matched, explanation
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
				// Character classes are written out as explicit ASCII
				// ([ \t\n\r\f], [0-9], [A-Za-z0-9_]) rather than \s/\d/\w,
				// whose meaning differs between regex engines: a Unicode-aware
				// \s also matches NBSP and friends, so the same obfuscated
				// payload would score differently depending on the engine.
				// These patterns are normative and must not drift.
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
	score, matched, explanation := scorePatterns(d.patterns, input, "injection")
	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matched,
		Explanation:     explanation,
	}
}

// --------------------------------------------------------------------------
// The normative heuristic detector (detection spec 3.5)
// --------------------------------------------------------------------------

// HeuristicDetectorName is the name of the normative heuristic detector;
// `heuristic_injection@1` once the id version suffix is appended.
const HeuristicDetectorName = "heuristic_injection"

// HeuristicFamily is one signal family of `heuristic_injection@1`: a name, the
// weight it contributes at most once, and the patterns any of which fires it.
type HeuristicFamily struct {
	Name     string
	Weight   uint32
	Patterns []string
}

// HeuristicFamilies are the signal families of `heuristic_injection@1`,
// verbatim from detection spec 3.5.3. Patterns are written in the HushSpec
// regex profile (ASCII classes, no lookaround) and matched against the
// NFC-normalized, ASCII-case-folded input, so they are lowercase. A family
// contributes its weight at most once; the sum is clamped to 100.
//
// This table is normative: it must stay byte-for-byte identical to the table
// in detection spec 3.5.3.
var HeuristicFamilies = []HeuristicFamily{
	{
		Name:   "instruction_override",
		Weight: 40,
		Patterns: []string{
			`ignore (all |any |the |every |your )?(previous|prior|above|earlier|preceding) (instructions?|prompts?|rules|guidance)`,
			`disregard (all |any |the |your )?(system|previous|prior|earlier|above) (prompts?|instructions?|rules)`,
			`forget (all |everything )?(you were told|your instructions|the instructions|previous instructions|prior instructions)`,
			`(new|updated|revised|override) instructions?[ \t]*:`,
		},
	},
	{
		Name:   "role_switch",
		Weight: 30,
		Patterns: []string{
			`you are now (a|an|the|my|in) `,
			`act as (a|an|the|my|if you were) `,
			`pretend (to be|you are|that you are|you have) `,
			`from now on,? you (are|will|must|should)`,
			`developer mode`,
			`do anything now`,
			`dan mode`,
		},
	},
	{
		Name:   "delimiter_smuggling",
		Weight: 30,
		Patterns: []string{
			`<\|(im_start|im_end|system|endoftext)\|>`,
			`\[/?inst\]`,
			`##+[ \t]*(system|assistant|instructions)`,
			`(begin|end) (system|hidden|secret) (prompt|instructions)`,
			`<(system|assistant)>`,
			`(---+|===+|` + "```" + `)[ \t]*(system|assistant|user)[ \t]*[:\n]`,
		},
	},
	{
		Name:   "exfiltration_coercion",
		Weight: 35,
		Patterns: []string{
			`(reveal|print|show|output|repeat|display|dump|leak|expose) (me )?(all )?(of )?(the |your )?(hidden |initial |original |secret |system |confidential |full )?(system prompt|prompt|instructions|rules|configuration|guidelines)`,
			`(send|post|upload|exfiltrate|forward) [^\n]{0,40} (to|at) https?://`,
			`what (is|are|were) your (system prompt|initial instructions|hidden instructions|original instructions)`,
		},
	},
	{
		Name:   "encoded_payload",
		Weight: 15,
		Patterns: []string{
			`[a-z0-9+/]{40,}={0,2}`,
			`(\\u[0-9a-f]{4}){4,}`,
			`(%[0-9a-f]{2}){8,}`,
		},
	},
	{
		Name:     "structural_punctuation",
		Weight:   10,
		Patterns: []string{`[!?]{4,}`},
	},
}

// The computed `structural_uppercase` family (detection spec 3.5.2 step 3):
// weight 10 when the NFC text has at least 40 ASCII letters and at least 60%
// of them are uppercase. Measured before case folding, since folding erases it.
const (
	HeuristicUppercaseWeight     uint32 = 10
	HeuristicUppercaseMinLetters        = 40
	HeuristicUppercaseMinPercent        = 60
)

type compiledHeuristicFamily struct {
	name     string
	weight   uint32
	patterns []*regexp.Regexp
}

// HeuristicInjectionDetector is the normative heuristic prompt-injection
// detector of detection spec 3.5.
//
// Integer arithmetic over a fixed signal table, so every conformant engine
// reproduces the score exactly: the input (already truncated to the policy's
// `max_scan_bytes`) is NFC-normalized, the uppercase signal is measured, the
// text is ASCII-case-folded, and each family whose pattern matches adds its
// weight once. The receipt carries `score / 100`.
type HeuristicInjectionDetector struct {
	families []compiledHeuristicFamily
}

// NewHeuristicInjectionDetector compiles the normative family table through
// the HushSpec regex profile. A pattern outside the profile is a defect in
// this package, not in a policy, so it panics rather than degrading silently.
func NewHeuristicInjectionDetector() *HeuristicInjectionDetector {
	families := make([]compiledHeuristicFamily, 0, len(HeuristicFamilies))
	for _, family := range HeuristicFamilies {
		compiled := compiledHeuristicFamily{name: family.Name, weight: family.Weight}
		for _, pattern := range family.Patterns {
			re, err := CompileProfileRegex(pattern)
			if err != nil {
				panic(fmt.Sprintf("heuristic family %s pattern %q: %v", family.Name, pattern, err))
			}
			compiled.patterns = append(compiled.patterns, re)
		}
		families = append(families, compiled)
	}
	return &HeuristicInjectionDetector{families: families}
}

func (d *HeuristicInjectionDetector) Name() string { return HeuristicDetectorName }

func (d *HeuristicInjectionDetector) Category() DetectionCategory {
	return DetectionCategoryPromptInjection
}

// IntegerScore is the spec's integer score in 0..=100 and the families that
// fired, in table order with the computed uppercase signal first.
func (d *HeuristicInjectionDetector) IntegerScore(input string) (uint32, []MatchedPattern) {
	normalized := norm.NFC.String(input)
	var total uint32
	var matched []MatchedPattern

	if heuristicUppercaseSignal(normalized) {
		total += HeuristicUppercaseWeight
		matched = append(matched, MatchedPattern{
			Name:   "structural_uppercase",
			Weight: float64(HeuristicUppercaseWeight) / 100.0,
		})
	}

	// Only ASCII letters fold (detection spec 3.5.2 step 4): asciiLower leaves
	// every non-ASCII code point alone, where strings.ToLower would not.
	folded := asciiLower(normalized)
	for _, family := range d.families {
		for _, pattern := range family.patterns {
			loc := pattern.FindStringIndex(folded)
			if loc == nil {
				continue
			}
			total += family.weight
			matched = append(matched, MatchedPattern{
				Name:        family.name,
				Weight:      float64(family.weight) / 100.0,
				MatchedText: folded[loc[0]:loc[1]],
			})
			break
		}
	}

	if total > 100 {
		total = 100
	}
	return total, matched
}

func (d *HeuristicInjectionDetector) Detect(input string) DetectionResult {
	score, matched := d.IntegerScore(input)
	var explanation string
	if len(matched) > 0 {
		names := make([]string, len(matched))
		for i, pattern := range matched {
			names[i] = pattern.Name
		}
		plural := "ies"
		if len(matched) == 1 {
			plural = "y"
		}
		explanation = fmt.Sprintf("heuristic score %d/100 from %d signal famil%s: %s",
			score, len(matched), plural, strings.Join(names, ", "))
	}
	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           float64(score) / 100.0,
		MatchedPatterns: matched,
		Explanation:     explanation,
	}
}

// heuristicUppercaseSignal is the `structural_uppercase` family: at least 40
// ASCII letters, at least 60% of them uppercase. Every ASCII letter counts,
// including letters inside encoded runs.
func heuristicUppercaseSignal(text string) bool {
	letters, upper := 0, 0
	for _, r := range text {
		switch {
		case r >= 'A' && r <= 'Z':
			letters++
			upper++
		case r >= 'a' && r <= 'z':
			letters++
		}
	}
	if letters < HeuristicUppercaseMinLetters {
		return false
	}
	return upper*100 >= letters*HeuristicUppercaseMinPercent
}

// heuristicIntegerScore recovers the integer score from its normalized
// `n / 100` form (exact: the normalized value is always n/100).
func heuristicIntegerScore(score float64) int {
	return int(math.Round(math.Max(score*100.0, 0)))
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
				// Explicit ASCII class instead of \s, for the reason given on
				// ignore_instructions above.
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
	score, matched, explanation := scorePatterns(d.patterns, input, "jailbreak")
	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matched,
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
				// Explicit ASCII non-digit boundaries instead of \b, and an
				// explicit [0-9] body instead of \d. Engines disagree on both:
				// a Unicode word boundary and a Unicode digit class would also
				// match a run of digits next to a non-ASCII letter (say
				// "café123-45-6789") or a fullwidth-digit SSN. Spelling the
				// boundaries as (?:^|[^0-9]) / (?:[^0-9]|$) makes only "is this
				// an ASCII digit" matter. The pattern is normative.
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
				// Explicit ASCII boundaries instead of \b, whose meaning
				// differs between engines: a Unicode word boundary would judge
				// an address next to a non-ASCII letter differently. Spelling
				// them as (?:^|[^A-Za-z0-9._%+-]) / (?:[^A-Za-z0-9.-]|$) leaves
				// no room for that. The pattern is normative.
				name:     "email_address",
				regex:    regexp.MustCompile(`(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[^A-Za-z0-9.-]|$)`),
				weight:   0.3,
				category: DetectionCategoryDataExfil,
			},
			{
				// Explicit ASCII classes instead of \s/\S, for the reason given
				// on ignore_instructions above.
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
	score, matched, explanation := scorePatterns(d.patterns, input, "exfiltration")
	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matched,
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
	defaultHeuristicDetector = NewHeuristicInjectionDetector()
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
// It is an exact no-op -- the returned Evaluation is `base` unchanged, with no
// Detections and an empty DetectionDecision -- whenever
// spec.Extensions.Detection is absent or action.Content is empty, so a policy
// that declares no detection extension is evaluated exactly as it would be
// without this pipeline.
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
	return cachedCompile(spec).EvaluateWithDetection(action)
}

// EvaluateWithDetection is [EvaluateWithDetection] against a compiled policy,
// whose detectors were wired once at compile time.
func (p *CompiledPolicy) EvaluateWithDetection(action *EvaluationAction) EvaluationWithDetection {
	traced := p.EvaluateWithDetectionTraced(action, nil, nil)
	return EvaluationWithDetection{
		Evaluation:        traced.Evaluation,
		Detections:        traced.Detections,
		DetectionDecision: traced.DetectionDecision,
	}
}

// compiledDetector is one wired built-in detector with the policy's thresholds
// already resolved to the scale its score is compared on.
type compiledDetector struct {
	detector Detector
	category DetectionCategory
	maxBytes int
	// scale converts the detector's normalized [0, 1] score to the scale the
	// policy writes its thresholds on: 1 for the DetectionLevel floors of
	// prompt_injection, 100 for the percentage thresholds of jailbreak.
	scale          float64
	blockThreshold float64
	warnThreshold  float64
	// minScore is the `heuristics.min_score` floor of detection spec 3.5.1,
	// applied to the heuristic detector's integer score: below it the detector
	// reports 0 with no contributing families. Zero for every other detector,
	// where it is inert.
	minScore int
}

// compiledDetection is the detection extension's detector registry, built once
// per policy: which built-in detectors are wired, in evaluation order, with
// their thresholds and scan bounds resolved.
type compiledDetection struct {
	// registry holds the same detectors, for callers that want to run the
	// policy's detector set directly.
	registry  *DetectorRegistry
	detectors []compiledDetector
}

func (c *compiledDetection) add(detector compiledDetector) {
	c.registry.Register(detector.detector)
	c.detectors = append(c.detectors, detector)
}

// Detectors is the detector registry the policy's `detection` extension wires,
// built once at compile time: the built-in detectors it enables, in evaluation
// order. It is nil when the policy declares no detection extension, and empty
// when the extension disables every detector. Use it to run the policy's
// detector set directly; the decision pipeline uses it through
// [CompiledPolicy.EvaluateWithDetection].
func (p *CompiledPolicy) Detectors() *DetectorRegistry {
	if p == nil || p.detection == nil {
		return nil
	}
	return p.detection.registry
}

// compileDetection wires the built-in detectors a detection extension enables.
// A present-but-fully-disabled extension compiles to an empty registry, which
// still counts as having run (an empty, not absent, detection_trace).
func compileDetection(detection *DetectionExtension) *compiledDetection {
	compiled := &compiledDetection{registry: NewDetectorRegistry()}

	if pi := detection.PromptInjection; pi != nil && (pi.Enabled == nil || *pi.Enabled) {
		maxBytes := defaultDetectionScanBytes
		if pi.MaxScanBytes != nil {
			maxBytes = *pi.MaxScanBytes
		}
		blockLevel := DetectionLevelHigh
		if pi.BlockAtOrAbove != nil {
			blockLevel = *pi.BlockAtOrAbove
		}
		warnLevel := DetectionLevelSuspicious
		if pi.WarnAtOrAbove != nil {
			warnLevel = *pi.WarnAtOrAbove
		}
		compiled.add(compiledDetector{
			detector:       defaultInjectionDetector,
			category:       DetectionCategoryPromptInjection,
			maxBytes:       maxBytes,
			scale:          1.0,
			blockThreshold: detectionLevelFloor(blockLevel),
			warnThreshold:  detectionLevelFloor(warnLevel),
		})

		// The normative heuristic detector runs alongside the regex one
		// against the same byte budget and the same level floors, and records
		// its own trace entry (detection spec 3.5). `heuristics.enabled: false`
		// turns it off entirely: it then records no entry at all.
		heuristicsEnabled := true
		minScore := 0
		if h := pi.Heuristics; h != nil {
			if h.Enabled != nil {
				heuristicsEnabled = *h.Enabled
			}
			if h.MinScore != nil {
				minScore = *h.MinScore
			}
		}
		if heuristicsEnabled {
			compiled.add(compiledDetector{
				detector:       defaultHeuristicDetector,
				category:       DetectionCategoryPromptInjection,
				maxBytes:       maxBytes,
				scale:          1.0,
				blockThreshold: detectionLevelFloor(blockLevel),
				warnThreshold:  detectionLevelFloor(warnLevel),
				minScore:       minScore,
			})
		}
	}

	if jb := detection.Jailbreak; jb != nil && (jb.Enabled == nil || *jb.Enabled) {
		maxBytes := defaultDetectionScanBytes
		if jb.MaxInputBytes != nil {
			maxBytes = *jb.MaxInputBytes
		}
		blockThreshold := 80.0
		if jb.BlockThreshold != nil {
			blockThreshold = float64(*jb.BlockThreshold)
		}
		warnThreshold := 50.0
		if jb.WarnThreshold != nil {
			warnThreshold = float64(*jb.WarnThreshold)
		}
		compiled.add(compiledDetector{
			detector:       defaultJailbreakDetector,
			category:       DetectionCategoryJailbreak,
			maxBytes:       maxBytes,
			scale:          100.0,
			blockThreshold: blockThreshold,
			warnThreshold:  warnThreshold,
		})
	}

	// threat_intel: intentionally not auto-wired -- see EvaluateWithDetection.
	return compiled
}

// defaultDetectionScanBytes is the scan bound both detectors default to.
const defaultDetectionScanBytes = 200000

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
	return cachedCompile(spec).EvaluateWithDetectionTraced(action, context, conditions)
}

// EvaluateWithDetectionTraced is [EvaluateWithDetectionTraced] against a
// compiled policy. It is the call receipts are built from.
func (p *CompiledPolicy) EvaluateWithDetectionTraced(
	action *EvaluationAction,
	context *RuntimeContext,
	conditions map[string]*Condition,
) TracedEvaluationWithDetection {
	traced := p.EvaluateTraced(action, context, conditions)
	base := traced.Result

	if p.detection == nil {
		return TracedEvaluationWithDetection{Traced: traced, Evaluation: base}
	}
	// Detection is emptiness-gated, not presence-gated: an explicitly empty
	// payload is a no-op here, unlike secret_patterns, where presence alone
	// makes the block applicable. The pipeline still counts as having run, so
	// the trace is empty, not absent.
	content := action.ContentOrEmpty()
	if content == "" {
		empty := []DetectorEvaluation{}
		return TracedEvaluationWithDetection{
			Traced: traced, Evaluation: base, DetectorTrace: &empty,
		}
	}

	var detections []DetectionResult
	detectorTrace := []DetectorEvaluation{}
	decision := Decision("")
	category := DetectionCategory("")

	for index := range p.detection.detectors {
		wired := &p.detection.detectors[index]
		result := wired.detector.Detect(truncateToBytes(content, wired.maxBytes))
		if wired.minScore > 0 && heuristicIntegerScore(result.Score) < wired.minScore {
			// Below the policy's floor the heuristic reports no signal
			// (detection spec 3.5.4).
			result.Score = 0
			result.MatchedPatterns = nil
			result.Explanation = ""
		}
		detections = append(detections, result)

		scaled := result.Score * wired.scale
		matched := true
		switch {
		case scaled >= wired.blockThreshold:
			decision, category = mergeDetectionDecision(decision, category, DecisionDeny, wired.category)
		case scaled >= wired.warnThreshold:
			decision, category = mergeDetectionDecision(decision, category, DecisionWarn, wired.category)
		default:
			matched = false
		}
		detectorTrace = append(detectorTrace, DetectorEvaluation{
			DetectorID: result.DetectorName + DetectorIDVersion,
			Category:   wired.category,
			Score:      result.Score,
			Level:      DetectorLevelFromScore(result.Score),
			Matched:    matched,
		})
	}

	// threat_intel is intentionally not auto-wired; see the doc comment above.

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
