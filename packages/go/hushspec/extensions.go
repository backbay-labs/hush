package hushspec

// Extensions groups optional extension blocks that augment the base policy.
type Extensions struct {
	Posture   *PostureExtension   `yaml:"posture,omitempty" json:"posture,omitempty"`
	Origins   *OriginsExtension   `yaml:"origins,omitempty" json:"origins,omitempty"`
	Detection *DetectionExtension `yaml:"detection,omitempty" json:"detection,omitempty"`
}

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

// PostureExtension defines a finite state machine for agent security posture.
type PostureExtension struct {
	States       []PostureState      `yaml:"states" json:"states"`
	InitialState string              `yaml:"initial_state" json:"initial_state"`
	Transitions  []PostureTransition `yaml:"transitions,omitempty" json:"transitions,omitempty"`
}

// PostureState represents a named security posture with an associated
// trust level.
type PostureState struct {
	Name       string `yaml:"name" json:"name"`
	TrustLevel int    `yaml:"trust_level" json:"trust_level"`
}

// PostureTransition describes a state machine edge between two posture
// states, triggered by a specific event.
type PostureTransition struct {
	From    string             `yaml:"from" json:"from"`
	To      string             `yaml:"to" json:"to"`
	Trigger TransitionTrigger  `yaml:"trigger" json:"trigger"`
	Timeout *TransitionTimeout `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// TransitionTrigger specifies what causes a posture transition.
type TransitionTrigger struct {
	Event     string `yaml:"event" json:"event"`
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"`
}

// TransitionTimeout reverts the posture back to a prior state after a
// duration elapses.
type TransitionTimeout struct {
	After string `yaml:"after" json:"after"`
	ReturnTo string `yaml:"return_to" json:"return_to"`
}

// ---------------------------------------------------------------------------
// Origins
// ---------------------------------------------------------------------------

// OriginsExtension configures origin-aware policy enforcement for agent
// workflows, allowing per-origin trust profiles and cross-origin bridges.
type OriginsExtension struct {
	Profiles []OriginProfile `yaml:"profiles" json:"profiles"`
	Bridges  []BridgePolicy  `yaml:"bridges,omitempty" json:"bridges,omitempty"`
}

// OriginProfile defines trust and budget settings for a specific origin.
type OriginProfile struct {
	ID         string            `yaml:"id" json:"id"`
	Match      OriginMatch       `yaml:"match" json:"match"`
	TrustLevel int               `yaml:"trust_level" json:"trust_level"`
	DataPolicy *OriginDataPolicy `yaml:"data_policy,omitempty" json:"data_policy,omitempty"`
	Budgets    *OriginBudgets    `yaml:"budgets,omitempty" json:"budgets,omitempty"`
}

// OriginMatch defines the criteria for matching an incoming request to an
// origin profile.
type OriginMatch struct {
	Provider string `yaml:"provider" json:"provider"`
	Channel  string `yaml:"channel,omitempty" json:"channel,omitempty"`
	Team     string `yaml:"team,omitempty" json:"team,omitempty"`
}

// OriginDataPolicy controls data handling for a specific origin.
type OriginDataPolicy struct {
	AllowExfiltration bool     `yaml:"allow_exfiltration" json:"allow_exfiltration"`
	RedactFields      []string `yaml:"redact_fields,omitempty" json:"redact_fields,omitempty"`
}

// OriginBudgets defines resource limits for a specific origin.
type OriginBudgets struct {
	MaxTokensPerMinute int `yaml:"max_tokens_per_minute,omitempty" json:"max_tokens_per_minute,omitempty"`
	MaxActionsPerHour  int `yaml:"max_actions_per_hour,omitempty" json:"max_actions_per_hour,omitempty"`
}

// BridgePolicy governs data and trust transfer between two origins.
type BridgePolicy struct {
	From                BridgeTarget `yaml:"from" json:"from"`
	To                  BridgeTarget `yaml:"to" json:"to"`
	AllowDataTransfer   bool         `yaml:"allow_data_transfer" json:"allow_data_transfer"`
	RequireApproval     bool         `yaml:"require_approval" json:"require_approval"`
	MaxTrustPropagation int          `yaml:"max_trust_propagation" json:"max_trust_propagation"`
}

// BridgeTarget identifies one side of a bridge by origin ID.
type BridgeTarget struct {
	OriginID string `yaml:"origin_id" json:"origin_id"`
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

// DetectionExtension configures ML/heuristic threat-detection guards.
type DetectionExtension struct {
	PromptInjection *PromptInjectionDetection `yaml:"prompt_injection,omitempty" json:"prompt_injection,omitempty"`
	Jailbreak       *JailbreakDetection       `yaml:"jailbreak,omitempty" json:"jailbreak,omitempty"`
	ThreatIntel     *ThreatIntelDetection     `yaml:"threat_intel,omitempty" json:"threat_intel,omitempty"`
}

// DetectionLevel controls the sensitivity of a detection guard.
type DetectionLevel string

const (
	DetectionLevelLow    DetectionLevel = "low"
	DetectionLevelMedium DetectionLevel = "medium"
	DetectionLevelHigh   DetectionLevel = "high"
)

// PromptInjectionDetection configures the prompt-injection detection guard.
type PromptInjectionDetection struct {
	Enabled    bool           `yaml:"enabled" json:"enabled"`
	Level      DetectionLevel `yaml:"level" json:"level"`
	Threshold  float64        `yaml:"threshold" json:"threshold"`
	SkipSystem bool           `yaml:"skip_system" json:"skip_system"`
}

// JailbreakDetection configures the 4-layer jailbreak detection guard.
type JailbreakDetection struct {
	Enabled            bool           `yaml:"enabled" json:"enabled"`
	Level              DetectionLevel `yaml:"level" json:"level"`
	HeuristicThreshold float64        `yaml:"heuristic_threshold" json:"heuristic_threshold"`
	StatisticalThreshold float64      `yaml:"statistical_threshold" json:"statistical_threshold"`
	MLThreshold        float64        `yaml:"ml_threshold" json:"ml_threshold"`
	UseLLMJudge        bool           `yaml:"use_llm_judge" json:"use_llm_judge"`
}

// ThreatIntelDetection configures the Spider Sense hierarchical threat
// screening guard.
type ThreatIntelDetection struct {
	Enabled             bool    `yaml:"enabled" json:"enabled"`
	PatternDBPath       string  `yaml:"pattern_db_path,omitempty" json:"pattern_db_path,omitempty"`
	SimilarityThreshold float64 `yaml:"similarity_threshold" json:"similarity_threshold"`
	UseLLMDeepPath      bool    `yaml:"use_llm_deep_path" json:"use_llm_deep_path"`
}
