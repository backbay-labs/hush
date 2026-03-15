package hushspec

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Parse tests
// ---------------------------------------------------------------------------

func TestParseMinimalValid(t *testing.T) {
	input := `hushspec: "0.1.0"`
	spec, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.HushSpecVersion != "0.1.0" {
		t.Errorf("expected version 0.1.0, got %q", spec.HushSpecVersion)
	}
}

func TestParseMissingVersion(t *testing.T) {
	input := `name: "test"`
	_, err := Parse(input)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !strings.Contains(err.Error(), "missing or empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseEmptyVersion(t *testing.T) {
	input := `hushspec: ""`
	_, err := Parse(input)
	if err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	input := `{{{not yaml`
	_, err := Parse(input)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParseWithRules(t *testing.T) {
	input := `
hushspec: "0.1.0"
name: "test-policy"
rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "~/.ssh/*"
      - "/etc/shadow"
    exceptions:
      - "~/.ssh/config"
  egress:
    enabled: true
    allow:
      - "api.example.com"
    block:
      - "evil.com"
    default: block
  secret_patterns:
    enabled: true
    patterns:
      - name: "aws_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
        description: "AWS Access Key ID"
      - name: "github_token"
        pattern: "gh[ps]_[A-Za-z0-9_]{36}"
        severity: error
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "rm -rf /"
      - "curl.*\\| sh"
  tool_access:
    enabled: true
    allow:
      - "read_file"
      - "write_file"
    block:
      - "execute_dangerous"
    require_confirmation:
      - "delete_file"
    default: block
    max_args_size: 4096
  patch_integrity:
    enabled: true
    max_additions: 500
    max_deletions: 200
    forbidden_patterns:
      - "eval\\("
    require_balance: true
    max_imbalance_ratio: 3.0
  path_allowlist:
    enabled: true
    read:
      - "/home/user/project/**"
    write:
      - "/home/user/project/src/**"
    patch:
      - "/home/user/project/src/**"
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - click
      - type
      - scroll
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: false
    drive_mapping: false
  input_injection:
    enabled: true
    allowed_types:
      - keyboard
      - mouse
    require_postcondition_probe: true
`
	spec, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Name != "test-policy" {
		t.Errorf("expected name 'test-policy', got %q", spec.Name)
	}
	if spec.Rules == nil {
		t.Fatal("expected rules to be non-nil")
	}

	// Forbidden paths.
	fp := spec.Rules.ForbiddenPaths
	if fp == nil {
		t.Fatal("expected forbidden_paths")
	}
	if !fp.Enabled {
		t.Error("expected forbidden_paths.enabled = true")
	}
	if len(fp.Patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(fp.Patterns))
	}
	if len(fp.Exceptions) != 1 {
		t.Errorf("expected 1 exception, got %d", len(fp.Exceptions))
	}

	// Egress.
	eg := spec.Rules.Egress
	if eg == nil {
		t.Fatal("expected egress")
	}
	if eg.Default != DefaultActionBlock {
		t.Errorf("expected default block, got %q", eg.Default)
	}
	if len(eg.Allow) != 1 || eg.Allow[0] != "api.example.com" {
		t.Errorf("unexpected allow list: %v", eg.Allow)
	}

	// Secret patterns.
	sp := spec.Rules.SecretPatterns
	if sp == nil {
		t.Fatal("expected secret_patterns")
	}
	if len(sp.Patterns) != 2 {
		t.Errorf("expected 2 secret patterns, got %d", len(sp.Patterns))
	}
	if sp.Patterns[0].Name != "aws_key" {
		t.Errorf("expected first pattern name 'aws_key', got %q", sp.Patterns[0].Name)
	}
	if sp.Patterns[0].Severity != SeverityCritical {
		t.Errorf("expected severity 'critical', got %q", sp.Patterns[0].Severity)
	}

	// Shell commands.
	sc := spec.Rules.ShellCommands
	if sc == nil {
		t.Fatal("expected shell_commands")
	}
	if len(sc.ForbiddenPatterns) != 2 {
		t.Errorf("expected 2 forbidden shell patterns, got %d", len(sc.ForbiddenPatterns))
	}

	// Tool access.
	ta := spec.Rules.ToolAccess
	if ta == nil {
		t.Fatal("expected tool_access")
	}
	if ta.Default != DefaultActionBlock {
		t.Errorf("expected default block, got %q", ta.Default)
	}
	if ta.MaxArgsSize == nil || *ta.MaxArgsSize != 4096 {
		t.Errorf("expected max_args_size 4096, got %v", ta.MaxArgsSize)
	}
	if len(ta.RequireConfirmation) != 1 {
		t.Errorf("expected 1 require_confirmation, got %d", len(ta.RequireConfirmation))
	}

	// Patch integrity.
	pi := spec.Rules.PatchIntegrity
	if pi == nil {
		t.Fatal("expected patch_integrity")
	}
	if pi.MaxAdditions != 500 {
		t.Errorf("expected max_additions 500, got %d", pi.MaxAdditions)
	}
	if pi.MaxImbalanceRatio != 3.0 {
		t.Errorf("expected max_imbalance_ratio 3.0, got %f", pi.MaxImbalanceRatio)
	}

	// Path allowlist.
	pa := spec.Rules.PathAllowlist
	if pa == nil {
		t.Fatal("expected path_allowlist")
	}
	if len(pa.Read) != 1 {
		t.Errorf("expected 1 read path, got %d", len(pa.Read))
	}

	// Computer use.
	cu := spec.Rules.ComputerUse
	if cu == nil {
		t.Fatal("expected computer_use")
	}
	if cu.Mode != ComputerUseModeGuardrail {
		t.Errorf("expected mode 'guardrail', got %q", cu.Mode)
	}
	if len(cu.AllowedActions) != 3 {
		t.Errorf("expected 3 allowed actions, got %d", len(cu.AllowedActions))
	}

	// Remote desktop channels.
	rdc := spec.Rules.RemoteDesktopChannels
	if rdc == nil {
		t.Fatal("expected remote_desktop_channels")
	}
	if rdc.Clipboard {
		t.Error("expected clipboard false")
	}

	// Input injection.
	ii := spec.Rules.InputInjection
	if ii == nil {
		t.Fatal("expected input_injection")
	}
	if !ii.RequirePostconditionProbe {
		t.Error("expected require_postcondition_probe true")
	}
	if len(ii.AllowedTypes) != 2 {
		t.Errorf("expected 2 allowed types, got %d", len(ii.AllowedTypes))
	}
}

func TestParseWithExtensions(t *testing.T) {
	input := `
hushspec: "0.1.0"
extensions:
  posture:
    states:
      - name: normal
        trust_level: 100
      - name: elevated
        trust_level: 50
      - name: lockdown
        trust_level: 10
    initial_state: normal
    transitions:
      - from: normal
        to: elevated
        trigger:
          event: anomaly_detected
          condition: "score > 0.8"
      - from: elevated
        to: lockdown
        trigger:
          event: threat_confirmed
        timeout:
          after: "30m"
          return_to: normal
  origins:
    profiles:
      - id: slack-internal
        match:
          provider: slack
          channel: "#engineering"
          team: T12345
        trust_level: 80
        data_policy:
          allow_exfiltration: false
          redact_fields:
            - ssn
            - credit_card
        budgets:
          max_tokens_per_minute: 1000
          max_actions_per_hour: 100
      - id: github-ci
        match:
          provider: github
        trust_level: 60
    bridges:
      - from:
          origin_id: slack-internal
        to:
          origin_id: github-ci
        allow_data_transfer: true
        require_approval: false
        max_trust_propagation: 50
  detection:
    prompt_injection:
      enabled: true
      level: high
      threshold: 0.85
      skip_system: true
    jailbreak:
      enabled: true
      level: medium
      heuristic_threshold: 0.7
      statistical_threshold: 0.6
      ml_threshold: 0.8
      use_llm_judge: false
    threat_intel:
      enabled: true
      pattern_db_path: "builtin:s2bench-v1"
      similarity_threshold: 0.75
      use_llm_deep_path: true
`
	spec, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Extensions == nil {
		t.Fatal("expected extensions to be non-nil")
	}

	// Posture.
	pos := spec.Extensions.Posture
	if pos == nil {
		t.Fatal("expected posture extension")
	}
	if len(pos.States) != 3 {
		t.Errorf("expected 3 states, got %d", len(pos.States))
	}
	if pos.InitialState != "normal" {
		t.Errorf("expected initial_state 'normal', got %q", pos.InitialState)
	}
	if len(pos.Transitions) != 2 {
		t.Errorf("expected 2 transitions, got %d", len(pos.Transitions))
	}
	if pos.Transitions[1].Timeout == nil {
		t.Fatal("expected transition[1] to have a timeout")
	}
	if pos.Transitions[1].Timeout.After != "30m" {
		t.Errorf("expected timeout after '30m', got %q", pos.Transitions[1].Timeout.After)
	}

	// Origins.
	orig := spec.Extensions.Origins
	if orig == nil {
		t.Fatal("expected origins extension")
	}
	if len(orig.Profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(orig.Profiles))
	}
	if orig.Profiles[0].ID != "slack-internal" {
		t.Errorf("expected first profile id 'slack-internal', got %q", orig.Profiles[0].ID)
	}
	if orig.Profiles[0].Match.Provider != "slack" {
		t.Errorf("expected provider 'slack', got %q", orig.Profiles[0].Match.Provider)
	}
	if orig.Profiles[0].DataPolicy == nil {
		t.Fatal("expected data_policy")
	}
	if orig.Profiles[0].DataPolicy.AllowExfiltration {
		t.Error("expected allow_exfiltration false")
	}
	if len(orig.Profiles[0].DataPolicy.RedactFields) != 2 {
		t.Errorf("expected 2 redact fields, got %d", len(orig.Profiles[0].DataPolicy.RedactFields))
	}
	if orig.Profiles[0].Budgets == nil {
		t.Fatal("expected budgets")
	}
	if orig.Profiles[0].Budgets.MaxTokensPerMinute != 1000 {
		t.Errorf("expected max_tokens_per_minute 1000, got %d", orig.Profiles[0].Budgets.MaxTokensPerMinute)
	}
	if len(orig.Bridges) != 1 {
		t.Errorf("expected 1 bridge, got %d", len(orig.Bridges))
	}
	if orig.Bridges[0].MaxTrustPropagation != 50 {
		t.Errorf("expected max_trust_propagation 50, got %d", orig.Bridges[0].MaxTrustPropagation)
	}

	// Detection.
	det := spec.Extensions.Detection
	if det == nil {
		t.Fatal("expected detection extension")
	}
	if det.PromptInjection == nil {
		t.Fatal("expected prompt_injection detection")
	}
	if det.PromptInjection.Threshold != 0.85 {
		t.Errorf("expected threshold 0.85, got %f", det.PromptInjection.Threshold)
	}
	if det.PromptInjection.Level != DetectionLevelHigh {
		t.Errorf("expected level 'high', got %q", det.PromptInjection.Level)
	}
	if det.Jailbreak == nil {
		t.Fatal("expected jailbreak detection")
	}
	if det.Jailbreak.HeuristicThreshold != 0.7 {
		t.Errorf("expected heuristic_threshold 0.7, got %f", det.Jailbreak.HeuristicThreshold)
	}
	if det.ThreatIntel == nil {
		t.Fatal("expected threat_intel detection")
	}
	if det.ThreatIntel.PatternDBPath != "builtin:s2bench-v1" {
		t.Errorf("expected pattern_db_path 'builtin:s2bench-v1', got %q", det.ThreatIntel.PatternDBPath)
	}
}

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		valid   bool
	}{
		{"supported version", "0.1.0", true},
		{"unsupported version", "99.0.0", false},
		{"empty version", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := &HushSpec{HushSpecVersion: tc.version}
			result := Validate(spec)
			if tc.valid && !result.IsValid() {
				t.Errorf("expected valid, got errors: %v", result.Errors)
			}
			if !tc.valid && result.IsValid() {
				t.Error("expected validation errors, got none")
			}
		})
	}
}

func TestValidateDuplicatePatternNames(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			SecretPatterns: &SecretPatternsRule{
				Enabled: true,
				Patterns: []SecretPattern{
					{Name: "aws_key", Pattern: "AKIA.*", Severity: SeverityCritical},
					{Name: "aws_key", Pattern: "AKIA2.*", Severity: SeverityError},
				},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected validation errors for duplicate pattern names")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "DUPLICATE_PATTERN_NAME" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DUPLICATE_PATTERN_NAME error")
	}
}

func TestValidatePostureInvalidInitialState(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Posture: &PostureExtension{
				States: []PostureState{
					{Name: "normal", TrustLevel: 100},
				},
				InitialState: "nonexistent",
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected validation errors for invalid initial state")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "INVALID_INITIAL_STATE" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected INVALID_INITIAL_STATE error")
	}
}

func TestValidatePostureTransitionInvalidState(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Posture: &PostureExtension{
				States: []PostureState{
					{Name: "normal", TrustLevel: 100},
				},
				InitialState: "normal",
				Transitions: []PostureTransition{
					{
						From:    "normal",
						To:      "ghost",
						Trigger: TransitionTrigger{Event: "test"},
					},
				},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected validation errors for invalid transition state")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "INVALID_TRANSITION_STATE" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected INVALID_TRANSITION_STATE error")
	}
}

func TestValidatePostureTimeoutMissingAfter(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Posture: &PostureExtension{
				States: []PostureState{
					{Name: "normal", TrustLevel: 100},
					{Name: "elevated", TrustLevel: 50},
				},
				InitialState: "normal",
				Transitions: []PostureTransition{
					{
						From:    "normal",
						To:      "elevated",
						Trigger: TransitionTrigger{Event: "test"},
						Timeout: &TransitionTimeout{
							After:    "",
							ReturnTo: "normal",
						},
					},
				},
			},
		},
	}
	result := Validate(spec)
	found := false
	for _, e := range result.Errors {
		if e.Code == "MISSING_TIMEOUT_AFTER" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected MISSING_TIMEOUT_AFTER error")
	}
}

func TestValidateDuplicateOriginIDs(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Origins: &OriginsExtension{
				Profiles: []OriginProfile{
					{ID: "slack", Match: OriginMatch{Provider: "slack"}, TrustLevel: 80},
					{ID: "slack", Match: OriginMatch{Provider: "slack"}, TrustLevel: 60},
				},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected validation errors for duplicate origin IDs")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "DUPLICATE_ORIGIN_ID" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DUPLICATE_ORIGIN_ID error")
	}
}

func TestValidateNegativeBudgets(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Origins: &OriginsExtension{
				Profiles: []OriginProfile{
					{
						ID:         "test",
						Match:      OriginMatch{Provider: "test"},
						TrustLevel: 80,
						Budgets: &OriginBudgets{
							MaxTokensPerMinute: -100,
						},
					},
				},
			},
		},
	}
	result := Validate(spec)
	found := false
	for _, e := range result.Errors {
		if e.Code == "NEGATIVE_BUDGET" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected NEGATIVE_BUDGET error")
	}
}

func TestValidateDetectionThresholdOutOfRange(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Detection: &DetectionExtension{
				PromptInjection: &PromptInjectionDetection{
					Enabled:   true,
					Level:     DetectionLevelHigh,
					Threshold: 1.5, // out of range
				},
			},
		},
	}
	result := Validate(spec)
	found := false
	for _, e := range result.Errors {
		if e.Code == "THRESHOLD_OUT_OF_RANGE" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected THRESHOLD_OUT_OF_RANGE error")
	}
}

func TestValidateThreatIntelSimilarityOutOfRange(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Detection: &DetectionExtension{
				ThreatIntel: &ThreatIntelDetection{
					Enabled:             true,
					SimilarityThreshold: -0.1,
				},
			},
		},
	}
	result := Validate(spec)
	found := false
	for _, e := range result.Errors {
		if e.Code == "THRESHOLD_OUT_OF_RANGE" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected THRESHOLD_OUT_OF_RANGE error")
	}
}

func TestValidateInvalidBridgeOrigin(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Origins: &OriginsExtension{
				Profiles: []OriginProfile{
					{ID: "slack", Match: OriginMatch{Provider: "slack"}, TrustLevel: 80},
				},
				Bridges: []BridgePolicy{
					{
						From:              BridgeTarget{OriginID: "slack"},
						To:                BridgeTarget{OriginID: "nonexistent"},
						AllowDataTransfer: true,
					},
				},
			},
		},
	}
	result := Validate(spec)
	found := false
	for _, e := range result.Errors {
		if e.Code == "INVALID_BRIDGE_ORIGIN" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected INVALID_BRIDGE_ORIGIN error")
	}
}

func TestValidateValidDocument(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "valid-policy",
		Rules: &Rules{
			ForbiddenPaths: &ForbiddenPathsRule{
				Enabled:  true,
				Patterns: []string{"~/.ssh/*"},
			},
			Egress: &EgressRule{
				Enabled: true,
				Allow:   []string{"api.example.com"},
				Default: DefaultActionBlock,
			},
		},
		Extensions: &Extensions{
			Posture: &PostureExtension{
				States: []PostureState{
					{Name: "normal", TrustLevel: 100},
					{Name: "elevated", TrustLevel: 50},
				},
				InitialState: "normal",
				Transitions: []PostureTransition{
					{
						From:    "normal",
						To:      "elevated",
						Trigger: TransitionTrigger{Event: "anomaly"},
					},
				},
			},
			Detection: &DetectionExtension{
				PromptInjection: &PromptInjectionDetection{
					Enabled:   true,
					Level:     DetectionLevelMedium,
					Threshold: 0.75,
				},
			},
		},
	}
	result := Validate(spec)
	if !result.IsValid() {
		t.Errorf("expected valid document, got errors: %v", result.Errors)
	}
}

// ---------------------------------------------------------------------------
// Merge tests
// ---------------------------------------------------------------------------

func TestMergeReplace(t *testing.T) {
	base := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "base",
		Rules: &Rules{
			ForbiddenPaths: &ForbiddenPathsRule{
				Enabled:  true,
				Patterns: []string{"/etc/shadow"},
			},
		},
	}
	child := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "child",
		MergeStrategy:   MergeStrategyReplace,
	}
	result := Merge(base, child)
	if result.Name != "child" {
		t.Errorf("expected name 'child', got %q", result.Name)
	}
	if result.Rules != nil {
		t.Error("expected rules to be nil after replace merge")
	}
}

func TestMergeMergeStrategy(t *testing.T) {
	base := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "base",
		Description:     "base description",
		Rules: &Rules{
			ForbiddenPaths: &ForbiddenPathsRule{
				Enabled:  true,
				Patterns: []string{"/etc/shadow"},
			},
			Egress: &EgressRule{
				Enabled: true,
				Allow:   []string{"example.com"},
				Default: DefaultActionBlock,
			},
		},
	}
	child := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "child",
		MergeStrategy:   MergeStrategyMerge,
		Rules: &Rules{
			Egress: &EgressRule{
				Enabled: true,
				Allow:   []string{"other.com"},
				Default: DefaultActionAllow,
			},
		},
	}
	result := Merge(base, child)
	if result.Name != "child" {
		t.Errorf("expected name 'child', got %q", result.Name)
	}
	if result.Description != "base description" {
		t.Errorf("expected base description preserved, got %q", result.Description)
	}
	// Forbidden paths should be preserved from base.
	if result.Rules.ForbiddenPaths == nil {
		t.Fatal("expected forbidden_paths to be preserved from base")
	}
	if len(result.Rules.ForbiddenPaths.Patterns) != 1 {
		t.Errorf("expected 1 forbidden pattern, got %d", len(result.Rules.ForbiddenPaths.Patterns))
	}
	// Egress should be overridden by child.
	if result.Rules.Egress == nil {
		t.Fatal("expected egress to be present")
	}
	if result.Rules.Egress.Default != DefaultActionAllow {
		t.Errorf("expected egress default 'allow', got %q", result.Rules.Egress.Default)
	}
	if len(result.Rules.Egress.Allow) != 1 || result.Rules.Egress.Allow[0] != "other.com" {
		t.Errorf("expected egress allow ['other.com'], got %v", result.Rules.Egress.Allow)
	}
}

func TestMergeDefaultDeepMerge(t *testing.T) {
	base := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "base",
		Rules: &Rules{
			ForbiddenPaths: &ForbiddenPathsRule{
				Enabled:  true,
				Patterns: []string{"/etc/shadow"},
			},
		},
	}
	child := &HushSpec{
		HushSpecVersion: "0.1.0",
		// No merge strategy specified - should default to deep_merge.
		Rules: &Rules{
			ShellCommands: &ShellCommandsRule{
				Enabled:           true,
				ForbiddenPatterns: []string{"rm -rf /"},
			},
		},
	}
	result := Merge(base, child)
	// Base rules should be preserved.
	if result.Rules.ForbiddenPaths == nil {
		t.Fatal("expected forbidden_paths to be preserved from base")
	}
	// Child rules should be merged in.
	if result.Rules.ShellCommands == nil {
		t.Fatal("expected shell_commands from child")
	}
}

func TestMergeExtensions(t *testing.T) {
	base := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Posture: &PostureExtension{
				States: []PostureState{
					{Name: "normal", TrustLevel: 100},
				},
				InitialState: "normal",
			},
		},
	}
	child := &HushSpec{
		HushSpecVersion: "0.1.0",
		MergeStrategy:   MergeStrategyMerge,
		Extensions: &Extensions{
			Detection: &DetectionExtension{
				PromptInjection: &PromptInjectionDetection{
					Enabled:   true,
					Level:     DetectionLevelHigh,
					Threshold: 0.9,
				},
			},
		},
	}
	result := Merge(base, child)
	if result.Extensions == nil {
		t.Fatal("expected extensions")
	}
	// Posture preserved from base.
	if result.Extensions.Posture == nil {
		t.Fatal("expected posture preserved from base")
	}
	// Detection added from child.
	if result.Extensions.Detection == nil {
		t.Fatal("expected detection from child")
	}
	if result.Extensions.Detection.PromptInjection.Threshold != 0.9 {
		t.Errorf("expected threshold 0.9, got %f", result.Extensions.Detection.PromptInjection.Threshold)
	}
}

// ---------------------------------------------------------------------------
// Roundtrip test
// ---------------------------------------------------------------------------

func TestRoundtrip(t *testing.T) {
	input := `
hushspec: "0.1.0"
name: roundtrip-test
description: Ensure parse-marshal-parse yields the same result
rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "~/.ssh/*"
  egress:
    enabled: true
    allow:
      - api.example.com
    default: block
  secret_patterns:
    enabled: true
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
extensions:
  detection:
    prompt_injection:
      enabled: true
      level: medium
      threshold: 0.75
      skip_system: false
`
	// Parse.
	spec1, err := Parse(input)
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}

	// Marshal.
	yamlOut, err := Marshal(spec1)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Parse again.
	spec2, err := Parse(yamlOut)
	if err != nil {
		t.Fatalf("second parse failed: %v", err)
	}

	// Verify key fields survived the roundtrip.
	if spec2.HushSpecVersion != spec1.HushSpecVersion {
		t.Errorf("version mismatch: %q vs %q", spec1.HushSpecVersion, spec2.HushSpecVersion)
	}
	if spec2.Name != spec1.Name {
		t.Errorf("name mismatch: %q vs %q", spec1.Name, spec2.Name)
	}
	if spec2.Rules == nil {
		t.Fatal("rules nil after roundtrip")
	}
	if spec2.Rules.ForbiddenPaths == nil {
		t.Fatal("forbidden_paths nil after roundtrip")
	}
	if len(spec2.Rules.ForbiddenPaths.Patterns) != 1 {
		t.Errorf("expected 1 forbidden pattern, got %d", len(spec2.Rules.ForbiddenPaths.Patterns))
	}
	if spec2.Rules.Egress == nil {
		t.Fatal("egress nil after roundtrip")
	}
	if spec2.Rules.Egress.Default != DefaultActionBlock {
		t.Errorf("egress default changed: %q", spec2.Rules.Egress.Default)
	}
	if spec2.Rules.SecretPatterns == nil || len(spec2.Rules.SecretPatterns.Patterns) != 1 {
		t.Fatal("secret_patterns lost after roundtrip")
	}
	if spec2.Extensions == nil || spec2.Extensions.Detection == nil || spec2.Extensions.Detection.PromptInjection == nil {
		t.Fatal("detection extension lost after roundtrip")
	}
	if spec2.Extensions.Detection.PromptInjection.Threshold != 0.75 {
		t.Errorf("threshold changed: %f", spec2.Extensions.Detection.PromptInjection.Threshold)
	}
}

// ---------------------------------------------------------------------------
// Version tests
// ---------------------------------------------------------------------------

func TestIsSupported(t *testing.T) {
	if !IsSupported("0.1.0") {
		t.Error("0.1.0 should be supported")
	}
	if IsSupported("99.99.99") {
		t.Error("99.99.99 should not be supported")
	}
	if IsSupported("") {
		t.Error("empty string should not be supported")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestParseUnknownFieldsSilentlyIgnored(t *testing.T) {
	// yaml.v3 does not reject unknown fields by default.
	// This test documents that behaviour.
	input := `
hushspec: "0.1.0"
unknown_field: "this should be ignored"
`
	spec, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.HushSpecVersion != "0.1.0" {
		t.Errorf("version mismatch: %q", spec.HushSpecVersion)
	}
}

func TestValidateInvalidMergeStrategy(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		MergeStrategy:   "invalid",
	}
	result := Validate(spec)
	found := false
	for _, e := range result.Errors {
		if e.Code == "INVALID_MERGE_STRATEGY" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected INVALID_MERGE_STRATEGY error")
	}
}

func TestMergeNilBase(t *testing.T) {
	child := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "child-only",
		MergeStrategy:   MergeStrategyReplace,
	}
	result := Merge(&HushSpec{}, child)
	if result.Name != "child-only" {
		t.Errorf("expected name 'child-only', got %q", result.Name)
	}
}
