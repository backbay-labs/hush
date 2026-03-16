package hushspec

import "testing"

func TestParseMinimalValid(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
name: test
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.HushSpecVersion != "0.1.0" {
		t.Fatalf("expected hushspec version 0.1.0, got %q", spec.HushSpecVersion)
	}
	if spec.Name != "test" {
		t.Fatalf("expected name test, got %q", spec.Name)
	}
	if !Validate(spec).IsValid() {
		t.Fatal("expected minimal document to validate")
	}
}

func TestParseRejectsUnknownNestedField(t *testing.T) {
	_, err := Parse(`
hushspec: "0.1.0"
rules:
  egress:
    default: block
    extra_field: true
`)
	if err == nil {
		t.Fatal("expected parse error for unknown nested field")
	}
}

func TestParseCanonicalExtensions(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access, tool_call]
      restricted:
        capabilities: [file_access]
    transitions:
      - from: "*"
        to: restricted
        on: critical_violation
  origins:
    default_behavior: deny
    profiles:
      - id: shared-channel
        match:
          provider: slack
          external_participants: true
        posture: restricted
        data:
          redact_before_send: true
  detection:
    prompt_injection:
      warn_at_or_above: suspicious
      block_at_or_above: high
      max_scan_bytes: 500000
    jailbreak:
      block_threshold: 85
      warn_threshold: 60
    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.7
      top_k: 10
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Extensions == nil || spec.Extensions.Posture == nil {
		t.Fatal("expected posture extension")
	}
	if spec.Extensions.Posture.Initial != "standard" {
		t.Fatalf("expected posture initial standard, got %q", spec.Extensions.Posture.Initial)
	}
	if len(spec.Extensions.Posture.States) != 2 {
		t.Fatalf("expected 2 posture states, got %d", len(spec.Extensions.Posture.States))
	}
	if spec.Extensions.Detection == nil || spec.Extensions.Detection.PromptInjection == nil {
		t.Fatal("expected prompt_injection config")
	}
	if spec.Extensions.Detection.PromptInjection.WarnAtOrAbove == nil || *spec.Extensions.Detection.PromptInjection.WarnAtOrAbove != DetectionLevelSuspicious {
		t.Fatal("expected prompt_injection.warn_at_or_above to parse")
	}
	if spec.Extensions.Detection.ThreatIntel == nil || spec.Extensions.Detection.ThreatIntel.PatternDB == nil || *spec.Extensions.Detection.ThreatIntel.PatternDB != "builtin:s2bench-v1" {
		t.Fatal("expected threat_intel.pattern_db to parse")
	}
	result := Validate(spec)
	if !result.IsValid() {
		t.Fatalf("expected canonical extension document to validate, got errors: %+v", result.Errors)
	}
}

func TestParseDefaultsEgressEnabledToTrueWhenOmitted(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  egress:
    allow: ["api.example.com"]
    default: block
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Rules == nil || spec.Rules.Egress == nil {
		t.Fatal("expected egress rule to parse")
	}
	if !spec.Rules.Egress.Enabled {
		t.Fatal("expected omitted egress.enabled to default to true")
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
					{Name: "aws_key", Pattern: "ASIA.*", Severity: SeverityError},
				},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected duplicate pattern names to fail validation")
	}
}

func TestValidateInvalidPostureInitial(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Posture: &PostureExtension{
				Initial: "ghost",
				States: map[string]PostureState{
					"standard": {},
				},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected invalid posture initial to fail validation")
	}
}

func TestValidateDetectionTopK(t *testing.T) {
	zero := 0
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Detection: &DetectionExtension{
				ThreatIntel: &ThreatIntelDetection{TopK: &zero},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected top_k=0 to fail validation")
	}
}

func TestMergeReplaceClearsExtends(t *testing.T) {
	base := mustParse(t, `
hushspec: "0.1.0"
name: base
rules:
  egress:
    allow: ["a.com"]
    default: block
`)
	child := mustParse(t, `
hushspec: "0.1.0"
name: child
extends: base
merge_strategy: replace
rules:
  tool_access:
    block: ["shell_exec"]
    default: allow
`)

	merged := Merge(base, child)
	if merged.Extends != "" {
		t.Fatalf("expected replace merge to clear extends, got %q", merged.Extends)
	}
	if merged.MergeStrategy != MergeStrategyReplace {
		t.Fatalf("expected merge strategy replace, got %q", merged.MergeStrategy)
	}
	if merged.Rules == nil || merged.Rules.Egress != nil || merged.Rules.ToolAccess == nil {
		t.Fatal("expected replace merge to keep only child rules")
	}
}

func TestMergeDeepExtensions(t *testing.T) {
	base := mustParse(t, `
hushspec: "0.1.0"
name: base
rules:
  forbidden_paths:
    patterns: ["**/.ssh/**"]
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access]
      restricted:
        capabilities: [tool_call]
    transitions:
      - from: standard
        to: restricted
        on: any_violation
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
`)
	child := mustParse(t, `
hushspec: "0.1.0"
extends: base
rules:
  egress:
    allow: ["api.openai.com"]
    default: block
extensions:
  posture:
    initial: restricted
    states:
      restricted:
        capabilities: [file_access, tool_call]
      locked:
        capabilities: []
    transitions:
      - from: "*"
        to: locked
        on: critical_violation
  origins:
    profiles:
      - id: github
        match:
          provider: github
  detection:
    prompt_injection:
      max_scan_bytes: 500000
    threat_intel:
      top_k: 5
`)

	merged := Merge(base, child)
	if merged.Extends != "" {
		t.Fatalf("expected merged spec to clear extends, got %q", merged.Extends)
	}
	if merged.Rules == nil || merged.Rules.ForbiddenPaths == nil || merged.Rules.Egress == nil {
		t.Fatal("expected deep merge to preserve base rules and add child rules")
	}
	if merged.Extensions == nil || merged.Extensions.Posture == nil {
		t.Fatal("expected merged posture extension")
	}
	if _, ok := merged.Extensions.Posture.States["standard"]; !ok {
		t.Fatal("expected posture deep merge to preserve base state")
	}
	if _, ok := merged.Extensions.Posture.States["locked"]; !ok {
		t.Fatal("expected posture deep merge to add child state")
	}
	if merged.Extensions.Origins == nil || len(merged.Extensions.Origins.Profiles) != 2 {
		t.Fatalf("expected origins deep merge by id, got %+v", merged.Extensions.Origins)
	}
	if merged.Extensions.Detection == nil || merged.Extensions.Detection.PromptInjection == nil {
		t.Fatal("expected merged detection.prompt_injection")
	}
	if merged.Extensions.Detection.PromptInjection.BlockAtOrAbove == nil || *merged.Extensions.Detection.PromptInjection.BlockAtOrAbove != DetectionLevelHigh {
		t.Fatal("expected detection deep merge to preserve block_at_or_above")
	}
	if merged.Extensions.Detection.PromptInjection.MaxScanBytes == nil || *merged.Extensions.Detection.PromptInjection.MaxScanBytes != 500000 {
		t.Fatal("expected detection deep merge to add max_scan_bytes")
	}
	if merged.Extensions.Detection.ThreatIntel == nil || merged.Extensions.Detection.ThreatIntel.TopK == nil || *merged.Extensions.Detection.ThreatIntel.TopK != 5 {
		t.Fatal("expected detection deep merge to add threat_intel")
	}
}

func TestMergeShallowExtensionsReplaceWholeBlock(t *testing.T) {
	base := mustParse(t, `
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      warn_at_or_above: suspicious
      block_at_or_above: high
`)
	child := mustParse(t, `
hushspec: "0.1.0"
extends: base
merge_strategy: merge
extensions:
  detection:
    prompt_injection:
      max_scan_bytes: 500000
`)

	merged := Merge(base, child)
	if merged.Extensions == nil || merged.Extensions.Detection == nil || merged.Extensions.Detection.PromptInjection == nil {
		t.Fatal("expected detection block after shallow merge")
	}
	if merged.Extensions.Detection.PromptInjection.BlockAtOrAbove != nil {
		t.Fatal("expected shallow merge to replace prompt_injection block")
	}
	if merged.Extensions.Detection.PromptInjection.MaxScanBytes == nil || *merged.Extensions.Detection.PromptInjection.MaxScanBytes != 500000 {
		t.Fatal("expected shallow merge to keep child prompt_injection block")
	}
}

func TestMarshalRoundTripExtensions(t *testing.T) {
	spec := mustParse(t, `
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
`)
	out, err := Marshal(spec)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	roundTrip, err := Parse(out)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if roundTrip.Extensions == nil || roundTrip.Extensions.Detection == nil || roundTrip.Extensions.Detection.PromptInjection == nil {
		t.Fatal("expected round-trip detection config")
	}
	if roundTrip.Extensions.Detection.PromptInjection.WarnAtOrAbove == nil || *roundTrip.Extensions.Detection.PromptInjection.WarnAtOrAbove != DetectionLevelSuspicious {
		t.Fatal("expected round-trip to preserve warn_at_or_above")
	}
}

func mustParse(t *testing.T, yaml string) *HushSpec {
	t.Helper()
	spec, err := Parse(yaml)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	return spec
}
