package hushspec

// Merge combines a base HushSpec with a child overlay according to the
// child's merge_strategy. If the child does not specify a strategy,
// deep_merge is used by default.
func Merge(base, child *HushSpec) *HushSpec {
	strategy := child.MergeStrategy
	if strategy == "" {
		strategy = MergeStrategyDeepMerge
	}

	switch strategy {
	case MergeStrategyReplace:
		result := deepCopySpec(child)
		result.Extends = ""
		return result
	case MergeStrategyMerge:
		return mergeSpecs(base, child, false)
	default:
		return mergeSpecs(base, child, true)
	}
}

// deepCopySpec creates a deep copy of a HushSpec by round-tripping through
// YAML serialisation. This guarantees full value isolation.
func deepCopySpec(spec *HushSpec) *HushSpec {
	if spec == nil {
		return nil
	}
	yamlStr, err := Marshal(spec)
	if err != nil {
		return spec
	}
	copied, err := Parse(yamlStr)
	if err != nil {
		return spec
	}
	return copied
}

func mergeSpecs(base, child *HushSpec, deep bool) *HushSpec {
	result := deepCopySpec(base)
	if result == nil {
		result = &HushSpec{}
	}

	result.HushSpecVersion = child.HushSpecVersion
	if child.Name != "" {
		result.Name = child.Name
	}
	if child.Description != "" {
		result.Description = child.Description
	}
	result.Extends = ""
	result.MergeStrategy = child.MergeStrategy

	if child.Rules != nil {
		if result.Rules == nil {
			result.Rules = &Rules{}
		}
		mergeRules(result.Rules, child.Rules)
	}

	if child.Extensions != nil {
		if result.Extensions == nil {
			result.Extensions = &Extensions{}
		}
		if deep {
			mergeExtensionsDeep(result.Extensions, child.Extensions)
		} else {
			mergeExtensionsShallow(result.Extensions, child.Extensions)
		}
	}

	return result
}

// mergeRules merges child rule blocks into base. Each non-nil child rule
// block replaces the corresponding base block entirely.
func mergeRules(base, child *Rules) {
	if child.ForbiddenPaths != nil {
		base.ForbiddenPaths = child.ForbiddenPaths
	}
	if child.PathAllowlist != nil {
		base.PathAllowlist = child.PathAllowlist
	}
	if child.Egress != nil {
		base.Egress = child.Egress
	}
	if child.SecretPatterns != nil {
		base.SecretPatterns = child.SecretPatterns
	}
	if child.PatchIntegrity != nil {
		base.PatchIntegrity = child.PatchIntegrity
	}
	if child.ShellCommands != nil {
		base.ShellCommands = child.ShellCommands
	}
	if child.ToolAccess != nil {
		base.ToolAccess = child.ToolAccess
	}
	if child.ComputerUse != nil {
		base.ComputerUse = child.ComputerUse
	}
	if child.RemoteDesktopChannels != nil {
		base.RemoteDesktopChannels = child.RemoteDesktopChannels
	}
	if child.InputInjection != nil {
		base.InputInjection = child.InputInjection
	}
}

// mergeExtensionsShallow merges child extension blocks into base. Each non-nil
// child extension block replaces the corresponding base block entirely.
func mergeExtensionsShallow(base, child *Extensions) {
	if child.Posture != nil {
		base.Posture = child.Posture
	}
	if child.Origins != nil {
		base.Origins = child.Origins
	}
	if child.Detection != nil {
		base.Detection = child.Detection
	}
}

// mergeExtensionsDeep applies the extension-specific deep-merge rules.
func mergeExtensionsDeep(base, child *Extensions) {
	if child.Posture != nil {
		base.Posture = mergePosture(base.Posture, child.Posture)
	}
	if child.Origins != nil {
		base.Origins = mergeOrigins(base.Origins, child.Origins)
	}
	if child.Detection != nil {
		base.Detection = mergeDetection(base.Detection, child.Detection)
	}
}

func mergePosture(base, child *PostureExtension) *PostureExtension {
	if child == nil {
		return base
	}
	if base == nil {
		return child
	}

	states := make(map[string]PostureState, len(base.States)+len(child.States))
	for name, state := range base.States {
		states[name] = state
	}
	for name, state := range child.States {
		states[name] = state
	}

	return &PostureExtension{
		Initial:     child.Initial,
		States:      states,
		Transitions: child.Transitions,
	}
}

func mergeOrigins(base, child *OriginsExtension) *OriginsExtension {
	if child == nil {
		return base
	}
	if base == nil {
		return child
	}

	mergedProfiles := append([]OriginProfile{}, base.Profiles...)
	for _, childProfile := range child.Profiles {
		found := false
		for i, existing := range mergedProfiles {
			if existing.ID == childProfile.ID {
				mergedProfiles[i] = childProfile
				found = true
				break
			}
		}
		if !found {
			mergedProfiles = append(mergedProfiles, childProfile)
		}
	}

	return &OriginsExtension{
		DefaultBehavior: firstOriginDefaultBehavior(child.DefaultBehavior, base.DefaultBehavior),
		Profiles:        mergedProfiles,
	}
}

func mergeDetection(base, child *DetectionExtension) *DetectionExtension {
	if child == nil {
		return base
	}
	if base == nil {
		return child
	}

	return &DetectionExtension{
		PromptInjection: mergePromptInjection(base.PromptInjection, child.PromptInjection),
		Jailbreak:       mergeJailbreak(base.Jailbreak, child.Jailbreak),
		ThreatIntel:     mergeThreatIntel(base.ThreatIntel, child.ThreatIntel),
	}
}

func mergePromptInjection(base, child *PromptInjectionDetection) *PromptInjectionDetection {
	if child == nil {
		return base
	}
	if base == nil {
		return child
	}

	return &PromptInjectionDetection{
		Enabled:        firstBool(child.Enabled, base.Enabled),
		WarnAtOrAbove:  firstDetectionLevel(child.WarnAtOrAbove, base.WarnAtOrAbove),
		BlockAtOrAbove: firstDetectionLevel(child.BlockAtOrAbove, base.BlockAtOrAbove),
		MaxScanBytes:   firstInt(child.MaxScanBytes, base.MaxScanBytes),
	}
}

func mergeJailbreak(base, child *JailbreakDetection) *JailbreakDetection {
	if child == nil {
		return base
	}
	if base == nil {
		return child
	}

	return &JailbreakDetection{
		Enabled:        firstBool(child.Enabled, base.Enabled),
		BlockThreshold: firstInt(child.BlockThreshold, base.BlockThreshold),
		WarnThreshold:  firstInt(child.WarnThreshold, base.WarnThreshold),
		MaxInputBytes:  firstInt(child.MaxInputBytes, base.MaxInputBytes),
	}
}

func mergeThreatIntel(base, child *ThreatIntelDetection) *ThreatIntelDetection {
	if child == nil {
		return base
	}
	if base == nil {
		return child
	}

	return &ThreatIntelDetection{
		Enabled:             firstBool(child.Enabled, base.Enabled),
		PatternDB:           firstString(child.PatternDB, base.PatternDB),
		SimilarityThreshold: firstFloat64(child.SimilarityThreshold, base.SimilarityThreshold),
		TopK:                firstInt(child.TopK, base.TopK),
	}
}

func firstBool(primary, fallback *bool) *bool {
	if primary != nil {
		return primary
	}
	return fallback
}

func firstInt(primary, fallback *int) *int {
	if primary != nil {
		return primary
	}
	return fallback
}

func firstFloat64(primary, fallback *float64) *float64 {
	if primary != nil {
		return primary
	}
	return fallback
}

func firstString(primary, fallback *string) *string {
	if primary != nil {
		return primary
	}
	return fallback
}

func firstDetectionLevel(primary, fallback *DetectionLevel) *DetectionLevel {
	if primary != nil {
		return primary
	}
	return fallback
}

func firstOriginDefaultBehavior(primary, fallback *OriginDefaultBehavior) *OriginDefaultBehavior {
	if primary != nil {
		return primary
	}
	return fallback
}
