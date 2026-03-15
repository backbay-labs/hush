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
		return deepCopySpec(child)
	default:
		return mergeSpecs(base, child)
	}
}

// deepCopySpec creates a deep copy of a HushSpec by round-tripping through
// YAML serialisation. This guarantees full value isolation.
func deepCopySpec(spec *HushSpec) *HushSpec {
	yamlStr, err := Marshal(spec)
	if err != nil {
		// Marshal should not fail on a well-formed struct; if it does
		// return the original as a fallback.
		return spec
	}
	copied, err := Parse(yamlStr)
	if err != nil {
		return spec
	}
	return copied
}

// mergeSpecs performs a shallow/deep merge of base and child. Child fields
// override base fields where present. Nil child pointers leave the base
// value intact.
func mergeSpecs(base, child *HushSpec) *HushSpec {
	result := deepCopySpec(base)

	// Scalar overrides.
	if child.HushSpecVersion != "" {
		result.HushSpecVersion = child.HushSpecVersion
	}
	if child.Name != "" {
		result.Name = child.Name
	}
	if child.Description != "" {
		result.Description = child.Description
	}
	if child.Extends != "" {
		result.Extends = child.Extends
	}
	if child.MergeStrategy != "" {
		result.MergeStrategy = child.MergeStrategy
	}

	// Rules merge.
	if child.Rules != nil {
		if result.Rules == nil {
			result.Rules = &Rules{}
		}
		mergeRules(result.Rules, child.Rules)
	}

	// Extensions merge.
	if child.Extensions != nil {
		if result.Extensions == nil {
			result.Extensions = &Extensions{}
		}
		mergeExtensions(result.Extensions, child.Extensions)
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

// mergeExtensions merges child extension blocks into base. Each non-nil
// child extension block replaces the corresponding base block.
func mergeExtensions(base, child *Extensions) {
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
