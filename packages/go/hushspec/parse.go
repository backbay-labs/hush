package hushspec

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type parsePresenceSpec struct {
	Rules *struct {
		ForbiddenPaths *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"forbidden_paths"`
		Egress *struct {
			Enabled *bool          `yaml:"enabled"`
			Default *DefaultAction `yaml:"default"`
		} `yaml:"egress"`
		SecretPatterns *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"secret_patterns"`
		PatchIntegrity *struct {
			Enabled           *bool    `yaml:"enabled"`
			MaxAdditions      *int     `yaml:"max_additions"`
			MaxDeletions      *int     `yaml:"max_deletions"`
			MaxImbalanceRatio *float64 `yaml:"max_imbalance_ratio"`
		} `yaml:"patch_integrity"`
		ShellCommands *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"shell_commands"`
		ToolAccess *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"tool_access"`
		RemoteDesktopChannels *struct {
			Audio *bool `yaml:"audio"`
		} `yaml:"remote_desktop_channels"`
		BrowserAutomation *struct {
			CredentialDetection *bool `yaml:"credential_detection"`
		} `yaml:"browser_automation"`
	} `yaml:"rules"`
}

// Parse decodes a YAML string into a HushSpec document. Unknown fields are
// rejected and the top-level "hushspec" version key must be present.
// Cross-field validation is performed separately by [Validate].
//
// Every refusal is a [*ValidationError] carrying a registered error code
// (spec/registries/error-codes.yaml), so a caller can read the code with
// errors.As rather than matching on the message: E001 for anything the
// document's shape refuses, E004 for a structural constraint a well-shaped
// document breaks.
func Parse(yamlStr string) (*HushSpec, error) {
	// The HushSpec YAML profile (core spec 2.4) is enforced before the typed
	// decode: single document, no anchors/aliases/merge keys, YAML 1.2 Core
	// booleans, and bounded size, depth, and node count.
	if err := enforceYAMLProfile(yamlStr); err != nil {
		return nil, parseError("failed to parse HushSpec YAML: %s", err.Error())
	}
	coreYAML, err := normalizeCoreYAML(yamlStr)
	if err != nil {
		return nil, parseError("failed to parse HushSpec YAML: %s", normalizeDecoderMessage(err.Error()))
	}
	yamlStr = coreYAML

	var spec HushSpec
	decoder := yaml.NewDecoder(strings.NewReader(yamlStr))
	decoder.KnownFields(true)
	err = decoder.Decode(&spec)
	if err != nil {
		return nil, parseError("failed to parse HushSpec YAML: %s", normalizeDecoderMessage(err.Error()))
	}
	if spec.HushSpecVersion == "" {
		return nil, parseError("missing field `hushspec`: the document must declare a spec version")
	}

	var presence parsePresenceSpec
	if err := yaml.Unmarshal([]byte(yamlStr), &presence); err != nil {
		return nil, parseError("failed to inspect HushSpec YAML defaults: %s",
			normalizeDecoderMessage(err.Error()))
	}
	applyParseDefaults(&spec, &presence)
	// Go cannot give a field a default and writes a nil slice as JSON `null`,
	// so a required collection that decoded to nil is given an empty value
	// here -- the same place the Python model does it. Without this the other
	// three SDKs would serialize an empty `states`, `transitions` or
	// `rule_paths` and Go alone would drop it.
	spec.initEmptyCollections()

	// Raw-document checks catch structural issues the typed decode swallows
	// (non-integer floats truncated into int fields, empty/invalid enum
	// sentinels, a posture missing its required transitions key), so a document
	// this engine accepts is one the schema accepts.
	if issues := validateRawDocument(yamlStr); len(issues) > 0 {
		messages := make([]string, 0, len(issues))
		for _, issue := range issues {
			messages = append(messages, issue.Message)
		}
		// The refusal reports the first issue's code and path; the message
		// lists every issue found, so one pass names every problem.
		return nil, &ValidationError{
			Code:    issues[0].Code,
			Kind:    issues[0].Kind,
			Path:    issues[0].Path,
			Message: "invalid HushSpec document: " + strings.Join(messages, "; "),
		}
	}

	return &spec, nil
}

// parseError is a shape refusal: E001, the code registered for anything the
// deny-unknown-fields model will not deserialize.
func parseError(format string, args ...any) *ValidationError {
	return &ValidationError{
		Code:    ErrorCodeParse,
		Kind:    "PARSE",
		Message: fmt.Sprintf(format, args...),
	}
}

// Rewrites of gopkg.in/yaml.v3's own diagnostics into the HushSpec refusal
// vocabulary, so the `message_contains` assertions of the invalid-vector
// sidecars hold. Only the wording changes; nothing is accepted or rejected
// differently.
var (
	decoderUnknownFieldPattern = regexp.MustCompile(
		"field ([^ ]+) not found in type ([^\\s]+)")
	decoderTypeMismatchPattern = regexp.MustCompile(
		"cannot unmarshal !!([a-z]+)(?: `([^`]*)`)? into (\\S+)")
	decoderDuplicateKeyPattern = regexp.MustCompile(
		`mapping key ("(?:[^"\\]|\\.)*") already defined at line (\d+)`)
)

func normalizeDecoderMessage(message string) string {
	message = decoderUnknownFieldPattern.ReplaceAllString(message, "unknown field `$1` in $2")
	message = decoderTypeMismatchPattern.ReplaceAllStringFunc(message, func(match string) string {
		groups := decoderTypeMismatchPattern.FindStringSubmatch(match)
		if groups[2] == "" {
			return fmt.Sprintf("invalid type: %s, expected %s", groups[1], groups[3])
		}
		return fmt.Sprintf("invalid type: %s `%s`, expected %s", groups[1], groups[2], groups[3])
	})
	message = decoderDuplicateKeyPattern.ReplaceAllString(
		message, "duplicate entry with key $1 (already defined at line $2)")
	return message
}

// defaultMaxImbalanceRatio is the schema default for
// `rules.patch_integrity.max_imbalance_ratio`. [applyParseDefaults]
// materializes it, so a parsed document always carries a limit and evaluation
// never has to invent one.
const defaultMaxImbalanceRatio = 10.0

func applyParseDefaults(spec *HushSpec, presence *parsePresenceSpec) {
	if spec.Rules != nil && spec.Rules.ForbiddenPaths != nil {
		if presence.Rules == nil || presence.Rules.ForbiddenPaths == nil || presence.Rules.ForbiddenPaths.Enabled == nil {
			spec.Rules.ForbiddenPaths.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.Egress != nil {
		if presence.Rules == nil || presence.Rules.Egress == nil || presence.Rules.Egress.Enabled == nil {
			spec.Rules.Egress.Enabled = true
		}
		if presence.Rules == nil || presence.Rules.Egress == nil || presence.Rules.Egress.Default == nil {
			spec.Rules.Egress.Default = DefaultActionBlock
		}
	}
	if spec.Rules != nil && spec.Rules.SecretPatterns != nil {
		if presence.Rules == nil || presence.Rules.SecretPatterns == nil || presence.Rules.SecretPatterns.Enabled == nil {
			spec.Rules.SecretPatterns.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.PatchIntegrity != nil {
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.Enabled == nil {
			spec.Rules.PatchIntegrity.Enabled = true
		}
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.MaxAdditions == nil {
			spec.Rules.PatchIntegrity.MaxAdditions = 1000
		}
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.MaxDeletions == nil {
			spec.Rules.PatchIntegrity.MaxDeletions = 500
		}
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.MaxImbalanceRatio == nil {
			ratio := defaultMaxImbalanceRatio
			spec.Rules.PatchIntegrity.MaxImbalanceRatio = &ratio
		}
	}
	if spec.Rules != nil && spec.Rules.RemoteDesktopChannels != nil {
		if presence.Rules == nil || presence.Rules.RemoteDesktopChannels == nil || presence.Rules.RemoteDesktopChannels.Audio == nil {
			spec.Rules.RemoteDesktopChannels.Audio = true
		}
	}
	if spec.Rules != nil && spec.Rules.ShellCommands != nil {
		if presence.Rules == nil || presence.Rules.ShellCommands == nil || presence.Rules.ShellCommands.Enabled == nil {
			spec.Rules.ShellCommands.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.ToolAccess != nil {
		if presence.Rules == nil || presence.Rules.ToolAccess == nil || presence.Rules.ToolAccess.Enabled == nil {
			spec.Rules.ToolAccess.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.BrowserAutomation != nil {
		if presence.Rules == nil || presence.Rules.BrowserAutomation == nil || presence.Rules.BrowserAutomation.CredentialDetection == nil {
			spec.Rules.BrowserAutomation.CredentialDetection = true
		}
	}
	// Origin profile rule blocks are tri-state overlays (origins spec 4): they
	// carry no `enabled` flag and their `default` stays unset unless the
	// document states one, so no defaults are materialized for them here.
}

// Marshal serializes a HushSpec document to YAML.
func Marshal(spec *HushSpec) (string, error) {
	data, err := yaml.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal HushSpec to YAML: %w", err)
	}
	return string(data), nil
}
