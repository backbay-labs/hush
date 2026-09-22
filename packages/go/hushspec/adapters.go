package hushspec

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Adapters map a runtime's tool-call shape onto an [EvaluationAction].
//
// The mapping is the security-relevant part of an integration: a tool call
// evaluated as a bare `tool_call` is checked against `tool_access` alone,
// while the same call mapped to `file_read` also meets `forbidden_paths` and
// `path_allowlist`. Each adapter therefore recognizes the tools whose meaning
// is fixed by the protocol and maps everything else to `tool_call`, which is
// the fail-safe reading: an unrecognized tool is still gated, just by the
// rules that apply to every tool.

// datedToolSuffix is the date Anthropic stamps on a versioned tool name
// (`text_editor_20250429`). A policy is written against the tool, not the
// revision, so the suffix is stripped before the name is matched.
var datedToolSuffix = regexp.MustCompile(`_20[0-9]{6}$`)

// MapClaudeToolToAction maps a Claude `tool_use` block onto an action.
//
// Recognized: `bash` and `terminal` (shell_command), the text editor tools
// (file_read for `view`, file_write otherwise), `computer` (computer_use), and
// `web_fetch` / `fetch` (egress against the URL's host). An
// `mcp__<server>__<tool>` name is evaluated under the inner tool name, so a
// policy names the tool rather than the transport. Everything else is a
// `tool_call` carrying the serialized size of its input.
func MapClaudeToolToAction(name string, input json.RawMessage) EvaluationAction {
	fields, argsSize := decodeToolArguments(input)

	switch datedToolSuffix.ReplaceAllString(name, "") {
	case "bash", "terminal":
		return EvaluationAction{Type: "shell_command", Target: stringField(fields, "command")}
	case "str_replace_editor", "str_replace_based_edit_tool", "text_editor":
		if stringField(fields, "command") == "view" {
			return EvaluationAction{Type: "file_read", Target: stringField(fields, "path")}
		}
		action := EvaluationAction{Type: "file_write", Target: stringField(fields, "path")}
		// `create` carries the whole file under `file_text`; an edit carries
		// the replacement under `new_str`. Either way the payload goes through
		// as content, so secret_patterns and the detection pipeline see what is
		// about to be written.
		content, ok := optionalStringField(fields, "new_str")
		if !ok {
			content, ok = optionalStringField(fields, "file_text")
		}
		if ok {
			action.Content = &content
		}
		return action
	case "computer":
		return EvaluationAction{Type: "computer_use", Target: stringField(fields, "action")}
	case "web_fetch", "fetch":
		return EvaluationAction{
			Type:   "egress",
			Target: ExtractDomain(stringField(fields, "url")),
		}
	}

	target := name
	if strings.HasPrefix(name, "mcp__") {
		if parts := strings.Split(name, "__"); len(parts) >= 3 {
			target = strings.Join(parts[2:], "__")
		}
	}
	return EvaluationAction{Type: "tool_call", Target: target, ArgsSize: argsSize}
}

// MapOpenAIToolCall maps an OpenAI function call onto an action.
//
// Function names are defined by whoever wrote the tool schema, so there is no
// protocol-fixed vocabulary to recognize: every call is a `tool_call` against
// the function name, carrying the canonical size of the arguments JSON (which
// is what `tool_access.max_args_size` bounds). A runtime whose functions do
// have fixed meanings should map them itself, or route them through
// [MapMCPToolCall].
func MapOpenAIToolCall(name string, arguments string) EvaluationAction {
	// The model hands these over already serialized, so the string is parsed
	// only to re-measure it canonically; arguments that are not JSON at all
	// are measured as received rather than left unmeasured, because an
	// unmeasured call is one `max_args_size` cannot bound.
	size := len(arguments)
	if canonical, ok := canonicalArgsSize(json.RawMessage(arguments)); ok {
		size = canonical
	}
	return EvaluationAction{Type: "tool_call", Target: name, ArgsSize: &size}
}

// MapMCPToolCall maps an MCP `tools/call` onto an action.
//
// Recognized: `read_file` and `list_directory` (file_read), `write_file`
// (file_write, with the payload as content so secret scanning sees it),
// `run_command` and `execute` (shell_command), and `fetch` and `http_request`
// (egress against the URL's host). Everything else is a `tool_call`.
func MapMCPToolCall(name string, arguments map[string]any) EvaluationAction {
	fields := arguments
	action := EvaluationAction{Type: "tool_call", Target: name}
	switch normalizeMCPToolName(name) {
	case "readfile", "read", "cat", "view", "viewfile", "listdirectory", "listdir", "ls":
		action = EvaluationAction{Type: "file_read", Target: firstStringField(fields, "path", "filePath", "file_path", "file", "filename", "directory")}
	case "writefile", "write", "createfile", "editfile", "edit", "appendfile", "strreplace":
		action = EvaluationAction{Type: "file_write", Target: firstStringField(fields, "path", "filePath", "file_path", "file", "filename", "directory")}
		if content, ok := firstOptionalStringField(fields, "content", "contents", "text", "data", "new_str", "newStr"); ok {
			action.Content = &content
		}
	case "bash", "sh", "shell", "exec", "execute", "executecommand", "runcommand", "terminal":
		action = EvaluationAction{Type: "shell_command", Target: firstStringField(fields, "command", "cmd", "script")}
	case "fetch", "webfetch", "http", "httprequest", "httpfetch", "request", "apicall":
		action = EvaluationAction{Type: "egress", Target: ExtractDomain(firstStringField(fields, "url", "endpoint", "uri", "href"))}
	}
	if arguments != nil {
		// The caller passes a live Go map, so it goes through JSON first and
		// is then measured canonically: `max_args_size` must mean the same
		// number here as it does behind an adapter handed raw bytes.
		if size, ok := canonicalGoValueArgsSize(arguments); ok {
			action.ArgsSize = &size
		}
	}
	return action
}

func normalizeMCPToolName(name string) string {
	var normalized strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			normalized.WriteRune(r)
		}
	}
	return normalized.String()
}

// ExtractDomain is the host a URL names, reduced as the evaluator reduces an
// egress target (core spec 3.14.2), or the string unchanged when it names no
// host. Reducing here with the evaluator's own algorithm keeps a URL a browser
// would read one way from being read another way by a URL parser with
// different delimiter rules, and the raw fallback keeps a malformed URL from
// silently becoming a host that matches an allowlist pattern.
func ExtractDomain(rawURL string) string {
	if host := NormalizeHost(rawURL); host != nil {
		return *host
	}
	return rawURL
}

// decodeToolArguments decodes a tool input object and measures its canonical
// size, which is what `tool_access.max_args_size` bounds.
//
// Input that is not a JSON object decodes to no fields but is still measured
// -- a target of "" then matches no allowlist entry, which is the fail-closed
// reading. Input that is not JSON at all is measured as received, because an
// unmeasured call is one `max_args_size` cannot bound.
func decodeToolArguments(input json.RawMessage) (map[string]any, *int) {
	if len(input) == 0 {
		return nil, nil
	}
	var decoded any
	if err := json.Unmarshal(input, &decoded); err != nil {
		size := len(input)
		return nil, &size
	}
	size := len(input)
	if canonical, ok := canonicalJSONSize(decoded); ok {
		size = canonical
	}
	fields, _ := decoded.(map[string]any)
	return fields, &size
}

// canonicalArgsSize measures already-serialized arguments as core spec 3.7
// requires, reporting false when they are not JSON.
func canonicalArgsSize(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return 0, false
	}
	return canonicalJSONSize(decoded)
}

// canonicalGoValueArgsSize measures a caller's live Go value by rendering it
// as the JSON tree a decoder would see first, so an `int`, a struct or a typed
// slice is measured as the JSON it serializes to rather than refused.
func canonicalGoValueArgsSize(value any) (int, bool) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0, false
	}
	return canonicalArgsSize(encoded)
}

// canonicalJSONSize is `args_size` as core spec 3.7 defines it: the length in
// bytes of the UTF-8 encoding of the arguments serialized in the canonical
// JSON form of spec/hushspec-canonical.md section 4 (RFC 8785). Measuring the
// canonical form rather than the bytes as received is what makes the number
// portable -- the same call reports the same size whatever whitespace, member
// order, or `\uXXXX` escaping the transport chose -- so one `max_args_size`
// bounds the same payload behind every adapter and in every SDK. Non-ASCII
// text is measured in UTF-8 bytes, never in UTF-16 code units or in the
// characters of an escaped form.
//
// value must be a decoded JSON tree; false means it has no canonical form.
func canonicalJSONSize(value any) (int, bool) {
	canonical, err := canonicalJSONValue(value)
	if err != nil {
		return 0, false
	}
	// Go string length is the UTF-8 byte count, which is the unit the
	// specification names.
	return len(canonical), true
}

func stringField(fields map[string]any, key string) string {
	value, _ := optionalStringField(fields, key)
	return value
}

func optionalStringField(fields map[string]any, key string) (string, bool) {
	if fields == nil {
		return "", false
	}
	value, ok := fields[key].(string)
	return value, ok
}

func firstStringField(fields map[string]any, keys ...string) string {
	value, _ := firstOptionalStringField(fields, keys...)
	return value
}

func firstOptionalStringField(fields map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := optionalStringField(fields, key); ok {
			return value, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Guarded handlers
// ---------------------------------------------------------------------------

// ToolDeniedError is returned by a guarded handler instead of running a tool
// the policy refused. It carries the decision and, when the guard built one,
// the receipt that recorded it.
type ToolDeniedError struct {
	ToolName string
	Result   EvaluationResult
	Receipt  *DecisionReceipt
}

func (e *ToolDeniedError) Error() string {
	reason := e.Result.Reason
	if reason == "" {
		reason = e.Result.MatchedRule
	}
	if reason == "" {
		reason = "policy denial"
	}
	return fmt.Sprintf("tool %q denied: %s", e.ToolName, reason)
}

// ToolActionMapper turns one runtime's tool call into an action to evaluate.
type ToolActionMapper[T any] func(name string, arguments T) EvaluationAction

// ToolHandler executes one tool call.
type ToolHandler[T any] func(ctx context.Context, name string, arguments T) (any, error)

// GuardedToolHandler wraps a tool handler so every call is checked first: the
// call is mapped to an action, the guard decides, and the handler runs only if
// the action may proceed. A refused call returns a [ToolDeniedError] and the
// handler is never invoked.
//
// An error from [Guard.Check] -- a cancelled context, an action the guard
// could not take -- stops the call too, the same way a denial does.
func GuardedToolHandler[T any](
	guard *Guard,
	mapper ToolActionMapper[T],
	next ToolHandler[T],
) ToolHandler[T] {
	return func(ctx context.Context, name string, arguments T) (any, error) {
		if guard == nil {
			return nil, fmt.Errorf("tool %q: no guard configured", name)
		}
		action := mapper(name, arguments)
		decision, err := guard.Check(ctx, &action)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed() {
			return nil, &ToolDeniedError{
				ToolName: name,
				Result:   decision.Result,
				Receipt:  decision.Receipt,
			}
		}
		return next(ctx, name, arguments)
	}
}

// CreateSecureToolHandler guards a Claude tool handler with
// [MapClaudeToolToAction]. The name is the one the other SDKs publish for the
// same thing.
func CreateSecureToolHandler(
	guard *Guard,
	next ToolHandler[json.RawMessage],
) ToolHandler[json.RawMessage] {
	return GuardedToolHandler(guard, MapClaudeToolToAction, next)
}

// GuardedOpenAIToolHandler guards an OpenAI function handler with
// [MapOpenAIToolCall].
func GuardedOpenAIToolHandler(guard *Guard, next ToolHandler[string]) ToolHandler[string] {
	return GuardedToolHandler(guard, MapOpenAIToolCall, next)
}

// GuardedMCPToolHandler guards an MCP tool handler with [MapMCPToolCall].
func GuardedMCPToolHandler(
	guard *Guard,
	next ToolHandler[map[string]any],
) ToolHandler[map[string]any] {
	return GuardedToolHandler(guard, MapMCPToolCall, next)
}
