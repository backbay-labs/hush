package hushspec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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

// MapAnthropicToolUse maps a Claude `tool_use` block onto an action.
//
// Recognized: `bash` and `terminal` (shell_command), the text editor tools
// (file_read for `view`, file_write otherwise), and `computer` (computer_use).
// An `mcp__<server>__<tool>` name is evaluated under the inner tool name, so a
// policy names the tool rather than the transport. Everything else is a
// `tool_call` carrying the serialized size of its input.
func MapAnthropicToolUse(name string, input json.RawMessage) EvaluationAction {
	fields, argsSize := decodeToolArguments(input)

	switch name {
	case "bash", "terminal":
		return EvaluationAction{Type: "shell_command", Target: stringField(fields, "command")}
	case "str_replace_editor", "str_replace_based_edit_tool",
		"text_editor_20250124", "text_editor_20250429":
		if stringField(fields, "command") == "view" {
			return EvaluationAction{Type: "file_read", Target: stringField(fields, "path")}
		}
		action := EvaluationAction{Type: "file_write", Target: stringField(fields, "path")}
		if content, ok := optionalStringField(fields, "new_str"); ok {
			action.Content = &content
		}
		return action
	case "computer":
		return EvaluationAction{Type: "computer_use", Target: stringField(fields, "action")}
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
// the function name, carrying the byte size of the arguments JSON as the
// runtime sent it (which is what `tool_access.max_args_size` bounds). A
// runtime whose functions do have fixed meanings should map them itself, or
// route them through [MapMCPToolCall].
func MapOpenAIToolCall(name string, arguments string) EvaluationAction {
	size := len(arguments)
	return EvaluationAction{Type: "tool_call", Target: name, ArgsSize: &size}
}

// MapMCPToolCall maps an MCP `tools/call` onto an action.
//
// Recognized: `read_file` and `list_directory` (file_read), `write_file`
// (file_write, with the payload as content so secret scanning sees it),
// `run_command` and `execute` (shell_command), and `fetch` and `http_request`
// (egress against the URL's host). Everything else is a `tool_call`.
func MapMCPToolCall(name string, arguments map[string]any) EvaluationAction {
	switch name {
	case "read_file", "list_directory":
		return EvaluationAction{Type: "file_read", Target: stringField(arguments, "path")}
	case "write_file":
		action := EvaluationAction{Type: "file_write", Target: stringField(arguments, "path")}
		if content, ok := optionalStringField(arguments, "content"); ok {
			action.Content = &content
		}
		return action
	case "run_command", "execute":
		return EvaluationAction{Type: "shell_command", Target: stringField(arguments, "command")}
	case "fetch", "http_request":
		return EvaluationAction{Type: "egress", Target: ExtractDomain(stringField(arguments, "url"))}
	}

	action := EvaluationAction{Type: "tool_call", Target: name}
	if arguments != nil {
		if encoded, err := json.Marshal(arguments); err == nil {
			size := len(encoded)
			action.ArgsSize = &size
		}
	}
	return action
}

// ExtractDomain is the host of a URL, or the string unchanged when it is not
// one. `egress` rules match hosts, and a malformed URL must not silently
// become a host that matches an allowlist pattern.
func ExtractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return rawURL
	}
	return parsed.Hostname()
}

// decodeToolArguments decodes a tool input object and measures its serialized
// size, which is what `tool_access.max_args_size` bounds.
//
// The size is measured over the compact re-encoding rather than the bytes as
// received, so the same call measured through any SDK reports the same number
// whatever whitespace the transport inserted. Input that is not a JSON object
// is measured as received and decodes to no fields -- a target of "" then
// matches no allowlist entry, which is the fail-closed reading.
func decodeToolArguments(input json.RawMessage) (map[string]any, *int) {
	if len(input) == 0 {
		return nil, nil
	}
	var fields map[string]any
	if err := json.Unmarshal(input, &fields); err != nil {
		size := len(input)
		return nil, &size
	}
	size := len(input)
	if encoded, err := json.Marshal(fields); err == nil {
		size = len(encoded)
	}
	return fields, &size
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
// It is stricter than [Guard.Check] in one way: a decision the guard could not
// record (a sink that failed) also stops the call. A tool whose decision left
// no evidence is not a tool that was allowed.
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

// GuardedAnthropicToolHandler guards a Claude tool handler with
// [MapAnthropicToolUse].
func GuardedAnthropicToolHandler(
	guard *Guard,
	next ToolHandler[json.RawMessage],
) ToolHandler[json.RawMessage] {
	return GuardedToolHandler(guard, MapAnthropicToolUse, next)
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
