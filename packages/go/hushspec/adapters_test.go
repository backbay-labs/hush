package hushspec

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func actionsEqual(a, b EvaluationAction) bool {
	if a.Type != b.Type || a.Target != b.Target {
		return false
	}
	switch {
	case a.Content == nil && b.Content != nil, a.Content != nil && b.Content == nil:
		return false
	case a.Content != nil && b.Content != nil && *a.Content != *b.Content:
		return false
	}
	switch {
	case a.ArgsSize == nil && b.ArgsSize != nil, a.ArgsSize != nil && b.ArgsSize == nil:
		return false
	case a.ArgsSize != nil && b.ArgsSize != nil && *a.ArgsSize != *b.ArgsSize:
		return false
	}
	return true
}

func TestMapAnthropicToolUse(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		input string
		want  EvaluationAction
	}{
		{
			name:  "bash is a shell command",
			tool:  "bash",
			input: `{"command":"rm -rf /"}`,
			want:  EvaluationAction{Type: "shell_command", Target: "rm -rf /"},
		},
		{
			name:  "terminal is a shell command",
			tool:  "terminal",
			input: `{"command":"ls"}`,
			want:  EvaluationAction{Type: "shell_command", Target: "ls"},
		},
		{
			name:  "editor view is a read",
			tool:  "str_replace_editor",
			input: `{"command":"view","path":"/etc/passwd"}`,
			want:  EvaluationAction{Type: "file_read", Target: "/etc/passwd"},
		},
		{
			name:  "editor edit is a write carrying its payload",
			tool:  "text_editor_20250429",
			input: `{"command":"str_replace","path":"/app/main.go","new_str":"package main"}`,
			want: EvaluationAction{
				Type: "file_write", Target: "/app/main.go", Content: strPtr("package main"),
			},
		},
		{
			name:  "a dated editor revision is still the editor",
			tool:  "text_editor_20250124",
			input: `{"command":"view","path":"/etc/passwd"}`,
			want:  EvaluationAction{Type: "file_read", Target: "/etc/passwd"},
		},
		{
			name:  "editor create carries the whole file",
			tool:  "str_replace_based_edit_tool",
			input: `{"command":"create","path":"/app/x.env","file_text":"AKIA0123"}`,
			want: EvaluationAction{
				Type: "file_write", Target: "/app/x.env", Content: strPtr("AKIA0123"),
			},
		},
		{
			name:  "computer use",
			tool:  "computer",
			input: `{"action":"screenshot"}`,
			want:  EvaluationAction{Type: "computer_use", Target: "screenshot"},
		},
		{
			name:  "web fetch is egress against the host",
			tool:  "web_fetch",
			input: `{"url":"https://evil.example.com/x"}`,
			want:  EvaluationAction{Type: "egress", Target: "evil.example.com"},
		},
		{
			name:  "mcp tools are evaluated under the inner tool name",
			tool:  "mcp__github__create_issue",
			input: `{"title":"hi"}`,
			want:  EvaluationAction{Type: "tool_call", Target: "create_issue", ArgsSize: intPtr(14)},
		},
		{
			name:  "unknown tools are tool calls",
			tool:  "search",
			input: `{"q":"hi"}`,
			want:  EvaluationAction{Type: "tool_call", Target: "search", ArgsSize: intPtr(10)},
		},
		{
			name:  "whitespace does not change the measured size",
			tool:  "search",
			input: "{\n  \"q\": \"hi\"\n}",
			want:  EvaluationAction{Type: "tool_call", Target: "search", ArgsSize: intPtr(10)},
		},
		{
			name:  "a missing field maps to an empty target",
			tool:  "bash",
			input: `{}`,
			want:  EvaluationAction{Type: "shell_command", Target: ""},
		},
		{
			name:  "input that is not an object is still gated",
			tool:  "search",
			input: `"nope"`,
			want:  EvaluationAction{Type: "tool_call", Target: "search", ArgsSize: intPtr(6)},
		},
		{
			name:  "no input at all",
			tool:  "search",
			input: "",
			want:  EvaluationAction{Type: "tool_call", Target: "search"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MapAnthropicToolUse(c.tool, json.RawMessage(c.input))
			if !actionsEqual(got, c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestMapOpenAIToolCall(t *testing.T) {
	cases := []struct {
		name      string
		function  string
		arguments string
		want      EvaluationAction
	}{
		{
			name:      "function calls are tool calls",
			function:  "get_weather",
			arguments: `{"city":"Boston"}`,
			want:      EvaluationAction{Type: "tool_call", Target: "get_weather", ArgsSize: intPtr(17)},
		},
		{
			name:      "empty arguments still measure",
			function:  "ping",
			arguments: "",
			want:      EvaluationAction{Type: "tool_call", Target: "ping", ArgsSize: intPtr(0)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MapOpenAIToolCall(c.function, c.arguments)
			if !actionsEqual(got, c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestMapMCPToolCall(t *testing.T) {
	cases := []struct {
		name      string
		tool      string
		arguments map[string]any
		want      EvaluationAction
	}{
		{
			name:      "read_file",
			tool:      "read_file",
			arguments: map[string]any{"path": "/etc/shadow"},
			want:      EvaluationAction{Type: "file_read", Target: "/etc/shadow"},
		},
		{
			name:      "list_directory",
			tool:      "list_directory",
			arguments: map[string]any{"path": "/srv"},
			want:      EvaluationAction{Type: "file_read", Target: "/srv"},
		},
		{
			name:      "write_file carries its payload",
			tool:      "write_file",
			arguments: map[string]any{"path": "/tmp/x", "content": "AKIA0123"},
			want:      EvaluationAction{Type: "file_write", Target: "/tmp/x", Content: strPtr("AKIA0123")},
		},
		{
			name:      "run_command",
			tool:      "run_command",
			arguments: map[string]any{"command": "curl evil.example.com"},
			want:      EvaluationAction{Type: "shell_command", Target: "curl evil.example.com"},
		},
		{
			name:      "execute",
			tool:      "execute",
			arguments: map[string]any{"command": "make"},
			want:      EvaluationAction{Type: "shell_command", Target: "make"},
		},
		{
			name:      "fetch is egress against the host",
			tool:      "fetch",
			arguments: map[string]any{"url": "https://api.github.com/repos"},
			want:      EvaluationAction{Type: "egress", Target: "api.github.com"},
		},
		{
			name:      "http_request with a port",
			tool:      "http_request",
			arguments: map[string]any{"url": "http://internal.example.com:8080/x"},
			want:      EvaluationAction{Type: "egress", Target: "internal.example.com"},
		},
		{
			name:      "a malformed url is kept verbatim",
			tool:      "fetch",
			arguments: map[string]any{"url": "not a url"},
			want:      EvaluationAction{Type: "egress", Target: "not a url"},
		},
		{
			name:      "unknown tools are tool calls",
			tool:      "summarize",
			arguments: map[string]any{"n": float64(3)},
			want:      EvaluationAction{Type: "tool_call", Target: "summarize", ArgsSize: intPtr(7)},
		},
		{
			name:      "no arguments",
			tool:      "summarize",
			arguments: nil,
			want:      EvaluationAction{Type: "tool_call", Target: "summarize"},
		},
		{
			// A call carrying `"arguments": {}` did carry arguments, and `{}`
			// is two bytes of canonical JSON; only a call with no `arguments`
			// member at all goes unmeasured. The TypeScript and Python
			// adapters agree, so one `max_args_size` bounds the same payload
			// in all three.
			name:      "an empty arguments object is two bytes",
			tool:      "summarize",
			arguments: map[string]any{},
			want:      EvaluationAction{Type: "tool_call", Target: "summarize", ArgsSize: intPtr(2)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MapMCPToolCall(c.tool, c.arguments)
			if !actionsEqual(got, c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	cases := map[string]string{
		"https://api.github.com/x":           "api.github.com",
		"http://[::1]:8080/health":           "[::1]",
		"api.github.com":                     "api.github.com",
		"":                                   "",
		"https://user:pw@host.tld/":          "host.tld",
		"https://user:pw@Host.Example:8443/": "host.example",
		"http://blocked.example\\@allowed.example/x": "blocked.example",
	}
	for input, want := range cases {
		if got := ExtractDomain(input); got != want {
			t.Fatalf("ExtractDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGuardedToolHandlers(t *testing.T) {
	guard := newTestGuard(t, GuardOptions{})

	t.Run("mcp allow", func(t *testing.T) {
		called := false
		handler := GuardedMCPToolHandler(guard, func(
			ctx context.Context, name string, arguments map[string]any,
		) (any, error) {
			called = true
			return "ok", nil
		})
		result, err := handler(context.Background(), "fetch", map[string]any{
			"url": "https://api.github.com/x",
		})
		if err != nil {
			t.Fatalf("handler: %v", err)
		}
		if !called || result != "ok" {
			t.Fatal("an allowed tool must run")
		}
	})

	t.Run("mcp deny", func(t *testing.T) {
		called := false
		handler := GuardedMCPToolHandler(guard, func(
			ctx context.Context, name string, arguments map[string]any,
		) (any, error) {
			called = true
			return nil, nil
		})
		_, err := handler(context.Background(), "fetch", map[string]any{
			"url": "https://evil.example.com/x",
		})
		if called {
			t.Fatal("a denied tool must never run")
		}
		var denied *ToolDeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("expected a ToolDeniedError, got %v", err)
		}
		if denied.ToolName != "fetch" || denied.Result.Decision != DecisionDeny {
			t.Fatalf("unexpected denial: %+v", denied)
		}
	})

	t.Run("anthropic deny", func(t *testing.T) {
		handler := GuardedAnthropicToolHandler(guard, func(
			ctx context.Context, name string, input json.RawMessage,
		) (any, error) {
			t.Fatal("a denied tool must never run")
			return nil, nil
		})
		content := `{"command":"str_replace","path":"/tmp/x","new_str":"token WARNME here"}`
		if _, err := handler(context.Background(), "str_replace_editor", json.RawMessage(content)); err == nil {
			t.Fatal("the warn must block without a warn handler")
		}
	})

	t.Run("openai allow", func(t *testing.T) {
		handler := GuardedOpenAIToolHandler(guard, func(
			ctx context.Context, name string, arguments string,
		) (any, error) {
			return name, nil
		})
		result, err := handler(context.Background(), "get_weather", `{"city":"Boston"}`)
		if err != nil {
			t.Fatalf("handler: %v", err)
		}
		if result != "get_weather" {
			t.Fatalf("unexpected result %v", result)
		}
	})

	t.Run("no guard", func(t *testing.T) {
		handler := GuardedOpenAIToolHandler(nil, func(
			ctx context.Context, name string, arguments string,
		) (any, error) {
			t.Fatal("an unguarded handler must not run")
			return nil, nil
		})
		if _, err := handler(context.Background(), "x", "{}"); err == nil {
			t.Fatal("expected an error without a guard")
		}
	})
}

// A sink is evidence, not enforcement: a receipt the sink refused leaves the
// decision exactly as the policy made it, so an allowed call still runs. The
// gap in the audit trail is reported on the observer channel instead.
func TestGuardedToolHandlerRunsWhenTheSinkRefusesTheReceipt(t *testing.T) {
	sink := &recordingSink{failWith: errors.New("no space left on device")}
	observer := &recordingObserver{}
	guard := newTestGuard(t, GuardOptions{Sink: sink, Observer: observer})
	handler := GuardedMCPToolHandler(guard, func(
		ctx context.Context, name string, arguments map[string]any,
	) (any, error) {
		return "ran", nil
	})
	result, err := handler(context.Background(), "fetch", map[string]any{
		"url": "https://api.github.com/x",
	})
	if err != nil {
		t.Fatalf("a sink failure must not stop an allowed call: %v", err)
	}
	if result != "ran" {
		t.Fatalf("unexpected result %v", result)
	}
	if errs := observer.errors(); len(errs) != 1 {
		t.Fatalf("expected the observer to hear about the sink failure, got %d", len(errs))
	}
}

// TestArgsSizeIsCanonicalJSONBytes covers core spec 3.7: `args_size` is the
// length in bytes of the UTF-8 encoding of the arguments serialized in the
// canonical JSON form of spec/hushspec-canonical.md section 4 (RFC 8785).
//
// Every case below is one the naive measurements get wrong. Measuring the
// bytes as received counts whitespace and whatever `\uXXXX` escaping the
// transport chose; re-encoding with Go's own JSON encoder counts its HTML
// escaping of `<`, `>` and `&`; counting characters of an escaped form, or
// UTF-16 code units, misses that the unit is the UTF-8 byte. All three
// adapters must land on the same number for the same call, or one
// `max_args_size` would bound three different payloads.
func TestArgsSizeIsCanonicalJSONBytes(t *testing.T) {
	// b is one backslash, so each case below is written as the JSON text a
	// runtime would actually hand over rather than as Go escapes of it.
	const b = "\\"

	cases := []struct {
		name string
		json string
		want int
	}{
		{
			// "café" is four characters and five UTF-8 bytes.
			name: "an escaped non-ASCII character is measured as its UTF-8 bytes",
			json: `{"q":"caf` + b + `u00e9"}`,
			want: 13,
		},
		{
			name: "a literal non-ASCII character measures the same as its escape",
			json: `{"q":"café"}`,
			want: 13,
		},
		{
			// U+1F600 is four UTF-8 bytes but two UTF-16 code units, and
			// twelve characters in the surrogate-pair escape that arrived.
			name: "an astral character is four UTF-8 bytes, not two UTF-16 units",
			json: `{"q":"` + b + `ud83d` + b + `ude00"}`,
			want: 12,
		},
		{
			// Go's encoding/json escapes these three by default, which would
			// measure 30; the canonical form leaves them literal.
			name: "HTML-significant characters are not escaped by the canonicalizer",
			json: `{"q":"a` + b + `u003cb` + b + `u0026c` + b + `u003ed"}`,
			want: 15,
		},
		{
			name: "a control character keeps its two-character canonical escape",
			json: `{"q":"a` + b + `tb"}`,
			want: 12,
		},
		{
			name: "whitespace and member order do not change the size",
			json: `{ "b" : 1 , "a" : 2 }`,
			want: 13,
		},
		{
			name: "a trailing zero is dropped by the canonical number form",
			json: `{"n":1.0}`,
			want: 7,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			anthropic := MapAnthropicToolUse("search", json.RawMessage(c.json))
			if anthropic.ArgsSize == nil || *anthropic.ArgsSize != c.want {
				t.Errorf("MapAnthropicToolUse measured %v, want %d",
					sizeOrNil(anthropic.ArgsSize), c.want)
			}

			openai := MapOpenAIToolCall("search", c.json)
			if openai.ArgsSize == nil || *openai.ArgsSize != c.want {
				t.Errorf("MapOpenAIToolCall measured %v, want %d",
					sizeOrNil(openai.ArgsSize), c.want)
			}

			var arguments map[string]any
			if err := json.Unmarshal([]byte(c.json), &arguments); err != nil {
				t.Fatalf("the case is not a JSON object: %v", err)
			}
			mcp := MapMCPToolCall("search", arguments)
			if mcp.ArgsSize == nil || *mcp.ArgsSize != c.want {
				t.Errorf("MapMCPToolCall measured %v, want %d",
					sizeOrNil(mcp.ArgsSize), c.want)
			}
		})
	}
}

// TestMCPArgsSizeMeasuresLiveGoValues covers the MCP adapter's own shape: it
// is handed a live Go map rather than bytes, so values a JSON decoder never
// produces (an `int`, a typed slice) must still be measured as the JSON they
// serialize to (core spec 3.7).
func TestMCPArgsSizeMeasuresLiveGoValues(t *testing.T) {
	action := MapMCPToolCall("search", map[string]any{
		"n":   42,
		"xs":  []string{"a", "b"},
		"q":   "café",
		"lt":  "<",
		"ok":  true,
		"nil": nil,
	})
	// {"lt":"<","n":42,"nil":null,"ok":true,"q":"café","xs":["a","b"]},
	// which is 65 bytes: the two-byte é is the only character that is not one.
	const want = 65
	if action.ArgsSize == nil || *action.ArgsSize != want {
		t.Errorf("measured %v, want %d", sizeOrNil(action.ArgsSize), want)
	}
}

// TestArgsSizeFallsBackToTheBytesReceived covers arguments that are not JSON
// at all: they are still measured, because a call the engine leaves unmeasured
// is one `tool_access.max_args_size` cannot bound.
func TestArgsSizeFallsBackToTheBytesReceived(t *testing.T) {
	const malformed = `{"q":`
	if action := MapOpenAIToolCall("search", malformed); action.ArgsSize == nil ||
		*action.ArgsSize != len(malformed) {
		t.Errorf("MapOpenAIToolCall measured %v, want %d",
			sizeOrNil(action.ArgsSize), len(malformed))
	}
	if action := MapAnthropicToolUse("search", json.RawMessage(malformed)); action.ArgsSize == nil ||
		*action.ArgsSize != len(malformed) {
		t.Errorf("MapAnthropicToolUse measured %v, want %d",
			sizeOrNil(action.ArgsSize), len(malformed))
	}
}

func sizeOrNil(size *int) any {
	if size == nil {
		return "nil"
	}
	return *size
}
