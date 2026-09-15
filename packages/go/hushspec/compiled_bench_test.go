package hushspec

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// benchActions is a mixed action set covering the rule blocks rulesets/default.yaml
// configures: path globs (forbidden_paths, path_allowlist), host patterns
// (egress), the secret_patterns regex set and tool_access name lists.
func benchActions() []*EvaluationAction {
	content := "deploy step: export TOKEN=redacted and run the build"
	clean := "nothing sensitive in this payload at all"
	return []*EvaluationAction{
		{Type: "file_read", Target: "src/main.go"},
		{Type: "file_read", Target: "/home/agent/.ssh/id_rsa"},
		{Type: "file_write", Target: "docs/notes.md", Content: &content},
		{Type: "patch_apply", Target: "src/lib.rs", Content: &content},
		{Type: "egress", Target: "https://api.github.com/repos"},
		{Type: "egress", Target: "evil.example.com", Content: &clean},
		{Type: "tool_call", Target: "read_file", Content: &clean},
		{Type: "tool_call", Target: "shell"},
		{Type: "shell_command", Target: "git status --porcelain"},
	}
}

func benchSpec(b *testing.B) *HushSpec {
	b.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		b.Fatal("failed to resolve test file path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../.."))
	source, err := os.ReadFile(filepath.Join(root, "rulesets", "default.yaml"))
	if err != nil {
		b.Fatalf("read default ruleset: %v", err)
	}
	spec, err := Parse(string(source))
	if err != nil {
		b.Fatalf("parse default ruleset: %v", err)
	}
	return spec
}

// BenchmarkEvaluateUncompiled evaluates through the free function, which owns
// the policy's compilation lifetime itself.
func BenchmarkEvaluateUncompiled(b *testing.B) {
	spec := benchSpec(b)
	actions := benchActions()

	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		for _, action := range actions {
			if Evaluate(spec, action).Decision == "" {
				b.Fatal("empty decision")
			}
		}
	}
}

// BenchmarkEvaluateCompiled evaluates through a policy compiled once up front,
// which is what a long-lived enforcement point holds.
func BenchmarkEvaluateCompiled(b *testing.B) {
	spec := benchSpec(b)
	policy, err := CompilePolicy(spec)
	if err != nil {
		b.Fatalf("compile default ruleset: %v", err)
	}
	actions := benchActions()

	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		for _, action := range actions {
			if policy.Evaluate(action).Decision == "" {
				b.Fatal("empty decision")
			}
		}
	}
}

// BenchmarkCompilePolicy is the one-time cost the other two amortize.
func BenchmarkCompilePolicy(b *testing.B) {
	spec := benchSpec(b)

	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := CompilePolicy(spec); err != nil {
			b.Fatalf("compile default ruleset: %v", err)
		}
	}
}
