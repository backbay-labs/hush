package hushspec

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func resetPanic() {
	DeactivatePanic()
}

func TestPanicActivateDeactivate(t *testing.T) {
	resetPanic()
	defer resetPanic()

	if IsPanicActive() {
		t.Fatal("expected panic to be inactive initially")
	}

	ActivatePanic()
	if !IsPanicActive() {
		t.Fatal("expected panic to be active after ActivatePanic()")
	}

	DeactivatePanic()
	if IsPanicActive() {
		t.Fatal("expected panic to be inactive after DeactivatePanic()")
	}
}

func TestPanicModeDeniesAll(t *testing.T) {
	resetPanic()
	defer resetPanic()

	ActivatePanic()

	spec := &HushSpec{HushSpecVersion: "0.1.0"}

	actionTypes := []string{
		"tool_call", "egress", "file_read", "file_write",
		"patch_apply", "shell_command", "computer_use", "unknown_action",
	}

	for _, actionType := range actionTypes {
		action := &EvaluationAction{
			Type:   actionType,
			Target: "anything",
		}
		result := Evaluate(spec, action)
		if result.Decision != DecisionDeny {
			t.Errorf("expected deny for action type %q, got %q", actionType, result.Decision)
		}
		if result.MatchedRule != "__hushspec_panic__" {
			t.Errorf("expected matched_rule '__hushspec_panic__', got %q", result.MatchedRule)
		}
		if result.Reason != "emergency panic mode is active" {
			t.Errorf("expected panic reason, got %q", result.Reason)
		}
	}
}

func TestDeactivateRestoresNormal(t *testing.T) {
	resetPanic()
	defer resetPanic()

	spec := &HushSpec{HushSpecVersion: "0.1.0"}
	action := &EvaluationAction{
		Type:   "tool_call",
		Target: "some_tool",
	}

	result := Evaluate(spec, action)
	if result.Decision != DecisionAllow {
		t.Fatalf("expected allow in normal mode, got %q", result.Decision)
	}

	ActivatePanic()
	result = Evaluate(spec, action)
	if result.Decision != DecisionDeny {
		t.Fatalf("expected deny in panic mode, got %q", result.Decision)
	}

	DeactivatePanic()
	result = Evaluate(spec, action)
	if result.Decision != DecisionAllow {
		t.Fatalf("expected allow after deactivation, got %q", result.Decision)
	}
}

func TestSentinelFileActivatesPanic(t *testing.T) {
	resetPanic()
	defer resetPanic()

	dir := t.TempDir()
	sentinel := filepath.Join(dir, ".hushspec_panic")

	if err := os.WriteFile(sentinel, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	if !CheckPanicSentinel(sentinel) {
		t.Fatal("expected CheckPanicSentinel to return true when file exists")
	}
	if !IsPanicActive() {
		t.Fatal("expected panic to be active after sentinel check")
	}
}

func TestSentinelFileMissingDoesNotActivate(t *testing.T) {
	resetPanic()
	defer resetPanic()

	sentinel := filepath.Join(t.TempDir(), "nonexistent")

	if CheckPanicSentinel(sentinel) {
		t.Fatal("expected CheckPanicSentinel to return false when file missing")
	}
	if IsPanicActive() {
		t.Fatal("expected panic to remain inactive when sentinel missing")
	}
}

// TestSentinelIndeterminateErrorFailsClosed covers the critical fix: this is
// a kill switch, so when the sentinel's existence cannot be determined (e.g.
// a permission error on a parent directory, as opposed to a definite
// not-found), CheckPanicSentinel must fail closed -- treat it as PRESENT and
// activate panic -- rather than fail open. Previously any os.Stat error
// (including EACCES) was treated as "absent".
func TestSentinelIndeterminateErrorFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("cannot exercise a permission-denied path while running as root")
	}

	resetPanic()
	defer resetPanic()

	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(blocked, ".hushspec_panic")
	if err := os.WriteFile(sentinel, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	// Strip all permissions from the parent directory so stat-ing the
	// sentinel inside it fails with a permission error instead of proving
	// the sentinel is absent.
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(blocked, 0o755) // restore so t.TempDir() cleanup can remove it

	if !CheckPanicSentinel(sentinel) {
		t.Fatal("expected CheckPanicSentinel to fail closed (return true) on an indeterminate stat error")
	}
	if !IsPanicActive() {
		t.Fatal("expected panic to be active after an indeterminate sentinel check")
	}
}
