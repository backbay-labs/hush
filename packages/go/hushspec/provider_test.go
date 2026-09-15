package hushspec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const policyAllowingGitHub = `hushspec: "0.2.0"
name: file-policy
rules:
  egress:
    enabled: true
    allow: ["api.github.com"]
    block: []
    default: block
`

const policyAllowingExample = `hushspec: "0.2.0"
name: file-policy
rules:
  egress:
    enabled: true
    allow: ["api.github.com", "api.example.com"]
    block: []
    default: block
`

func writePolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// Move the modification time back so a rewrite within the same filesystem
	// timestamp granularity still looks like a change.
	stale := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, stale, stale); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func egressAllowed(t *testing.T, guard *Guard, host string) bool {
	t.Helper()
	decision, err := guard.Check(context.Background(), &EvaluationAction{Type: "egress", Target: host})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return decision.Allowed()
}

func TestFileProviderLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, policyAllowingGitHub)

	provider := NewFileProvider(path, ResolveOptions{})
	if provider.Source() != path {
		t.Fatalf("Source = %q", provider.Source())
	}
	resolution, err := provider.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if resolution.Spec.Name != "file-policy" || resolution.ContentHash == "" {
		t.Fatalf("unexpected resolution: %+v", resolution.Spec)
	}

	guard, err := NewGuardFromProvider(provider, GuardOptions{})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	if guard.Provider() != provider {
		t.Fatal("the guard did not keep its provider")
	}
	if !egressAllowed(t, guard, "api.github.com") {
		t.Fatal("the provider's policy is not in force")
	}
}

func TestFileProviderRefusesUnsignedPolicyForGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, policyAllowingGitHub)

	provider := NewFileProvider(path, ResolveOptions{RequireSignature: true})
	if _, err := provider.Load(); err == nil {
		t.Fatal("Load must fail closed when a signature is required")
	}
	guard, err := NewGuardFromProvider(provider, GuardOptions{})
	if err != nil {
		t.Fatalf("a refusable provider must still produce a guard: %v", err)
	}
	if refused, _ := guard.Refused(); !refused {
		t.Fatal("expected the guard to be refused")
	}
	if egressAllowed(t, guard, "api.github.com") {
		t.Fatal("a refused guard must deny everything")
	}
}

func TestPolicyWatcherSwapsPolicyOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, policyAllowingGitHub)

	provider := NewFileProvider(path, ResolveOptions{})
	guard, err := NewGuardFromProvider(provider, GuardOptions{})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}

	var changes []string
	watcher, err := NewPolicyWatcher(provider, ReloadOptions{
		Guard:    guard,
		OnChange: func(r *Resolution) { changes = append(changes, r.ContentHash) },
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher: %v", err)
	}

	// The first check sees the file the guard already loaded: same content
	// hash, so nothing is swapped.
	changed, err := watcher.CheckOnce()
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if changed {
		t.Fatal("an unchanged policy must not be swapped")
	}
	// A second check without touching the file reads nothing at all.
	if changed, err := watcher.CheckOnce(); changed || err != nil {
		t.Fatalf("CheckOnce: changed=%v err=%v", changed, err)
	}
	if egressAllowed(t, guard, "api.example.com") {
		t.Fatal("the new host must not be allowed yet")
	}

	writePolicy(t, path, policyAllowingExample)
	changed, err = watcher.CheckOnce()
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if !changed {
		t.Fatal("the rewritten policy was not picked up")
	}
	if !egressAllowed(t, guard, "api.example.com") {
		t.Fatal("the new policy is not in force")
	}
	if len(changes) != 1 {
		t.Fatalf("expected one change notification, got %d", len(changes))
	}
	if watcher.Current().ContentHash != guard.Resolution().ContentHash {
		t.Fatal("the watcher and the guard disagree about the policy in force")
	}
}

func TestPolicyWatcherKeepsLastGoodPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, policyAllowingGitHub)

	provider := NewFileProvider(path, ResolveOptions{})
	observer := &recordingObserver{}
	guard, err := NewGuardFromProvider(provider, GuardOptions{Observer: observer})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	good := guard.Resolution().ContentHash

	var reloadErrors []error
	watcher, err := NewPolicyWatcher(provider, ReloadOptions{
		Guard:   guard,
		OnError: func(err error) { reloadErrors = append(reloadErrors, err) },
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher: %v", err)
	}
	if _, err := watcher.CheckOnce(); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}

	writePolicy(t, path, "hushspec: \"0.2.0\"\nname: broken\nrules:\n  egress:\n    nope: true\n")
	if changed, err := watcher.CheckOnce(); changed || err == nil {
		t.Fatalf("a policy that does not parse must be rejected: changed=%v err=%v", changed, err)
	}
	if len(reloadErrors) != 1 {
		t.Fatalf("expected one reload error, got %d", len(reloadErrors))
	}
	if _, _, errs := observer.counts(); errs != 1 {
		t.Fatalf("the guard's observer must hear about a failed reload, got %d", errs)
	}
	if guard.Resolution().ContentHash != good {
		t.Fatal("a failed reload must leave the previous policy in force")
	}
	if !egressAllowed(t, guard, "api.github.com") {
		t.Fatal("the previous policy must keep working")
	}
}

func TestPolicyWatcherChecksPanicSentinel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	sentinel := filepath.Join(dir, "PANIC")
	writePolicy(t, path, policyAllowingGitHub)

	provider := NewFileProvider(path, ResolveOptions{})
	watcher, err := NewPolicyWatcher(provider, ReloadOptions{PanicSentinel: sentinel})
	if err != nil {
		t.Fatalf("NewPolicyWatcher: %v", err)
	}
	if _, err := watcher.CheckOnce(); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if IsPanicActive() {
		t.Fatal("panic mode must not be active without a sentinel")
	}

	if err := os.WriteFile(sentinel, nil, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	defer DeactivatePanic()
	if _, err := watcher.CheckOnce(); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if !IsPanicActive() {
		t.Fatal("the sentinel must be honoured on every tick")
	}
}

func TestPolicyWatcherStartStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, path, policyAllowingGitHub)

	provider := NewFileProvider(path, ResolveOptions{})
	guard, err := NewGuardFromProvider(provider, GuardOptions{})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	changed := make(chan string, 4)
	watcher, err := NewPolicyWatcher(provider, ReloadOptions{
		Guard:    guard,
		Interval: 5 * time.Millisecond,
		OnChange: func(r *Resolution) { changed <- r.ContentHash },
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher: %v", err)
	}
	if err := watcher.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()
	if err := watcher.Start(context.Background()); err == nil {
		t.Fatal("a second Start must be refused")
	}

	writePolicy(t, path, policyAllowingExample)
	select {
	case <-changed:
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher never noticed the change")
	}
	if !egressAllowed(t, guard, "api.example.com") {
		t.Fatal("the reloaded policy is not in force")
	}
	watcher.Stop()
	watcher.Stop() // idempotent
}

// stubProvider serves a scripted sequence of loads.
type stubProvider struct {
	mu      sync.Mutex
	loads   []func() (*Resolution, error)
	calls   int
	current func() (*Resolution, error)
}

func (p *stubProvider) Load() (*Resolution, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if len(p.loads) > 0 {
		next := p.loads[0]
		p.loads = p.loads[1:]
		p.current = next
		return next()
	}
	if p.current != nil {
		return p.current()
	}
	return nil, errors.New("no policy")
}

func (p *stubProvider) Source() string { return "stub://policy" }

func TestPolicyPollerDeliversChanges(t *testing.T) {
	first := guardSpec()
	second := guardSpec()
	second.Rules.Egress.Allow = []string{"api.github.com", "api.example.com"}

	firstResolution, err := NewResolutionFromResolved(first, "stub://policy")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	secondResolution, err := NewResolutionFromResolved(second, "stub://policy")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	provider := &stubProvider{loads: []func() (*Resolution, error){
		func() (*Resolution, error) { return firstResolution, nil },
		func() (*Resolution, error) { return firstResolution, nil },
		func() (*Resolution, error) { return nil, errors.New("control plane down") },
		func() (*Resolution, error) { return secondResolution, nil },
	}}

	guard, err := NewGuardFromProvider(provider, GuardOptions{})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	var errs []error
	poller, err := NewPolicyPoller(provider, ReloadOptions{
		Guard:   guard,
		OnError: func(err error) { errs = append(errs, err) },
	})
	if err != nil {
		t.Fatalf("NewPolicyPoller: %v", err)
	}

	if changed, err := poller.CheckOnce(); changed || err != nil {
		t.Fatalf("the same policy must not be swapped: changed=%v err=%v", changed, err)
	}
	if changed, err := poller.CheckOnce(); changed || err == nil {
		t.Fatalf("a failed poll must be reported: changed=%v err=%v", changed, err)
	}
	if len(errs) != 1 {
		t.Fatalf("expected one poll error, got %d", len(errs))
	}
	if egressAllowed(t, guard, "api.example.com") {
		t.Fatal("a failed poll must leave the previous policy in force")
	}

	if changed, err := poller.CheckOnce(); !changed || err != nil {
		t.Fatalf("the new policy was not delivered: changed=%v err=%v", changed, err)
	}
	if !egressAllowed(t, guard, "api.example.com") {
		t.Fatal("the polled policy is not in force")
	}
}

func TestPolicyPollerStartStop(t *testing.T) {
	resolution := guardResolution(t, guardSpec())
	provider := &stubProvider{current: func() (*Resolution, error) { return resolution, nil }}
	poller, err := NewPolicyPoller(provider, ReloadOptions{Interval: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewPolicyPoller: %v", err)
	}
	if err := poller.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		provider.mu.Lock()
		calls := provider.calls
		provider.mu.Unlock()
		if calls >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	poller.Stop()
	provider.mu.Lock()
	calls := provider.calls
	provider.mu.Unlock()
	if calls < 2 {
		t.Fatalf("the poller did not tick, %d calls", calls)
	}
	if poller.Current() == nil {
		t.Fatal("the poller has no current policy")
	}
}

func TestPolicyWatcherRequiresProviderAndPath(t *testing.T) {
	if _, err := NewPolicyWatcher(nil, ReloadOptions{}); err == nil {
		t.Fatal("a watcher needs a provider")
	}
	if _, err := NewPolicyPoller(nil, ReloadOptions{}); err == nil {
		t.Fatal("a poller needs a provider")
	}
	if _, err := NewPolicyWatcher(&stubProvider{}, ReloadOptions{}); err != nil {
		t.Fatalf("a non-empty source is enough to build a watcher: %v", err)
	}
}
