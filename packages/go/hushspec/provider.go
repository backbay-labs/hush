package hushspec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileProvider loads a policy from a path on disk, resolving and verifying its
// `extends` chain against the file's own directory.
//
// Resolution happens here rather than in the guard because a file policy's
// relative `extends` references are only meaningful against this file's
// directory, and its detached signature is only findable next to the file
// itself.
type FileProvider struct {
	path    string
	options ResolveOptions
	loader  ResolveLoader
}

// NewFileProvider provides the policy at path, verified under options. The
// zero [ResolveOptions] merges the chain and enforces digest pins without
// looking for a signature.
func NewFileProvider(path string, options ResolveOptions) *FileProvider {
	return &FileProvider{path: path, options: options}
}

// WithLoader resolves `extends` references through loader instead of the
// default (`builtin:` from the embedded rulesets, everything else from the
// filesystem). It returns the provider so it can be chained.
func (p *FileProvider) WithLoader(loader ResolveLoader) *FileProvider {
	p.loader = loader
	return p
}

// Path is the file this provider reads.
func (p *FileProvider) Path() string { return p.path }

// Source is the file this provider reads.
func (p *FileProvider) Source() string { return p.path }

// Load reads, resolves and verifies the policy.
func (p *FileProvider) Load() (*Resolution, error) {
	spec, source, err := loadSpecFile(p.path)
	if err != nil {
		return nil, err
	}
	return ResolveWithOptions(spec, source, p.loader, p.options)
}

// LoadForGuard is [FileProvider.Load], except that a chain which fails the
// signature requirement is returned as a refusal rather than an error, so the
// guard can record every action it denies under it.
func (p *FileProvider) LoadForGuard() (*Resolution, *GuardRefusal, error) {
	return resolveFileForGuard(p.path, p.options, p.loader)
}

// ---------------------------------------------------------------------------
// Hot reload
// ---------------------------------------------------------------------------

// DefaultWatchInterval is how often a [PolicyWatcher] stats its file.
const DefaultWatchInterval = 2 * time.Second

// DefaultPollInterval is how often a [PolicyPoller] reloads from its provider.
const DefaultPollInterval = 60 * time.Second

// ReloadOptions configures a [PolicyWatcher] or a [PolicyPoller].
type ReloadOptions struct {
	// Interval is the tick period. Zero means [DefaultWatchInterval] for a
	// watcher and [DefaultPollInterval] for a poller.
	Interval time.Duration
	// Guard, when set, has each new policy swapped into it. A swap that fails
	// leaves the previous policy in force and is reported through OnError.
	Guard *Guard
	// OnChange is called with each new resolution, after a successful swap.
	OnChange func(*Resolution)
	// OnError is called with every failure: a file that cannot be read, a
	// chain that will not resolve or verify, a policy that will not compile.
	// The previous policy stays in force.
	OnError func(error)
	// PanicSentinel, when set, is checked on every tick: the kill switch has
	// to work even while the policy source is unreachable, so it is checked
	// before anything is loaded and it fails closed (an unreadable sentinel
	// counts as present).
	PanicSentinel string
}

func (o ReloadOptions) interval(fallback time.Duration) time.Duration {
	if o.Interval > 0 {
		return o.Interval
	}
	return fallback
}

// policyReloader is the machinery a watcher and a poller share: the last good
// policy, the delivery path into a guard, and the ticker goroutine.
type policyReloader struct {
	provider PolicyProvider
	options  ReloadOptions

	mu      sync.Mutex
	current *Resolution
	// lastHash is the content hash last delivered. It is what makes a reload
	// idempotent: a file rewritten with identical bytes is not a policy change.
	lastHash string

	startMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
}

func newPolicyReloader(provider PolicyProvider, options ReloadOptions) *policyReloader {
	reloader := &policyReloader{provider: provider, options: options}
	// Seed from the guard: a watcher started against a guard that already
	// holds this policy must not swap the identical document straight back in.
	if options.Guard != nil {
		if resolution := options.Guard.Resolution(); resolution != nil {
			reloader.current = resolution
			reloader.lastHash = resolution.ContentHash
		}
	}
	return reloader
}

// Current is the last policy successfully delivered, or the one the guard
// started with.
func (r *policyReloader) Current() *Resolution {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

func (r *policyReloader) report(err error) {
	if err == nil {
		return
	}
	if r.options.OnError != nil {
		r.options.OnError(err)
	}
	if r.options.Guard != nil {
		r.options.Guard.ReportError(err)
	}
}

// reload loads from the provider and delivers the policy when it differs from
// the one in force. It reports whether a new policy took effect.
//
// Every failure keeps the last good policy: an unreadable, unresolvable,
// unverifiable or uncompilable document must never displace one that worked.
func (r *policyReloader) reload() (bool, error) {
	resolution, err := r.provider.Load()
	if err != nil {
		err = fmt.Errorf("policy reload from %s: %w", r.provider.Source(), err)
		r.report(err)
		return false, err
	}
	if resolution == nil || resolution.Spec == nil {
		err = fmt.Errorf("policy reload from %s: provider returned no policy", r.provider.Source())
		r.report(err)
		return false, err
	}

	r.mu.Lock()
	unchanged := resolution.ContentHash != "" && resolution.ContentHash == r.lastHash
	r.mu.Unlock()
	if unchanged {
		return false, nil
	}

	if guard := r.options.Guard; guard != nil {
		if err := guard.SwapPolicy(resolution); err != nil {
			err = fmt.Errorf("policy reload from %s: %w", r.provider.Source(), err)
			r.report(err)
			return false, err
		}
	}

	r.mu.Lock()
	r.current = resolution
	r.lastHash = resolution.ContentHash
	r.mu.Unlock()

	if r.options.OnChange != nil {
		r.options.OnChange(resolution)
	}
	return true, nil
}

// checkPanic runs the sentinel check a tick owes the kill switch.
func (r *policyReloader) checkPanic() {
	if r.options.PanicSentinel != "" {
		CheckPanicSentinel(r.options.PanicSentinel)
	}
}

// start runs tick on a ticker until ctx ends or stop is called.
func (r *policyReloader) start(ctx context.Context, interval time.Duration, tick func()) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.done != nil {
		return errors.New("policy reload: already started")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.cancel, r.done = cancel, done

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				tick()
			}
		}
	}()
	return nil
}

// stop ends the ticker goroutine and waits for it.
func (r *policyReloader) stop() {
	r.startMu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.startMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// PolicyWatcher reloads a file-backed policy when the file changes.
//
// It polls rather than subscribing to filesystem events: an editor that
// replaces a file by rename, a container that swaps a mounted ConfigMap, and a
// deploy that writes through a symlink all look different to an event API and
// identical to a stat. A tick that sees the same modification time and size
// reads nothing; a tick that sees a change reloads, and a document whose
// content hash is unchanged is not delivered as a swap.
type PolicyWatcher struct {
	*policyReloader
	path string

	statMu   sync.Mutex
	lastSize int64
	lastMod  time.Time
	statSeen bool
}

// NewPolicyWatcher watches the file a [FileProvider] reads. Any provider whose
// Source is a filesystem path works; for one that is not, use a
// [PolicyPoller].
func NewPolicyWatcher(provider PolicyProvider, options ReloadOptions) (*PolicyWatcher, error) {
	if provider == nil {
		return nil, errors.New("policy watcher: a provider is required")
	}
	path := provider.Source()
	if path == "" {
		return nil, errors.New("policy watcher: provider has no source path")
	}
	return &PolicyWatcher{
		policyReloader: newPolicyReloader(provider, options),
		path:           filepath.Clean(path),
	}, nil
}

// Path is the file being watched.
func (w *PolicyWatcher) Path() string { return w.path }

// CheckOnce performs exactly one check: the panic sentinel, then the file's
// modification time and size, then a reload if either moved. It reports
// whether a new policy took effect.
//
// It is the whole of what a tick does, exposed so a test can drive reload
// deterministically instead of waiting on a ticker.
func (w *PolicyWatcher) CheckOnce() (bool, error) {
	w.checkPanic()

	info, err := os.Stat(w.path)
	if err != nil {
		err = fmt.Errorf("policy watcher: stat %s: %w", w.path, err)
		w.report(err)
		return false, err
	}

	w.statMu.Lock()
	changed := !w.statSeen || info.Size() != w.lastSize || !info.ModTime().Equal(w.lastMod)
	// The stamp is updated even when the reload below fails: a broken file is
	// reported once, and the next attempt waits for the file to change again.
	w.lastSize, w.lastMod, w.statSeen = info.Size(), info.ModTime(), true
	w.statMu.Unlock()

	if !changed {
		return false, nil
	}
	return w.reload()
}

// Start begins watching on a background goroutine until ctx is cancelled or
// [PolicyWatcher.Stop] is called. It performs one check immediately, so a file
// that changed between the guard's construction and the watch is picked up.
func (w *PolicyWatcher) Start(ctx context.Context) error {
	if err := w.start(ctx, w.options.interval(DefaultWatchInterval), func() {
		_, _ = w.CheckOnce()
	}); err != nil {
		return err
	}
	_, _ = w.CheckOnce()
	return nil
}

// Stop ends the watch and waits for the goroutine to finish. It is safe to
// call more than once.
func (w *PolicyWatcher) Stop() { w.stop() }

// PolicyPoller reloads from a provider on a fixed interval, whatever the
// provider is: an object store, a control-plane API, a file.
//
// A poll that returns a policy with the content hash already in force is not a
// change and is not delivered; a poll that fails leaves the last good policy
// alone.
type PolicyPoller struct {
	*policyReloader
}

// NewPolicyPoller polls provider.
func NewPolicyPoller(provider PolicyProvider, options ReloadOptions) (*PolicyPoller, error) {
	if provider == nil {
		return nil, errors.New("policy poller: a provider is required")
	}
	return &PolicyPoller{policyReloader: newPolicyReloader(provider, options)}, nil
}

// CheckOnce performs exactly one poll: the panic sentinel, then a load. It
// reports whether a new policy took effect.
func (p *PolicyPoller) CheckOnce() (bool, error) {
	p.checkPanic()
	return p.reload()
}

// Start begins polling on a background goroutine until ctx is cancelled or
// [PolicyPoller.Stop] is called. It polls once immediately.
func (p *PolicyPoller) Start(ctx context.Context) error {
	if err := p.start(ctx, p.options.interval(DefaultPollInterval), func() {
		_, _ = p.CheckOnce()
	}); err != nil {
		return err
	}
	_, _ = p.CheckOnce()
	return nil
}

// Stop ends the polling and waits for the goroutine to finish. It is safe to
// call more than once.
func (p *PolicyPoller) Stop() { p.stop() }
