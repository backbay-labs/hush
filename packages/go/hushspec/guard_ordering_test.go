package hushspec

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

type guardLogEntry struct{ kind, hash string }
type orderedGuardSink struct {
	mu          sync.Mutex
	entries     []guardLogEntry
	beforeSend  func()
	beforeEvent func(*PolicyEvent)
}

func (s *orderedGuardSink) Send(receipt *DecisionReceipt) error {
	if s.beforeSend != nil {
		s.beforeSend()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, guardLogEntry{"receipt", receipt.Policy.ContentHash})
	return nil
}

func (s *orderedGuardSink) RecordPolicyEvent(event *PolicyEvent) error {
	if s.beforeEvent != nil {
		s.beforeEvent(event)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, guardLogEntry{"policy", event.Policy.ContentHash})
	return nil
}

func TestReloadAndEvaluationWaitForSinkDelivery(t *testing.T) {
	for _, blockEvent := range []bool{false, true} {
		t.Run(map[bool]string{false: "receipt", true: "policy"}[blockEvent], func(t *testing.T) {
			sink := &orderedGuardSink{}
			guard := newTestGuard(t, GuardOptions{Sink: sink})
			entered, release := make(chan struct{}), make(chan struct{})
			pause := func() {
				close(entered)
				select {
				case <-release:
				case <-time.After(5 * time.Second):
				}
			}
			if blockEvent {
				sink.beforeEvent = func(*PolicyEvent) { pause() }
			} else {
				sink.beforeSend = pause
			}
			next := guardSpec()
			name := "changed"
			next.Name = &name
			resolution := guardResolution(t, next)
			check := func() {
				_, err := guard.Evaluate(context.Background(), &EvaluationAction{Type: "egress", Target: "api.example.com"})
				if err != nil {
					t.Error(err)
				}
			}
			swap := func() {
				if err := guard.SwapPolicy(resolution); err != nil {
					t.Error(err)
				}
			}
			first, second := check, swap
			if blockEvent {
				first, second = swap, check
			}
			doneFirst, doneSecond := make(chan struct{}), make(chan struct{})
			go func() { defer close(doneFirst); first() }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("sink not reached")
			}
			go func() { defer close(doneSecond); second() }()
			early := false
			select {
			case <-doneSecond:
				early = true
			case <-time.After(200 * time.Millisecond):
			}
			close(release)
			for _, done := range []chan struct{}{doneFirst, doneSecond} {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("operation stuck")
				}
			}
			if early {
				t.Error("operation passed incomplete sink delivery")
			}
			current := ""
			for _, e := range sink.entries {
				if e.kind == "policy" {
					current = e.hash
				} else if e.hash != current {
					t.Fatalf("misordered evidence: %+v", sink.entries)
				}
			}
		})
	}
}

type reenterGuardObserver struct {
	guard  *Guard
	kind   string
	called bool
}

func (o *reenterGuardObserver) OnPolicyLoaded(load PolicyLoadObservation) {
	if load.IsSwap() {
		o.enter("load")
	}
}
func (o *reenterGuardObserver) OnEvaluation(EvaluationObservation) { o.enter("evaluation") }
func (o *reenterGuardObserver) OnError(error)                      { o.enter("error") }
func (o *reenterGuardObserver) enter(kind string) {
	if o.guard == nil || kind != o.kind || o.called {
		return
	}
	o.called = true
	if kind == "load" {
		_, _ = o.guard.Evaluate(context.Background(), &EvaluationAction{Type: "egress", Target: "api.example.com"})
	} else {
		if err := o.guard.SwapPolicy(o.guard.Resolution()); err != nil {
			panic(err)
		}
	}
}

func TestGuardObserversReenterAfterGateRelease(t *testing.T) {
	for _, kind := range []string{"load", "evaluation", "error"} {
		t.Run(kind, func(t *testing.T) {
			observer := &reenterGuardObserver{kind: kind}
			sink := &recordingSink{}
			guard := newTestGuard(t, GuardOptions{Sink: sink, Observer: observer})
			observer.guard = guard
			if kind == "error" {
				sink.failWith = errors.New("unavailable")
			}
			done := make(chan struct{})
			resolution := guardResolution(t, guardSpec())
			go func() {
				defer close(done)
				if kind == "load" {
					_ = guard.SwapPolicy(resolution)
				} else {
					_, _ = guard.Evaluate(context.Background(), &EvaluationAction{Type: "egress", Target: "api.example.com"})
				}
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("observer deadlocked")
			}
			if !observer.called {
				t.Fatal("observer did not reenter")
			}
		})
	}
}

func TestConfirmationGoexitReleasesReloadGate(t *testing.T) {
	guard := newTestGuard(t, GuardOptions{OnWarn: func(EvaluationResult, *EvaluationAction) bool { runtime.Goexit(); return false }})
	done := make(chan struct{})
	go func() {
		defer close(done)
		content := "WARNME"
		_, _ = guard.Check(context.Background(), &EvaluationAction{Type: "file_write", Target: "notes.txt", Content: &content})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("confirmation did not exit")
	}
	reloaded := make(chan error, 1)
	resolution := guardResolution(t, guardSpec())
	go func() { reloaded <- guard.SwapPolicy(resolution) }()
	select {
	case err := <-reloaded:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Goexit retained the reload gate")
	}
}

func TestReloadWaitsForConfirmationAndOldReceipt(t *testing.T) {
	sink := &orderedGuardSink{}
	entered, release, checked, swapped := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
	guard := newTestGuard(t, GuardOptions{Sink: sink, OnWarn: func(EvaluationResult, *EvaluationAction) bool {
		close(entered)
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			return false
		}
		return true
	}})
	content := "token WARNME here"
	go func() {
		defer close(checked)
		_, _ = guard.Check(context.Background(), &EvaluationAction{Type: "file_write", Target: "notes.txt", Content: &content})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("confirmation not reached")
	}
	next := guardSpec()
	nextName := "new-policy"
	next.Name = &nextName
	resolution := guardResolution(t, next)
	go func() { swapped <- guard.SwapPolicy(resolution) }()
	completedEarly := false
	select {
	case err := <-swapped:
		completedEarly = true
		if err != nil {
			t.Error(err)
		}
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-checked:
	case <-time.After(5 * time.Second):
		t.Fatal("check did not finish")
	}
	if !completedEarly {
		select {
		case err := <-swapped:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reload did not finish")
		}
	}
	if completedEarly {
		t.Error("reload passed an outstanding confirmation")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.entries) != 3 {
		t.Fatalf("missing evidence: %+v", sink.entries)
	}
	if sink.entries[1].kind != "receipt" || sink.entries[1].hash != sink.entries[0].hash || sink.entries[2].hash != resolution.ContentHash {
		t.Fatalf("policy events do not bracket receipts: %+v", sink.entries)
	}
}
