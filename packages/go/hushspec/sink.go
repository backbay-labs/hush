package hushspec

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReceiptSink persists or forwards decision receipts.
type ReceiptSink interface {
	Send(receipt *DecisionReceipt) error
}

// PolicyEventSink is a sink that can also record which policy is in force
// (log spec 6).
//
// It is a separate, optional interface rather than a second method on
// [ReceiptSink] so that every sink written against the 0.1 API keeps
// compiling; [RecordPolicyEvent] routes an event to a sink that implements it
// and drops it for one that does not.
type PolicyEventSink interface {
	ReceiptSink
	RecordPolicyEvent(event *PolicyEvent) error
}

// RecordPolicyEvent writes a policy-in-effect record to sink when it can carry
// one, and reports whether it did. A plain [ReceiptSink] -- stderr, a filter,
// a callback over receipts -- has nowhere to put the event and is not an
// error: only a hash-linked log needs the record to tie receipts to the policy
// that produced them.
func RecordPolicyEvent(sink ReceiptSink, event *PolicyEvent) (bool, error) {
	target, ok := sink.(PolicyEventSink)
	if !ok {
		return false, nil
	}
	return true, target.RecordPolicyEvent(event)
}

// FileReceiptSink appends receipts as JSON Lines to a file.
type FileReceiptSink struct {
	path string
}

func NewFileReceiptSink(path string) *FileReceiptSink {
	return &FileReceiptSink{path: path}
}

func (s *FileReceiptSink) Send(receipt *DecisionReceipt) error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("sink: open file: %w", err)
	}
	defer f.Close()

	data, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("sink: marshal receipt: %w", err)
	}

	_, err = fmt.Fprintf(f, "%s\n", data)
	if err != nil {
		return fmt.Errorf("sink: write receipt: %w", err)
	}

	return nil
}

// StderrReceiptSink writes pretty-printed receipts to stderr.
type StderrReceiptSink struct{}

func (s *StderrReceiptSink) Send(receipt *DecisionReceipt) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("sink: marshal receipt: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[hushspec] %s\n", data)
	return nil
}

// FilteredSink only forwards receipts matching the configured decisions.
type FilteredSink struct {
	inner     ReceiptSink
	decisions []Decision
}

func NewFilteredSink(sink ReceiptSink, decisions []Decision) *FilteredSink {
	return &FilteredSink{
		inner:     sink,
		decisions: decisions,
	}
}

func NewDenyOnlySink(sink ReceiptSink) *FilteredSink {
	return NewFilteredSink(sink, []Decision{DecisionDeny})
}

func (s *FilteredSink) Send(receipt *DecisionReceipt) error {
	for _, d := range s.decisions {
		if receipt.Decision == d {
			return s.inner.Send(receipt)
		}
	}
	return nil
}

// RecordPolicyEvent forwards the event whatever the filter is: the filter
// selects which *decisions* are worth keeping, and a policy event is what ties
// the kept receipts to the policy that produced them.
func (s *FilteredSink) RecordPolicyEvent(event *PolicyEvent) error {
	_, err := RecordPolicyEvent(s.inner, event)
	return err
}

// MultiSink fans out to all sinks. Returns the first error but always
// attempts every sink.
type MultiSink struct {
	sinks []ReceiptSink
}

func NewMultiSink(sinks []ReceiptSink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (s *MultiSink) Send(receipt *DecisionReceipt) error {
	var firstErr error
	for _, sink := range s.sinks {
		if err := sink.Send(receipt); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// RecordPolicyEvent fans the event out to every sink that can carry one,
// returning the first error but always attempting each sink.
func (s *MultiSink) RecordPolicyEvent(event *PolicyEvent) error {
	var firstErr error
	for _, sink := range s.sinks {
		if _, err := RecordPolicyEvent(sink, event); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// CallbackSink invokes a function for each receipt.
type CallbackSink struct {
	callback func(*DecisionReceipt) error
}

func NewCallbackSink(callback func(*DecisionReceipt) error) *CallbackSink {
	return &CallbackSink{callback: callback}
}

func (s *CallbackSink) Send(receipt *DecisionReceipt) error {
	return s.callback(receipt)
}

// NullSink discards all receipts.
type NullSink struct{}

func (s *NullSink) Send(receipt *DecisionReceipt) error {
	return nil
}

// RecordPolicyEvent discards the event, like everything else a NullSink is
// handed.
func (s *NullSink) RecordPolicyEvent(event *PolicyEvent) error {
	return nil
}
