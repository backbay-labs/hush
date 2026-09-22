package hushspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Hash-linked receipt log (spec/hushspec-log.md, format 0.1).
//
// A log is a JSON Lines file of [LogEntry] records. Each entry carries a
// sequence number, the hash of the previous entry, its own hash over its
// canonical form, and optionally an Ed25519 signature over that hash. A
// verifier can therefore detect a line that was edited, deleted, inserted, or
// reordered, without any other source of truth.
//
// Entries wrap a [DecisionReceipt] or a [PolicyEvent] (which policy was loaded
// or swapped in, with its provenance) so the log proves not only what was
// decided but what was in force when.

// LogVersion is the log-entry format this file writes and verifies.
const LogVersion = "0.1"

// GenesisHash is the `prev_hash` of the first entry of a log that continues
// nothing: "sha256:" and 64 zeros.
const GenesisHash = contentHashPrefix +
	"0000000000000000000000000000000000000000000000000000000000000000"

// ReasonEntryUnsigned is reported for an unsigned entry when the verifier
// requires signatures (log spec 7).
const ReasonEntryUnsigned = "entry_unsigned"

// SDKName is the name this SDK writes into a log entry's `sdk` member.
const SDKName = "hushspec-go"

// LogLockTimeout is how long an append waits for another writer's lock before
// failing. A lock this SDK cannot acquire is an error, never something to
// bypass: two writers appending to one file interleave chains and corrupt
// both (log spec 9).
const LogLockTimeout = 5 * time.Second

// --------------------------------------------------------------------------
// Wire types
// --------------------------------------------------------------------------

// EntryType says which payload member an entry carries.
type EntryType string

const (
	EntryTypeReceipt       EntryType = "receipt"
	EntryTypePolicyLoaded  EntryType = "policy_loaded"
	EntryTypePolicySwapped EntryType = "policy_swapped"
	EntryTypeLogStarted    EntryType = "log_started"
)

// SdkInfo names the SDK that wrote an entry.
type SdkInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ThisSDK is this package's own identity.
func ThisSDK() SdkInfo {
	return SdkInfo{Name: SDKName, Version: Version}
}

// PolicyEventKind distinguishes a policy first taking effect from one
// replacing another.
type PolicyEventKind string

const (
	PolicyEventLoaded  PolicyEventKind = "loaded"
	PolicyEventSwapped PolicyEventKind = "swapped"
)

// PolicyEvent is a policy-in-effect record (log spec 6): what was enforced
// from this moment on, with the same identity a receipt carries.
//
// An enforcement point MUST write one when it starts enforcing a policy and
// when it replaces one, before any receipt evaluated under the new policy, so
// a reader can map every receipt to the exact policy in force by walking back
// to the nearest policy event.
type PolicyEvent struct {
	Event PolicyEventKind `json:"event"`
	// Timestamp is RFC 3339 UTC with millisecond precision.
	Timestamp       string          `json:"timestamp"`
	Policy          PolicySummary   `json:"policy"`
	EnforcementMode EnforcementMode `json:"enforcement_mode"`
	SDK             SdkInfo         `json:"sdk"`
	// SpecVersion is the HushSpec version the engine implements.
	SpecVersion string `json:"spec_version"`
	// PreviousContentHash is, for a swap, the content hash of the policy that
	// was replaced.
	PreviousContentHash string `json:"previous_content_hash,omitempty"`
}

// NewPolicyLoadedEvent is the `policy_loaded` record for a resolution, stamped
// now. It is the record an enforcement point writes before the first receipt
// it evaluates under that policy.
//
// A zero sdk means [ThisSDK].
func NewPolicyLoadedEvent(
	resolution *Resolution,
	enforcement EnforcementMode,
	sdk SdkInfo,
) PolicyEvent {
	if sdk.Name == "" && sdk.Version == "" {
		sdk = ThisSDK()
	}
	if enforcement == "" {
		enforcement = EnforcementModeEnforce
	}
	return PolicyEvent{
		Event:           PolicyEventLoaded,
		Timestamp:       FormatTimestamp(time.Now()),
		Policy:          NewPolicySummary(resolution),
		EnforcementMode: enforcement,
		SDK:             sdk,
		SpecVersion:     Version,
	}
}

// NewPolicySwappedEvent is the `policy_swapped` record for a policy replacing
// the one whose content hash is previousContentHash (a hot reload, or the
// panic policy taking over).
func NewPolicySwappedEvent(
	resolution *Resolution,
	enforcement EnforcementMode,
	sdk SdkInfo,
	previousContentHash string,
) PolicyEvent {
	event := NewPolicyLoadedEvent(resolution, enforcement, sdk)
	event.Event = PolicyEventSwapped
	event.PreviousContentHash = previousContentHash
	return event
}

// LogStarted is the first entry of a rotated file: where the chain came from
// (log spec 5).
type LogStarted struct {
	Timestamp    string `json:"timestamp"`
	PreviousFile string `json:"previous_file,omitempty"`
	// PreviousEntryHash is the last `entry_hash` of the previous file; it
	// equals this entry's `prev_hash`.
	PreviousEntryHash string `json:"previous_entry_hash,omitempty"`
}

// LogSignature is an entry signature: the 0.2 signature envelope (signing spec
// 4) whose `content_hash` is the entry's `entry_hash`. It is exactly an
// [Envelope] -- the same members, produced and checked the same way -- so the
// alias lets the signing code work on it unchanged.
type LogSignature = Envelope

// LogEntry is one line of a log.
type LogEntry struct {
	LogVersion string `json:"log_version"`
	// Seq starts at 1 in every file and increases by exactly 1.
	Seq uint64 `json:"seq"`
	// PrevHash is the previous entry's `entry_hash`, or [GenesisHash].
	PrevHash  string    `json:"prev_hash"`
	EntryType EntryType `json:"entry_type"`

	Receipt     *DecisionReceipt `json:"receipt,omitempty"`
	PolicyEvent *PolicyEvent     `json:"policy_event,omitempty"`
	LogStarted  *LogStarted      `json:"log_started,omitempty"`

	// EntryHash is "sha256:" over the canonical form of this entry with
	// `entry_hash` and `signature` removed.
	EntryHash string        `json:"entry_hash"`
	Signature *LogSignature `json:"signature,omitempty"`
}

// ComputeEntryHash recomputes the hash this entry should carry: "sha256:" over
// the RFC 8785 canonical form of the entry with `entry_hash` and `signature`
// removed (log spec 4).
//
// Because `prev_hash` is inside the hashed content, every entry's hash commits
// to the entire history before it.
func (e *LogEntry) ComputeEntryHash() (string, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("cannot serialize the log entry: %w", err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return "", fmt.Errorf("cannot re-read the log entry: %w", err)
	}
	delete(object, "entry_hash")
	delete(object, "signature")
	canonical, err := canonicalJSONValue(object)
	if err != nil {
		return "", fmt.Errorf("the log entry has no canonical form: %w", err)
	}
	return DigestOf(canonical), nil
}

// PayloadMatchesType reports whether exactly the payload named by `entry_type`
// is present (log spec 8, step 4).
func (e *LogEntry) PayloadMatchesType() bool {
	receipt, event, started := e.Receipt != nil, e.PolicyEvent != nil, e.LogStarted != nil
	switch e.EntryType {
	case EntryTypeReceipt:
		return receipt && !event && !started
	case EntryTypePolicyLoaded:
		return !receipt && !started && event && e.PolicyEvent.Event == PolicyEventLoaded
	case EntryTypePolicySwapped:
		return !receipt && !started && event && e.PolicyEvent.Event == PolicyEventSwapped
	case EntryTypeLogStarted:
		return started && !receipt && !event
	default:
		return false
	}
}

// LogPayload is what an entry wraps when appending: exactly one member is
// non-nil.
type LogPayload struct {
	Receipt     *DecisionReceipt
	PolicyEvent *PolicyEvent
	LogStarted  *LogStarted
}

func (p LogPayload) entryType() (EntryType, error) {
	set := 0
	entryType := EntryType("")
	if p.Receipt != nil {
		set++
		entryType = EntryTypeReceipt
	}
	if p.PolicyEvent != nil {
		set++
		switch p.PolicyEvent.Event {
		case PolicyEventSwapped:
			entryType = EntryTypePolicySwapped
		default:
			entryType = EntryTypePolicyLoaded
		}
	}
	if p.LogStarted != nil {
		set++
		entryType = EntryTypeLogStarted
	}
	if set != 1 {
		return "", fmt.Errorf("a log entry wraps exactly one payload, got %d", set)
	}
	return entryType, nil
}

// --------------------------------------------------------------------------
// Chained sink
// --------------------------------------------------------------------------

// ChainedFileSink appends hash-linked entries to a JSON Lines file, syncing
// each one to durable storage before reporting it written (log spec 3).
//
// Opening an existing file continues its chain from the last entry. Appends
// are serialized in-process by a mutex and across processes by the
// `<path>.lock` sentinel every SDK takes, under which the log file itself is
// flocked too where the platform has it (log spec 4); a lock held longer than
// [LogLockTimeout] is reported as an error rather than bypassed. Each entry's
// `seq` and `prev_hash` come from the file's current last entry, read while
// that lock is held, so a second sink or process writing the same log extends
// the chain instead of forking it.
// [ChainedFileSink.Rotate] carries the chain into a new file through a
// `log_started` entry.
type ChainedFileSink struct {
	mu       sync.Mutex
	path     string
	seq      uint64
	prevHash string
	// clock fixes `log_started` timestamps and signature `signed_at` for
	// conformance vectors; production sinks use the wall clock.
	clock     func() time.Time
	signerPEM []byte
}

// OpenChainedFileSink opens (or creates) the log at path and continues its
// chain from the last entry. A file whose last line is not a log entry is an
// error: appending to it would produce a chain nothing can verify.
func OpenChainedFileSink(path string) (*ChainedFileSink, error) {
	sink := &ChainedFileSink{path: path, prevHash: GenesisHash}
	last, err := lastLogEntry(path)
	if err != nil {
		return nil, err
	}
	if last != nil {
		sink.seq, sink.prevHash = last.Seq, last.EntryHash
	}
	return sink, nil
}

// WithSigner signs every appended entry with an Ed25519 private key in PEM
// PKCS#8 form (signing spec 4, over `entry_hash`). It returns the sink so it
// can be chained onto [OpenChainedFileSink].
func (s *ChainedFileSink) WithSigner(privateKeyPEM []byte) *ChainedFileSink {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signerPEM = privateKeyPEM
	return s
}

// WithClock uses a fixed clock for `log_started` timestamps and entry
// signatures, so a conformance vector is byte-stable. Nil restores the wall
// clock.
func (s *ChainedFileSink) WithClock(clock func() time.Time) *ChainedFileSink {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = clock
	return s
}

// Path is the file currently being written.
func (s *ChainedFileSink) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// Head is the last sequence number and entry hash written, or 0 and
// [GenesisHash] for an empty log. Writers SHOULD publish the head hash
// periodically: it is the external anchor that makes truncation detectable
// (log spec 9).
func (s *ChainedFileSink) Head() (uint64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq, s.prevHash
}

func (s *ChainedFileSink) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// Append writes one entry, linked to the previous one, and returns it.
//
// The chain head is re-read from the file under the write lock, so an entry
// continues what the file holds rather than what this sink last wrote. A tail
// that cannot be parsed fails the append: continuing past it would leave a
// second, unlinked chain in the file.
func (s *ChainedFileSink) Append(payload LogPayload) (*LogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.appendTo(s.path, s.seq, s.prevHash, payload)
	if err != nil {
		return nil, err
	}
	s.seq, s.prevHash = entry.Seq, entry.EntryHash
	return entry, nil
}

// appendTo writes one entry to path, continuing from cachedSeq and
// cachedPrevHash when the file holds no entry of its own, and returns it
// without touching the chain head.
//
// The caller commits the head, so an append that fails leaves the sink
// describing the file it was describing before.
func (s *ChainedFileSink) appendTo(
	path string, cachedSeq uint64, cachedPrevHash string, payload LogPayload,
) (*LogEntry, error) {
	entryType, err := payload.entryType()
	if err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}

	// The lock file lives next to the log, so the directory has to exist for
	// the lock itself to be creatable.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("log: cannot create %s: %w", dir, err)
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("log: cannot open %s: %w", path, err)
	}
	defer file.Close()

	unlock, err := lockLogFile(file, path)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// A missing or empty file means a fresh log, or a rotation whose
	// `log_started` entry is about to seed the new file; both continue from
	// the head this sink carries.
	seq, prevHash := cachedSeq, cachedPrevHash
	head, err := lastLogEntryIn(file, path)
	if err != nil {
		return nil, err
	}
	if head != nil {
		seq, prevHash = head.Seq, head.EntryHash
	}

	entry := &LogEntry{
		LogVersion:  LogVersion,
		Seq:         seq + 1,
		PrevHash:    prevHash,
		EntryType:   entryType,
		Receipt:     payload.Receipt,
		PolicyEvent: payload.PolicyEvent,
		LogStarted:  payload.LogStarted,
	}
	entry.EntryHash, err = entry.ComputeEntryHash()
	if err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}
	// Signing belongs under the lock too: the signature covers `entry_hash`,
	// which depends on the `prev_hash` just read.
	if len(s.signerPEM) > 0 {
		signedAt := s.now()
		envelope, err := SignContentHash(entry.EntryHash, s.signerPEM, SignOptions{SignedAt: &signedAt})
		if err != nil {
			return nil, fmt.Errorf("log: cannot sign entry %d: %w", entry.Seq, err)
		}
		entry.Signature = envelope
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("log: cannot serialize entry %d: %w", entry.Seq, err)
	}
	if err := writeLine(file, path, append(line, '\n')); err != nil {
		return nil, err
	}
	return entry, nil
}

// Send appends a decision receipt, satisfying [ReceiptSink].
func (s *ChainedFileSink) Send(receipt *DecisionReceipt) error {
	_, err := s.Append(LogPayload{Receipt: receipt})
	return err
}

// RecordPolicyEvent appends a policy-in-effect record, satisfying
// [PolicyEventSink].
func (s *ChainedFileSink) RecordPolicyEvent(event *PolicyEvent) error {
	_, err := s.Append(LogPayload{PolicyEvent: event})
	return err
}

// Rotate starts writing to newPath, whose first entry is a `log_started`
// record naming the file this chain continues from and its last hash
// (log spec 5). Sequence numbers restart at 1 in the new file; `prev_hash`
// carries over, so a verifier given both files in order sees one chain.
//
// The new file must not already exist. The switch is committed only once that
// entry is on disk: a rotation that cannot write it leaves the sink on the old
// file, still linked and still verifiable, rather than on a new one whose
// first receipt would continue nothing.
func (s *ChainedFileSink) Rotate(newPath string) (*LogEntry, error) {
	if _, err := os.Stat(newPath); err == nil {
		return nil, fmt.Errorf("log: cannot rotate into the existing file %s", newPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("log: cannot rotate into %s: %w", newPath, err)
	}

	// The switch and the `log_started` entry happen under one lock: a
	// concurrent Send must not slip a receipt into the new file ahead of the
	// record that links it to the old one (log spec 5).
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only the file name: logs are moved between hosts, and a path would leak
	// the writer's layout for no verification benefit.
	previousFile := filepath.Base(s.path)
	previousHash := s.prevHash
	// The link is always recorded, the genesis value included (log spec 5): a
	// verifier given both files compares it against the previous file's last
	// hash, and an omitted member is not that hash.
	started := &LogStarted{
		Timestamp:         FormatTimestamp(s.now()),
		PreviousFile:      previousFile,
		PreviousEntryHash: previousHash,
	}

	entry, err := s.appendTo(newPath, 0, previousHash, LogPayload{LogStarted: started})
	if err != nil {
		return nil, err
	}
	s.path = newPath
	s.seq, s.prevHash = entry.Seq, entry.EntryHash
	return entry, nil
}

// lastLogEntry reads the last non-empty line of path as an entry, or nil for a
// missing or empty file.
func lastLogEntry(path string) (*LogEntry, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("log: cannot open %s: %w", path, err)
	}
	defer file.Close()
	return lastLogEntryIn(file, path)
}

// lastLogEntryIn reads the last non-empty line of an already open log as an
// entry, or nil for an empty file.
func lastLogEntryIn(file *os.File, path string) (*LogEntry, error) {
	last, err := lastLogLine(file, path)
	if err != nil || last == nil {
		return nil, err
	}
	var entry LogEntry
	if err := strictUnmarshalJSON(last, &entry); err != nil {
		return nil, fmt.Errorf("log: the last line of %s is not a log entry: %w", path, err)
	}
	// Reading the head loosely would seed the chain from a malformed tail. A
	// sequence number starts at 1 and an entry hash is never empty, so the zero
	// values mean the member was absent -- and continuing from them would make
	// the next entry start a second, unlinked chain inside the file.
	if entry.Seq == 0 {
		return nil, fmt.Errorf("log: the last line of %s has no seq", path)
	}
	if entry.EntryHash == "" {
		return nil, fmt.Errorf("log: the last line of %s has no entry_hash", path)
	}
	return &entry, nil
}

// maxLogLineBytes caps one JSON Lines record. A receipt is a few kilobytes; a
// megabyte is generous and keeps a corrupt file from exhausting memory.
const maxLogLineBytes = 1 << 20

// tailChunkBytes is how much of the tail to read at a time when looking for
// the last line.
const tailChunkBytes = 8 * 1024

// lastLogLine is the last non-empty line of file, read by seeking back from
// the end. Every append reads the head this way, so the cost has to be the
// size of one entry rather than the size of the log.
func lastLogLine(file *os.File, path string) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("log: cannot read %s: %w", path, err)
	}
	end := info.Size()
	var tail []byte
	for end > 0 {
		// Checked before the next chunk is read, so a file with no newline in
		// it is never pulled into memory whole. The line itself is checked
		// again below: the last chunk can carry it past the cap.
		if len(tail) > maxLogLineBytes {
			return nil, fmt.Errorf(
				"log: the last line of %s is longer than %d bytes", path, maxLogLineBytes)
		}
		start := end - tailChunkBytes
		if start < 0 {
			start = 0
		}
		chunk := make([]byte, end-start)
		if _, err := file.ReadAt(chunk, start); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("log: cannot read %s: %w", path, err)
		}
		tail = append(chunk, tail...)
		end = start
		if line, ok := lastLineOf(tail, end == 0); ok {
			if len(line) > maxLogLineBytes {
				return nil, fmt.Errorf(
					"log: the last line of %s is longer than %d bytes", path, maxLogLineBytes)
			}
			return line, nil
		}
	}
	return nil, nil
}

// lastLineOf is the last non-empty line inside buffer, or ok false when it may
// still begin earlier in the file. atStart says buffer reaches the file's
// first byte, so a line with no newline before it is already complete.
func lastLineOf(buffer []byte, atStart bool) ([]byte, bool) {
	trimmed := bytes.TrimRight(buffer, " \t\n\v\f\r")
	if len(trimmed) == 0 {
		return nil, false
	}
	newline := bytes.LastIndexByte(trimmed, '\n')
	if newline < 0 && !atStart {
		return nil, false
	}
	return trimmed[newline+1:], true
}

// writeLine writes one whole line to an already locked log and fsyncs it
// before returning (log spec 3).
func writeLine(file *os.File, path string, line []byte) error {
	if _, err := file.Write(line); err != nil {
		return fmt.Errorf("log: cannot write to %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("log: cannot flush %s: %w", path, err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Verification (log spec 8)
// --------------------------------------------------------------------------

// LogVerifyOptions is what a verifier trusts and demands.
type LogVerifyOptions struct {
	// RequireSignatures makes an unsigned entry a break
	// ([ReasonEntryUnsigned]), and a signed entry that cannot be checked
	// because no keyring was supplied a break too.
	RequireSignatures bool
	// Keyring is the set of keys entry signatures are verified against. Nil
	// counts signed entries without checking them, which is an error only
	// under RequireSignatures.
	Keyring *Keyring
	// Verify carries the remaining verifier inputs: Now and
	// MaxClockSkewSeconds (signing spec 6.1).
	Verify VerifyOptions
}

// LogVerifyReport summarizes a verified log.
type LogVerifyReport struct {
	Files              int    `json:"files"`
	Entries            int    `json:"entries"`
	Receipts           int    `json:"receipts"`
	PolicyEvents       int    `json:"policy_events"`
	Signed             int    `json:"signed"`
	VerifiedSignatures int    `json:"verified_signatures"`
	LastSeq            uint64 `json:"last_seq"`
	LastEntryHash      string `json:"last_entry_hash"`
}

// LogError says why a log did not verify. File and Line locate the first
// break; Line is 0 for a whole-file condition.
type LogError struct {
	File    string
	Line    int
	Message string
}

func (e *LogError) Error() string {
	return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Message)
}

// LogFile is one named log text, for verifying a rotation in order without
// touching the filesystem.
type LogFile struct {
	Name string
	Text string
}

// VerifyLog verifies one log file's text.
func VerifyLog(name, text string, options *LogVerifyOptions) (*LogVerifyReport, error) {
	return VerifyLogs([]LogFile{{Name: name, Text: text}}, options)
}

// VerifyLogFiles verifies the log files at paths, in order.
func VerifyLogFiles(paths []string, options *LogVerifyOptions) (*LogVerifyReport, error) {
	files := make([]LogFile, 0, len(paths))
	for _, path := range paths {
		text, err := os.ReadFile(path)
		if err != nil {
			return nil, &LogError{File: path, Line: 0, Message: "cannot read: " + err.Error()}
		}
		files = append(files, LogFile{Name: path, Text: string(text)})
	}
	return VerifyLogs(files, options)
}

// VerifyLogs verifies a sequence of rotated log files in order: each file
// after the first must start with a `log_started` entry whose
// `previous_entry_hash` is the previous file's last hash (log spec 5).
//
// It runs the ordered checks of log spec 8 and stops at the first failure,
// returning a [LogError] that names the file and line of the break.
func VerifyLogs(files []LogFile, options *LogVerifyOptions) (*LogVerifyReport, error) {
	effective := LogVerifyOptions{}
	if options != nil {
		effective = *options
	}
	report := &LogVerifyReport{LastEntryHash: GenesisHash}
	carriedHash := ""
	haveCarried := false

	for index, file := range files {
		report.Files++
		expectedSeq := uint64(1)
		prevHash := GenesisHash
		if haveCarried {
			prevHash = carriedHash
		}
		sawEntry := false

		for lineIndex, line := range strings.Split(file.Text, "\n") {
			lineNo := lineIndex + 1
			if strings.TrimSpace(line) == "" {
				continue
			}
			fail := func(format string, args ...any) *LogError {
				return &LogError{
					File:    file.Name,
					Line:    lineNo,
					Message: fmt.Sprintf(format, args...),
				}
			}

			// 1. Parse; unknown fields are a break.
			var entry LogEntry
			if err := strictUnmarshalJSON([]byte(line), &entry); err != nil {
				return nil, fail("not a log entry: %s", err)
			}
			// 2. Format version.
			if entry.LogVersion != LogVersion {
				return nil, fail(
					"unsupported log_version %q, expected %q", entry.LogVersion, LogVersion)
			}
			// 3. Sequence.
			if entry.Seq != expectedSeq {
				return nil, fail("sequence gap: expected seq %d, found %d", expectedSeq, entry.Seq)
			}
			// 4. Exactly the payload the entry type names.
			if !entry.PayloadMatchesType() {
				return nil, fail("payload does not match entry_type %q", entry.EntryType)
			}
			// 5. A continued file links to the previous file's last hash.
			if expectedSeq == 1 && index > 0 {
				if entry.LogStarted == nil {
					return nil, fail("a continued file must start with a log_started entry")
				}
				if entry.LogStarted.PreviousEntryHash != carriedHash {
					return nil, fail(
						"log_started.previous_entry_hash does not match the previous file's last hash")
				}
			}
			// The first file of a set may itself continue an earlier file the
			// verifier was not given; its prev_hash must then be that file's
			// last hash, which it carries in log_started.
			if expectedSeq == 1 && index == 0 && entry.LogStarted != nil &&
				entry.LogStarted.PreviousEntryHash != "" {
				prevHash = entry.LogStarted.PreviousEntryHash
			}
			// 6. The link itself.
			if entry.PrevHash != prevHash {
				return nil, fail(
					"prev_hash %s does not link to the previous entry %s", entry.PrevHash, prevHash)
			}
			// 7. The entry's own hash, over the line as written: hashing a
			// re-serialization of the typed entry would cover the members
			// this SDK materializes rather than the ones the file holds, and
			// would report a payload it cannot model exactly as a hash
			// mismatch instead of letting the check that names it run.
			object, err := entryObjectOfLine(line)
			if err != nil {
				return nil, fail("cannot canonicalize entry: %s", err)
			}
			receiptDocument := object["receipt"]
			recomputed, err := entryHashOfObject(object)
			if err != nil {
				return nil, fail("cannot canonicalize entry: %s", err)
			}
			if recomputed != entry.EntryHash {
				return nil, fail(
					"entry_hash %s does not match the entry's canonical form (%s)",
					entry.EntryHash, recomputed)
			}
			// 8. A receipt payload is a format 0.2 receipt. The entry hash
			// covers whatever JSON the line held, so a hash-consistent line
			// can still carry something that is not a receipt; the payload
			// has to validate, not merely name the version.
			if entry.Receipt != nil {
				if entry.Receipt.ReceiptVersion != ReceiptVersion {
					return nil, fail("receipt_version %q is not %q",
						entry.Receipt.ReceiptVersion, ReceiptVersion)
				}
				problems := documentProblems(receiptDocument, entry.Receipt)
				if len(problems) > 0 {
					return nil, fail(
						"receipt does not validate against the 0.2 receipt schema: %s",
						strings.Join(problems, "; "))
				}
				report.Receipts++
			}
			if entry.PolicyEvent != nil {
				report.PolicyEvents++
			}
			// 9. The entry signature, when there is one.
			if err := verifyEntrySignature(&entry, &effective, report, fail); err != nil {
				return nil, err
			}

			prevHash = entry.EntryHash
			expectedSeq++
			sawEntry = true
			report.Entries++
			report.LastSeq = entry.Seq
			report.LastEntryHash = entry.EntryHash
		}

		if !sawEntry && index > 0 {
			return nil, &LogError{File: file.Name, Line: 0, Message: "continued file is empty"}
		}
		carriedHash, haveCarried = prevHash, true
	}
	return report, nil
}

// entryObjectOfLine reads one JSON Lines record as the object the line holds,
// which is what both the entry hash and the receipt payload check read: the
// typed entry cannot answer for members it does not model.
func entryObjectOfLine(line string) (map[string]any, error) {
	var object map[string]any
	if err := json.Unmarshal([]byte(line), &object); err != nil {
		return nil, fmt.Errorf("cannot re-read the log entry: %w", err)
	}
	return object, nil
}

// entryHashOfObject is the `entry_hash` one record should carry: "sha256:"
// over the RFC 8785 canonical form of the object with `entry_hash` and
// `signature` removed (log spec 4).
func entryHashOfObject(object map[string]any) (string, error) {
	hashed := make(map[string]any, len(object))
	for key, value := range object {
		if key == "entry_hash" || key == "signature" {
			continue
		}
		hashed[key] = value
	}
	canonical, err := canonicalJSONValue(hashed)
	if err != nil {
		return "", fmt.Errorf("the log entry has no canonical form: %w", err)
	}
	return DigestOf(canonical), nil
}

// verifyEntrySignature runs log spec 8 step 9 for one entry.
func verifyEntrySignature(
	entry *LogEntry,
	options *LogVerifyOptions,
	report *LogVerifyReport,
	fail func(string, ...any) *LogError,
) error {
	if entry.Signature == nil {
		if options.RequireSignatures {
			return fail("%s: signatures are required", ReasonEntryUnsigned)
		}
		return nil
	}
	report.Signed++
	if entry.Signature.ContentHash != entry.EntryHash {
		return fail("signature.content_hash does not name this entry's entry_hash")
	}
	if options.Keyring == nil {
		if options.RequireSignatures {
			return fail("no_keyring: cannot verify a required signature")
		}
		return nil
	}
	verify := options.Verify
	verify.Keyring = options.Keyring
	result := VerifyContentHash(entry.Signature, entry.EntryHash, verify)
	if !result.OK {
		return fail("signature: %s: %s", result.Reason, result.Detail)
	}
	report.VerifiedSignatures++
	return nil
}
