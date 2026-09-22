package hushspec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Hash-linked log (spec/hushspec-log.md): the chained sink, rotation, signing,
// verification, and the normative vectors under fixtures/log.
//
// The vectors are recorded under the fixed inputs of
// fixtures/receipts/expected/README.md, so this SDK both verifies them and
// reproduces their entry hashes from the same inputs -- which is the byte-level
// check, the entry hash being the hash of the entry's canonical form.

func logFixtureDir(t *testing.T, kind string) string {
	t.Helper()
	return filepath.Join(fixtureRepoRoot(t), "fixtures", "log", kind)
}

func logFixtureFiles(t *testing.T, kind string) []string {
	t.Helper()
	dir := logFixtureDir(t, kind)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".jsonl") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	if len(files) == 0 {
		t.Fatalf("no log vectors found in %s", dir)
	}
	return files
}

// logVectorClock is the instant every log vector was written under.
func logVectorClock(t *testing.T) time.Time {
	t.Helper()
	return time.UnixMilli(expectedReceiptClockMillis).UTC()
}

// --------------------------------------------------------------------------
// Vectors
// --------------------------------------------------------------------------

func TestValidLogVectorsVerify(t *testing.T) {
	dir := logFixtureDir(t, "valid")
	keyring := testKeyring(t)
	verify := VerifyOptions{Keyring: keyring, Now: logVectorClock(t)}

	t.Run("basic", func(t *testing.T) {
		// The unsigned chain verifies with no key material at all.
		report, err := VerifyLogFiles([]string{filepath.Join(dir, "basic.jsonl")}, nil)
		if err != nil {
			t.Fatalf("basic.jsonl must verify: %v", err)
		}
		if report.Entries != 4 || report.Receipts != 3 || report.PolicyEvents != 1 {
			t.Errorf("unexpected report: %+v", report)
		}
		if report.Signed != 0 {
			t.Errorf("basic.jsonl carries no signatures, got %d", report.Signed)
		}
	})

	t.Run("signed", func(t *testing.T) {
		options := &LogVerifyOptions{
			RequireSignatures: true,
			Keyring:           keyring,
			Verify:            verify,
		}
		report, err := VerifyLogFiles([]string{filepath.Join(dir, "signed.jsonl")}, options)
		if err != nil {
			t.Fatalf("signed.jsonl must verify: %v", err)
		}
		if report.Signed != 4 || report.VerifiedSignatures != 4 {
			t.Errorf("expected four verified signatures, got %+v", report)
		}
	})

	t.Run("rotation_in_order", func(t *testing.T) {
		paths := []string{
			filepath.Join(dir, "rotated-1.jsonl"),
			filepath.Join(dir, "rotated-2.jsonl"),
		}
		report, err := VerifyLogFiles(paths, nil)
		if err != nil {
			t.Fatalf("a rotation must verify as one chain: %v", err)
		}
		if report.Files != 2 {
			t.Errorf("expected two files, got %d", report.Files)
		}
		if report.Entries != 6 {
			t.Errorf("expected six entries across the rotation, got %d", report.Entries)
		}
	})

	t.Run("rotation_second_file_alone", func(t *testing.T) {
		// A verifier given only the later file accepts the chain from
		// log_started.previous_entry_hash onward; it cannot vouch for what
		// came before (log spec 5).
		_, err := VerifyLogFiles([]string{filepath.Join(dir, "rotated-2.jsonl")}, nil)
		if err != nil {
			t.Fatalf("rotated-2.jsonl must verify alone: %v", err)
		}
	})

	t.Run("rotation_out_of_order_is_a_break", func(t *testing.T) {
		paths := []string{
			filepath.Join(dir, "rotated-2.jsonl"),
			filepath.Join(dir, "rotated-1.jsonl"),
		}
		if _, err := VerifyLogFiles(paths, nil); err == nil {
			t.Fatal("a rotation verified out of order must be rejected")
		}
	})
}

// TestInvalidLogVectorsAreRejectedAtTheNamedLine locks in the README's
// contract: each file name ends with the line a verifier must identify as the
// first break.
func TestInvalidLogVectorsAreRejectedAtTheNamedLine(t *testing.T) {
	files := logFixtureFiles(t, "invalid")
	// bad-signature needs the keyring; the others break without one.
	needsKeyring := map[string]bool{"bad-signature-line-4.jsonl": true}

	for _, path := range files {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			wantLine := lineFromVectorName(t, name)
			var options *LogVerifyOptions
			if needsKeyring[name] {
				options = &LogVerifyOptions{
					Keyring: testKeyring(t),
					Verify:  VerifyOptions{Keyring: testKeyring(t), Now: logVectorClock(t)},
				}
			}
			_, err := VerifyLogFiles([]string{path}, options)
			if err == nil {
				t.Fatal("an invalid log must be rejected")
			}
			logErr, ok := err.(*LogError)
			if !ok {
				t.Fatalf("expected a *LogError, got %T: %v", err, err)
			}
			if logErr.Line != wantLine {
				t.Errorf("expected the break at line %d, got line %d: %s",
					wantLine, logErr.Line, logErr.Message)
			}
		})
	}
	t.Logf("rejected %d invalid log vectors", len(files))
}

// lineFromVectorName reads the trailing "-line-N" of an invalid vector's name.
func lineFromVectorName(t *testing.T, name string) int {
	t.Helper()
	stem := strings.TrimSuffix(name, ".jsonl")
	index := strings.LastIndex(stem, "-line-")
	if index < 0 {
		t.Fatalf("the vector name %q does not end with -line-N", name)
	}
	line := 0
	for _, digit := range stem[index+len("-line-"):] {
		if digit < '0' || digit > '9' {
			t.Fatalf("the vector name %q does not end with -line-N", name)
		}
		line = line*10 + int(digit-'0')
	}
	return line
}

// --------------------------------------------------------------------------
// The chained sink reproduces the vectors
// --------------------------------------------------------------------------

// vectorResolution is the policy the log vectors were written under: the
// `default` builtin, already resolved, recorded under its builtin source.
func vectorResolution(t *testing.T) *Resolution {
	t.Helper()
	spec, err := LoadBuiltin("builtin:default")
	if err != nil {
		t.Fatalf("the default builtin is missing: %v", err)
	}
	resolution, err := NewResolutionFromResolved(spec, "builtin:default")
	if err != nil {
		t.Fatalf("cannot resolve the default builtin: %v", err)
	}
	return resolution
}

// vectorPolicyEvent is the `policy_loaded` record the vectors carry. The SDK
// name is the conformance harness's, not this package's, because the vectors
// must be identical in every SDK.
func vectorPolicyEvent(t *testing.T, resolution *Resolution) *PolicyEvent {
	t.Helper()
	return &PolicyEvent{
		Event:           PolicyEventLoaded,
		Timestamp:       "2026-09-15T12:00:00.000Z",
		Policy:          NewPolicySummary(resolution),
		EnforcementMode: EnforcementModeEnforce,
		SDK:             SdkInfo{Name: "hushspec-conformance", Version: "0.2"},
		SpecVersion:     "0.2.0",
	}
}

// vectorActions are the three actions the vectors evaluate, in order.
func vectorActions() []*EvaluationAction {
	return []*EvaluationAction{
		{Type: "tool_call", Target: "read_file"},
		{Type: "egress", Target: "api.github.com"},
		{Type: "file_read", Target: "/home/me/.ssh/id_rsa"},
	}
}

// writeVectorChain writes the policy_loaded entry plus the three receipts the
// vectors carry, under the fixed inputs.
func writeVectorChain(t *testing.T, path string, signed bool) *ChainedFileSink {
	t.Helper()
	clock := logVectorClock(t)
	sink, err := OpenChainedFileSink(path)
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	sink.WithClock(func() time.Time { return clock })
	if signed {
		sink.WithSigner(testSigningKeyPEM(t))
	}

	resolution := vectorResolution(t)
	if err := sink.RecordPolicyEvent(vectorPolicyEvent(t, resolution)); err != nil {
		t.Fatalf("cannot record the policy event: %v", err)
	}
	for index, action := range vectorActions() {
		receipt, err := EvaluateAudited(resolution, action, expectedReceiptConfig(),
			expectedReceiptContext(index))
		if err != nil {
			t.Fatalf("audited: %v", err)
		}
		if err := sink.Send(&receipt); err != nil {
			t.Fatalf("cannot append receipt %d: %v", index, err)
		}
	}
	return sink
}

// entryHashes reads the entry_hash of every line of a log file.
func entryHashes(t *testing.T, path string) []string {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var hashes []string
	for _, line := range strings.Split(string(text), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry LogEntry
		if err := strictUnmarshalJSON([]byte(line), &entry); err != nil {
			t.Fatalf("%s: not a log entry: %v", path, err)
		}
		hashes = append(hashes, entry.EntryHash)
	}
	return hashes
}

// TestChainedSinkReproducesTheVectorHashes is the cross-SDK byte check: an
// entry hash is the hash of the entry's RFC 8785 canonical form, so producing
// the vectors' hashes from the same inputs proves this SDK canonicalizes
// receipts, policy events and entries exactly as the reference does.
func TestChainedSinkReproducesTheVectorHashes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	sink := writeVectorChain(t, path, false)

	seq, head := sink.Head()
	if seq != 4 {
		t.Errorf("expected four entries, got seq %d", seq)
	}

	got := entryHashes(t, path)
	want := entryHashes(t, filepath.Join(logFixtureDir(t, "valid"), "basic.jsonl"))
	if len(got) != len(want) {
		t.Fatalf("expected %d entries, wrote %d", len(want), len(got))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("entry %d: expected hash %s, got %s", index+1, want[index], got[index])
		}
	}
	if head != want[len(want)-1] {
		t.Errorf("Head() must be the last entry hash, got %s", head)
	}

	if _, err := VerifyLogFiles([]string{path}, nil); err != nil {
		t.Fatalf("the log this SDK wrote must verify: %v", err)
	}
}

// TestChainedSinkSignsEveryEntry pins that a signing sink reproduces the
// signed vector too: Ed25519 is deterministic and the signing input is
// canonical, so the signatures are byte-identical as well.
func TestChainedSinkSignsEveryEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signed.jsonl")
	writeVectorChain(t, path, true)

	got := entryHashes(t, path)
	want := entryHashes(t, filepath.Join(logFixtureDir(t, "valid"), "signed.jsonl"))
	for index := range want {
		if index >= len(got) || got[index] != want[index] {
			t.Fatalf("entry %d does not match the signed vector", index+1)
		}
	}

	options := &LogVerifyOptions{
		RequireSignatures: true,
		Keyring:           testKeyring(t),
		Verify:            VerifyOptions{Keyring: testKeyring(t), Now: logVectorClock(t)},
	}
	report, err := VerifyLogFiles([]string{path}, options)
	if err != nil {
		t.Fatalf("a signed log must verify: %v", err)
	}
	if report.VerifiedSignatures != 4 {
		t.Errorf("expected four verified signatures, got %d", report.VerifiedSignatures)
	}
}

// TestRotationCarriesTheChain pins log spec 5: the new file restarts at seq 1
// with a log_started entry that names the previous file and its last hash, so
// a verifier given both sees one unbroken chain.
func TestRotationCarriesTheChain(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "rotated-1.jsonl")
	second := filepath.Join(dir, "rotated-2.jsonl")

	sink := writeVectorChain(t, first, false)
	_, headBefore := sink.Head()

	started, err := sink.Rotate(second)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if started.Seq != 1 {
		t.Errorf("a rotated file restarts at seq 1, got %d", started.Seq)
	}
	if started.PrevHash != headBefore {
		t.Errorf("prev_hash must carry over: expected %s, got %s", headBefore, started.PrevHash)
	}
	if started.LogStarted == nil || started.LogStarted.PreviousEntryHash == nil ||
		*started.LogStarted.PreviousEntryHash != headBefore {
		t.Errorf("log_started must repeat the previous hash, got %+v", started.LogStarted)
	}
	// Only the file name: a path would leak the writer's layout for no
	// verification benefit.
	if started.LogStarted.PreviousFile != "rotated-1.jsonl" {
		t.Errorf("expected the previous file name, got %q", started.LogStarted.PreviousFile)
	}
	if sink.Path() != second {
		t.Errorf("the sink must now write to the new file, got %q", sink.Path())
	}

	// Compare against the committed rotation vectors, which were produced the
	// same way.
	wantFirst := entryHashes(t, filepath.Join(logFixtureDir(t, "valid"), "rotated-1.jsonl"))
	if got := entryHashes(t, first); len(got) != len(wantFirst) || got[0] != wantFirst[0] {
		t.Errorf("rotated-1 does not match the vector")
	}
	wantSecond := entryHashes(t, filepath.Join(logFixtureDir(t, "valid"), "rotated-2.jsonl"))
	if got := entryHashes(t, second); got[0] != wantSecond[0] {
		t.Errorf("the log_started entry does not match the vector: %s vs %s", got[0], wantSecond[0])
	}

	if _, err := VerifyLogFiles([]string{first, second}, nil); err != nil {
		t.Fatalf("the rotation this SDK wrote must verify: %v", err)
	}
}

// TestRotationLinksTheLastEntryOnDisk covers a writer whose cached head is
// stale because another sink extended the file: the link it records is the
// file's last hash as it is on disk, not the one this writer last wrote.
func TestRotationLinksTheLastEntryOnDisk(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "log-1.jsonl")
	second := filepath.Join(dir, "log-2.jsonl")
	clock := logVectorClock(t)
	rotating, err := OpenChainedFileSink(first)
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	other, err := OpenChainedFileSink(first)
	if err != nil {
		t.Fatalf("cannot open the log twice: %v", err)
	}
	rotating.WithClock(func() time.Time { return clock })
	other.WithClock(func() time.Time { return clock })

	resolution := vectorResolution(t)
	if err := rotating.RecordPolicyEvent(vectorPolicyEvent(t, resolution)); err != nil {
		t.Fatalf("cannot record the policy event: %v", err)
	}
	receipt, err := EvaluateAudited(resolution, vectorActions()[0], expectedReceiptConfig(),
		expectedReceiptContext(1))
	if err != nil {
		t.Fatalf("audited: %v", err)
	}
	if err := other.Send(&receipt); err != nil {
		t.Fatalf("cannot append the other writer's receipt: %v", err)
	}
	_, onDisk := other.Head()
	if _, cached := rotating.Head(); cached == onDisk {
		t.Fatalf("the rotating sink's head must be stale for this test")
	}

	started, err := rotating.Rotate(second)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if started.PrevHash != onDisk {
		t.Errorf("prev_hash must be the last hash on disk %s, got %s", onDisk, started.PrevHash)
	}
	if started.LogStarted == nil || started.LogStarted.PreviousEntryHash == nil ||
		*started.LogStarted.PreviousEntryHash != onDisk {
		t.Errorf("log_started must name the last hash on disk, got %+v", started.LogStarted)
	}
	report, err := VerifyLogFiles([]string{first, second}, nil)
	if err != nil {
		t.Fatalf("the rotation must verify: %v", err)
	}
	if report.Entries != 3 {
		t.Errorf("expected three entries across both files, got %d", report.Entries)
	}
}

// TestRotateAtGenesisVerifies covers a writer that rotates before it has
// written anything: the link it records is the genesis hash, and a verifier
// given both files has to see one chain.
func TestRotateAtGenesisVerifies(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "log-1.jsonl")
	second := filepath.Join(dir, "log-2.jsonl")
	if err := os.WriteFile(first, nil, 0o644); err != nil {
		t.Fatalf("cannot create the file: %v", err)
	}

	sink, err := OpenChainedFileSink(first)
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	clock := logVectorClock(t)
	sink.WithClock(func() time.Time { return clock })

	started, err := sink.Rotate(second)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if started.PrevHash != GenesisHash {
		t.Errorf("expected the genesis hash, got %s", started.PrevHash)
	}
	if started.LogStarted == nil || started.LogStarted.PreviousEntryHash == nil ||
		*started.LogStarted.PreviousEntryHash != GenesisHash {
		t.Fatalf("log_started must record the link even at genesis, got %+v", started.LogStarted)
	}

	resolution := vectorResolution(t)
	receipt, err := EvaluateAudited(resolution, vectorActions()[0], expectedReceiptConfig(),
		expectedReceiptContext(0))
	if err != nil {
		t.Fatalf("cannot build the receipt: %v", err)
	}
	if err := sink.Send(&receipt); err != nil {
		t.Fatalf("cannot append the receipt: %v", err)
	}

	report, err := VerifyLogFiles([]string{first, second}, nil)
	if err != nil {
		t.Fatalf("a chain rotated at genesis must verify: %v", err)
	}
	if report.Files != 2 || report.Entries != 2 {
		t.Errorf("expected 2 files and 2 entries, got %d and %d", report.Files, report.Entries)
	}
}

// TestOpenRefusesATailWithNoChainHead covers a tail that parses but carries
// nothing to continue from. Reading it loosely would seed the next entry from
// seq 0 and an empty hash, leaving a second, unlinked chain in the file.
func TestOpenRefusesATailWithNoChainHead(t *testing.T) {
	for name, tail := range map[string]string{
		"no seq":        `{"log_version":"0.1","prev_hash":"x","entry_type":"receipt","entry_hash":"sha256:00"}`,
		"no entry_hash": `{"log_version":"0.1","seq":5,"prev_hash":"x","entry_type":"receipt"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log.jsonl")
			if err := os.WriteFile(path, []byte(tail+"\n"), 0o644); err != nil {
				t.Fatalf("cannot create the file: %v", err)
			}
			if sink, err := OpenChainedFileSink(path); err == nil {
				t.Fatalf("a tail with no chain head must be refused, got %+v", sink)
			}
		})
	}
}

// TestLastLineIsCappedBeforeItIsAssembled covers a file with no newline in it:
// the cap has to stop the read before the whole file is in memory.
func TestLastLineIsCappedBeforeItIsAssembled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), maxLogLineBytes+1), 0o644); err != nil {
		t.Fatalf("cannot create the file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("cannot open the file: %v", err)
	}
	defer file.Close()
	if _, err := lastLogLine(file, path); err == nil {
		t.Fatal("a line longer than the cap must be refused")
	}
}

// TestRotateRefusesAnExistingFile locks in that rotation never appends into a
// file that already holds a chain: two chains in one file corrupt both.
func TestRotateRefusesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.jsonl")
	other := filepath.Join(dir, "other.jsonl")
	if err := os.WriteFile(other, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("cannot create the file: %v", err)
	}
	sink := writeVectorChain(t, path, false)
	if _, err := sink.Rotate(other); err == nil {
		t.Fatal("rotating into an existing file must be refused")
	}
	if sink.Path() != path {
		t.Errorf("a refused rotation must not move the sink, got %q", sink.Path())
	}
}

// TestRotationThatCannotBeWrittenKeepsTheOldFile covers the failure the switch
// has to survive: the sink may move to the new file only once the log_started
// entry that links it is on disk, or the next receipt becomes line 1 of a file
// that continues nothing.
func TestRotationThatCannotBeWrittenKeepsTheOldFile(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "log-1.jsonl")
	sink := writeVectorChain(t, first, false)
	seqBefore, headBefore := sink.Head()

	// A regular file where the new log's directory would be: neither the file
	// nor its lock can be created there.
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatalf("cannot create the file: %v", err)
	}
	if _, err := sink.Rotate(filepath.Join(blocker, "log-2.jsonl")); err == nil {
		t.Fatal("a rotation whose entry cannot be written must fail")
	}

	if sink.Path() != first {
		t.Errorf("the sink must still write the old file, got %q", sink.Path())
	}
	if seq, head := sink.Head(); seq != seqBefore || head != headBefore {
		t.Errorf("the chain head must be unchanged, got (%d, %s)", seq, head)
	}

	resolution := vectorResolution(t)
	receipt, err := EvaluateAudited(resolution, vectorActions()[0], expectedReceiptConfig(),
		expectedReceiptContext(9))
	if err != nil {
		t.Fatalf("cannot build the receipt: %v", err)
	}
	if err := sink.Send(&receipt); err != nil {
		t.Fatalf("cannot append the receipt: %v", err)
	}
	if _, err := VerifyLogFiles([]string{first}, nil); err != nil {
		t.Fatalf("the old file must still verify: %v", err)
	}
}

// TestAppendCreatesTheParentDirectory covers opening a log in a workspace that
// does not have the directory yet: the sentinel lock lives next to the file, so
// the directory has to exist before the first append takes it.
func TestAppendCreatesTheParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "audit.jsonl")
	sink, err := OpenChainedFileSink(path)
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	if err := sink.RecordPolicyEvent(vectorPolicyEvent(t, vectorResolution(t))); err != nil {
		t.Fatalf("cannot append the policy event: %v", err)
	}
	report, err := VerifyLogFiles([]string{path}, nil)
	if err != nil {
		t.Fatalf("the log must verify: %v", err)
	}
	if report.Entries != 1 {
		t.Errorf("expected one entry, got %d", report.Entries)
	}
}

// TestEmptyPreviousEntryHashIsNotAnAbsentLink pins the distinction the pointer
// makes: `"previous_entry_hash": ""` names no hash, so a first file that
// carries one links to nothing and must be refused, as it is in every SDK.
func TestEmptyPreviousEntryHashIsNotAnAbsentLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	empty := ""
	sink, err := OpenChainedFileSink(path)
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	clock := logVectorClock(t)
	sink.WithClock(func() time.Time { return clock })
	if _, err := sink.Append(LogPayload{LogStarted: &LogStarted{
		Timestamp:         FormatTimestamp(clock),
		PreviousFile:      "log-0.jsonl",
		PreviousEntryHash: &empty,
	}}); err != nil {
		t.Fatalf("cannot append the log_started entry: %v", err)
	}

	if _, err := VerifyLogFiles([]string{path}, nil); err == nil {
		t.Fatal("an empty previous_entry_hash must break the chain")
	}
}

// TestChainedSinkContinuesAnExistingChain locks in that reopening a log picks
// up where it left off rather than restarting the sequence.
func TestChainedSinkContinuesAnExistingChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	first := writeVectorChain(t, path, false)
	seqBefore, headBefore := first.Head()

	reopened, err := OpenChainedFileSink(path)
	if err != nil {
		t.Fatalf("cannot reopen the log: %v", err)
	}
	seqAfter, headAfter := reopened.Head()
	if seqAfter != seqBefore || headAfter != headBefore {
		t.Fatalf("reopening must continue the chain: (%d, %s) vs (%d, %s)",
			seqAfter, headAfter, seqBefore, headBefore)
	}

	receipt, err := EvaluateAudited(vectorResolution(t),
		&EvaluationAction{Type: "egress", Target: "example.com"},
		expectedReceiptConfig(), expectedReceiptContext(9))
	if err != nil {
		t.Fatalf("audited: %v", err)
	}
	if err := reopened.Send(&receipt); err != nil {
		t.Fatalf("cannot append: %v", err)
	}
	report, err := VerifyLogFiles([]string{path}, nil)
	if err != nil {
		t.Fatalf("the continued chain must verify: %v", err)
	}
	if report.LastSeq != seqBefore+1 {
		t.Errorf("expected seq %d, got %d", seqBefore+1, report.LastSeq)
	}
}

// TestTwoSinksOnOneFileExtendOneChain locks in log spec 4: a writer derives
// `seq` and `prev_hash` from the file's current last entry while it holds the
// write lock, so two sinks open on one log extend a single chain instead of
// appending the same sequence number twice.
func TestTwoSinksOnOneFileExtendOneChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	clock := logVectorClock(t)
	first, err := OpenChainedFileSink(path)
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	second, err := OpenChainedFileSink(path)
	if err != nil {
		t.Fatalf("cannot open the log twice: %v", err)
	}
	first.WithClock(func() time.Time { return clock })
	second.WithClock(func() time.Time { return clock })

	resolution := vectorResolution(t)
	if err := first.RecordPolicyEvent(vectorPolicyEvent(t, resolution)); err != nil {
		t.Fatalf("cannot record the policy event: %v", err)
	}
	for index, action := range vectorActions() {
		sink := first
		if index%2 == 0 {
			sink = second
		}
		receipt, err := EvaluateAudited(resolution, action, expectedReceiptConfig(),
			expectedReceiptContext(index))
		if err != nil {
			t.Fatalf("audited: %v", err)
		}
		if err := sink.Send(&receipt); err != nil {
			t.Fatalf("cannot append receipt %d: %v", index, err)
		}
	}

	report, err := VerifyLogFiles([]string{path}, nil)
	if err != nil {
		t.Fatalf("the shared chain must verify: %v", err)
	}
	if report.Entries != 4 || report.LastSeq != 4 {
		t.Fatalf("expected four consecutive entries, got %+v", report)
	}
	hashes := entryHashes(t, path)
	if seq, head := second.Head(); seq != 4 || head != hashes[3] {
		t.Errorf("the last writer must hold the file head, got (%d, %s)", seq, head)
	}
}

// TestVerifierRequiresSignaturesWhenAsked locks in log spec 7: a verifier
// configured to require signatures rejects an unsigned entry with
// entry_unsigned rather than passing it.
func TestVerifierRequiresSignaturesWhenAsked(t *testing.T) {
	path := filepath.Join(logFixtureDir(t, "valid"), "basic.jsonl")
	options := &LogVerifyOptions{RequireSignatures: true, Keyring: testKeyring(t)}
	_, err := VerifyLogFiles([]string{path}, options)
	if err == nil {
		t.Fatal("an unsigned entry must be rejected when signatures are required")
	}
	if !strings.Contains(err.Error(), ReasonEntryUnsigned) {
		t.Errorf("expected %s, got: %v", ReasonEntryUnsigned, err)
	}
}

// TestTamperingAnEntryBreaksTheChain is the property the whole format exists
// for: editing any line changes its hash and breaks the link the next line
// declares.
func TestTamperingAnEntryBreaksTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	writeVectorChain(t, path, false)

	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(text), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], `"decision":"allow"`, `"decision":"deny"`, 1)
	tampered := strings.Join(lines, "\n") + "\n"

	_, err = VerifyLog("tampered.jsonl", tampered, nil)
	if err == nil {
		t.Fatal("a tampered entry must break verification")
	}
	logErr, ok := err.(*LogError)
	if !ok {
		t.Fatalf("expected a *LogError, got %T", err)
	}
	if logErr.Line != 2 {
		t.Errorf("expected the break at line 2, got %d: %s", logErr.Line, logErr.Message)
	}
}

// --------------------------------------------------------------------------
// Policy events on sinks
// --------------------------------------------------------------------------

func TestNewPolicyLoadedEvent(t *testing.T) {
	resolution := vectorResolution(t)
	event := NewPolicyLoadedEvent(resolution, EnforcementModeMonitor, SdkInfo{})

	if event.Event != PolicyEventLoaded {
		t.Errorf("expected a loaded event, got %q", event.Event)
	}
	if event.SDK != ThisSDK() {
		t.Errorf("a zero SdkInfo means this SDK, got %+v", event.SDK)
	}
	if event.SDK.Name != "hushspec-go" {
		t.Errorf("expected hushspec-go, got %q", event.SDK.Name)
	}
	if event.SpecVersion != Version {
		t.Errorf("expected spec_version %q, got %q", Version, event.SpecVersion)
	}
	if event.EnforcementMode != EnforcementModeMonitor {
		t.Errorf("expected monitor mode, got %q", event.EnforcementMode)
	}
	if event.Policy.ContentHash != resolution.ContentHash {
		t.Errorf("the event carries the policy identity a receipt does, got %+v", event.Policy)
	}
	if !receiptTimeRE.MatchString(event.Timestamp) {
		t.Errorf("timestamp %q is not millisecond precision", event.Timestamp)
	}

	swapped := NewPolicySwappedEvent(resolution, EnforcementModeEnforce, ThisSDK(), DigestOf("old"))
	if swapped.Event != PolicyEventSwapped || swapped.PreviousContentHash != DigestOf("old") {
		t.Errorf("a swap names the policy it replaced, got %+v", swapped)
	}
}

// TestRecordPolicyEventRoutesToSinksThatCarryOne locks in that the optional
// interface reaches a chained log through a fan-out or a filter, and is a
// silent no-op for a sink with nowhere to put it.
func TestRecordPolicyEventRoutesToSinksThatCarryOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	chained, err := OpenChainedFileSink(path)
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	event := vectorPolicyEvent(t, vectorResolution(t))

	multi := NewMultiSink([]ReceiptSink{&StderrReceiptSink{}, chained})
	carried, err := RecordPolicyEvent(multi, event)
	if err != nil {
		t.Fatalf("RecordPolicyEvent failed: %v", err)
	}
	if !carried {
		t.Error("a MultiSink holding a chained log carries policy events")
	}

	// A filter selects which decisions are kept; a policy event is what ties
	// the kept receipts to the policy that produced them, so it passes.
	filtered := NewDenyOnlySink(chained)
	if _, err := RecordPolicyEvent(filtered, event); err != nil {
		t.Fatalf("RecordPolicyEvent through a filter failed: %v", err)
	}

	if carried, err := RecordPolicyEvent(&StderrReceiptSink{}, event); err != nil || carried {
		t.Errorf("a receipt-only sink drops the event silently, got (%v, %v)", carried, err)
	}

	report, err := VerifyLogFiles([]string{path}, nil)
	if err != nil {
		t.Fatalf("the log must verify: %v", err)
	}
	if report.PolicyEvents != 2 {
		t.Errorf("expected two policy events, got %d", report.PolicyEvents)
	}
}

// TestAppendRejectsAnAmbiguousPayload locks in the log spec's rule that an
// entry wraps exactly the payload its entry_type names.
func TestAppendRejectsAnAmbiguousPayload(t *testing.T) {
	sink, err := OpenChainedFileSink(filepath.Join(t.TempDir(), "log.jsonl"))
	if err != nil {
		t.Fatalf("cannot open the log: %v", err)
	}
	if _, err := sink.Append(LogPayload{}); err == nil {
		t.Error("an empty payload must be refused")
	}
	receipt := minimalReceipt()
	both := LogPayload{Receipt: &receipt, LogStarted: &LogStarted{Timestamp: "2026-09-15T12:00:00.000Z"}}
	if _, err := sink.Append(both); err == nil {
		t.Error("two payloads in one entry must be refused")
	}
}
