package hushspec

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Locking a log for append (log spec 4).
//
// A writer derives `seq` and `prev_hash` from the file's current last entry
// and appends under one lock, so two writers never build entries from the same
// predecessor and fork the chain.
//
// The lock has two parts, taken in this order:
//
//   - A `<path>.lock` sentinel file, created with O_EXCL so that creating it
//     is acquiring it. This is the part every SDK implements, on every
//     platform, and it is therefore what makes writers in different languages
//     exclude each other.
//   - An exclusive advisory lock on the log file itself, where the platform
//     has one. The kernel releases it even if the writer dies, and it also
//     excludes a writer that takes only the advisory lock.
//
// A lock this SDK cannot acquire within [LogLockTimeout] is an error, never
// something to bypass: two writers appending to one file interleave chains and
// corrupt both (log spec 9). Breaking a sentinel this SDK cannot prove is
// stale would do exactly that.

// lockLogFile takes both locks and returns the function that releases them.
func lockLogFile(file *os.File, path string) (func(), error) {
	deadline := time.Now().Add(LogLockTimeout)
	releaseSentinel, err := lockSentinel(path, deadline)
	if err != nil {
		return nil, err
	}
	releaseAdvisory, err := flockLogFile(file, path, deadline)
	if err != nil {
		releaseSentinel()
		return nil, err
	}
	return func() {
		releaseAdvisory()
		releaseSentinel()
	}, nil
}

// lockSentinel holds `<path>.lock` until the returned function is called.
func lockSentinel(path string, deadline time.Time) (func(), error) {
	lockPath := path + ".lock"
	for {
		lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_ = lock.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("log: cannot lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf(
				"log: timed out after %s waiting for %s", LogLockTimeout, lockPath)
		}
		time.Sleep(logLockPollInterval)
	}
}

// logLockPollInterval is how long to wait between attempts while another
// writer holds the lock.
const logLockPollInterval = 5 * time.Millisecond
