//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris)

package hushspec

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// lockLogFile is the portable fallback for platforms without flock: a
// `<path>.lock` file created atomically with O_EXCL.
//
// It is weaker than an advisory lock on the file itself -- a writer that dies
// leaves the lock file behind -- so a wait longer than [LogLockTimeout] is
// reported as an error rather than bypassed. Breaking a lock this SDK cannot
// prove is stale would let two writers interleave chains and corrupt both
// (log spec 9).
func lockLogFile(file *os.File, path string) (func(), error) {
	lockPath := path + ".lock"
	deadline := time.Now().Add(LogLockTimeout)
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
		time.Sleep(5 * time.Millisecond)
	}
}
