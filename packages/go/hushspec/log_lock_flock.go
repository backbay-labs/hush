//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package hushspec

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockLogFile takes an exclusive advisory lock on the log file itself, which
// the kernel releases even if the writer dies -- so a crashed enforcement
// point never leaves a lock that a later one has to break (log spec 9).
//
// The lock is taken non-blocking and retried, so a writer that cannot get it
// within [LogLockTimeout] reports an error rather than blocking forever or
// bypassing the lock.
func lockLogFile(file *os.File, path string) (func(), error) {
	deadline := time.Now().Add(LogLockTimeout)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return nil, fmt.Errorf("log: cannot lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf(
				"log: timed out after %s waiting for another writer to release %s",
				LogLockTimeout, path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
