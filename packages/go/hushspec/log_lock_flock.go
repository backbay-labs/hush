//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package hushspec

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// flockLogFile takes an exclusive advisory lock on the log file itself, under
// the sentinel. The kernel releases it even if the writer dies, so a crashed
// enforcement point never leaves this half of the lock behind.
//
// It is taken non-blocking and retried, so a writer that cannot get it before
// the deadline reports an error rather than blocking forever or bypassing it.
func flockLogFile(file *os.File, path string, deadline time.Time) (func(), error) {
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
		time.Sleep(logLockPollInterval)
	}
}
