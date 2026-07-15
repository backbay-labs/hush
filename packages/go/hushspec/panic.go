package hushspec

import (
	"os"
	"sync/atomic"
)

var panicActive atomic.Bool

// ActivatePanic enables global panic mode. All Evaluate calls will deny.
func ActivatePanic() {
	panicActive.Store(true)
}

// DeactivatePanic disables panic mode, restoring normal evaluation.
func DeactivatePanic() {
	panicActive.Store(false)
}

func IsPanicActive() bool {
	return panicActive.Load()
}

// CheckPanicSentinel activates panic mode if the file at path exists.
//
// This is a kill switch, so it fails closed: if the sentinel's existence
// cannot be determined (e.g. a permission error), that is treated as
// "present" and panic mode is activated. Only a definite not-found result
// (including a path component that is not a directory, which os.IsNotExist
// also recognizes) is treated as absent.
func CheckPanicSentinel(path string) bool {
	_, err := os.Stat(path)

	var present bool
	switch {
	case err == nil:
		present = true
	case os.IsNotExist(err):
		present = false
	default:
		// Any other error (permission denied, etc.) means we could not prove
		// the sentinel is absent; fail closed rather than fail open.
		present = true
	}

	if present {
		ActivatePanic()
	}
	return present
}
