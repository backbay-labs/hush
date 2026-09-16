//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris)

package hushspec

import (
	"os"
	"time"
)

// flockLogFile is the no-op for platforms with no advisory lock on an open
// file. The `<path>.lock` sentinel is the whole lock there, which is the part
// every SDK takes anyway.
func flockLogFile(file *os.File, path string, deadline time.Time) (func(), error) {
	return func() {}, nil
}
