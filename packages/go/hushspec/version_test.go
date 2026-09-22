package hushspec

import (
	"strings"
	"testing"
)

// TestMajorVersionIsBoundedToUint32 pins the bound every SDK applies: a major
// that does not fit an unsigned 32-bit integer names no supported format.
func TestMajorVersionIsBoundedToUint32(t *testing.T) {
	if major, ok := MajorVersion("4294967295.0.0"); !ok || major != 4294967295 {
		t.Fatalf("expected the largest 32-bit major to parse, got (%d, %v)", major, ok)
	}
	if major, ok := MajorVersion("00000000001.0.0"); !ok || major != 1 {
		t.Fatalf("leading zeros do not widen a major: got (%d, %v)", major, ok)
	}
	for _, version := range []string{"4294967296.0.0", strings.Repeat("9", 5000) + ".0.0"} {
		if _, ok := MajorVersion(version); ok {
			t.Errorf("%q must not parse as a major version", version[:20])
		}
	}
}
