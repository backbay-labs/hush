// Package hushspec provides parsing, validation, merging, and evaluation of
// HushSpec security policy documents.
package hushspec

import "strings"

// [SDKName] is this package's own identity, as a receipt log's `sdk` member
// records it (spec/hushspec-log.md section 6) -- distinct from [Version],
// which is the *specification* version the engine implements.

// Version is the HushSpec version this engine writes by default.
const Version = "0.2.0"

// SupportedMinors lists the minor versions this engine accepts, as "X.Y"
// strings. Version acceptance follows core spec 2.2: an engine that supports a
// minor version X.Y accepts every X.Y.Z document, because patch versions carry
// only clarifications and errata.
var SupportedMinors = []string{"0.1", "0.2"}

// SupportedVersions lists one representative full version per supported minor.
// It is for display only -- use [IsSupported] for acceptance, which accepts
// every patch level of a supported minor.
var SupportedVersions = []string{"0.1.0", "0.2.0"}

// IsSupported reports whether version is a well-formed "X.Y.Z" string whose
// minor version this engine supports. Any patch level of a supported minor is
// accepted (core spec 2.2).
func IsSupported(version string) bool {
	return SupportedMinor(version) != ""
}

// SupportedMinor returns the "X.Y" minor of a well-formed, supported version
// string, or "" when the version is malformed or its minor is unsupported.
func SupportedMinor(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return ""
	}
	for _, part := range parts {
		if !isASCIIDigits(part) {
			return ""
		}
	}
	minor := parts[0] + "." + parts[1]
	for _, supported := range SupportedMinors {
		if supported == minor {
			return supported
		}
	}
	return ""
}
