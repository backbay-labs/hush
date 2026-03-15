// Package hushspec provides parsing, validation, and merging of HushSpec
// policy documents. It mirrors the Rust, TypeScript, and Python implementations
// of the HushSpec schema.
package hushspec

// Version is the current version of this SDK.
const Version = "0.1.0"

// SupportedVersions lists the HushSpec schema versions this SDK can process.
var SupportedVersions = []string{"0.1.0"}

// IsSupported returns true if the given schema version string is supported
// by this SDK.
func IsSupported(version string) bool {
	for _, v := range SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
