package hushspec

// stringValue reads an optional string of the document model for its text
// alone: both an absent property and one written as "" read as "".
//
// An optional string is a *string, because the distinction is part of the wire
// format: the canonical form keeps a present empty string and drops an absent
// one, so the two carry different content hashes. The other three SDKs draw
// the same distinction with Option<String>, `str | None` and
// `string | undefined`.
//
// Use this only where absent and empty mean the same thing to the caller --
// matching, formatting, comparing against a value that is never empty. Where
// presence itself is load-bearing -- merging, the canonical projection,
// validation, the identity a receipt or a bundle records -- compare the
// pointer against nil instead.
func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
