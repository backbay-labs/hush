package hushspec

// Optional scalars of the document model.
//
// An optional string is a `*string`: nil is an absent property and a pointer
// to "" is a property written as the empty string. The distinction is part of
// the wire format -- the canonical form keeps a present empty string and drops
// an absent one, so the two carry different content hashes -- and the other
// three SDKs draw it with `Option<String>`, `str | None` and
// `string | undefined`.

// stringValue reads an optional string for its text alone: both an absent
// property and one written as "" read as "".
//
// Use it only where the two mean the same thing to the caller -- matching,
// formatting, comparing against a value that is never empty. Where presence
// itself is load-bearing -- merging, the canonical projection, validation, the
// identity a receipt or a bundle records -- compare the pointer against nil
// instead.
func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
