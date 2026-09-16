package hushspec

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The HushSpec regex profile: the one regex dialect every HushSpec engine must
// implement, so a user-authored pattern in secret_patterns,
// patch_integrity.forbidden_patterns, or shell_commands.forbidden_patterns
// produces the *same* decision in Rust, TypeScript, Python, and Go.
//
// The four SDK engines (Rust `regex`, JavaScript `RegExp`, Python `re`, Go
// RE2) agree on syntax but disagree on semantics, so the profile is reached by
// *translating* the author's pattern into an equivalent pattern in each host
// dialect before compiling it. The same translation runs in Validate and in
// Evaluate, so the two can never disagree about what a pattern means.
//
// Profile (normative summary; keep in sync with
// crates/hushspec/src/regex_profile.rs, packages/hushspec/src/regex.ts and
// packages/python/hushspec/regex_profile.py):
//
//  1. Syntax is RE2-class -- lookaround, backreferences, possessive
//     quantifiers, atomic/conditional/recursive groups and nested unbounded
//     quantifiers are rejected. The group forms are (...), (?:...) and the
//     named pair (?<name>...) / (?P<name>...), whose names are ASCII letters,
//     digits and underscores not starting with a digit; any other (?...)
//     opener is rejected.
//  2. Inline flags only as a leading group: (?i), (?s), (?m), (?is) at the very
//     start (one or more consecutive groups). A flag group anywhere else --
//     including the scoped form (?i:...) and negations like (?-i) -- is an
//     error. Go RE2 accepts all of those natively, so this is a rejection Go
//     has to add.
//  3. \d \w \s \b and their negations are ASCII-only: \d = [0-9],
//     \w = [0-9A-Za-z_], \s = [\t\n\v\f\r ] and \b/\B are boundaries under that
//     ASCII \w. Go's RE2 \d and \w are ASCII already, but its \s is
//     [\t\n\f\r ] -- it omits the vertical tab -- so \s must be rewritten.
//     They are translated, not rejected, including inside character classes
//     ([\d_] -> [0-9_]). The negated shorthands \D \W \S and the boundaries
//     \b \B are rejected *inside* a class, where they cannot be expressed as
//     members.
//  4. `.` matches any scalar value except \n; with a leading (?s) it matches
//     everything. Go behaves this way already.
//  5. `$` matches only at end of text unless a leading (?m). Go behaves this
//     way already (its `$` is \z, not \Z); the Python SDK rewrites `$` to \Z.
//  6. (?i) folds ASCII letters only. Each ASCII letter is expanded into a
//     two-member class (s -> [sS]) and no case-insensitive flag reaches RE2,
//     whose own (?i) would fold U+017F and U+212A into a match for s and k.
//  7. Unanchored search semantics.
//  8. Compile failure at evaluation time denies, carrying the offending rule
//     path (see evaluate.go).
//
// A character class is a set of scalar values: an unescaped [ inside one is
// rejected (so POSIX bracket expressions are not mistaken for a class of their
// own), and a range endpoint outside the Basic Multilingual Plane is rejected
// because the SDKs cannot express such a range alike. A pattern is limited to
// 2048 UTF-8 bytes (core spec 3.14.3).
//
// Escapes are restricted to the intersection the four engines agree on:
// \n \r \t \f \v, \xHH, \d \D \w \W \s \S \b \B, and any escaped ASCII
// punctuation. \A, \Z, \z, \Q, \E, \p{...}, \P{...}, \uXXXX, \0, \a and every
// other alphanumeric escape are rejected: each is unsupported by at least one
// engine, or -- worse -- silently reinterpreted by JavaScript as the bare
// letter. \Q...\E and \p{...} in particular are Go-only among the four.

// Character-class body for ASCII \d.
const digitClassBody = "0-9"

// Character-class body for ASCII \w.
const wordClassBody = "0-9A-Za-z_"

// Character-class body for ASCII \s -- includes \v, which RE2's own \s omits.
const spaceClassBody = `\t\n\v\f\r `

// maxPatternBytes is the size limit of a policy-authored pattern, in UTF-8
// bytes (core spec 3.14.3).
const maxPatternBytes = 2048

// nestedQuantifierMessage is the shared rejection message for nested unbounded
// quantifiers, kept identical to the other three SDKs.
const nestedQuantifierMessage = "pattern contains a nested unbounded quantifier (e.g. (a+)+) that can cause catastrophic backtracking (ReDoS)"

// patternTooLongMessage is the shared rejection message for an over-long
// pattern.
const patternTooLongMessage = "pattern exceeds the HushSpec regex profile limit of 2048 bytes"

// groupFormMessage is the shared rejection message for group openers outside
// the profile.
const groupFormMessage = "this group form is not portable across the HushSpec SDK regex engines; the profile allows (?:...), the named forms (?<name>...) and (?P<name>...), and a leading inline flag group such as (?i)"

// groupNameMessage is the shared rejection message for a malformed or
// non-portable group name.
const groupNameMessage = "a named group's name must be ASCII letters, digits and underscores, must not start with a digit, and must be closed by >"

// nestedClassMessage is the shared rejection message for an unescaped [ inside
// a character class.
const nestedClassMessage = `an unescaped [ inside a character class is not portable across the HushSpec SDK regex engines (Rust and Go read [[:alpha:]] as a POSIX class, JavaScript and Python as a literal [); escape it as \[`

// astralRangeMessage is the shared rejection message for a class range
// reaching outside the BMP.
const astralRangeMessage = "a character-class range with an endpoint outside the Basic Multilingual Plane is not portable across the HushSpec SDK regex engines"

// emptyClassMessage is the shared rejection message for an empty character
// class.
const emptyClassMessage = "empty character classes [] and [^] are not portable across the HushSpec SDK regex engines"

// profileFlags carries the flags of a leading inline flag group.
type profileFlags struct {
	caseInsensitive bool
	dotAll          bool
	multiLine       bool
}

// isInlineFlagChar reports whether c can appear inside an inline flag group.
// Used only to detect such a group so it can be rejected when it is not
// leading.
func isInlineFlagChar(c rune) bool {
	switch c {
	case 'i', 'm', 's', 'x', 'u', 'U', 'a', 'L', 'n', '-':
		return true
	}
	return false
}

// CompileProfileRegex compiles pattern under the HushSpec regex profile.
//
// This is the only way policy-authored regexes are compiled in this SDK: both
// Validate and Evaluate route through it, so validation and evaluation can
// never disagree about what a pattern means. It returns an error for any
// pattern outside the profile -- the evaluator turns that into a deny.
func CompileProfileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxPatternBytes {
		return nil, errors.New(patternTooLongMessage)
	}
	// Portability pre-check and the ReDoS nested-quantifier heuristic run here,
	// not only in Validate, so the evaluator denies on exactly the patterns the
	// validator rejects even for a hand-built, never-validated HushSpec.
	if message, bad := disallowedRegexFeature(pattern); bad {
		return nil, errors.New(message)
	}
	if hasNestedQuantifier(pattern) {
		return nil, errors.New(nestedQuantifierMessage)
	}

	chars := []rune(pattern)
	flags, bodyStart := splitLeadingFlags(chars)
	source, err := translateProfileBody(chars[bodyStart:], flags)
	if err != nil {
		return nil, err
	}
	// `i` is deliberately absent from the prefix: the profile folds ASCII
	// letters only, which translateProfileBody has already done by expanding
	// each one into a two-member class.
	var engineFlags string
	if flags.dotAll {
		engineFlags += "s"
	}
	if flags.multiLine {
		engineFlags += "m"
	}
	if engineFlags != "" {
		source = "(?" + engineFlags + ")" + source
	}

	re, err := regexp.Compile(source)
	if err != nil {
		return nil, err
	}
	return re, nil
}

// splitLeadingFlags consumes the leading run of (?flags) groups, returning the
// accumulated flags and the index at which the pattern body starts. Only i, s
// and m are recognized; anything else leaves the group in place, where
// translateProfileBody rejects it as a non-leading inline flag group.
func splitLeadingFlags(chars []rune) (profileFlags, int) {
	var flags profileFlags
	index := 0
	for index+2 < len(chars) && chars[index] == '(' && chars[index+1] == '?' {
		cursor := index + 2
		start := cursor
		for cursor < len(chars) && (chars[cursor] == 'i' || chars[cursor] == 's' || chars[cursor] == 'm') {
			cursor++
		}
		if cursor == start || cursor >= len(chars) || chars[cursor] != ')' {
			break
		}
		for _, flag := range chars[start:cursor] {
			switch flag {
			case 'i':
				flags.caseInsensitive = true
			case 's':
				flags.dotAll = true
			case 'm':
				flags.multiLine = true
			}
		}
		index = cursor + 1
	}
	return flags, index
}

// inlineFlagGroupError rejects (?flags) and (?flags:...) groups outside the
// leading position.
func inlineFlagGroupError(chars []rune, index int) error {
	if index+1 >= len(chars) || chars[index+1] != '?' {
		return nil
	}
	cursor := index + 2
	start := cursor
	for cursor < len(chars) && isInlineFlagChar(chars[cursor]) {
		cursor++
	}
	if cursor == start || cursor >= len(chars) {
		return nil
	}
	if chars[cursor] == ')' || chars[cursor] == ':' {
		return errors.New("inline flags are only allowed as a leading group such as (?i), (?s), (?m) or (?is); " +
			"a flag group elsewhere in the pattern is not portable across the HushSpec SDK regex engines")
	}
	return nil
}

// escapeLength returns the number of runes consumed by the escape sequence
// starting at index (the backslash included).
func escapeLength(chars []rune, index int) int {
	if index+1 < len(chars) && chars[index+1] == 'x' {
		return 4
	}
	return 2
}

func isASCIIHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isASCIIAlphanumeric(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func hexDigitValue(c rune) rune {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// asciiCaseCounterpart returns the other ASCII case of c, and false when c is
// not an ASCII letter.
func asciiCaseCounterpart(c rune) (rune, bool) {
	switch {
	case c >= 'a' && c <= 'z':
		return c - 'a' + 'A', true
	case c >= 'A' && c <= 'Z':
		return c - 'A' + 'a', true
	}
	return 0, false
}

// foldedClassRange returns the class-body ranges that fold lo..hi to its other
// ASCII case: one for the part inside a-z and one for the part inside A-Z, so
// [a-f] under (?i) becomes [a-fA-F] and a range over digits is left alone.
func foldedClassRange(lo, hi rune) string {
	var out strings.Builder
	lowerStart, lowerEnd := maxRune(lo, 'a'), minRune(hi, 'z')
	if lowerStart <= lowerEnd {
		out.WriteRune(lowerStart - 'a' + 'A')
		out.WriteRune('-')
		out.WriteRune(lowerEnd - 'a' + 'A')
	}
	upperStart, upperEnd := maxRune(lo, 'A'), minRune(hi, 'Z')
	if upperStart <= upperEnd {
		out.WriteRune(upperStart - 'A' + 'a')
		out.WriteRune('-')
		out.WriteRune(upperEnd - 'A' + 'a')
	}
	return out.String()
}

func maxRune(a, b rune) rune {
	if a > b {
		return a
	}
	return b
}

func minRune(a, b rune) rune {
	if a < b {
		return a
	}
	return b
}

// translateEscape translates one escape sequence into RE2 source. fold asks for
// the profile's ASCII case folding, which applies only outside a character
// class -- translateCharacterClass folds its own members.
func translateEscape(escaped rune, inClass, fold bool, chars []rune, index int) (string, error) {
	switch escaped {
	case 'd', 'w', 's':
		body := digitClassBody
		if escaped == 'w' {
			body = wordClassBody
		} else if escaped == 's' {
			body = spaceClassBody
		}
		if inClass {
			return body, nil
		}
		return "[" + body + "]", nil
	case 'D', 'W', 'S':
		if inClass {
			return "", fmt.Errorf("\\%c is not portable inside a character class; a negated shorthand cannot be expressed as a class member", escaped)
		}
		body := digitClassBody
		if escaped == 'W' {
			body = wordClassBody
		} else if escaped == 'S' {
			body = spaceClassBody
		}
		return "[^" + body + "]", nil
	case 'b', 'B':
		if inClass {
			return "", fmt.Errorf("\\%c is not portable inside a character class (JavaScript and Python read it as a backspace; Rust and Go reject it)", escaped)
		}
		// RE2 word boundaries are ASCII already, which is the profile
		// definition; Rust needs (?-u:\b) to get here.
		return "\\" + string(escaped), nil
	case 'A', 'Z', 'z':
		return "", fmt.Errorf("\\%c is not portable across the HushSpec SDK regex engines (JavaScript reads it as a literal letter); anchor with ^ and $", escaped)
	case 'Q', 'E':
		return "", errors.New("\\Q ... \\E literal spans are not portable across the HushSpec SDK regex engines; escape the literal characters individually")
	case 'p', 'P':
		return "", fmt.Errorf("Unicode property escapes (\\%c) are not portable across the HushSpec SDK regex engines; spell the character class out", escaped)
	case 'x':
		if index+3 >= len(chars) || !isASCIIHexDigit(chars[index+2]) || !isASCIIHexDigit(chars[index+3]) {
			return "", errors.New("\\x must be followed by exactly two hex digits (\\x41); the braced form \\x{...} is not portable across the HushSpec SDK regex engines")
		}
		escape := "\\x" + string(chars[index+2:index+4])
		if fold {
			value := hexDigitValue(chars[index+2])*16 + hexDigitValue(chars[index+3])
			if other, ok := asciiCaseCounterpart(value); ok {
				return "[" + escape + string(other) + "]", nil
			}
		}
		return escape, nil
	case 'n', 'r', 't', 'f', 'v':
		return "\\" + string(escaped), nil
	}
	if isASCIIAlphanumeric(escaped) || escaped == '_' {
		return "", fmt.Errorf("\\%c is not a HushSpec regex profile escape", escaped)
	}
	if escaped <= 0x7f {
		return "\\" + string(escaped), nil
	}
	return "", fmt.Errorf("escaping the non-ASCII character '%c' is not portable across the HushSpec SDK regex engines", escaped)
}

// escapeLiteralValue returns the scalar value an escape sequence stands for,
// and false when it stands for a set of them. Only reached for escapes
// translateEscape accepted.
func escapeLiteralValue(chars []rune, index int) (rune, bool) {
	switch escaped := chars[index+1]; escaped {
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'f':
		return '\f', true
	case 'v':
		return '\v', true
	case 'd', 'w', 's':
		return 0, false
	case 'x':
		return hexDigitValue(chars[index+2])*16 + hexDigitValue(chars[index+3]), true
	default:
		return escaped, true
	}
}

// classAtom is one member of a character class: its translated source, the
// scalar value it stands for (absent for a multi-member shorthand such as \d),
// and the number of runes it spans.
type classAtom struct {
	source   string
	value    rune
	hasValue bool
	length   int
}

// readClassAtom reads the class member starting at chars[index].
func readClassAtom(chars []rune, index int) (classAtom, error) {
	c := chars[index]
	if c == '\\' {
		if index+1 >= len(chars) {
			return classAtom{}, errors.New("pattern ends with a trailing backslash")
		}
		source, err := translateEscape(chars[index+1], true, false, chars, index)
		if err != nil {
			return classAtom{}, err
		}
		value, hasValue := escapeLiteralValue(chars, index)
		return classAtom{source: source, value: value, hasValue: hasValue, length: escapeLength(chars, index)}, nil
	}
	if c == '[' {
		return classAtom{}, errors.New(nestedClassMessage)
	}
	return classAtom{source: string(c), value: c, hasValue: true, length: 1}, nil
}

// translateCharacterClass translates the character class starting at
// chars[start], returning its RE2 source and the index just past its closing ].
//
// Members are read one at a time so that an unescaped [ can be refused, a range
// can be checked for a non-BMP endpoint, and -- under (?i) -- both the members
// and the ranges can be folded to their other ASCII case.
func translateCharacterClass(chars []rune, start int, caseInsensitive bool) (string, int, error) {
	n := len(chars)
	index := start + 1
	negated := index < n && chars[index] == '^'
	if negated {
		index++
	}
	// `[]` / `[^]` read as an empty class (a compile error) in Rust, Python and
	// Go but as "match nothing"/"match anything" in JavaScript, so they are
	// never portable.
	if index >= n || chars[index] == ']' {
		return "", 0, errors.New(emptyClassMessage)
	}

	var body strings.Builder
	for index < n && chars[index] != ']' {
		atom, err := readClassAtom(chars, index)
		if err != nil {
			return "", 0, err
		}
		after := index + atom.length
		// A `-` is a range only between two single members and never just
		// before the closing `]`, where it is a literal hyphen.
		if atom.hasValue && after < n && chars[after] == '-' && after+1 < n && chars[after+1] != ']' {
			high, err := readClassAtom(chars, after+1)
			if err != nil {
				return "", 0, err
			}
			if high.hasValue {
				if atom.value > 0xffff || high.value > 0xffff {
					return "", 0, errors.New(astralRangeMessage)
				}
				body.WriteString(atom.source)
				body.WriteRune('-')
				body.WriteString(high.source)
				if caseInsensitive {
					body.WriteString(foldedClassRange(atom.value, high.value))
				}
				index = after + 1 + high.length
				continue
			}
		}
		body.WriteString(atom.source)
		if caseInsensitive && atom.hasValue {
			if other, ok := asciiCaseCounterpart(atom.value); ok {
				body.WriteRune(other)
			}
		}
		index = after
	}

	prefix := ""
	if negated {
		prefix = "^"
	}
	if index >= n {
		// Unterminated: hand it to RE2, whose own diagnostic names the class.
		return "[" + prefix + body.String(), index, nil
	}
	return "[" + prefix + body.String() + "]", index + 1, nil
}

// translateGroup translates the group opener starting at chars[start], writing
// it to out and returning the index just past it.
//
// (, (?: and the two named spellings are the profile's only group forms;
// (?=, (?!, (?>, (?#, (?(, (?R) and (?P=name) are rejected here rather than
// left to a host engine that may accept them.
func translateGroup(chars []rune, start int, out *strings.Builder) (int, error) {
	n := len(chars)
	if start+1 >= n || chars[start+1] != '?' {
		out.WriteRune('(')
		return start + 1, nil
	}
	if err := inlineFlagGroupError(chars, start); err != nil {
		return 0, err
	}
	if start+2 >= n {
		return 0, errors.New(groupFormMessage)
	}
	switch chars[start+2] {
	case ':':
		out.WriteString("(?:")
		return start + 3, nil
	case '<':
		// `(?<name>...)` is the JavaScript/Rust spelling; `(?P<name>...)` is
		// accepted by Rust, Python and Go alike, so normalize to it.
		if start+3 < n && (chars[start+3] == '=' || chars[start+3] == '!') {
			return 0, errors.New(groupFormMessage)
		}
		return translateGroupName(chars, start+3, out)
	case 'P':
		if start+3 < n && chars[start+3] == '<' {
			return translateGroupName(chars, start+4, out)
		}
	}
	return 0, errors.New(groupFormMessage)
}

// translateGroupName copies the group name that starts at start and ends at >,
// returning the index just past the >. The name is never case-folded: it is an
// identifier, not subject text.
func translateGroupName(chars []rune, start int, out *strings.Builder) (int, error) {
	cursor := start
	for cursor < len(chars) && chars[cursor] != '>' {
		cursor++
	}
	if cursor >= len(chars) {
		return 0, errors.New(groupNameMessage)
	}
	name := string(chars[start:cursor])
	if !isGroupName(name) {
		return 0, errors.New(groupNameMessage)
	}
	out.WriteString("(?P<")
	out.WriteString(name)
	out.WriteRune('>')
	return cursor + 1, nil
}

// isGroupName reports whether name is [A-Za-z_][0-9A-Za-z_]*, the group names
// every SDK engine accepts alike.
func isGroupName(name string) bool {
	for index, c := range name {
		if index == 0 && !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
		if index > 0 && !(c == '_' || isASCIIAlphanumeric(c)) {
			return false
		}
	}
	return name != ""
}

// translateProfileBody walks the pattern body, translating profile constructs
// into RE2 source and rejecting anything that is not portable across the four
// SDKs. Go's `.`, `$` and `\b` already have profile semantics, and (?s) / (?m)
// are re-attached as a (?flags) prefix; case insensitivity is the exception,
// compiled here by expanding every ASCII letter into a two-member class,
// because RE2's own (?i) would fold with the full Unicode table.
func translateProfileBody(chars []rune, flags profileFlags) (string, error) {
	n := len(chars)
	var out strings.Builder
	out.Grow(n + 16)
	index := 0

	for index < n {
		c := chars[index]

		if c == '\\' {
			if index+1 >= n {
				return "", errors.New("pattern ends with a trailing backslash")
			}
			translated, err := translateEscape(chars[index+1], false, flags.caseInsensitive, chars, index)
			if err != nil {
				return "", err
			}
			out.WriteString(translated)
			index += escapeLength(chars, index)
			continue
		}

		switch c {
		case '[':
			source, next, err := translateCharacterClass(chars, index, flags.caseInsensitive)
			if err != nil {
				return "", err
			}
			out.WriteString(source)
			index = next
		case '(':
			next, err := translateGroup(chars, index, &out)
			if err != nil {
				return "", err
			}
			index = next
		default:
			if other, ok := asciiCaseCounterpart(c); ok && flags.caseInsensitive {
				out.WriteRune('[')
				out.WriteRune(c)
				out.WriteRune(other)
				out.WriteRune(']')
			} else {
				out.WriteRune(c)
			}
			index++
		}
	}

	return out.String(), nil
}
