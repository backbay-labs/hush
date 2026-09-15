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
//     quantifiers are rejected.
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
//  4. `.` matches any character except \n; with a leading (?s) it matches
//     everything. Go behaves this way already.
//  5. `$` matches only at end of text unless a leading (?m). Go behaves this
//     way already (its `$` is \z, not \Z); the Python SDK rewrites `$` to \Z.
//  6. Unanchored search semantics.
//  7. Compile failure at evaluation time denies, carrying the offending rule
//     path (see evaluate.go).
//
// Escapes are restricted to the intersection the four engines agree on:
// \n \r \t \f \v, \xHH, \d \D \w \W \s \S \b \B, and any escaped ASCII
// punctuation. \A, \Z, \z, \Q, \E, \p{...}, \P{...}, \uXXXX, \0, \a and every
// other alphanumeric escape are rejected: each is unsupported by at least one
// engine, or -- worse -- silently reinterpreted by JavaScript as the bare
// letter. \Q...\E and \p{...} in particular are Go-only among the four.
//
// Known residual divergence: under a leading (?i), Go RE2 and Rust `regex`
// case-fold with the full Unicode table while JavaScript (no `u` flag) and
// Python (re.ASCII) fold only ASCII.

// Character-class body for ASCII \d.
const digitClassBody = "0-9"

// Character-class body for ASCII \w.
const wordClassBody = "0-9A-Za-z_"

// Character-class body for ASCII \s -- includes \v, which RE2's own \s omits.
const spaceClassBody = `\t\n\v\f\r `

// nestedQuantifierMessage is the shared rejection message for nested unbounded
// quantifiers, kept identical to the other three SDKs.
const nestedQuantifierMessage = "pattern contains a nested unbounded quantifier (e.g. (a+)+) that can cause catastrophic backtracking (ReDoS)"

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
	source, err := translateProfileBody(chars[bodyStart:])
	if err != nil {
		return nil, err
	}
	if flags != "" {
		source = "(?" + flags + ")" + source
	}

	re, err := regexp.Compile(source)
	if err != nil {
		return nil, err
	}
	return re, nil
}

// splitLeadingFlags consumes the leading run of (?flags) groups, returning the
// accumulated flag letters and the index at which the pattern body starts. Only
// i, s and m are recognized; anything else leaves the group in place, where
// translateProfileBody rejects it as a non-leading inline flag group.
func splitLeadingFlags(chars []rune) (string, int) {
	var flags []rune
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
			if !strings.ContainsRune(string(flags), flag) {
				flags = append(flags, flag)
			}
		}
		index = cursor + 1
	}
	return string(flags), index
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

// translateEscape translates one escape sequence into RE2 source.
func translateEscape(escaped rune, inClass bool, chars []rune, index int) (string, error) {
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
		return "\\x" + string(chars[index+2:index+4]), nil
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

// translateProfileBody walks the pattern body, translating profile constructs
// into RE2 source and rejecting anything that is not portable across the four
// SDKs. Go needs no flag argument: its `.`, `$` and `\b` already have profile
// semantics, and the leading flags are re-attached as a (?flags) prefix.
func translateProfileBody(chars []rune) (string, error) {
	n := len(chars)
	var out strings.Builder
	out.Grow(n + 16)
	inClass := false
	index := 0

	for index < n {
		c := chars[index]

		if c == '\\' {
			if index+1 >= n {
				return "", errors.New("pattern ends with a trailing backslash")
			}
			translated, err := translateEscape(chars[index+1], inClass, chars, index)
			if err != nil {
				return "", err
			}
			out.WriteString(translated)
			index += escapeLength(chars, index)
			continue
		}

		if inClass {
			if c == ']' {
				inClass = false
			}
			out.WriteRune(c)
			index++
			continue
		}

		switch c {
		case '[':
			// `[]` / `[^]` read as an empty class (a compile error) in Rust,
			// Python and Go but as "match nothing"/"match anything" in
			// JavaScript, so they are never portable.
			cursor := index + 1
			if cursor < n && chars[cursor] == '^' {
				cursor++
			}
			if cursor >= n || chars[cursor] == ']' {
				return "", errors.New("empty character classes [] and [^] are not portable across the HushSpec SDK regex engines")
			}
			inClass = true
			out.WriteRune('[')
			index++
		case '(':
			if err := inlineFlagGroupError(chars, index); err != nil {
				return "", err
			}
			// `(?<name>...)` is the JavaScript/Rust spelling; `(?P<name>...)`
			// is accepted by Rust, Python and Go alike, so normalize to it.
			if index+3 < n && chars[index+1] == '?' && chars[index+2] == '<' &&
				chars[index+3] != '=' && chars[index+3] != '!' {
				out.WriteString("(?P<")
				index += 3
				continue
			}
			out.WriteRune('(')
			index++
		default:
			out.WriteRune(c)
			index++
		}
	}

	return out.String(), nil
}
