//! The **HushSpec regex profile**: the one regex dialect every HushSpec engine
//! must implement, so a user-authored pattern in `secret_patterns`,
//! `patch_integrity.forbidden_patterns`, or `shell_commands.forbidden_patterns`
//! produces the *same* decision in Rust, TypeScript, Python, and Go.
//!
//! The four SDK engines (Rust `regex`, JavaScript `RegExp`, Python `re`, Go
//! RE2) agree on syntax but disagree on semantics, so the profile is defined
//! once here and reached by *translating* the author's pattern into an
//! equivalent pattern in each host dialect before compiling it. The same
//! translation runs in `validate` and in `evaluate`, so the two can never
//! disagree about what a pattern means.
//!
//! # Profile (normative summary; keep in sync with the other three SDKs)
//!
//! 1. **Syntax is RE2-class.** Lookaround, backreferences, possessive
//!    quantifiers, atomic/conditional/recursive groups, and nested unbounded
//!    quantifiers are rejected (see [`crate::validate`]).
//! 2. **Inline flags only as a leading group.** `(?i)`, `(?s)`, `(?m)`, `(?is)`
//!    at the very start of the pattern (one or more consecutive groups). An
//!    inline flag group anywhere else -- including the scoped form `(?i:...)`
//!    and negations like `(?-i)` -- is an error in all four SDKs.
//! 3. **`\d \w \s \b` and their negations are ASCII-only**:
//!    `\d` = `[0-9]`, `\w` = `[0-9A-Za-z_]`, `\s` = `[\t\n\v\f\r ]` (includes
//!    the vertical tab, excludes NBSP and the Unicode space separators), and
//!    `\b`/`\B` are boundaries under that ASCII `\w`. They are *translated*,
//!    not rejected, including inside character classes (`[\d_]` -> `[0-9_]`).
//!    The negated shorthands `\D \W \S` and the boundaries `\b \B` cannot be
//!    expressed as character-class members, so they are rejected *inside* a
//!    class.
//! 4. **`.` matches any character except `\n`.** With a leading `(?s)` it
//!    matches everything.
//! 5. **`$` matches only at end of text** unless a leading `(?m)` is present.
//!    `^` is unchanged.
//! 6. **Unanchored search semantics** -- a pattern matches if it matches
//!    anywhere in the subject.
//! 7. **Compile failure at evaluation time denies**, carrying the rule path of
//!    the offending pattern.
//!
//! Escapes are restricted to the intersection the four engines agree on:
//! `\n \r \t \f \v`, `\xHH`, `\d \D \w \W \s \S \b \B`, and any escaped ASCII
//! punctuation. `\A`, `\Z`, `\z`, `\Q`, `\E`, `\p{...}`, `\P{...}`, `\uXXXX`,
//! `\0`, `\a`, `\e`, `\cX` and every other alphanumeric escape are rejected:
//! each of them is either unsupported by at least one engine or, worse,
//! silently reinterpreted as a literal by JavaScript.
//!
//! # Known, deliberate residual divergence
//!
//! Under a leading `(?i)`, Rust `regex` and Go RE2 case-fold using the full
//! Unicode simple case-folding table, while JavaScript `RegExp` (no `u` flag)
//! and Python `re` compiled with `re.ASCII` fold only ASCII. A pattern such as
//! `(?i)stra(ss|ß)e` can therefore match differently across SDKs. Use explicit
//! alternations instead of `(?i)` when a pattern must fold non-ASCII letters.
//! `.` also matches a single UTF-16 code unit in JavaScript versus a single
//! code point in the other three, so a pattern using `.` against astral-plane
//! text (emoji) can differ.

use regex::{Regex, RegexBuilder};
use std::fmt;

/// Character-class body for ASCII `\d`.
const DIGIT_BODY: &str = "0-9";
/// Character-class body for ASCII `\w`.
const WORD_BODY: &str = "0-9A-Za-z_";
/// Character-class body for ASCII `\s`. Includes `\v` (U+000B) and excludes
/// NBSP/Unicode space separators, which JavaScript's `\s` would otherwise
/// include and Go's RE2 `\s` would otherwise omit.
const SPACE_BODY: &str = r"\t\n\v\f\r ";

/// Shared rejection message for nested unbounded quantifiers. Kept identical to
/// the message `validate` reports and to the other three SDKs.
pub(crate) const NESTED_QUANTIFIER_MESSAGE: &str = "pattern contains a nested unbounded quantifier (e.g. (a+)+) \
     that can cause catastrophic backtracking (ReDoS)";

/// A pattern that is not expressible in the HushSpec regex profile, or that the
/// host engine rejected after translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexProfileError {
    message: String,
}

impl RegexProfileError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The human-readable reason the pattern was rejected.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RegexProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RegexProfileError {}

/// Flags carried by a leading inline flag group.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProfileFlags {
    case_insensitive: bool,
    dot_all: bool,
    multi_line: bool,
}

/// Compile `pattern` under the HushSpec regex profile.
///
/// This is the *only* way policy-authored regexes are compiled in this crate:
/// both [`crate::validate`] and [`crate::evaluate`] route through it so
/// validation and evaluation can never disagree.
pub fn compile_profile_regex(pattern: &str) -> Result<Regex, RegexProfileError> {
    // Portability pre-check (possessive quantifiers, `\Z`/`\z`, empty classes)
    // and the ReDoS nested-quantifier heuristic run here rather than only in
    // `validate`, so the evaluator denies on exactly the patterns the validator
    // rejects even when a caller hands `evaluate` a hand-built, never-validated
    // `HushSpec`.
    if let Some(message) = crate::validate::disallowed_regex_feature(pattern) {
        return Err(RegexProfileError::new(message));
    }
    if crate::validate::has_nested_quantifier(pattern) {
        return Err(RegexProfileError::new(NESTED_QUANTIFIER_MESSAGE));
    }

    let chars: Vec<char> = pattern.chars().collect();
    let (flags, body_start) = split_leading_flags(&chars);
    let translated = translate(&chars[body_start..])?;

    RegexBuilder::new(&translated)
        .case_insensitive(flags.case_insensitive)
        .dot_matches_new_line(flags.dot_all)
        .multi_line(flags.multi_line)
        .build()
        .map_err(|error| RegexProfileError::new(error.to_string()))
}

/// Translate `pattern` into its profile-equivalent Rust `regex` source without
/// compiling it. Exposed for the cross-SDK translator tests.
#[cfg(test)]
fn translate_for_test(pattern: &str) -> Result<String, RegexProfileError> {
    let chars: Vec<char> = pattern.chars().collect();
    let (_, body_start) = split_leading_flags(&chars);
    translate(&chars[body_start..])
}

/// Consume the leading run of `(?flags)` groups, returning the accumulated
/// flags and the index at which the pattern body starts. Only `i`, `s`, and `m`
/// are recognized; anything else leaves the group in place, where [`translate`]
/// rejects it as a non-leading inline flag group.
fn split_leading_flags(chars: &[char]) -> (ProfileFlags, usize) {
    let mut flags = ProfileFlags::default();
    let mut index = 0;
    while index + 2 < chars.len() && chars[index] == '(' && chars[index + 1] == '?' {
        let mut cursor = index + 2;
        let start = cursor;
        while cursor < chars.len() && matches!(chars[cursor], 'i' | 's' | 'm') {
            cursor += 1;
        }
        if cursor == start || cursor >= chars.len() || chars[cursor] != ')' {
            break;
        }
        for flag in &chars[start..cursor] {
            match flag {
                'i' => flags.case_insensitive = true,
                's' => flags.dot_all = true,
                'm' => flags.multi_line = true,
                _ => unreachable!("only i/s/m are accepted above"),
            }
        }
        index = cursor + 1;
    }
    (flags, index)
}

/// True for characters that can appear inside an inline flag group. Used only
/// to *detect* such a group so it can be rejected when it is not leading.
fn is_inline_flag_char(c: char) -> bool {
    matches!(c, 'i' | 'm' | 's' | 'x' | 'u' | 'U' | 'a' | 'L' | 'n' | '-')
}

/// Walk the pattern body, translating profile constructs into Rust `regex`
/// source and rejecting anything that is not portable across the four SDKs.
///
/// Unlike the TypeScript and Python translators this one needs no flag
/// argument: Rust's `.` and `$` already have profile semantics, and `(?s)` /
/// `(?m)` are applied through `RegexBuilder` instead of by rewriting.
fn translate(chars: &[char]) -> Result<String, RegexProfileError> {
    let n = chars.len();
    let mut out = String::with_capacity(n + 16);
    let mut in_class = false;
    let mut index = 0;

    while index < n {
        let c = chars[index];

        if c == '\\' {
            if index + 1 >= n {
                return Err(RegexProfileError::new(
                    "pattern ends with a trailing backslash",
                ));
            }
            translate_escape(chars[index + 1], in_class, chars, index, &mut out)?;
            index += escape_len(chars, index);
            continue;
        }

        if in_class {
            if c == ']' {
                in_class = false;
            }
            out.push(c);
            index += 1;
            continue;
        }

        match c {
            '[' => {
                // `[]` / `[^]` are read as an empty class by Rust/Python/Go
                // (a compile error) but as "match nothing"/"match anything" by
                // JavaScript, so they are never portable.
                let mut cursor = index + 1;
                if cursor < n && chars[cursor] == '^' {
                    cursor += 1;
                }
                if cursor >= n || chars[cursor] == ']' {
                    return Err(RegexProfileError::new(
                        "empty character classes [] and [^] are not portable across the \
                         HushSpec SDK regex engines",
                    ));
                }
                in_class = true;
                out.push('[');
                index += 1;
            }
            '(' => {
                if let Some(error) = inline_flag_group_error(chars, index) {
                    return Err(error);
                }
                out.push('(');
                index += 1;
            }
            '.' => {
                // Rust `.` already excludes `\n`, and `dot_matches_new_line`
                // carries a leading `(?s)`, so no rewrite is needed here. The
                // TypeScript SDK rewrites `.` to `[^\n]` because JavaScript's
                // `.` also excludes `\r`, U+2028 and U+2029.
                out.push('.');
                index += 1;
            }
            '$' => {
                // Rust `$` is already an end-of-text anchor without `(?m)`.
                // The Python SDK rewrites it to `\Z`, because Python's `$` also
                // matches just before a trailing newline.
                out.push('$');
                index += 1;
            }
            _ => {
                out.push(c);
                index += 1;
            }
        }
    }

    Ok(out)
}

/// Number of chars consumed by the escape sequence starting at `index`
/// (the backslash included).
fn escape_len(chars: &[char], index: usize) -> usize {
    if chars.get(index + 1) == Some(&'x') {
        4
    } else {
        2
    }
}

/// Reject `(?flags)` and `(?flags:...)` groups outside the leading position.
fn inline_flag_group_error(chars: &[char], index: usize) -> Option<RegexProfileError> {
    if chars.get(index + 1) != Some(&'?') {
        return None;
    }
    let mut cursor = index + 2;
    let start = cursor;
    while cursor < chars.len() && is_inline_flag_char(chars[cursor]) {
        cursor += 1;
    }
    if cursor == start {
        return None;
    }
    match chars.get(cursor) {
        Some(')') | Some(':') => Some(RegexProfileError::new(
            "inline flags are only allowed as a leading group such as (?i), (?s), (?m) or (?is); \
             a flag group elsewhere in the pattern is not portable across the HushSpec SDK regex \
             engines",
        )),
        _ => None,
    }
}

/// Translate one escape sequence. `escaped` is the character after the
/// backslash; `chars`/`index` are supplied so `\xHH` can read its digits.
fn translate_escape(
    escaped: char,
    in_class: bool,
    chars: &[char],
    index: usize,
    out: &mut String,
) -> Result<(), RegexProfileError> {
    match escaped {
        'd' | 'w' | 's' => {
            let body = match escaped {
                'd' => DIGIT_BODY,
                'w' => WORD_BODY,
                _ => SPACE_BODY,
            };
            if in_class {
                out.push_str(body);
            } else {
                out.push('[');
                out.push_str(body);
                out.push(']');
            }
            Ok(())
        }
        'D' | 'W' | 'S' => {
            if in_class {
                return Err(RegexProfileError::new(format!(
                    "\\{escaped} is not portable inside a character class; a negated shorthand \
                     cannot be expressed as a class member"
                )));
            }
            let body = match escaped {
                'D' => DIGIT_BODY,
                'W' => WORD_BODY,
                _ => SPACE_BODY,
            };
            out.push_str("[^");
            out.push_str(body);
            out.push(']');
            Ok(())
        }
        'b' | 'B' => {
            if in_class {
                return Err(RegexProfileError::new(format!(
                    "\\{escaped} is not portable inside a character class (JavaScript and Python \
                     read it as a backspace; Rust and Go reject it)"
                )));
            }
            // `(?-u:\b)` pins Rust's word boundary to the profile's ASCII `\w`;
            // JavaScript, Python (`re.ASCII`) and Go RE2 are ASCII already.
            out.push_str(if escaped == 'b' {
                r"(?-u:\b)"
            } else {
                r"(?-u:\B)"
            });
            Ok(())
        }
        'A' | 'Z' | 'z' => Err(RegexProfileError::new(format!(
            "\\{escaped} is not portable across the HushSpec SDK regex engines (JavaScript reads \
             it as a literal letter); anchor with ^ and $"
        ))),
        'Q' | 'E' => Err(RegexProfileError::new(
            "\\Q ... \\E literal spans are not portable across the HushSpec SDK regex engines; \
             escape the literal characters individually",
        )),
        'p' | 'P' => Err(RegexProfileError::new(format!(
            "Unicode property escapes (\\{escaped}) are not portable across the HushSpec SDK \
             regex engines; spell the character class out"
        ))),
        'x' => {
            let hi = chars.get(index + 2).copied();
            let lo = chars.get(index + 3).copied();
            match (hi, lo) {
                (Some(hi), Some(lo)) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                    out.push_str("\\x");
                    out.push(hi);
                    out.push(lo);
                    Ok(())
                }
                _ => Err(RegexProfileError::new(
                    "\\x must be followed by exactly two hex digits (\\x41); the braced form \
                     \\x{...} is not portable across the HushSpec SDK regex engines",
                )),
            }
        }
        'n' | 'r' | 't' | 'f' | 'v' => {
            out.push('\\');
            out.push(escaped);
            Ok(())
        }
        _ if escaped.is_ascii_alphanumeric() || escaped == '_' => Err(RegexProfileError::new(
            format!("\\{escaped} is not a HushSpec regex profile escape"),
        )),
        _ if escaped.is_ascii() => {
            out.push('\\');
            out.push(escaped);
            Ok(())
        }
        _ => Err(RegexProfileError::new(format!(
            "escaping the non-ASCII character '{escaped}' is not portable across the HushSpec \
             SDK regex engines"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, haystack: &str) -> bool {
        compile_profile_regex(pattern)
            .unwrap_or_else(|error| panic!("{pattern} should compile: {error}"))
            .is_match(haystack)
    }

    fn rejects(pattern: &str) -> String {
        compile_profile_regex(pattern)
            .map(|_| String::new())
            .expect_err(&format!("{pattern} should be rejected"))
            .message()
            .to_string()
    }

    // ---- the six cross-SDK divergences the profile closes ----

    #[test]
    fn digit_shorthand_is_ascii_only() {
        assert!(matches(r"key\d{3}", "key123"));
        // Arabic-Indic digits: Rust's Unicode `\d` used to match these.
        assert!(!matches(r"key\d{3}", "key\u{661}\u{662}\u{663}"));
    }

    #[test]
    fn word_shorthand_is_ascii_only() {
        assert!(matches(r"\w+", "abc_123"));
        assert!(!matches(r"^\w$", "\u{e9}"));
    }

    #[test]
    fn dollar_is_end_of_text_only() {
        assert!(matches("token$", "token"));
        assert!(!matches("token$", "token\n"));
        assert!(matches("(?m)token$", "token\nmore"));
        // Only `\n` breaks a line: JavaScript's `m` flag would also break at
        // `\r`, U+2028 and U+2029, so the TypeScript SDK spells `(?m)` out.
        assert!(!matches("(?m)token$", "token\rmore"));
        assert!(matches("(?m)^more", "token\nmore"));
        assert!(!matches("(?m)^more", "token\rmore"));
    }

    #[test]
    fn word_boundary_is_ascii() {
        // ASCII `\b` sees a boundary between `é` and `f`, so `\bfoo` matches
        // "éfoo" -- but `\bfoo\b` still needs the trailing boundary.
        assert!(matches(r"\bfoo", "\u{e9}foo"));
        assert!(matches(r"\bfoo\b", "\u{e9}foo"));
        assert!(!matches(r"\bfoo\b", "foobar"));
        assert!(matches(r"\Bfoo", "barfoo"));
    }

    #[test]
    fn dot_excludes_only_newline() {
        assert!(matches("a.b", "a\rb"));
        assert!(!matches("a.b", "a\nb"));
        assert!(matches("(?s)a.b", "a\nb"));
        // `.` consumes one code point, astral included.
        assert!(matches("^a.b$", "a\u{1F600}b"));
    }

    #[test]
    fn space_shorthand_is_ascii_and_includes_vertical_tab() {
        assert!(matches(r"a\sb", "a\u{b}b"));
        assert!(matches(r"a\sb", "a b"));
        assert!(matches(r"a\sb", "a\tb"));
        // NBSP is not ASCII whitespace.
        assert!(!matches(r"a\sb", "a\u{a0}b"));
        assert!(!matches(r"a\Sb", "a b"));
        assert!(matches(r"a\Sb", "axb"));
    }

    #[test]
    fn mid_pattern_inline_flags_are_rejected() {
        assert!(compile_profile_regex("(?i)foobar").is_ok());
        assert!(compile_profile_regex("(?is)foobar").is_ok());
        assert!(compile_profile_regex("(?i)(?m)foobar").is_ok());
        assert!(rejects("foo(?i)bar").contains("leading group"));
        assert!(rejects("(?i:foo)").contains("leading group"));
        assert!(rejects("foo(?-i)bar").contains("leading group"));
        assert!(rejects("(?i)foo(?s)bar").contains("leading group"));
    }

    // ---- escaping edge cases ----

    #[test]
    fn escaped_backslash_is_not_a_shorthand() {
        // `\\d` is a literal backslash followed by `d`, never `[0-9]`.
        assert_eq!(translate_for_test(r"\\d").unwrap(), r"\\d");
        assert!(matches(r"\\d", "\\d"));
        assert!(!matches(r"\\d", "5"));
    }

    #[test]
    fn shorthands_inside_character_classes_are_expanded() {
        assert_eq!(translate_for_test(r"[\d_]").unwrap(), "[0-9_]");
        assert_eq!(translate_for_test(r"[\w-]").unwrap(), "[0-9A-Za-z_-]");
        assert_eq!(translate_for_test(r"[\s]").unwrap(), r"[\t\n\v\f\r ]");
        assert!(matches(r"[\d_]+", "_1"));
        assert!(!matches(r"^[\d_]+$", "\u{661}"));
    }

    #[test]
    fn escaped_bracket_stays_literal() {
        assert!(matches(r"[\]]", "]"));
        assert!(matches(r"a\[b", "a[b"));
        assert_eq!(translate_for_test(r"[\]]").unwrap(), r"[\]]");
    }

    #[test]
    fn negated_shorthands_and_boundaries_are_rejected_inside_classes() {
        assert!(rejects(r"[\D]").contains("character class"));
        assert!(rejects(r"[\W]").contains("character class"));
        assert!(rejects(r"[a\S]").contains("character class"));
        assert!(rejects(r"[\b]").contains("character class"));
        assert!(rejects(r"[\B]").contains("character class"));
    }

    #[test]
    fn non_portable_escapes_are_rejected() {
        assert!(rejects(r"\Qa.b\E").contains("\\Q"));
        assert!(rejects(r"\Afoo").contains("anchor with"));
        assert!(rejects(r"foo\Z").contains("anchor with"));
        assert!(rejects(r"foo\z").contains("anchor with"));
        assert!(rejects(r"\p{L}").contains("Unicode property"));
        assert!(rejects(r"\P{L}").contains("Unicode property"));
        assert!(rejects(r"\u00a0").contains("profile escape"));
        assert!(rejects(r"\a").contains("profile escape"));
        assert!(rejects(r"\0").contains("profile escape"));
        assert!(rejects(r"a\x{41}").contains("two hex digits"));
        assert!(rejects("foo\\").contains("trailing backslash"));
        assert!(rejects("\\\u{e9}").contains("non-ASCII"));
    }

    #[test]
    fn supported_escapes_survive() {
        assert!(matches(r"a\x41b", "aAb"));
        assert!(matches(r"a\tb", "a\tb"));
        assert!(matches(r"a\vb", "a\u{b}b"));
        assert!(matches(r"a\.b", "a.b"));
        assert!(!matches(r"a\.b", "axb"));
        assert!(matches(r"a\-b", "a-b"));
    }

    #[test]
    fn empty_character_classes_are_rejected() {
        assert!(rejects("[]").contains("empty character class"));
        assert!(rejects("[^]").contains("empty character class"));
    }

    #[test]
    fn both_named_group_spellings_are_accepted() {
        // Rust `regex` takes both; the TypeScript SDK rewrites `(?P<` to `(?<`
        // and the Python and Go SDKs rewrite `(?<` to `(?P<`, so a policy can
        // use either spelling in any SDK.
        assert!(matches("(?P<year>[0-9]{4})", "in 2026"));
        assert!(matches("(?<year>[0-9]{4})", "in 2026"));
    }

    #[test]
    fn library_patterns_still_compile_and_match() {
        assert!(matches(
            r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
            "ssn 123-45-6789."
        ));
        assert!(matches("(AKIA|ASIA)[0-9A-Z]{16}", "AKIA1234567890ABCDEF"));
        assert!(matches(
            r"(?i)\b(mrn|medical[ \t\n\r\f_-]?record)[ \t\n\r\f]*:?[ \t\n\r\f]*[A-Z0-9]{6,15}\b",
            "MRN: AB12345",
        ));
    }
}
