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
//!    quantifiers are rejected (see [`crate::validate`]). The group forms are
//!    `(...)`, `(?:...)`, and the named pair `(?<name>...)` / `(?P<name>...)`,
//!    whose names are ASCII letters, digits and underscores not starting with
//!    a digit; any other `(?...)` opener is rejected.
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
//! 4. **`.` matches any scalar value except `\n`.** With a leading `(?s)` it
//!    matches everything.
//! 5. **`$` matches only at end of text** unless a leading `(?m)` is present.
//!    `^` is unchanged.
//! 6. **`(?i)` folds ASCII letters only.** Each ASCII letter is expanded into
//!    a two-member class (`s` -> `[sS]`) and no case-insensitive flag reaches
//!    the host engine, so the Unicode simple case-folding table never pulls
//!    U+017F or U+212A into a match for `s` or `k`.
//! 7. **Unanchored search semantics** -- a pattern matches if it matches
//!    anywhere in the subject.
//! 8. **Compile failure at evaluation time denies**, carrying the rule path of
//!    the offending pattern.
//!
//! A character class is a set of scalar values: an unescaped `[` inside one is
//! rejected (so POSIX bracket expressions are not mistaken for a class of
//! their own), and a range endpoint outside the Basic Multilingual Plane is
//! rejected because the SDKs cannot express such a range alike. A pattern is
//! limited to 2048 UTF-8 bytes (core spec 3.14.3).
//!
//! Escapes are restricted to the intersection the four engines agree on:
//! `\n \r \t \f \v`, `\xHH`, `\d \D \w \W \s \S \b \B`, and any escaped ASCII
//! punctuation. `\A`, `\Z`, `\z`, `\Q`, `\E`, `\p{...}`, `\P{...}`, `\uXXXX`,
//! `\0`, `\a`, `\e`, `\cX` and every other alphanumeric escape are rejected:
//! each of them is either unsupported by at least one engine or, worse,
//! silently reinterpreted as a literal by JavaScript.

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

/// Maximum size of a policy-authored pattern, in UTF-8 bytes (core spec
/// 3.14.3).
const MAX_PATTERN_BYTES: usize = 2048;

/// Shared rejection message for an over-long pattern.
const PATTERN_TOO_LONG_MESSAGE: &str =
    "pattern exceeds the HushSpec regex profile limit of 2048 bytes";

/// Shared rejection message for group openers outside the profile.
const GROUP_FORM_MESSAGE: &str = "this group form is not portable across the HushSpec SDK regex engines; the profile \
     allows (?:...), the named forms (?<name>...) and (?P<name>...), and a leading \
     inline flag group such as (?i)";

/// Shared rejection message for a malformed or non-portable group name.
const GROUP_NAME_MESSAGE: &str = "a named group's name must be ASCII letters, digits and underscores, must not start \
     with a digit, and must be closed by >";

/// Shared rejection message for an unescaped `[` inside a character class.
const NESTED_CLASS_MESSAGE: &str = "an unescaped [ inside a character class is not portable across the HushSpec SDK \
     regex engines (Rust and Go read [[:alpha:]] as a POSIX class, JavaScript and \
     Python as a literal [); escape it as \\[";

/// Shared rejection message for a class range reaching outside the BMP.
const ASTRAL_RANGE_MESSAGE: &str = "a character-class range with an endpoint outside the Basic Multilingual Plane is \
     not portable across the HushSpec SDK regex engines";

/// Shared rejection message for an empty character class.
const EMPTY_CLASS_MESSAGE: &str = "empty character classes [] and [^] are not portable across the HushSpec SDK \
     regex engines";

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
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(RegexProfileError::new(PATTERN_TOO_LONG_MESSAGE));
    }
    // Portability pre-check (possessive quantifiers, `\Z`/`\z`, `{,n}`, empty
    // classes) and the ReDoS nested-quantifier heuristic run here rather than
    // only in `validate`, so the evaluator denies on exactly the patterns the
    // validator rejects even when a caller hands `evaluate` a hand-built,
    // never-validated `HushSpec`.
    if let Some(message) = crate::validate::disallowed_regex_feature(pattern) {
        return Err(RegexProfileError::new(message));
    }
    if crate::validate::has_nested_quantifier(pattern) {
        return Err(RegexProfileError::new(NESTED_QUANTIFIER_MESSAGE));
    }

    let chars: Vec<char> = pattern.chars().collect();
    let (flags, body_start) = split_leading_flags(&chars);
    let translated = translate(&chars[body_start..], flags)?;

    // `case_insensitive` is deliberately not set: the profile folds ASCII
    // letters only, which `translate` has already done by expanding each one
    // into a two-member class.
    RegexBuilder::new(&translated)
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
    let (flags, body_start) = split_leading_flags(&chars);
    translate(&chars[body_start..], flags)
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

/// The other ASCII case of `c`, or `None` when `c` is not an ASCII letter.
fn ascii_case_counterpart(c: char) -> Option<char> {
    if c.is_ascii_lowercase() {
        Some(c.to_ascii_uppercase())
    } else if c.is_ascii_uppercase() {
        Some(c.to_ascii_lowercase())
    } else {
        None
    }
}

/// The class-body ranges that fold `lo..=hi` to its other ASCII case.
///
/// A range is emitted for the part of `lo..=hi` inside `a-z` and for the part
/// inside `A-Z`, so `[a-f]` under `(?i)` becomes `[a-fA-F]` and a range over
/// digits is left alone.
fn folded_class_range(lo: char, hi: char) -> String {
    let mut out = String::new();
    let lower_start = lo.max('a');
    let lower_end = hi.min('z');
    if lower_start <= lower_end {
        out.push(lower_start.to_ascii_uppercase());
        out.push('-');
        out.push(lower_end.to_ascii_uppercase());
    }
    let upper_start = lo.max('A');
    let upper_end = hi.min('Z');
    if upper_start <= upper_end {
        out.push(upper_start.to_ascii_lowercase());
        out.push('-');
        out.push(upper_end.to_ascii_lowercase());
    }
    out
}

/// Walk the pattern body, translating profile constructs into Rust `regex`
/// source and rejecting anything that is not portable across the four SDKs.
///
/// Rust's `.` and `$` already have profile semantics -- `.` excludes only `\n`
/// (the TypeScript SDK has to rewrite it, because JavaScript's `.` also
/// excludes `\r`, U+2028 and U+2029) and `$` is an end-of-text anchor (the
/// Python SDK rewrites it to `\Z`, because Python's `$` also matches just
/// before a trailing newline) -- so both pass through unchanged, and `(?s)` /
/// `(?m)` are applied through `RegexBuilder`. `flags.case_insensitive` is the
/// exception: it is compiled here, by expanding every ASCII letter into a
/// two-member class, because the host engine would otherwise fold with the
/// full Unicode table.
fn translate(chars: &[char], flags: ProfileFlags) -> Result<String, RegexProfileError> {
    let n = chars.len();
    let mut out = String::with_capacity(n + 16);
    let mut index = 0;

    while index < n {
        let c = chars[index];

        if c == '\\' {
            if index + 1 >= n {
                return Err(RegexProfileError::new(
                    "pattern ends with a trailing backslash",
                ));
            }
            translate_escape(
                chars[index + 1],
                false,
                flags.case_insensitive,
                chars,
                index,
                &mut out,
            )?;
            index += escape_len(chars, index);
            continue;
        }

        match c {
            '[' => {
                let (source, next) =
                    translate_character_class(chars, index, flags.case_insensitive)?;
                out.push_str(&source);
                index = next;
            }
            '(' => {
                index = translate_group(chars, index, &mut out)?;
            }
            _ => {
                match ascii_case_counterpart(c).filter(|_| flags.case_insensitive) {
                    Some(other) => {
                        out.push('[');
                        out.push(c);
                        out.push(other);
                        out.push(']');
                    }
                    None => out.push(c),
                }
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

/// Translate the group opener starting at `chars[start]`, returning the index
/// just past it.
///
/// `(`, `(?:` and the two named spellings are the profile's only group forms;
/// `(?=`, `(?!`, `(?>`, `(?#`, `(?(`, `(?R)` and `(?P=name)` are rejected here
/// rather than left to a host engine that may accept them.
fn translate_group(
    chars: &[char],
    start: usize,
    out: &mut String,
) -> Result<usize, RegexProfileError> {
    if chars.get(start + 1) != Some(&'?') {
        out.push('(');
        return Ok(start + 1);
    }
    if let Some(error) = inline_flag_group_error(chars, start) {
        return Err(error);
    }
    match chars.get(start + 2) {
        Some(':') => {
            out.push_str("(?:");
            Ok(start + 3)
        }
        // Rust `regex` accepts both named spellings; normalizing to `(?P<`
        // keeps the translated source the same shape as the Python and Go
        // SDKs', which accept only that one.
        Some('<') if !matches!(chars.get(start + 3), Some('=') | Some('!')) => {
            translate_group_name(chars, start + 3, out)
        }
        Some('P') if chars.get(start + 3) == Some(&'<') => {
            translate_group_name(chars, start + 4, out)
        }
        _ => Err(RegexProfileError::new(GROUP_FORM_MESSAGE)),
    }
}

/// Copy the group name that starts at `start` and ends at `>`, returning the
/// index just past the `>`. The name is never case-folded: it is an identifier,
/// not subject text.
fn translate_group_name(
    chars: &[char],
    start: usize,
    out: &mut String,
) -> Result<usize, RegexProfileError> {
    let mut cursor = start;
    while cursor < chars.len() && chars[cursor] != '>' {
        cursor += 1;
    }
    if cursor >= chars.len() {
        return Err(RegexProfileError::new(GROUP_NAME_MESSAGE));
    }
    let name: String = chars[start..cursor].iter().collect();
    if !is_group_name(&name) {
        return Err(RegexProfileError::new(GROUP_NAME_MESSAGE));
    }
    out.push_str("(?P<");
    out.push_str(&name);
    out.push('>');
    Ok(cursor + 1)
}

/// `[A-Za-z_][0-9A-Za-z_]*`: the group names every SDK engine accepts alike.
fn is_group_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One member of a character class: its translated source, the scalar value it
/// stands for (absent for a multi-member shorthand such as `\d`), and the
/// number of chars it spans.
struct ClassAtom {
    source: String,
    value: Option<char>,
    len: usize,
}

/// Read the class member starting at `chars[index]`.
fn read_class_atom(chars: &[char], index: usize) -> Result<ClassAtom, RegexProfileError> {
    let c = chars[index];
    if c == '\\' {
        if index + 1 >= chars.len() {
            return Err(RegexProfileError::new(
                "pattern ends with a trailing backslash",
            ));
        }
        let mut source = String::new();
        translate_escape(chars[index + 1], true, false, chars, index, &mut source)?;
        Ok(ClassAtom {
            source,
            value: escape_literal_value(chars, index),
            len: escape_len(chars, index),
        })
    } else if c == '[' {
        Err(RegexProfileError::new(NESTED_CLASS_MESSAGE))
    } else {
        Ok(ClassAtom {
            source: c.to_string(),
            value: Some(c),
            len: 1,
        })
    }
}

/// The scalar value an escape sequence stands for, or `None` when it stands for
/// a set of them. Only reached for escapes [`translate_escape`] accepted.
fn escape_literal_value(chars: &[char], index: usize) -> Option<char> {
    match chars[index + 1] {
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        'f' => Some('\u{c}'),
        'v' => Some('\u{b}'),
        'd' | 'w' | 's' => None,
        'x' => {
            let hex: String = chars[index + 2..index + 4].iter().collect();
            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
        }
        escaped => Some(escaped),
    }
}

/// Translate the character class starting at `chars[start]`, returning its Rust
/// `regex` source and the index just past its closing `]`.
///
/// Members are read one at a time so that an unescaped `[` can be refused, a
/// range can be checked for a non-BMP endpoint, and -- under `(?i)` -- both the
/// members and the ranges can be folded to their other ASCII case.
fn translate_character_class(
    chars: &[char],
    start: usize,
    case_insensitive: bool,
) -> Result<(String, usize), RegexProfileError> {
    let n = chars.len();
    let mut index = start + 1;
    let negated = chars.get(index) == Some(&'^');
    if negated {
        index += 1;
    }
    // `[]` / `[^]` are read as an empty class by Rust/Python/Go (a compile
    // error) but as "match nothing"/"match anything" by JavaScript, so they are
    // never portable.
    if index >= n || chars[index] == ']' {
        return Err(RegexProfileError::new(EMPTY_CLASS_MESSAGE));
    }

    let mut body = String::new();
    while index < n && chars[index] != ']' {
        let atom = read_class_atom(chars, index)?;
        let after = index + atom.len;
        // A `-` is a range only between two single members and never just
        // before the closing `]`, where it is a literal hyphen.
        if let Some(lo) = atom.value
            && chars.get(after) == Some(&'-')
            && after + 1 < n
            && chars[after + 1] != ']'
        {
            let high = read_class_atom(chars, after + 1)?;
            if let Some(hi) = high.value {
                if lo > '\u{ffff}' || hi > '\u{ffff}' {
                    return Err(RegexProfileError::new(ASTRAL_RANGE_MESSAGE));
                }
                body.push_str(&atom.source);
                body.push('-');
                body.push_str(&high.source);
                if case_insensitive {
                    body.push_str(&folded_class_range(lo, hi));
                }
                index = after + 1 + high.len;
                continue;
            }
        }
        body.push_str(&atom.source);
        if case_insensitive && let Some(other) = atom.value.and_then(ascii_case_counterpart) {
            body.push(other);
        }
        index = after;
    }

    let prefix = if negated { "^" } else { "" };
    if index >= n {
        // Unterminated: hand it to `regex`, whose own diagnostic names the
        // class.
        return Ok((format!("[{prefix}{body}"), index));
    }
    Ok((format!("[{prefix}{body}]"), index + 1))
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
/// `fold` asks for the profile's ASCII case folding, which applies only outside
/// a character class -- [`translate_character_class`] folds its own members.
fn translate_escape(
    escaped: char,
    in_class: bool,
    fold: bool,
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
                    let counterpart = u32::from_str_radix(&format!("{hi}{lo}"), 16)
                        .ok()
                        .and_then(char::from_u32)
                        .and_then(ascii_case_counterpart)
                        .filter(|_| fold);
                    if let Some(other) = counterpart {
                        out.push('[');
                        out.push_str("\\x");
                        out.push(hi);
                        out.push(lo);
                        out.push(other);
                        out.push(']');
                    } else {
                        out.push_str("\\x");
                        out.push(hi);
                        out.push(lo);
                    }
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
        // Arabic-Indic digits are digits to a Unicode-aware `\d`, but not to
        // the profile.
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
        assert_eq!(
            translate_for_test("(?<year>x)").unwrap(),
            translate_for_test("(?P<year>x)").unwrap()
        );
    }

    #[test]
    fn group_names_are_ascii_identifiers() {
        assert!(rejects("(?<1st>x)").contains("named group's name"));
        assert!(rejects("(?<ann\u{e9}e>x)").contains("named group's name"));
        assert!(rejects("(?<year x)").contains("named group's name"));
    }

    #[test]
    fn non_profile_group_openers_are_rejected() {
        for pattern in [
            "a(?#comment)b",
            "a(?=b)",
            "a(?!b)",
            "(?<=a)b",
            "(?<!a)b",
            "(?>a)",
            "(?(1)a|b)",
            "(?R)",
            "(?1)",
            "(?P<a>x)(?P=a)",
        ] {
            assert!(
                rejects(pattern).contains("group form"),
                "{pattern} should be refused as a group form"
            );
        }
        assert!(compile_profile_regex("(?:ab)+").is_ok());
    }

    #[test]
    fn posix_bracket_expressions_are_rejected() {
        assert!(rejects("[[:alpha:]]").contains("unescaped ["));
        assert!(rejects("[a[b]").contains("unescaped ["));
        // An escaped `[` is an ordinary class member.
        assert!(matches(r"[a\[]", "["));
    }

    #[test]
    fn open_lower_bound_quantifier_is_rejected() {
        assert!(rejects("a{,3}").contains("{,n} quantifier"));
        assert!(compile_profile_regex("a{0,3}").is_ok());
    }

    #[test]
    fn over_long_patterns_are_rejected() {
        let pattern = "a".repeat(2049);
        assert!(rejects(&pattern).contains("2048 bytes"));
        assert!(compile_profile_regex(&"a".repeat(2048)).is_ok());
    }

    #[test]
    fn class_ranges_stay_inside_the_bmp() {
        assert!(
            rejects("[\u{1F600}-\u{1F64F}]").contains("Basic Multilingual Plane"),
            "an astral range is not expressible in every SDK"
        );
        // An astral character is still an ordinary class member.
        assert!(matches("^[\u{1F600}a]$", "\u{1F600}"));
        assert!(matches("^[\u{1F600}a]$", "a"));
        assert!(!matches("^[^\u{1F600}]$", "\u{1F600}"));
        assert!(matches("^[^\u{1F600}]$", "a"));
    }

    // ---- ASCII-only case folding ----

    #[test]
    fn case_insensitive_folds_ascii_letters_only() {
        assert!(matches("(?i)stra", "STRA"));
        assert!(matches("(?i)stra", "Stra"));
        // U+017F (long s) and U+212A (Kelvin sign) simple-case-fold to ASCII
        // under the full Unicode table; the profile folds ASCII only.
        assert!(!matches("(?i)s", "\u{17f}"));
        assert!(!matches("(?i)k", "\u{212a}"));
    }

    #[test]
    fn case_insensitive_folds_class_members_and_ranges() {
        assert!(matches("(?i)^[a-f]$", "C"));
        assert!(!matches("(?i)^[a-f]$", "G"));
        assert!(matches("(?i)^[sq]$", "S"));
        assert!(!matches("(?i)^[sq]$", "\u{17f}"));
        assert!(!matches("(?i)^[^s]$", "S"));
        assert!(matches("(?i)^[^s]$", "\u{17f}"));
        // Digit ranges are untouched.
        assert_eq!(translate_for_test("(?i)[0-9]").unwrap(), "[0-9]");
    }

    #[test]
    fn case_insensitive_folds_hex_escapes_and_spares_group_names() {
        assert!(matches(r"(?i)\x41", "a"));
        assert!(matches(r"(?i)\x61", "A"));
        assert_eq!(translate_for_test("(?i)(?P<ab>c)").unwrap(), "(?P<ab>[cC])");
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
