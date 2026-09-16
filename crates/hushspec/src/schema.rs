//! Document parsing under the HushSpec YAML profile (core spec 2.4).
//!
//! `serde_yaml` already parses with the YAML 1.2 Core schema (so `yes`/`no`
//! are strings), rejects duplicate mapping keys for `deny_unknown_fields`
//! structs, and rejects tab indentation. The profile additionally forbids
//! anchors, aliases, merge keys, and multi-document streams, and bounds the
//! input size, nesting depth, and node count; those checks live here.

pub use crate::generated_models::{HushSpec, MergeStrategy};
use serde::de::Error as _;

/// Maximum accepted document size in bytes (core spec 2.4, RECOMMENDED default).
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
/// Maximum accepted nesting depth (core spec 2.4, RECOMMENDED default).
pub const MAX_DOCUMENT_DEPTH: usize = 32;
/// Maximum accepted node count (core spec 2.4, RECOMMENDED default).
pub const MAX_NODE_COUNT: usize = 100_000;

impl HushSpec {
    /// Parse a HushSpec document, enforcing the YAML profile of core spec 2.4.
    pub fn parse(yaml: &str) -> Result<Self, serde_yaml::Error> {
        if yaml.len() > MAX_DOCUMENT_BYTES {
            return Err(serde_yaml::Error::custom(format!(
                "document exceeds the maximum size of {MAX_DOCUMENT_BYTES} bytes"
            )));
        }
        if let Some(message) = yaml_profile_violation(yaml) {
            return Err(serde_yaml::Error::custom(message));
        }

        // Bound depth and node count before the typed parse; anchors and
        // aliases are already rejected above, so this cannot blow up.
        let value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
        let (depth, nodes) = measure(&value, 1);
        if depth > MAX_DOCUMENT_DEPTH {
            return Err(serde_yaml::Error::custom(format!(
                "document nesting exceeds the maximum depth of {MAX_DOCUMENT_DEPTH}"
            )));
        }
        if nodes > MAX_NODE_COUNT {
            return Err(serde_yaml::Error::custom(format!(
                "document exceeds the maximum node count of {MAX_NODE_COUNT}"
            )));
        }

        // A written `null` deserializes into `None`, so the typed document
        // cannot tell one from an absent key; the raw value tree can, and a
        // document that writes one is not the document the typed parse below
        // would report on.
        if let Err(message) = crate::raw_validate::reject_null_properties(&value) {
            return Err(serde_yaml::Error::custom(message));
        }

        serde_yaml::from_str(yaml)
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

fn measure(value: &serde_yaml::Value, depth: usize) -> (usize, usize) {
    match value {
        serde_yaml::Value::Sequence(items) => items.iter().fold((depth, 1), |(d, n), item| {
            let (id, inn) = measure(item, depth + 1);
            (d.max(id), n + inn)
        }),
        serde_yaml::Value::Mapping(map) => map.iter().fold((depth, 1), |(d, n), (key, item)| {
            let (kd, kn) = measure(key, depth + 1);
            let (id, inn) = measure(item, depth + 1);
            (d.max(kd).max(id), n + kn + inn)
        }),
        serde_yaml::Value::Tagged(tagged) => {
            let (d, n) = measure(&tagged.value, depth + 1);
            (d, n + 1)
        }
        _ => (depth, 1),
    }
}

/// Scan the raw text for constructs the YAML profile forbids: a second
/// document, anchors (`&name`), aliases (`*name`), and merge keys (`<<:`).
///
/// The scanner tracks comments, quoted scalars, and block scalars so that a
/// `*` or `&` inside them is not mistaken for an indicator. In YAML a plain
/// scalar cannot begin with `&` or `*`, so an indicator at a node-start
/// position is always an anchor or alias.
pub fn yaml_profile_violation(yaml: &str) -> Option<String> {
    let mut block_scalar_indent: Option<usize> = None;
    let mut saw_content = false;
    let mut line_number = 0usize;

    for line in yaml.lines() {
        line_number += 1;
        let indent = line.chars().take_while(|c| *c == ' ').count();
        let trimmed = line.trim();

        if let Some(min_indent) = block_scalar_indent {
            if trimmed.is_empty() || indent >= min_indent {
                continue;
            }
            block_scalar_indent = None;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "---" || trimmed.starts_with("--- ") {
            if saw_content {
                return Some(format!(
                    "line {line_number}: multi-document streams are not allowed (YAML profile)"
                ));
            }
            continue;
        }
        if trimmed == "..." {
            saw_content = true;
            continue;
        }
        saw_content = true;

        if let Some(message) = scan_line(line, line_number) {
            return Some(message);
        }
        if line_starts_block_scalar(line) {
            block_scalar_indent = Some(indent + 1);
        }
    }
    None
}

/// Whether the line's value (outside quotes and comments) ends with a block
/// scalar indicator (`|`, `>`, with optional chomping/indentation modifiers).
fn line_starts_block_scalar(line: &str) -> bool {
    let code = strip_comment_and_quotes(line);
    let code = code.trim_end();
    let Some(last_space) = code.rfind(' ') else {
        return false;
    };
    let token = &code[last_space + 1..];
    let mut chars = token.chars();
    matches!(chars.next(), Some('|' | '>'))
        && chars.all(|c| c == '+' || c == '-' || c.is_ascii_digit())
        && code[..last_space].trim_end().ends_with([':', '-'])
}

/// Replace quoted scalars with spaces and drop trailing comments so indicator
/// scanning only sees structural text.
fn strip_comment_and_quotes(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_space = true;
    while let Some(c) = chars.next() {
        if in_double {
            if c == '\\' {
                chars.next();
                out.push(' ');
                out.push(' ');
                continue;
            }
            if c == '"' {
                in_double = false;
            }
            out.push(' ');
            continue;
        }
        if in_single {
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    out.push(' ');
                    out.push(' ');
                    continue;
                }
                in_single = false;
            }
            out.push(' ');
            continue;
        }
        match c {
            '"' => {
                in_double = true;
                out.push(' ');
            }
            '\'' => {
                in_single = true;
                out.push(' ');
            }
            '#' if prev_space => break,
            _ => out.push(c),
        }
        prev_space = c == ' ';
    }
    out
}

fn scan_line(line: &str, line_number: usize) -> Option<String> {
    let code = strip_comment_and_quotes(line);
    let bytes = code.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        if byte != b'&' && byte != b'*' && byte != b'<' {
            continue;
        }
        let next_is_word = bytes
            .get(index + 1)
            .is_some_and(|b| !b.is_ascii_whitespace() && *b != b',' && *b != b']' && *b != b'}');
        let at_node_start = index == 0
            || matches!(bytes[index - 1], b' ' | b'[' | b'{' | b',' | b'\t')
                && (index < 2
                    || bytes[..index]
                        .iter()
                        .rev()
                        .find(|b| **b != b' ')
                        .is_none_or(|b| matches!(b, b':' | b'-' | b'?' | b'[' | b'{' | b',')));
        if !at_node_start {
            continue;
        }
        match byte {
            b'&' if next_is_word => {
                return Some(format!(
                    "line {line_number}: anchors are not allowed (YAML profile)"
                ));
            }
            b'*' if next_is_word => {
                return Some(format!(
                    "line {line_number}: aliases are not allowed (YAML profile)"
                ));
            }
            b'<' if code[index..].starts_with("<<") => {
                let rest = code[index + 2..].trim_start();
                if rest.starts_with(':') {
                    return Some(format!(
                        "line {line_number}: merge keys are not allowed (YAML profile)"
                    ));
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_documents_pass_the_profile() {
        let yaml = "hushspec: \"0.2.0\"\nname: a*b & c\nrules:\n  egress:\n    allow: [\"*.example.com\", \"**.x\"]\n    default: block\n";
        assert_eq!(yaml_profile_violation(yaml), None);
        assert!(HushSpec::parse(yaml).is_ok());
    }

    #[test]
    fn anchors_and_aliases_are_rejected() {
        let yaml = "hushspec: \"0.2.0\"\nrules:\n  forbidden_paths:\n    patterns: &secrets\n      - \"**/.env\"\n    exceptions: *secrets\n";
        let message = yaml_profile_violation(yaml).unwrap();
        assert!(message.contains("anchors"), "{message}");
        assert!(HushSpec::parse(yaml).is_err());
    }

    #[test]
    fn merge_keys_are_rejected() {
        let yaml = "hushspec: \"0.2.0\"\nrules:\n  egress:\n    <<: {default: block}\n";
        let message = yaml_profile_violation(yaml).unwrap();
        assert!(message.contains("merge keys"), "{message}");
    }

    #[test]
    fn multi_document_streams_are_rejected() {
        let yaml = "hushspec: \"0.2.0\"\nname: first\n---\nhushspec: \"0.2.0\"\nname: second\n";
        assert!(
            yaml_profile_violation(yaml)
                .unwrap()
                .contains("multi-document")
        );
        assert!(HushSpec::parse(yaml).is_err());
        // A leading directive-end marker on its own is fine.
        assert_eq!(yaml_profile_violation("---\nhushspec: \"0.2.0\"\n"), None);
    }

    #[test]
    fn indicators_inside_scalars_are_not_flagged() {
        let yaml = "hushspec: \"0.2.0\"\ndescription: |\n  * bullet\n  & ampersand\nname: \"*not-an-alias\"\nrules:\n  shell_commands:\n    forbidden_patterns:\n      - 'rm *'\n      - \"a&b\"\n";
        assert_eq!(yaml_profile_violation(yaml), None);
    }

    #[test]
    fn yaml_1_1_booleans_are_strings() {
        let yaml = "hushspec: \"0.2.0\"\nrules:\n  egress:\n    enabled: yes\n";
        assert!(HushSpec::parse(yaml).is_err());
    }

    #[test]
    fn oversized_documents_are_rejected() {
        let yaml = format!(
            "hushspec: \"0.2.0\"\nname: \"{}\"\n",
            "x".repeat(MAX_DOCUMENT_BYTES)
        );
        assert!(HushSpec::parse(&yaml).is_err());
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let mut yaml = String::from("hushspec: \"0.2.0\"\nrules:\n  shell_commands:\n    when:\n");
        let mut indent = 6;
        for _ in 0..40 {
            yaml.push_str(&format!("{}not:\n", " ".repeat(indent)));
            indent += 2;
        }
        yaml.push_str(&format!("{}context: {{a: 1}}\n", " ".repeat(indent)));
        assert!(HushSpec::parse(&yaml).is_err());
    }
}
