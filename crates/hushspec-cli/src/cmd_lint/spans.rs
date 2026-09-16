//! Source positions for lint findings.
//!
//! `serde_yaml` throws positions away the moment a document deserializes, so
//! there is no way to ask the parsed [`HushSpec`](hushspec::HushSpec) where any
//! of its values came from. This module re-scans the same bytes with
//! `saphyr-parser`'s event stream, which carries a start/end [`Marker`] for
//! every token, and builds a map from *document path* (`rules.egress.allow[1]`,
//! `extensions.posture.states.locked`) to the position of the offending key or
//! list item.
//!
//! A real YAML event stream is used rather than a line scanner on purpose: the
//! shipped policies use quoted keys, block scalars, flow sequences (`[]`),
//! comments between entries and multi-line strings, all of which a
//! `grep`-shaped indexer gets wrong. The parser has already agreed with
//! `serde_yaml` about the document's structure by the time a span map is built
//! -- span maps are only ever constructed for text that already parsed into a
//! `HushSpec` -- so the path the events walk is the same path the model
//! describes.
//!
//! Paths use the same grammar the lint checks already emit in `location`:
//! mapping keys joined with `.`, sequence entries suffixed with `[index]`. Keys
//! that themselves contain a `.` are therefore ambiguous; the model's keys
//! (rule-block names, posture state names) are not expected to, and a lookup
//! miss degrades to "no span", never to a wrong span for a different finding.

use saphyr_parser::{Event, Marker, Parser, Span as YamlSpan};
use std::collections::HashMap;

/// A source position range in SARIF's `region` convention: `line`/`column` are
/// 1-based and inclusive, `end_line`/`end_column` are 1-based with the end
/// column pointing at the character *after* the region.
///
/// `saphyr`'s own markers are 1-based for lines but 0-based for columns (its
/// `Marker::col` doc says otherwise; the value does not), so every column
/// crosses this boundary exactly once, here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Span {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) end_line: usize,
    pub(crate) end_column: usize,
}

impl Span {
    fn between(start: Marker, end: Marker) -> Self {
        let mut span = Span {
            line: start.line().max(1),
            column: start.col() + 1,
            end_line: end.line().max(1),
            end_column: end.col() + 1,
        };
        // saphyr's end marker is exclusive, and an empty/degenerate range would
        // make a SARIF region invalid (`endColumn` must be >= `startColumn` on
        // the same line). Clamp rather than drop the span.
        if span.end_line < span.line {
            span.end_line = span.line;
            span.end_column = span.column;
        } else if span.end_line == span.line && span.end_column < span.column {
            span.end_column = span.column;
        }
        span
    }
}

/// Document path -> position of the key (for mapping entries) or of the entry
/// itself (for sequence items).
#[derive(Debug, Default)]
pub(crate) struct SpanMap {
    entries: HashMap<String, Span>,
}

impl SpanMap {
    /// Build a span map for one YAML document. A stream error yields whatever
    /// was collected before the failure: spans are a reporting nicety, and a
    /// missing one must never turn a finding into an error.
    pub(crate) fn build(yaml: &str) -> Self {
        let mut collector = Collector::default();
        let mut parser = Parser::new_from_str(yaml);
        while let Some(event) = parser.next_event() {
            match event {
                Ok((Event::StreamEnd, _)) => break,
                Ok((event, span)) => collector.on_event(&event, span),
                Err(_) => break,
            }
        }
        SpanMap {
            entries: collector.spans,
        }
    }

    pub(crate) fn get(&self, path: &str) -> Option<Span> {
        self.entries.get(path).copied()
    }

    /// The span for `path`, or for the nearest ancestor that has one. A finding
    /// about `rules.egress.allow[7]` in a document that writes the list inline
    /// still lands on `rules.egress.allow`, and one about a key the parser
    /// never saw (an inherited default, say) lands on its enclosing block.
    pub(crate) fn nearest(&self, path: &str) -> Option<Span> {
        if let Some(span) = self.get(path) {
            return Some(span);
        }
        let mut rest = path;
        while let Some(cut) = rest.rfind(['.', '[']) {
            rest = &rest[..cut];
            if rest.is_empty() {
                break;
            }
            if let Some(span) = self.get(rest) {
                return Some(span);
            }
        }
        None
    }
}

/// One open container in the event stream.
enum Frame {
    /// A mapping. `key` holds the pending key between a key event and its
    /// value event (YAML mapping events strictly alternate).
    Map {
        path: String,
        key: Option<(String, YamlSpan)>,
    },
    Seq {
        path: String,
        index: usize,
    },
}

#[derive(Default)]
struct Collector {
    stack: Vec<Frame>,
    spans: HashMap<String, Span>,
}

impl Collector {
    fn on_event(&mut self, event: &Event<'_>, span: YamlSpan) {
        match event {
            Event::Scalar(value, ..) => {
                if let Some(Frame::Map { key, .. }) = self.stack.last_mut()
                    && key.is_none()
                {
                    *key = Some((value.to_string(), span));
                    return;
                }
                self.record_value(span, true);
            }
            Event::Alias(_) => {
                self.record_value(span, true);
            }
            Event::MappingStart(..) => {
                let path = self.record_value(span, false);
                self.stack.push(Frame::Map {
                    path: path.unwrap_or_default(),
                    key: None,
                });
            }
            Event::SequenceStart(..) => {
                let path = self.record_value(span, false);
                self.stack.push(Frame::Seq {
                    path: path.unwrap_or_default(),
                    index: 0,
                });
            }
            Event::MappingEnd | Event::SequenceEnd => {
                self.stack.pop();
            }
            _ => {}
        }
    }

    /// Consume the slot the current container is waiting to fill, record its
    /// span and return its path.
    ///
    /// `value_is_scalar` decides the end marker: a scalar's own end is exactly
    /// the end of the offending text, while a nested block's end is the end of
    /// the whole block -- accurate but useless for pointing a reader at the
    /// problem, so a block reports the end of its key instead.
    fn record_value(&mut self, value: YamlSpan, value_is_scalar: bool) -> Option<String> {
        let (path, span) = match self.stack.last_mut() {
            Some(Frame::Map { path, key }) => {
                let (name, key_span) = key.take()?;
                let child = join(path, &name);
                let end = if value_is_scalar {
                    value.end
                } else {
                    key_span.end
                };
                (child, Span::between(key_span.start, end))
            }
            Some(Frame::Seq { path, index }) => {
                let child = format!("{path}[{index}]");
                *index += 1;
                let end = if value_is_scalar {
                    value.end
                } else {
                    value.start
                };
                (child, Span::between(value.start, end))
            }
            // The document's root node. It has no path of its own; the frame it
            // opens is what gives `rules`, `metadata`, ... their prefix.
            None => return Some(String::new()),
        };
        self.spans.entry(path.clone()).or_insert(span);
        Some(path)
    }
}

fn join(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"hushspec: "0.1.0"
name: span-demo
rules:
  egress:
    allow:
      - "api.example.com"
      # a comment between entries
      - "cdn.example.com"
    block: []
    default: block
  secret_patterns:
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{16}"
        severity: warn
  shell_commands:
    forbidden_patterns:
      - |
        multi
        line
"quoted key holder":
  nested: 1
"#;

    #[test]
    fn maps_block_mapping_keys_to_their_own_position() {
        let map = SpanMap::build(DOC);
        // `rules:` is on line 3, column 1.
        let rules = map.get("rules").expect("rules has a span");
        assert_eq!((rules.line, rules.column), (3, 1));
        // `egress:` is indented two spaces on line 4.
        let egress = map.get("rules.egress").expect("rules.egress has a span");
        assert_eq!((egress.line, egress.column), (4, 3));
    }

    #[test]
    fn maps_sequence_entries_to_the_entry_not_the_list() {
        let map = SpanMap::build(DOC);
        let first = map.get("rules.egress.allow[0]").expect("first entry");
        assert_eq!(first.line, 6);
        // A comment between entries must not shift the index.
        let second = map.get("rules.egress.allow[1]").expect("second entry");
        assert_eq!(second.line, 8);
        assert_eq!(second.end_line, 8);
        assert!(second.end_column > second.column);
    }

    #[test]
    fn maps_nested_mapping_entries_inside_sequences() {
        let map = SpanMap::build(DOC);
        let severity = map
            .get("rules.secret_patterns.patterns[0].severity")
            .expect("severity of the first secret pattern");
        assert_eq!(severity.line, 15);
        assert_eq!(severity.column, 9);
    }

    #[test]
    fn handles_flow_sequences_block_scalars_and_quoted_keys() {
        let map = SpanMap::build(DOC);
        // `block: []` -- a flow sequence with no entries still maps its key.
        let block = map.get("rules.egress.block").expect("flow sequence key");
        assert_eq!((block.line, block.column), (9, 5));
        // A block scalar entry reports its first content line (the line after
        // the `|` indicator) and spans to the end of the block, not to the end
        // of the first line -- a line indexer would report the `- |` line and
        // stop there.
        let scalar = map
            .get("rules.shell_commands.forbidden_patterns[0]")
            .expect("block scalar entry");
        assert_eq!(scalar.line, 19);
        assert!(
            scalar.end_line > scalar.line,
            "block scalar spans its lines"
        );
        // A quoted key is reported at the opening quote, and its value nests.
        let quoted = map
            .get("quoted key holder.nested")
            .expect("quoted key child");
        assert_eq!(quoted.line, 22);
    }

    #[test]
    fn nearest_falls_back_to_the_enclosing_key() {
        let map = SpanMap::build(DOC);
        // Index past the end of the list: no exact span, but the list key has one.
        let fallback = map
            .nearest("rules.egress.allow[9]")
            .expect("falls back to rules.egress.allow");
        assert_eq!(map.get("rules.egress.allow"), Some(fallback));
        // A key the document never writes falls back to its block.
        let inherited = map
            .nearest("rules.egress.enabled")
            .expect("falls back to rules.egress");
        assert_eq!(map.get("rules.egress"), Some(inherited));
        assert_eq!(map.nearest("metadata.controls[0]"), None);
    }

    #[test]
    fn a_malformed_document_yields_no_panic() {
        // Spans are best-effort: a stream that stops early keeps whatever it
        // collected instead of failing the lint run.
        let map = SpanMap::build("rules:\n  egress:\n    allow:\n      - \"a\n");
        assert!(map.get("rules").is_some());
    }
}
