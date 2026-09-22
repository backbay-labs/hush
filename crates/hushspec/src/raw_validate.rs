//! Document checks that only the raw YAML can answer.
//!
//! `serde` maps a written `null` onto `None` for every optional field, so a
//! document that writes one for a declared property deserializes exactly as if
//! the property were absent: `rules: {egress: null}` becomes a policy with no
//! egress block, and hashes as one. No HushSpec property is nullable
//! (canonical spec 2.2 and 3.2), so the walk below refuses such a document at
//! parse time rather than leaving the refusal to canonicalization -- an engine
//! that never hashes a policy must reject it too.
//!
//! The same rule holds wherever else the schema types a value. A null element
//! of a string array decodes into `""` -- `allow: [null]` becomes an egress
//! allowlist with one empty entry -- and a null value in a schema map decodes
//! into that entry's zero value, neither of which the author wrote.
//!
//! The walk is driven by the same embedded schemas the canonical projection
//! uses, so the two can never disagree about which values a document declares.
//! A value the schema does not describe -- a `when.context` entry -- is a leaf:
//! the null there is a value to compare against the runtime context, not a
//! property of the document format.
//!
//! The safe-integer bound of canonical spec 4.3 is answered here for the same
//! reason: it belongs to integer *syntax*, and the raw value tree is the last
//! place a document still carries any.

use crate::canonical::{SchemaSet, resolve_ref, schemas};
use serde_json::Value as Schema;
use serde_yaml::Value as Yaml;

/// Largest integer an IEEE 754 double holds exactly (canonical spec 4.3).
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Refuse an integer whose magnitude an IEEE 754 double cannot hold exactly,
/// naming the first one found in document order (canonical spec 4.3).
///
/// The bound belongs to integer syntax: `10000000000000000` names an exact
/// integer a double cannot hold, while `1.0e+16` names the double itself and
/// is accepted whatever its magnitude. Applying it at parse time keeps a
/// rounded integer out of a content hash, and refuses the document even for an
/// engine that never hashes it. A literal past `u64` is already refused by the
/// YAML decode, so every integer that reaches this walk fits one of the two
/// 64-bit forms.
///
/// # Errors
///
/// The diagnostic for the offending value.
pub(crate) fn reject_unsafe_integers(document: &Yaml) -> Result<(), String> {
    walk_integers(document, "$")
}

/// JSON Schema integer properties accept integral doubles within the portable
/// integer range. Free-form context and number properties retain their doubles.
pub(crate) fn normalize_integer_fields(document: &mut Yaml) -> Result<(), String> {
    let schemas = schemas().map_err(|error| error.to_string())?;
    if let Some(mapping) = document.as_mapping_mut() {
        for (key, value) in mapping {
            let Some(key) = key.as_str() else { continue };
            if key == "extensions" {
                if let Some(blocks) = value.as_mapping_mut() {
                    for (name, block) in blocks {
                        if let Some((_, _, schema)) = schemas
                            .extensions
                            .iter()
                            .find(|(key, _, _)| Some(*key) == name.as_str())
                        {
                            normalize_integer_node(
                                block,
                                schema,
                                schema,
                                &format!("extensions.{}", name.as_str().unwrap()),
                            )?;
                        }
                    }
                }
            } else if let Some(property) = schemas.core.get("properties").and_then(|p| p.get(key)) {
                normalize_integer_node(value, property, &schemas.core, key)?;
            }
        }
    }
    Ok(())
}

fn normalize_integer_node(
    value: &mut Yaml,
    schema: &Schema,
    root: &Schema,
    path: &str,
) -> Result<(), String> {
    let (schema, _) = resolve_ref(root, schema, 0).map_err(|error| error.to_string())?;
    if schema.get("type").and_then(Schema::as_str) == Some("integer") {
        if let Yaml::Number(number) = value
            && number.is_f64()
        {
            let number = number.as_f64().unwrap();
            if !number.is_finite() || number.abs() > MAX_SAFE_INTEGER as f64 {
                return Err(format!(
                    "{path}: integer field exceeds the safe range (2^53-1)"
                ));
            }
            if number.fract() == 0.0 {
                #[allow(clippy::cast_possible_truncation)]
                {
                    *value = Yaml::Number((number as i64).into());
                }
            }
        }
        return Ok(());
    }
    match value {
        Yaml::Mapping(mapping) => {
            for (key, child) in mapping {
                let Some(key) = key.as_str() else { continue };
                let property = schema
                    .get("properties")
                    .and_then(|p| p.get(key))
                    .or_else(|| schema.get("additionalProperties").filter(|p| p.is_object()));
                if let Some(property) = property {
                    normalize_integer_node(child, property, root, &format!("{path}.{key}"))?;
                }
            }
        }
        Yaml::Sequence(items) => {
            if let Some(item_schema) = schema.get("items") {
                for (index, child) in items.iter_mut().enumerate() {
                    normalize_integer_node(child, item_schema, root, &format!("{path}[{index}]"))?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn walk_integers(value: &Yaml, path: &str) -> Result<(), String> {
    match value {
        Yaml::Number(number) => {
            let unsafe_magnitude = match (number.as_i64(), number.as_u64()) {
                (Some(signed), _) => !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&signed),
                #[allow(clippy::cast_sign_loss)]
                (None, Some(unsigned)) => unsigned > MAX_SAFE_INTEGER as u64,
                // Float syntax carries no bound.
                (None, None) => false,
            };
            if unsafe_magnitude {
                return Err(format!(
                    "{path}: integer {number} exceeds the safe range (2^53-1)"
                ));
            }
            Ok(())
        }
        Yaml::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_integers(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Yaml::Mapping(mapping) => {
            for (key, entry) in mapping {
                let name = key.as_str().unwrap_or("?");
                walk_integers(entry, &format!("{path}.{name}"))?;
            }
            Ok(())
        }
        Yaml::Tagged(tagged) => walk_integers(&tagged.value, path),
        _ => Ok(()),
    }
}

/// Refuse a `null` written for any value the schemas type, naming the first
/// one found in document order.
///
/// # Errors
///
/// The diagnostic for the offending value, or for an embedded schema that
/// cannot be read.
pub(crate) fn reject_null_properties(document: &Yaml) -> Result<(), String> {
    let Some(document) = document.as_mapping() else {
        return Ok(());
    };
    let schemas = schemas().map_err(|error| error.to_string())?;
    let Some(properties) = schemas.core.get("properties").and_then(Schema::as_object) else {
        return Ok(());
    };

    for (key, value) in document {
        let Some(key) = key.as_str() else { continue };
        // `extensions` is opaque to the core schema: each block is declared by
        // its own module schema (canonical spec 3.4).
        if key == "extensions" {
            check_extensions(value, schemas)?;
            continue;
        }
        let Some(property) = properties.get(key) else {
            continue;
        };
        check_property(value, property, &schemas.core, key)?;
    }
    Ok(())
}

/// Check one value the schema types -- a declared property, an array element,
/// a schema-map entry -- then descend into it.
fn check_property(value: &Yaml, schema: &Schema, root: &Schema, path: &str) -> Result<(), String> {
    if value.is_null() {
        let (resolved, _) = resolve_ref(root, schema, 0).map_err(|error| error.to_string())?;
        return Err(format!(
            "{path}: invalid type: null, expected {}",
            describe(resolved)
        ));
    }
    walk(value, schema, root, path)
}

/// Check each extension block against the root of its own module schema.
fn check_extensions(value: &Yaml, schemas: &SchemaSet) -> Result<(), String> {
    if value.is_null() {
        return Err("extensions: invalid type: null, expected an object".to_string());
    }
    let Some(blocks) = value.as_mapping() else {
        return Ok(());
    };
    for (name, block) in blocks {
        let Some(name) = name.as_str() else { continue };
        let Some((_, _, schema)) = schemas.extensions.iter().find(|(key, _, _)| *key == name)
        else {
            // An unknown extension is refused by the typed model.
            continue;
        };
        let path = format!("extensions.{name}");
        if block.is_null() {
            return Err(format!("{path}: invalid type: null, expected an object"));
        }
        walk(block, schema, schema, &path)?;
    }
    Ok(())
}

/// Descend a value that the schema describes, checking every value it types
/// below: declared properties, array elements, and schema-map entries. A value
/// whose schema types nothing below it -- a scalar, or a free-form object --
/// ends the walk.
fn walk(value: &Yaml, schema: &Schema, root: &Schema, path: &str) -> Result<(), String> {
    let (schema, _) = resolve_ref(root, schema, 0).map_err(|error| error.to_string())?;

    if let Some(mapping) = value.as_mapping() {
        if let Some(properties) = schema.get("properties").and_then(Schema::as_object) {
            for (key, entry) in mapping {
                let Some(key) = key.as_str() else { continue };
                let Some(property) = properties.get(key) else {
                    continue;
                };
                check_property(entry, property, root, &format!("{path}.{key}"))?;
            }
            return Ok(());
        }
        // A schema map (`additionalProperties` as a schema, e.g. posture
        // `states`): every key is the author's, every value is described.
        if let Some(entry_schema) = schema
            .get("additionalProperties")
            .filter(|entry| entry.is_object())
        {
            for (key, entry) in mapping {
                let Some(key) = key.as_str() else { continue };
                check_property(entry, entry_schema, root, &format!("{path}.{key}"))?;
            }
        }
        return Ok(());
    }

    if let Some(items) = value.as_sequence()
        && schema.get("type").and_then(Schema::as_str) == Some("array")
        && let Some(item_schema) = schema.get("items").filter(|item| item.is_object())
    {
        for (index, item) in items.iter().enumerate() {
            check_property(item, item_schema, root, &format!("{path}[{index}]"))?;
        }
    }
    Ok(())
}

/// Name a typed value's expected type the way a decoder does in an "invalid
/// type" diagnostic.
fn describe(schema: &Schema) -> &'static str {
    match schema.get("type").and_then(Schema::as_str) {
        Some("object") => "an object",
        Some("array") => "an array",
        Some("string") => "a string",
        Some("integer") => "an integer",
        Some("number") => "a number",
        Some("boolean") => "a boolean",
        _ => "a value",
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::HushSpec;

    fn refusal(yaml: &str) -> String {
        HushSpec::parse(yaml)
            .expect_err("the document should be refused")
            .to_string()
    }

    #[test]
    fn a_null_written_for_a_declared_property_is_refused() {
        assert!(
            refusal("hushspec: \"1.0.0\"\nrules:\n  egress: null\n")
                .contains("rules.egress: invalid type: null, expected an object")
        );
        assert!(
            refusal("hushspec: \"1.0.0\"\nname: null\n")
                .contains("name: invalid type: null, expected a string")
        );
        assert!(
            refusal("hushspec: \"1.0.0\"\ndescription: null\n")
                .contains("description: invalid type: null, expected a string")
        );
        assert!(
            refusal("hushspec: \"1.0.0\"\nextends: null\n")
                .contains("extends: invalid type: null, expected a string")
        );
        assert!(
            refusal("hushspec: \"1.0.0\"\nmetadata:\n  author: null\n")
                .contains("metadata.author: invalid type: null, expected a string")
        );
    }

    #[test]
    fn the_walk_reaches_every_depth() {
        assert!(
            refusal("hushspec: \"1.0.0\"\nrules:\n  egress:\n    allow: null\n")
                .contains("rules.egress.allow: invalid type: null, expected an array")
        );
        assert!(
            refusal(
                "hushspec: \"1.0.0\"\nrules:\n  egress:\n    when:\n      all_of:\n        - capability: null\n"
            )
            .contains("rules.egress.when.all_of[0].capability: invalid type: null, expected a string")
        );
        assert!(
            refusal(
                "hushspec: \"1.0.0\"\nextensions:\n  posture:\n    initial: standard\n    transitions: []\n    states:\n      standard:\n        description: null\n"
            )
            .contains(
                "extensions.posture.states.standard.description: invalid type: null, expected a string"
            )
        );
    }

    #[test]
    fn a_null_array_element_is_refused() {
        assert!(
            refusal("hushspec: \"1.0.0\"\nrules:\n  egress:\n    allow: [null]\n")
                .contains("rules.egress.allow[0]: invalid type: null, expected a string")
        );
        assert!(
            refusal(
                "hushspec: \"1.0.0\"\nrules:\n  secret_patterns:\n    patterns:\n      - null\n"
            )
            .contains("rules.secret_patterns.patterns[0]: invalid type: null, expected an object")
        );
        assert!(
            refusal(
                "hushspec: \"1.0.0\"\nrules:\n  egress:\n    when:\n      all_of:\n        - null\n"
            )
            .contains("rules.egress.when.all_of[0]: invalid type: null, expected an object")
        );
    }

    #[test]
    fn a_null_schema_map_entry_is_refused() {
        assert!(
            refusal(
                "hushspec: \"1.0.0\"\nextensions:\n  posture:\n    initial: standard\n    transitions: []\n    states:\n      standard: null\n"
            )
            .contains("extensions.posture.states.standard: invalid type: null, expected an object")
        );
        assert!(
            refusal(
                "hushspec: \"1.0.0\"\nextensions:\n  posture:\n    initial: standard\n    transitions: []\n    states:\n      standard:\n        budgets:\n          file_writes: null\n"
            )
            .contains(
                "extensions.posture.states.standard.budgets.file_writes: invalid type: null, expected an integer"
            )
        );
    }

    /// Canonical spec 4.3: integer syntax is bounded by the IEEE 754 safe
    /// range wherever it appears, and float syntax is not bounded at all.
    #[test]
    fn an_integer_beyond_the_safe_range_is_refused() {
        assert!(
            refusal("hushspec: \"1.0.0\"\nmetadata:\n  policy_version: 9007199254740993\n")
                .contains("metadata.policy_version: integer 9007199254740993 exceeds the safe range (2^53-1)")
        );
        assert!(
            refusal(
                "hushspec: \"1.0.0\"\nrules:\n  egress:\n    default: block\n    when:\n      context:\n        budget: -9007199254740993\n"
            )
            .contains("exceeds the safe range (2^53-1)")
        );
        assert!(
            HushSpec::parse("hushspec: \"1.0.0\"\nmetadata:\n  policy_version: 9007199254740991\n")
                .is_ok()
        );
        assert!(
            HushSpec::parse(
                "hushspec: \"1.0.0\"\nrules:\n  egress:\n    default: block\n    when:\n      context:\n        budget: 1.0e+21\n"
            )
            .is_ok()
        );
    }

    /// `when.context` holds values to compare against the runtime context, so
    /// a null there is data rather than a property of the document format.
    #[test]
    fn a_null_inside_a_context_value_is_a_leaf() {
        let yaml = "hushspec: \"1.0.0\"\nrules:\n  egress:\n    default: block\n    when:\n      context:\n        user.tenant: null\n";
        assert!(HushSpec::parse(yaml).is_ok());
    }
}
