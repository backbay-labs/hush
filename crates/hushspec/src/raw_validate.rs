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
//! The walk is driven by the same embedded schemas the canonical projection
//! uses, so the two can never disagree about which properties a document
//! declares. A value the schema does not describe -- a `when.context` entry --
//! is a leaf: the null there is a value to compare against the runtime
//! context, not a property of the document format.

use crate::canonical::{SchemaSet, resolve_ref, schemas};
use serde_json::Value as Schema;
use serde_yaml::Value as Yaml;

/// Refuse a `null` written for any property the schemas declare, naming the
/// first one found in document order.
///
/// # Errors
///
/// The diagnostic for the offending property, or for an embedded schema that
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

/// Check one declared property, then descend into it.
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

/// Descend a value that the schema describes, checking every declared property
/// below it. A value whose schema declares none -- a scalar, or a free-form
/// object -- ends the walk.
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
                walk(entry, entry_schema, root, &format!("{path}.{key}"))?;
            }
        }
        return Ok(());
    }

    if let Some(items) = value.as_sequence()
        && schema.get("type").and_then(Schema::as_str) == Some("array")
        && let Some(item_schema) = schema.get("items").filter(|item| item.is_object())
    {
        for (index, item) in items.iter().enumerate() {
            walk(item, item_schema, root, &format!("{path}[{index}]"))?;
        }
    }
    Ok(())
}

/// Name a declared property's type the way a decoder does in an "invalid type"
/// diagnostic.
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

    /// `when.context` holds values to compare against the runtime context, so
    /// a null there is data rather than a property of the document format.
    #[test]
    fn a_null_inside_a_context_value_is_a_leaf() {
        let yaml = "hushspec: \"1.0.0\"\nrules:\n  egress:\n    default: block\n    when:\n      context:\n        user.tenant: null\n";
        assert!(HushSpec::parse(yaml).is_ok());
    }
}
