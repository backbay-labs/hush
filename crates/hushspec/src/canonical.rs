//! Canonical form and content hash (spec/hushspec-canonical.md).
//!
//! A policy's identity has to be the same in every SDK, on every platform,
//! regardless of which optional keys the author omitted or which language
//! serialized the document. This module produces that identity in three
//! steps, exactly as the specification defines them:
//!
//! 1. **Canonical projection** (canonical spec 3): walk the resolved document
//!    alongside the published JSON Schemas, materializing every schema
//!    default that a *present* object left out, dropping the resolution-only
//!    fields, and normalizing empty containers.
//! 2. **Canonical serialization** (canonical spec 4): RFC 8785 (JCS) over the
//!    projected value -- UTF-16 key order, JCS string escaping, ECMAScript
//!    number formatting, no whitespace.
//! 3. **Content hash** (canonical spec 5): `sha256:` followed by the
//!    lowercase hex SHA-256 of the canonical UTF-8 bytes.
//!
//! Only **resolved** documents have a canonical form: a hash computed over an
//! unresolved document would identify a fragment rather than the policy that
//! is actually enforced, so a document that still declares `extends` is
//! rejected ([`CanonicalError::Unresolved`]). `merge_strategy` is a
//! resolution field and never appears in the canonical form, not even as its
//! schema default.
//!
//! # Which entry point to use
//!
//! [`canonical_json_value`] and [`content_hash_value`] take the generic JSON
//! data model of the document (a tree of maps, arrays, and scalars). This is
//! the path canonical spec 6 recommends and the one the normative vectors in
//! `fixtures/core/hash/` exercise, because a value tree can represent every
//! distinction the projection cares about.
//!
//! [`canonical_json`] and [`content_hash`] take the typed [`HushSpec`], which
//! is what a caller holds after `resolve`. They serialize it into the same
//! value tree and run the same projection, so both entry points always agree:
//! the one field whose emptiness is significant ([`PRESERVE_EMPTY`]) is an
//! optional object in the typed model, which represents it faithfully.

use crate::generated_canonical_schemas::{
    CORE_SCHEMA, CORE_SCHEMA_NAME, EXTENSION_SCHEMAS, ORIGINS_SCHEMA_NAME,
};
use crate::schema::HushSpec;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Prefix of the self-describing content-hash wire form (canonical spec 5).
pub const CONTENT_HASH_PREFIX: &str = "sha256:";

/// Fields consumed by resolution; never part of a resolved document
/// (canonical spec 3.1).
const RESOLUTION_FIELDS: [&str; 2] = ["extends", "merge_strategy"];

/// Reserved for an inline signature (signing spec 7). Excluded from the
/// canonical form so a signature never covers itself.
const INLINE_SIGNATURE_FIELD: &str = "signature";

/// Largest integer an IEEE 754 double represents exactly (canonical spec 4.3).
const SAFE_INTEGER_MAX: u64 = (1u64 << 53) - 1;

/// Guards against a `$ref` cycle in a hand-edited schema. The published
/// schemas nest at most a handful of levels.
const MAX_REF_DEPTH: usize = 16;

/// Fields whose *presence* changes meaning even when the value is empty
/// (canonical spec 3.3), keyed by `(schema file, $defs name, property)`.
/// Everything else that is an empty container with no schema default is
/// equivalent to absence and is omitted -- the origins profile overlay lists
/// included, because an absent overlay list and an empty one evaluate
/// identically (origins spec 4).
const PRESERVE_EMPTY: &[(&str, &str, &str)] = &[(ORIGINS_SCHEMA_NAME, "OriginProfile", "match")];

/// Why a document has no canonical form. Every variant is fail-closed: the
/// caller gets an error instead of a digest that would identify the wrong
/// document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// The document still declares `extends` (canonical spec 2.1).
    #[error("document declares `extends`; resolve the chain before canonicalizing")]
    Unresolved,
    /// The value at `path` had to be a JSON object and was not.
    #[error("{0} must be an object")]
    ExpectedObject(String),
    /// A key the schema does not define (canonical spec 2.3).
    #[error("unknown field {0}")]
    UnknownField(String),
    /// A `null` written for a property the schema declares (canonical spec 2.2).
    #[error("{0} is null; no property is nullable")]
    NullProperty(String),
    /// An `extensions` key with no published schema (canonical spec 3.4).
    #[error("unknown extension `{0}`")]
    UnknownExtension(String),
    /// An integer outside the IEEE 754 safe range (canonical spec 4.3).
    #[error("integer {0} exceeds the safe range (2^53-1)")]
    UnsafeInteger(String),
    /// NaN or an infinity, which JSON cannot represent (canonical spec 4.3).
    #[error("NaN and infinities are not representable in JSON")]
    NonFiniteNumber,
    /// The typed document could not be turned into the JSON data model.
    #[error("failed to serialize the document: {0}")]
    Serialize(String),
    /// The embedded schemas are unusable (a generator or build error).
    #[error("embedded schema {0} is unusable: {1}")]
    Schema(String, String),
}

/// The canonical JSON text of a resolved document (canonical spec 4).
///
/// A thin wrapper over [`canonical_json_value`]: the typed document is
/// serialized into the JSON data model and projected there.
///
/// # Errors
///
/// Returns [`CanonicalError::Unresolved`] when `spec.extends` is set, and any
/// projection or serialization error described by [`CanonicalError`].
pub fn canonical_json(spec: &HushSpec) -> Result<String, CanonicalError> {
    if spec.extends.is_some() {
        return Err(CanonicalError::Unresolved);
    }
    let value =
        serde_json::to_value(spec).map_err(|error| CanonicalError::Serialize(error.to_string()))?;
    canonicalize(&value)
}

/// The content hash of a resolved document: `sha256:<64 lowercase hex>`
/// (canonical spec 5).
///
/// # Errors
///
/// As [`canonical_json`].
pub fn content_hash(spec: &HushSpec) -> Result<String, CanonicalError> {
    Ok(digest(&canonical_json(spec)?))
}

/// The canonical JSON text of a resolved document supplied as a JSON value.
///
/// This is the normative path (canonical spec 6): a value tree represents
/// every distinction the projection makes.
///
/// # Errors
///
/// As [`canonical_json`], plus [`CanonicalError::ExpectedObject`] when the
/// document is not a JSON object.
pub fn canonical_json_value(document: &Value) -> Result<String, CanonicalError> {
    canonicalize(document)
}

/// The content hash of a resolved document supplied as a JSON value.
///
/// # Errors
///
/// As [`canonical_json_value`].
pub fn content_hash_value(document: &Value) -> Result<String, CanonicalError> {
    Ok(digest(&canonical_json_value(document)?))
}

/// The canonical projection of a resolved document (canonical spec 3), as a
/// JSON value, before serialization.
///
/// [`canonical_json`] is exactly [`serialize_jcs`] applied to this. A caller
/// that has to *embed* the canonical document inside a larger JSON structure
/// -- a policy bundle's `predicate.resolved` (bundle spec 4.2) -- needs the
/// value rather than the text, so that the enclosing document canonicalizes
/// as one whole.
///
/// # Errors
///
/// As [`canonical_json`].
pub fn canonical_value(spec: &HushSpec) -> Result<Value, CanonicalError> {
    if spec.extends.is_some() {
        return Err(CanonicalError::Unresolved);
    }
    let value =
        serde_json::to_value(spec).map_err(|error| CanonicalError::Serialize(error.to_string()))?;
    canonical_value_of(&value)
}

/// The canonical projection of a resolved document supplied as a JSON value.
///
/// # Errors
///
/// As [`canonical_json_value`].
pub fn canonical_value_of(document: &Value) -> Result<Value, CanonicalError> {
    let Some(object) = document.as_object() else {
        return Err(CanonicalError::ExpectedObject("document".to_string()));
    };
    project(object)
}

/// SHA-256 of already-canonical bytes, in the `sha256:` wire form.
///
/// Use this only when the canonical text is already in hand (a signature
/// envelope, a receipt re-check); it does no projection of its own.
#[must_use]
pub fn digest(canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{CONTENT_HASH_PREFIX}{:x}", hasher.finalize())
}

fn canonicalize(document: &Value) -> Result<String, CanonicalError> {
    let projected = canonical_value_of(document)?;
    let mut out = String::new();
    write_value(&projected, &mut out)?;
    Ok(out)
}

// --------------------------------------------------------------------------
// Schemas
// --------------------------------------------------------------------------

struct SchemaSet {
    core: Value,
    /// `(extensions key, schema file name, parsed schema)`.
    extensions: Vec<(&'static str, &'static str, Value)>,
}

fn schemas() -> Result<&'static SchemaSet, CanonicalError> {
    static SCHEMAS: OnceLock<Result<SchemaSet, (String, String)>> = OnceLock::new();
    match SCHEMAS.get_or_init(load_schemas) {
        Ok(set) => Ok(set),
        Err((name, message)) => Err(CanonicalError::Schema(name.clone(), message.clone())),
    }
}

fn load_schemas() -> Result<SchemaSet, (String, String)> {
    let parse = |name: &str, body: &str| -> Result<Value, (String, String)> {
        serde_json::from_str(body).map_err(|error| (name.to_string(), error.to_string()))
    };
    let core = parse(CORE_SCHEMA_NAME, CORE_SCHEMA)?;
    let mut extensions = Vec::with_capacity(EXTENSION_SCHEMAS.len());
    for (key, file, body) in EXTENSION_SCHEMAS {
        extensions.push((*key, *file, parse(file, body)?));
    }
    Ok(SchemaSet { core, extensions })
}

// --------------------------------------------------------------------------
// Projection (canonical spec 3)
// --------------------------------------------------------------------------

fn project(document: &Map<String, Value>) -> Result<Value, CanonicalError> {
    // A written `extends: null` is an absent base, as it is to the typed
    // model and to the other SDKs.
    if document.get("extends").is_some_and(|base| !base.is_null()) {
        return Err(CanonicalError::Unresolved);
    }
    let schemas = schemas()?;

    let mut top = document.clone();
    for field in RESOLUTION_FIELDS {
        top.remove(field);
    }
    if let Some(Value::Object(metadata)) = top.get_mut("metadata") {
        metadata.remove(INLINE_SIGNATURE_FIELD);
    }
    // `extensions` is opaque to the core schema; each block is projected
    // against the root of its own schema instead (canonical spec 3.4).
    let extensions = top.remove("extensions");

    let mut out = project_object(
        &top,
        &schemas.core,
        &schemas.core,
        CORE_SCHEMA_NAME,
        None,
        "$",
        &RESOLUTION_FIELDS,
    )?;

    if let Some(extensions) = extensions {
        let Some(blocks) = extensions.as_object() else {
            return Err(CanonicalError::ExpectedObject("$.extensions".to_string()));
        };
        let mut projected = Map::new();
        for (name, block) in blocks {
            let Some((_, file, schema)) = schemas
                .extensions
                .iter()
                .find(|(key, _, _)| *key == name.as_str())
            else {
                return Err(CanonicalError::UnknownExtension(name.clone()));
            };
            let value =
                project_value(block, schema, schema, file, &format!("$.extensions.{name}"))?;
            if is_empty_container(&value) {
                continue;
            }
            projected.insert(name.clone(), value);
        }
        if !projected.is_empty() {
            out.insert("extensions".to_string(), Value::Object(projected));
        }
    }

    Ok(Value::Object(out))
}

/// Project a JSON object against a schema object (canonical spec 3.2 and 3.3).
fn project_object(
    value: &Map<String, Value>,
    schema: &Value,
    root: &Value,
    root_name: &str,
    def_name: Option<&str>,
    path: &str,
    skip_defaults: &[&str],
) -> Result<Map<String, Value>, CanonicalError> {
    static NO_PROPERTIES: OnceLock<Map<String, Value>> = OnceLock::new();
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or_else(|| NO_PROPERTIES.get_or_init(Map::new));

    for (key, present) in value {
        if !properties.contains_key(key) {
            return Err(CanonicalError::UnknownField(format!("{path}.{key}")));
        }
        // Canonical spec 2.2: no HushSpec property is nullable, so a `null`
        // written for one is a validation error with no canonical form. A
        // `null` inside a free-form value is an ordinary leaf and never
        // reaches here.
        if present.is_null() {
            return Err(CanonicalError::NullProperty(format!("{path}.{key}")));
        }
    }

    let mut out = Map::new();
    for (key, property) in properties {
        let Some(present) = value.get(key) else {
            // An absent property takes its schema default, if it has one.
            // Resolution fields keep theirs hidden (canonical spec 3.1).
            if let Some(default) = property.get("default")
                && !skip_defaults.contains(&key.as_str())
            {
                out.insert(key.clone(), default.clone());
            }
            continue;
        };

        let projected =
            project_value(present, property, root, root_name, &format!("{path}.{key}"))?;

        // Canonical spec 3.3: a present-but-empty container for a property
        // with no schema default, not required, and not presence-significant
        // means the same thing as absence, so it is omitted.
        if property.get("default").is_none()
            && !is_required(schema, key)
            && is_empty_container(&projected)
            && !preserves_empty(root_name, def_name, key)
        {
            continue;
        }
        out.insert(key.clone(), projected);
    }
    Ok(out)
}

fn project_value(
    value: &Value,
    schema: &Value,
    root: &Value,
    root_name: &str,
    path: &str,
) -> Result<Value, CanonicalError> {
    let (schema, def_name) = resolve_ref(root, schema, 0)?;

    if let Some(object) = value.as_object()
        && schema.get("properties").is_some()
    {
        return Ok(Value::Object(project_object(
            object,
            schema,
            root,
            root_name,
            def_name,
            path,
            &[],
        )?));
    }

    if let Some(items) = value.as_array()
        && schema.get("type").and_then(Value::as_str) == Some("array")
    {
        let Some(item_schema) = schema.get("items").filter(|item| item.is_object()) else {
            return Ok(value.clone());
        };
        let mut out = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            out.push(project_value(
                item,
                item_schema,
                root,
                root_name,
                &format!("{path}[{index}]"),
            )?);
        }
        return Ok(Value::Array(out));
    }

    // A schema map (`additionalProperties` as a schema, e.g. posture
    // `states`): every key is kept as written and every value projected.
    if let Some(object) = value.as_object()
        && let Some(entry_schema) = schema
            .get("additionalProperties")
            .filter(|entry| entry.is_object())
    {
        let mut out = Map::new();
        for (key, entry) in object {
            out.insert(
                key.clone(),
                project_value(
                    entry,
                    entry_schema,
                    root,
                    root_name,
                    &format!("{path}.{key}"),
                )?,
            );
        }
        return Ok(Value::Object(out));
    }

    // Leaf values, and free-form objects the schema does not describe
    // (`when.context`), are kept exactly as written.
    Ok(value.clone())
}

/// Follow a local `#/$defs/...` reference, returning the target schema and
/// the `$defs` name it was reached through (`None` for an inline schema).
fn resolve_ref<'a>(
    root: &'a Value,
    node: &'a Value,
    depth: usize,
) -> Result<(&'a Value, Option<&'a str>), CanonicalError> {
    let Some(reference) = node.get("$ref").and_then(Value::as_str) else {
        return Ok((node, None));
    };
    if depth >= MAX_REF_DEPTH {
        return Err(CanonicalError::Schema(
            reference.to_string(),
            "$ref nesting is too deep".to_string(),
        ));
    }
    let Some(name) = reference.strip_prefix("#/$defs/") else {
        return Err(CanonicalError::Schema(
            reference.to_string(),
            "only local #/$defs/ references are supported".to_string(),
        ));
    };
    let Some(target) = root.get("$defs").and_then(|defs| defs.get(name)) else {
        return Err(CanonicalError::Schema(
            reference.to_string(),
            "reference target is missing".to_string(),
        ));
    };
    let (resolved, inner) = resolve_ref(root, target, depth + 1)?;
    Ok((resolved, inner.or(Some(name))))
}

fn is_required(schema: &Value, key: &str) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|entry| entry.as_str() == Some(key)))
}

fn is_empty_container(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn preserves_empty(root_name: &str, def_name: Option<&str>, key: &str) -> bool {
    let Some(def_name) = def_name else {
        return false;
    };
    PRESERVE_EMPTY
        .iter()
        .any(|(schema, def, property)| (*schema, *def, *property) == (root_name, def_name, key))
}

// --------------------------------------------------------------------------
// RFC 8785 serialization (canonical spec 4)
// --------------------------------------------------------------------------

/// RFC 8785 (JCS) serialization of an arbitrary JSON value, with **no**
/// canonical projection (canonical spec 4).
///
/// The projection of canonical spec 3 is defined against the policy schemas,
/// so it applies to policy documents only. Other signed objects -- a
/// signature envelope (signing spec 4.1) above all -- are canonicalized by
/// serialization alone. They share this serializer so that every HushSpec
/// digest comes from one implementation of RFC 8785.
///
/// # Errors
///
/// [`CanonicalError::UnsafeInteger`] or [`CanonicalError::NonFiniteNumber`]
/// for a number RFC 8785 cannot represent.
pub fn serialize_jcs(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 3.2.3: members sort by UTF-16 code unit, which is not
            // code-point order above the BMP. Comparing the encoding
            // iterators avoids materializing the code units.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 3.2.2.2: escape only quote, reverse solidus, and the control
/// characters. Non-ASCII, U+007F, U+2028, U+2029, and astral characters are
/// emitted literally.
fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            control if control < '\u{20}' => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

fn write_number(number: &serde_json::Number, out: &mut String) -> Result<(), CanonicalError> {
    if let Some(value) = number.as_u64() {
        if value > SAFE_INTEGER_MAX {
            return Err(CanonicalError::UnsafeInteger(value.to_string()));
        }
        out.push_str(&value.to_string());
        return Ok(());
    }
    if let Some(value) = number.as_i64() {
        if value.unsigned_abs() > SAFE_INTEGER_MAX {
            return Err(CanonicalError::UnsafeInteger(value.to_string()));
        }
        out.push_str(&value.to_string());
        return Ok(());
    }
    let Some(value) = number.as_f64() else {
        return Err(CanonicalError::NonFiniteNumber);
    };
    out.push_str(&es6_number(value)?);
    Ok(())
}

/// Format a double exactly as ECMAScript `Number::toString` does
/// (RFC 8785 3.2.2.3, canonical spec 4.3).
///
/// Rust's `{:e}` yields the same shortest round-tripping digits as ECMAScript
/// but always uses exponent notation; the positional/exponential choice and
/// the exponent's own shape are applied here.
fn es6_number(value: f64) -> Result<String, CanonicalError> {
    if !value.is_finite() {
        return Err(CanonicalError::NonFiniteNumber);
    }
    // Negative zero prints as `0` (canonical spec 4.3).
    if value == 0.0 {
        return Ok("0".to_string());
    }
    let sign = if value < 0.0 { "-" } else { "" };

    let formatted = format!("{:e}", value.abs());
    let (mantissa, exponent) = formatted
        .split_once('e')
        .ok_or(CanonicalError::NonFiniteNumber)?;
    let exponent: i32 = exponent
        .parse()
        .map_err(|_| CanonicalError::NonFiniteNumber)?;

    let mut digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    // `value == 0.<digits> x 10^n`; trailing zeros do not move `n`.
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let k = i32::try_from(digits.len()).map_err(|_| CanonicalError::NonFiniteNumber)?;
    let n = exponent + 1;

    let body = if k <= n && n <= 21 {
        let mut body = digits;
        body.push_str(&"0".repeat((n - k) as usize));
        body
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        format!("{}.{}", &digits[..split], &digits[split..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let exponent = n - 1;
        let mantissa = if k == 1 {
            digits
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let signum = if exponent >= 0 { '+' } else { '-' };
        format!("{mantissa}e{signum}{}", exponent.abs())
    };
    Ok(format!("{sign}{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical(document: &Value) -> String {
        canonical_json_value(document).expect("document canonicalizes")
    }

    #[test]
    fn minimal_document_is_the_version_alone() {
        let document = json!({"hushspec": "0.1.0"});
        assert_eq!(canonical(&document), r#"{"hushspec":"0.1.0"}"#);
        assert_eq!(
            content_hash_value(&document).expect("hashes"),
            "sha256:9aa550f8eed15366ce9db38b22818179d79c382fa6423f159ef0b228aca25108"
        );
    }

    #[test]
    fn present_blocks_materialize_defaults_and_absent_blocks_are_not_invented() {
        let document = json!({
            "hushspec": "0.1.0",
            "rules": {"egress": {"allow": ["api.example.com"]}, "forbidden_paths": {"patterns": [], "when": {}}},
            "metadata": {},
        });
        assert_eq!(
            canonical(&document),
            concat!(
                r#"{"hushspec":"0.1.0","rules":{"#,
                r#""egress":{"allow":["api.example.com"],"block":[],"default":"block","enabled":true},"#,
                r#""forbidden_paths":{"enabled":true,"exceptions":[],"patterns":[]}}}"#,
            )
        );
    }

    #[test]
    fn merge_strategy_is_stripped_and_extends_is_refused() {
        let resolved = json!({"hushspec": "0.1.0", "merge_strategy": "deep_merge"});
        assert_eq!(canonical(&resolved), r#"{"hushspec":"0.1.0"}"#);

        let unresolved = json!({"hushspec": "0.1.0", "extends": "builtin:default"});
        assert_eq!(
            canonical_json_value(&unresolved),
            Err(CanonicalError::Unresolved)
        );
        let spec =
            HushSpec::parse("hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n").expect("parses");
        assert_eq!(canonical_json(&spec), Err(CanonicalError::Unresolved));
    }

    #[test]
    fn inline_metadata_signature_is_not_covered_by_the_hash() {
        let signed = json!({
            "hushspec": "0.1.0",
            "metadata": {"author": "a@example.com", "signature": "sig"},
        });
        let unsigned = json!({"hushspec": "0.1.0", "metadata": {"author": "a@example.com"}});
        assert_eq!(canonical(&signed), canonical(&unsigned));
    }

    #[test]
    fn unknown_fields_and_extensions_are_refused() {
        assert_eq!(
            canonical_json_value(&json!({"hushspec": "0.1.0", "nope": 1})),
            Err(CanonicalError::UnknownField("$.nope".to_string()))
        );
        assert_eq!(
            canonical_json_value(&json!({"hushspec": "0.1.0", "rules": {"egress": {"nope": 1}}})),
            Err(CanonicalError::UnknownField(
                "$.rules.egress.nope".to_string()
            ))
        );
        assert_eq!(
            canonical_json_value(&json!({"hushspec": "0.1.0", "extensions": {"nope": {}}})),
            Err(CanonicalError::UnknownExtension("nope".to_string()))
        );
    }

    /// RFC 8785 3.2.3: U+20AC sorts before U+1F600 because the astral
    /// character encodes as the surrogate pair D83D DE00, above U+20AC.
    #[test]
    fn keys_sort_by_utf16_code_unit_not_code_point() {
        let document = json!({
            "hushspec": "0.1.0",
            "rules": {"egress": {"when": {"context": {
                "z": 1, "a": 2, "\u{20AC}": 3, "\u{1F600}": 4, "Z": 5, "\u{e9}": 6,
            }}}},
        });
        let canonical = canonical(&document);
        let context = canonical
            .split_once(r#""context":"#)
            .expect("context is present")
            .1;
        assert!(
            context.starts_with(
                "{\"Z\":5,\"a\":2,\"z\":1,\"\u{e9}\":6,\"\u{20AC}\":3,\"\u{1F600}\":4}"
            ),
            "{context}"
        );
    }

    #[test]
    fn a_null_written_for_a_declared_property_is_refused() {
        assert_eq!(
            canonical_json_value(&json!({"hushspec": "0.1.0", "rules": {"egress": null}})),
            Err(CanonicalError::NullProperty("$.rules.egress".to_string()))
        );
        assert_eq!(
            canonical_json_value(&json!({"hushspec": "0.1.0", "name": null})),
            Err(CanonicalError::NullProperty("$.name".to_string()))
        );
        // A `null` inside a free-form value is an ordinary JSON leaf.
        let free_form =
            json!({"hushspec": "0.1.0", "rules": {"egress": {"when": {"context": {"a": null}}}}});
        assert!(canonical(&free_form).contains(r#""context":{"a":null}"#));
    }

    /// A written `extends: null` names no base, so the document is resolved.
    #[test]
    fn a_null_extends_is_an_absent_base() {
        assert_eq!(
            canonical(&json!({"hushspec": "0.1.0", "extends": null})),
            r#"{"hushspec":"0.1.0"}"#
        );
    }

    /// Canonical spec 4.3: an integer literal beyond the safe range is refused
    /// rather than rounded. `serde_yaml` refuses one that overflows `u64`
    /// outright, so the two literals are refused at different layers and the
    /// document has no canonical form either way.
    #[test]
    fn integer_literals_beyond_the_safe_range_are_refused() {
        let document =
            json!({"hushspec": "0.1.0", "metadata": {"policy_version": 9_007_199_254_740_993u64}});
        assert_eq!(
            canonical_json_value(&document),
            Err(CanonicalError::UnsafeInteger(
                "9007199254740993".to_string()
            ))
        );

        let context = |literal: &str| {
            format!(
                "hushspec: \"0.1.0\"\nrules:\n  egress:\n    when:\n      context:\n        budget: {literal}\n"
            )
        };
        let safe_overflow: Value =
            serde_yaml::from_str(&context("9007199254740993")).expect("parses as a value tree");
        assert_eq!(
            canonical_json_value(&safe_overflow),
            Err(CanonicalError::UnsafeInteger(
                "9007199254740993".to_string()
            ))
        );
        assert!(serde_yaml::from_str::<Value>(&context("18446744073709551617")).is_err());
        assert!(HushSpec::parse(&context("18446744073709551617")).is_err());
    }

    /// Canonical spec 4.3: float syntax carries no safe-integer bound, so a
    /// magnitude an integer literal could not have keeps its ECMAScript form.
    #[test]
    fn float_syntax_is_unbounded() {
        let document: Value = serde_yaml::from_str(concat!(
            "hushspec: \"0.1.0\"\nrules:\n  egress:\n    when:\n      context:\n",
            "        a: 1.0e+16\n        b: 1.0e+21\n        c: 1.5e+300\n        d: -0.0\n",
        ))
        .expect("parses as a value tree");
        assert!(
            canonical(&document)
                .contains(r#""context":{"a":10000000000000000,"b":1e+21,"c":1.5e+300,"d":0}"#),
            "{}",
            canonical(&document)
        );
    }

    /// Canonical spec 4.3 with the ECMAScript `Number::toString` cases the
    /// spec calls out, plus the classic float-formatting traps.
    #[test]
    fn numbers_follow_the_ecmascript_algorithm() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (10.0, "10"),
            (1e16, "10000000000000000"),
            (0.35, "0.35"),
            (0.000_001, "0.000001"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (2.5e-8, "2.5e-8"),
            (1.5e21, "1.5e+21"),
            (0.1 + 0.2, "0.30000000000000004"),
            (-1.5, "-1.5"),
            (-1e-7, "-1e-7"),
            (1e20, "100000000000000000000"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (123_456.789, "123456.789"),
            (100.0, "100"),
        ];
        for (value, expected) in cases {
            assert_eq!(&es6_number(*value).expect("formats"), expected, "{value}");
        }
        assert_eq!(es6_number(f64::NAN), Err(CanonicalError::NonFiniteNumber));
        assert_eq!(
            es6_number(f64::INFINITY),
            Err(CanonicalError::NonFiniteNumber)
        );
    }

    /// Every ECMAScript number string must parse back to the same double.
    #[test]
    fn number_formatting_round_trips() {
        let values = [
            1.0,
            -1.0,
            0.1,
            1.0 / 3.0,
            2.0_f64.powi(53),
            1e-300,
            1e300,
            f64::MIN_POSITIVE,
            std::f64::consts::PI,
        ];
        for value in values {
            let text = es6_number(value).expect("formats");
            let parsed: f64 = text.parse().expect("round-trips");
            assert_eq!(parsed, value, "{text}");
        }
    }

    #[test]
    fn strings_use_jcs_escapes_only() {
        let mut short = String::new();
        write_string("q\" b\\ \u{08}\u{09}\u{0a}\u{0c}\u{0d}", &mut short);
        assert_eq!(short, r#""q\" b\\ \b\t\n\f\r""#);

        // Controls without a short escape: lowercase four-hex escapes.
        // Assembled from parts so this source file stays plain ASCII.
        let mut controls = String::new();
        write_string("\u{01}\u{1f}", &mut controls);
        let backslash = '\\';
        assert_eq!(controls, format!("\"{backslash}u0001{backslash}u001f\""));

        // Non-ASCII, DEL, NBSP, U+2028, astral characters and `/` stay literal.
        let mut literal = String::new();
        write_string("\u{e9}\u{20ac}\u{7f}\u{a0}\u{2028}\u{1F600}/", &mut literal);
        assert_eq!(literal, "\"\u{e9}\u{20ac}\u{7f}\u{a0}\u{2028}\u{1F600}/\"");
    }

    /// Canonical spec 3.3: an overlay list written empty means what an absent
    /// one means (origins spec 4), so it is omitted -- and an overlay left
    /// empty by that omission is dropped in turn. `match: {}` is the one
    /// presence-significant field and survives. Both entry points agree.
    #[test]
    fn origins_overlay_empties_are_omitted_and_match_is_preserved() {
        let document = json!({
            "hushspec": "0.1.0",
            "extensions": {"origins": {"profiles": [
                {"id": "fallback", "match": {}, "tool_access": {"allow": []}, "egress": {"block": []}},
            ]}},
        });
        let expected = concat!(
            r#"{"extensions":{"origins":{"default_behavior":"deny","#,
            r#""profiles":[{"id":"fallback","match":{}}]}},"hushspec":"0.1.0"}"#,
        );
        assert_eq!(canonical(&document), expected);

        let yaml = serde_yaml::to_string(&document).expect("re-encodes");
        let spec = HushSpec::parse(&yaml).expect("parses");
        assert_eq!(canonical_json(&spec).expect("canonicalizes"), expected);
    }

    #[test]
    fn the_two_entry_points_agree_on_a_typical_policy() {
        let yaml = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: agree\n",
            "rules:\n",
            "  egress:\n",
            "    allow: [\"api.example.com\"]\n",
            "  forbidden_paths:\n",
            "    patterns: [\"**/.env\"]\n",
            "metadata:\n",
            "  author: a@example.com\n",
        );
        let spec = HushSpec::parse(yaml).expect("parses");
        let raw: Value = serde_yaml::from_str(yaml).expect("parses as a value tree");
        assert_eq!(
            canonical_json(&spec).expect("typed"),
            canonical_json_value(&raw).expect("document")
        );
    }

    #[test]
    fn content_hash_is_the_prefixed_sha256_of_the_canonical_bytes() {
        let document = json!({"hushspec": "0.1.0"});
        let canonical = canonical(&document);
        assert_eq!(
            content_hash_value(&document).expect("hashes"),
            digest(&canonical)
        );
        let hash = content_hash_value(&document).expect("hashes");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), "sha256:".len() + 64);
        assert!(
            hash["sha256:".len()..]
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }
}
