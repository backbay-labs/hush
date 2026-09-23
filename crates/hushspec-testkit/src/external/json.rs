//! Duplicate-aware bounded JSON, before schema or typed decoding.
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::cell::Cell;
use std::fmt;

#[derive(Clone, Copy)]
struct Seed<'a> {
    depth: usize,
    remaining: Option<&'a Cell<usize>>,
}
impl Seed<'_> {
    fn charge<E: de::Error>(&self, bytes: usize) -> Result<(), E> {
        if let Some(remaining) = self.remaining {
            remaining.set(
                remaining
                    .get()
                    .checked_sub(bytes)
                    .ok_or_else(|| E::custom("decoded fixture byte limit exceeded"))?,
            );
        }
        Ok(())
    }
    fn child(self) -> Self {
        Self {
            depth: self.depth + 1,
            ..self
        }
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        // Charge each value before visiting it, including repeated YAML aliases.
        // The fixed charge also bounds collections of small scalar values.
        self.charge(64)?;
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unambiguous JSON of depth at most 64")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        self.charge(v.len())?;
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.charge(v.len())?;
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        if self.depth >= 64 {
            return Err(de::Error::custom("JSON nesting exceeds 64"));
        }
        let mut items = Vec::new();
        while let Some(v) = a.next_element_seed(self.child())? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        if self.depth >= 64 {
            return Err(de::Error::custom("JSON nesting exceeds 64"));
        }
        let mut items = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            self.charge(k.len().saturating_add(64))?;
            if items.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate JSON key {k:?}")));
            }
            items.insert(k, a.next_value_seed(self.child())?);
        }
        Ok(Value::Object(items))
    }
}

pub fn parse_json(bytes: &[u8]) -> Result<Value, String> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed {
        depth: 0,
        remaining: None,
    }
    .deserialize(&mut decoder)
    .map_err(|e| e.to_string())?;
    decoder.end().map_err(|e| e.to_string())?;
    Ok(value)
}

/// Fixture containers use the same duplicate/depth/finite-number checks. Raw
/// policy text never takes this path before it is supplied to the engine.
pub(crate) fn parse_yaml(bytes: &[u8]) -> Result<Value, String> {
    let mut documents = serde_yaml::Deserializer::from_slice(bytes);
    let document = documents.next().ok_or("empty YAML fixture container")?;
    // Source-file caps do not bound alias-expanded values. Keep a separate
    // decoded budget; raw policy spelling is still passed untouched to engines.
    let remaining = Cell::new(64 * super::model::MIB);
    let value = Seed {
        depth: 0,
        remaining: Some(&remaining),
    }
    .deserialize(document)
    .map_err(|e| e.to_string())?;
    if documents.next().is_some() {
        return Err("multiple YAML fixture documents".into());
    }
    Ok(value)
}

pub fn validate(value: &Value, schema: &str) -> Result<(), String> {
    validate_schema(value, schema, None)
}

pub fn validate_at(value: &Value, schema: &str, definition: &str) -> Result<(), String> {
    validate_schema(value, schema, Some(definition))
}

fn validate_schema(value: &Value, schema: &str, definition: Option<&str>) -> Result<(), String> {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<BTreeMap<String, Arc<jsonschema::JSONSchema>>>> = OnceLock::new();
    let key = format!("{schema}#{}", definition.unwrap_or(""));
    let mut cache = CACHE
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| "schema cache poisoned")?;
    let compiled = if let Some(compiled) = cache.get(&key) {
        compiled.clone()
    } else {
        let body = crate::generated_schemas::schema_body(schema)
            .ok_or_else(|| format!("unknown schema {schema}"))?;
        let mut schema_value: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
        if let Some(definition) = definition {
            if schema_value["$defs"].get(definition).is_none() {
                return Err(format!("unknown schema definition {definition}"));
            }
            schema_value = serde_json::json!({"$schema":schema_value["$schema"],"$id":schema_value["$id"],"$defs":schema_value["$defs"],"$ref":format!("#/$defs/{definition}")});
        }
        let compiled = Arc::new(
            jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema_value)
                .map_err(|e| e.to_string())?,
        );
        cache.insert(key, compiled.clone());
        compiled
    };
    drop(cache);
    if let Err(errors) = compiled.validate(value) {
        return Err(errors
            .take(8)
            .map(|e| format!("{}: {e}", e.instance_path))
            .collect::<Vec<_>>()
            .join("; "));
    }
    Ok(())
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8], schema: &str) -> Result<T, String> {
    let value = parse_json(bytes)?;
    validate(&value, schema)?;
    serde_json::from_value(value).map_err(|e| e.to_string())
}
