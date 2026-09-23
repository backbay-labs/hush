//! Duplicate-aware bounded JSON, before schema or typed decoding.
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

struct Seed(usize);

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
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
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        if self.0 >= 64 {
            return Err(de::Error::custom("JSON nesting exceeds 64"));
        }
        let mut items = Vec::new();
        while let Some(v) = a.next_element_seed(Seed(self.0 + 1))? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        if self.0 >= 64 {
            return Err(de::Error::custom("JSON nesting exceeds 64"));
        }
        let mut items = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if items.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate JSON key {k:?}")));
            }
            items.insert(k, a.next_value_seed(Seed(self.0 + 1))?);
        }
        Ok(Value::Object(items))
    }
}

pub fn parse_json(bytes: &[u8]) -> Result<Value, String> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(0)
        .deserialize(&mut decoder)
        .map_err(|e| e.to_string())?;
    decoder.end().map_err(|e| e.to_string())?;
    Ok(value)
}

pub fn validate(value: &Value, schema: &str) -> Result<(), String> {
    let body = crate::generated_schemas::schema_body(schema)
        .ok_or_else(|| format!("unknown schema {schema}"))?;
    let schema_value: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema_value)
        .map_err(|e| e.to_string())?;
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
