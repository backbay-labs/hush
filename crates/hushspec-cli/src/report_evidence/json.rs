use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;

use super::model::{EvidenceCode, EvidenceError};

/// Parse before schema validation without discarding repeated object members.
pub(crate) fn parse_json(bytes: &[u8], max_depth: usize) -> Result<Value, EvidenceError> {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let result = JsonSeed {
        depth: 0,
        max_depth,
    }
    .deserialize(&mut parser)
    .and_then(|value| parser.end().map(|()| value));
    result.map_err(|error| EvidenceError {
        code: EvidenceCode::Malformed,
        source: None,
        line: Some(error.line()),
        message: "invalid, ambiguous or excessively nested JSON".into(),
    })
}

#[derive(Clone, Copy)]
struct JsonSeed {
    depth: usize,
    max_depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, parser: D) -> Result<Value, D::Error> {
        parser.deserialize_any(self)
    }
}

impl JsonSeed {
    fn child<E: Error>(self) -> Result<Self, E> {
        if self.depth >= self.max_depth {
            return Err(E::custom("JSON depth exceeded"));
        }
        Ok(Self {
            depth: self.depth + 1,
            ..self
        })
    }
}

impl<'de> Visitor<'de> for JsonSeed {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unambiguous bounded JSON")
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let child = self.child()?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(child)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let child = self.child()?;
        let mut seen = BTreeSet::new();
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom("duplicate member"));
            }
            values.insert(key, object.next_value_seed(child)?);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_json;

    #[test]
    fn rejects_duplicate_members() {
        for raw in [
            br#"{"key":1,"key":2}"#.as_slice(),
            br#"{"outer":{"x":1,"x":2}}"#,
            br#"{"x":1,"\u0078":2}"#,
        ] {
            assert!(parse_json(raw, 64).is_err());
        }
    }

    #[test]
    fn enforces_depth_at_the_boundary() {
        let too_deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(parse_json(too_deep.as_bytes(), 64).is_err());
        assert!(parse_json(br#"{"ok":[1,true,"x"]}"#, 64).is_ok());
        let boundary = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        assert!(parse_json(boundary.as_bytes(), 64).is_ok());
    }

    #[test]
    fn rejects_invalid_json_without_echoing_values() {
        for raw in [
            b"{} {}".as_slice(),
            b"\xff",
            b"1e999",
            br#"{"secret":"TOKEN", invalid}"#,
        ] {
            let error = parse_json(raw, 64).unwrap_err();
            assert!(!error.to_string().contains("TOKEN"));
        }
        assert_eq!(parse_json(b"null", 64).unwrap(), serde_json::Value::Null);
    }
}
