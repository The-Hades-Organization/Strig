use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Valor de atributo usado pelas condições ABAC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
}

/// Atributos nomeados de um sujeito, recurso ou ambiente.
pub type Attributes = BTreeMap<String, Value>;

impl Value {
    /// Ordem entre valores comparáveis. Inteiro e real se comparam entre si; tipos diferentes
    /// não têm ordem.
    pub fn compare(&self, other: &Value) -> Option<Ordering> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
            (Value::Float(a), Value::Float(b)) => a.partial_cmp(b),
            (Value::Int(a), Value::Float(b)) => (*a as f64).partial_cmp(b),
            (Value::Float(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)),
            (Value::Str(a), Value::Str(b)) => Some(a.cmp(b)),
            (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
            _ => None,
        }
    }

    /// Igualdade que trata `Int(1)` e `Float(1.0)` como iguais.
    pub fn loosely_eq(&self, other: &Value) -> bool {
        match self.compare(other) {
            Some(ordering) => ordering == Ordering::Equal,
            None => self == other,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Int(v.into())
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::Int(v.into())
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Str(v.to_string())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Str(v)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::List(v.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Value::Null, Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_and_float_compare() {
        assert!(Value::Int(1).loosely_eq(&Value::Float(1.0)));
        assert_eq!(Value::Int(2).compare(&Value::Float(1.5)), Some(Ordering::Greater));
    }

    #[test]
    fn different_types_have_no_order() {
        assert_eq!(Value::Int(1).compare(&Value::from("1")), None);
        assert!(!Value::Int(1).loosely_eq(&Value::from("1")));
    }

    #[test]
    fn json_round_trip() {
        let v: Value = serde_json::from_str(r#"[1, 2.5, "a", true, null]"#).unwrap();
        assert_eq!(
            v,
            Value::List(vec![
                Value::Int(1),
                Value::Float(2.5),
                Value::from("a"),
                Value::Bool(true),
                Value::Null
            ])
        );
    }
}
