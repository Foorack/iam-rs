use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
struct StringList(Vec<String>);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
struct BooleanList(Vec<bool>);

/// Represents different types of context values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ContextValue {
    /// String value (e.g., user ID, IP address)
    #[cfg_attr(feature = "utoipa", schema(title = "String"))]
    String(String),
    /// Boolean value (e.g., MFA present)
    #[cfg_attr(feature = "utoipa", schema(title = "Boolean"))]
    Boolean(bool),
    /// Numeric value (e.g., MFA age in seconds, epoch time)
    #[cfg_attr(feature = "utoipa", schema(title = "Number"))]
    Number(f64),
    /// `DateTime` value (e.g., request time)
    #[cfg_attr(feature = "utoipa", schema(title = "DateTime"))]
    DateTime(DateTime<Utc>),
    /// List of strings (e.g., list of ARNs)
    #[cfg_attr(feature = "utoipa", schema(title = "StringList", value_type = StringList))]
    StringList(Vec<String>),
    /// List of booleans
    #[cfg_attr(feature = "utoipa", schema(title = "BooleanList", value_type = BooleanList))]
    BooleanList(Vec<bool>),
}

impl ContextValue {
    /// Converts the context value to a string representation
    #[must_use]
    pub fn as_string(&self) -> Option<&String> {
        match self {
            ContextValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Converts the context value to a boolean
    #[must_use]
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            ContextValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Converts the context value to a number
    #[must_use]
    pub fn as_number(&self) -> Option<f64> {
        match self {
            ContextValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Converts the context value to a `DateTime`
    #[must_use]
    pub fn as_datetime(&self) -> Option<&DateTime<Utc>> {
        match self {
            ContextValue::DateTime(dt) => Some(dt),
            _ => None,
        }
    }

    /// Converts the context value to a list of strings
    #[must_use]
    pub fn as_string_list(&self) -> Option<&Vec<String>> {
        match self {
            ContextValue::StringList(list) => Some(list),
            _ => None,
        }
    }
}

/// Context for IAM evaluation containing key-value pairs
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Context {
    /// Context keys and their values
    pub data: HashMap<String, ContextValue>,
}

// Impl serialization and deserialization for Context (hide the data internal structure)
impl Serialize for Context {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = HashMap::<String, ContextValue>::deserialize(deserializer)?;
        Ok(Context { data })
    }
}

impl Context {
    /// Creates a new empty context
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Creates a context with initial data
    #[must_use]
    pub fn with_data(data: HashMap<String, ContextValue>) -> Self {
        Self { data }
    }

    /// Get a context value by key
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ContextValue> {
        self.data.get(key)
    }

    /// Insert a context value
    pub fn insert(&mut self, key: String, value: ContextValue) {
        self.data.insert(key, value);
    }

    /// Adds a string context value
    #[must_use]
    pub fn with_string<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.data
            .insert(key.into(), ContextValue::String(value.into()));
        self
    }

    /// Adds a boolean context value
    #[must_use]
    pub fn with_boolean<K: Into<String>>(mut self, key: K, value: bool) -> Self {
        self.data.insert(key.into(), ContextValue::Boolean(value));
        self
    }

    /// Adds a numeric context value
    #[must_use]
    pub fn with_number<K: Into<String>>(mut self, key: K, value: f64) -> Self {
        self.data.insert(key.into(), ContextValue::Number(value));
        self
    }

    /// Checks if a context key exists
    #[must_use]
    pub fn has_key(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Gets all context keys
    #[must_use]
    pub fn keys(&self) -> Vec<&String> {
        self.data.keys().collect()
    }

    /// Extends the context with another context
    pub fn extend(&mut self, other: Context) {
        self.data.extend(other.data);
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let context = Context::new()
            .with_string("key1", "value1")
            .with_boolean("key2", true)
            .with_number("key3", 42.0);

        assert_eq!(context.get("key1").unwrap().as_string().unwrap(), "value1");
        assert_eq!(context.get("key2").unwrap().as_boolean().unwrap(), true);
        assert_eq!(context.get("key3").unwrap().as_number().unwrap(), 42.0);
    }
}
