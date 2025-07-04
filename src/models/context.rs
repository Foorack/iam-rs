use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents the request context gathered when a principal makes a request
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    /// The principal making the request (e.g., AROA123456789EXAMPLE)
    pub principal: String,

    /// The action being requested (e.g., iam:DeactivateMFADevice)
    pub action: String,

    /// The resource being accessed (e.g., arn:aws:iam::user/martha)
    pub resource: String,

    /// Context keys and their values
    pub context: HashMap<String, ContextValue>,
}

/// Represents different types of context values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextValue {
    /// String value (e.g., user ID, IP address)
    String(String),
    /// Boolean value (e.g., MFA present)
    Boolean(bool),
    /// Numeric value (e.g., MFA age in seconds, epoch time)
    Number(f64),
    /// DateTime value (e.g., request time)
    DateTime(DateTime<Utc>),
}

impl RequestContext {
    /// Creates a new request context
    pub fn new<S: Into<String>>(principal: S, action: S, resource: S) -> Self {
        Self {
            principal: principal.into(),
            action: action.into(),
            resource: resource.into(),
            context: HashMap::new(),
        }
    }

    /// Creates an empty request context (for evaluation context only)
    pub fn empty() -> Self {
        Self {
            principal: String::new(),
            action: String::new(),
            resource: String::new(),
            context: HashMap::new(),
        }
    }

    /// Adds all context
    pub fn with_context(mut self, context: HashMap<String, ContextValue>) -> Self {
        self.context.extend(context);
        self
    }

    /// Get a context value by key
    pub fn get(&self, key: &str) -> Option<&ContextValue> {
        self.context.get(key)
    }

    /// Insert a context value
    pub fn insert(&mut self, key: String, value: ContextValue) {
        self.context.insert(key, value);
    }

    /// Adds a string context value
    pub fn with_string_context<K: Into<String>, V: Into<String>>(
        mut self,
        key: K,
        value: V,
    ) -> Self {
        self.context
            .insert(key.into(), ContextValue::String(value.into()));
        self
    }

    /// Adds a boolean context value
    pub fn with_boolean_context<K: Into<String>>(mut self, key: K, value: bool) -> Self {
        self.context
            .insert(key.into(), ContextValue::Boolean(value));
        self
    }

    /// Adds a numeric context value
    pub fn with_number_context<K: Into<String>>(mut self, key: K, value: f64) -> Self {
        self.context.insert(key.into(), ContextValue::Number(value));
        self
    }

    /// Gets a context value by key
    pub fn get_context(&self, key: &str) -> Option<&ContextValue> {
        self.context.get(key)
    }

    /// Checks if a context key exists
    pub fn has_context(&self, key: &str) -> bool {
        self.context.contains_key(key)
    }

    /// Gets all context keys
    pub fn context_keys(&self) -> Vec<&String> {
        self.context.keys().collect()
    }
}

impl ContextValue {
    /// Converts the context value to a string representation
    pub fn as_string(&self) -> Option<&String> {
        match self {
            ContextValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Converts the context value to a boolean
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            ContextValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Converts the context value to a number
    pub fn as_number(&self) -> Option<f64> {
        match self {
            ContextValue::Number(n) => Some(*n),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_creation() {
        let context = RequestContext::new(
            "AROA123456789EXAMPLE",
            "iam:DeactivateMFADevice",
            "arn:aws:iam::user/martha",
        );

        assert_eq!(context.principal, "AROA123456789EXAMPLE");
        assert_eq!(context.action, "iam:DeactivateMFADevice");
        assert_eq!(context.resource, "arn:aws:iam::user/martha");
    }

    #[test]
    fn test_context_value_types() {
        let mut context = RequestContext::new("principal", "action", "resource");

        context = context
            .with_string_context("string_key", "string_value")
            .with_boolean_context("bool_key", true)
            .with_number_context("number_key", 42.0);

        // Test string value
        let string_val = context.get_context("string_key").unwrap();
        assert_eq!(string_val.as_string().unwrap(), "string_value");

        // Test boolean value
        let bool_val = context.get_context("bool_key").unwrap();
        assert_eq!(bool_val.as_boolean().unwrap(), true);

        // Test number value
        let number_val = context.get_context("number_key").unwrap();
        assert_eq!(number_val.as_number().unwrap(), 42.0);
    }

    #[test]
    fn test_context_utilities() {
        let context = RequestContext::new("principal", "action", "resource")
            .with_string_context("key1", "value1")
            .with_boolean_context("key2", false);

        // Test has_context
        assert!(context.has_context("key1"));
        assert!(context.has_context("key2"));
        assert!(!context.has_context("key3"));

        // Test context_keys
        let keys = context.context_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&&"key1".to_string()));
        assert!(keys.contains(&&"key2".to_string()));
    }
}
