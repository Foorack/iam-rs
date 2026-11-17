use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
struct StringList(Vec<String>);

#[allow(dead_code)]
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
pub struct Context {
    /// Context keys and their values
    pub data: HashMap<String, ContextValue>,
}

// `Context` serializes as its inner map, so its published schema has to describe
// that map rather than the struct. Deriving `ToSchema` would publish an object with
// a required `data` property, which is not the JSON clients actually receive.
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for Context {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        // The map `Context` serializes as. `propertyNames` is what utoipa's own
        // `HashMap<String, _>` derive emitted, so keeping it leaves the published schema
        // identical to the previous one apart from the removed `data` wrapper.
        let key = utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String);
        utoipa::openapi::schema::ObjectBuilder::new()
            .description(Some(
                "Context for IAM evaluation containing key-value pairs",
            ))
            .property_names(Some(key))
            .additional_properties(Some(utoipa::openapi::Ref::from_schema_name("ContextValue")))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for Context {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Context")
    }

    fn schemas(
        schemas: &mut Vec<(
            String,
            utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
        )>,
    ) {
        schemas.push((
            <ContextValue as utoipa::ToSchema>::name().into_owned(),
            <ContextValue as utoipa::PartialSchema>::schema(),
        ));
        <ContextValue as utoipa::ToSchema>::schemas(schemas);
    }
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

    /// Get a context value by key.
    ///
    /// AWS treats context key names as case-insensitive (e.g. `aws:SourceIP`
    /// and `AWS:sourceip` are the same key), so lookup falls back to a
    /// case-insensitive scan if the exact key is not present.
    ///
    /// If the exact spelling is not present but several stored keys match
    /// case-insensitively (e.g. `aws:PrincipalTag/team` and
    /// `aws:PrincipalTag/TEAM` both exist), the lexicographically smallest
    /// matching key wins. This is a total order chosen purely so the lookup is
    /// deterministic: a policy decision must never depend on `HashMap` iteration
    /// order. AWS documents no rule for such duplicates, only that they can lead
    /// to unexpected condition failures.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ContextValue> {
        self.data.get(key).or_else(|| {
            self.data
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(key))
                .min_by(|(a, _), (b, _)| a.cmp(b))
                .map(|(_, value)| value)
        })
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

    /// Checks if a context key exists.
    ///
    /// Uses the same case-insensitive lookup as [`Context::get`], so
    /// `has_key(k)` is exactly `get(k).is_some()`.
    #[must_use]
    pub fn has_key(&self, key: &str) -> bool {
        self.get(key).is_some()
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
    #[allow(clippy::float_cmp)]
    fn test_context_creation() {
        let context = Context::new()
            .with_string("key1", "value1")
            .with_boolean("key2", true)
            .with_number("key3", 42.0);

        assert_eq!(context.get("key1").unwrap().as_string().unwrap(), "value1");
        assert!(context.get("key2").unwrap().as_boolean().unwrap());
        assert_eq!(context.get("key3").unwrap().as_number().unwrap(), 42.0);
    }

    /// The serialized form is the flat map, not a struct with a `data` field.
    #[test]
    fn test_context_serializes_as_flat_map() {
        let context = Context::new().with_string("key", "value");

        let json = serde_json::to_value(&context).unwrap();
        assert_eq!(json, serde_json::json!({ "key": "value" }));
        assert!(json.get("data").is_none());
    }

    /// The published schema describes the flat map the Serialize impl writes.
    #[test]
    #[cfg(feature = "utoipa")]
    fn test_context_schema_is_flat_map() {
        use utoipa::PartialSchema;

        let json = serde_json::to_value(Context::schema()).unwrap();

        assert_eq!(json["type"], "object");
        assert_eq!(
            json["additionalProperties"],
            serde_json::json!({ "$ref": "#/components/schemas/ContextValue" })
        );
        // The old derived schema required `data`, and a client generated from it reads
        // `json['data']`. Neither a `properties` entry nor a `required` list may come back.
        assert!(json.get("properties").is_none());
        assert!(json.get("required").is_none());
    }

    #[test]
    fn test_get_case_insensitive() {
        let context = Context::new().with_string("AWS:SourceIp", "1.2.3.4");

        // Exact-case lookup works.
        assert_eq!(
            context.get("AWS:SourceIp").unwrap().as_string().unwrap(),
            "1.2.3.4"
        );
        // Lookup is case-insensitive, matching AWS (key names ignore case).
        assert_eq!(
            context.get("aws:sourceip").unwrap().as_string().unwrap(),
            "1.2.3.4"
        );
        // Missing keys stay missing.
        assert!(context.get("aws:nonexistent").is_none());
    }

    #[test]
    fn test_has_key_is_case_insensitive() {
        let context = Context::new()
            .with_string("aws:SourceIp", "10.0.0.1")
            .with_boolean("aws:SecureTransport", true);

        assert!(context.has_key("aws:SourceIp"));
        assert!(context.has_key("aws:sourceip"));
        assert!(context.has_key("AWS:SOURCEIP"));
        assert!(context.has_key("aws:securetransport"));

        // Genuinely absent keys stay absent.
        assert!(!context.has_key("aws:nonexistent"));
        assert!(!context.has_key("aws:SourceIP2"));
        assert!(!context.has_key(""));

        // `has_key` must answer exactly like `get` for every spelling.
        for key in [
            "aws:SourceIp",
            "aws:sourceip",
            "AWS:SOURCEIP",
            "aws:SourceIp ",
            " aws:sourceip",
            "aws:securetransport",
            "aws:nonexistent",
            "",
        ] {
            assert_eq!(context.has_key(key), context.get(key).is_some(), "{key}");
        }
    }

    /// The documented tie-break: with duplicate case-variants and no exact match,
    /// the lexicographically smallest key wins. `aws:PrincipalTag/TEAM` sorts
    /// before `aws:PrincipalTag/team` (uppercase `T` < lowercase `t`).
    #[test]
    fn test_duplicate_case_variants_resolve_to_smallest_key() {
        let blocked = ContextValue::String("blocked".into());
        let alice = ContextValue::String("alice".into());

        let mut context = Context::new();
        context.insert("aws:PrincipalTag/team".into(), blocked.clone());
        let mut other = Context::new();
        other.insert("aws:PrincipalTag/TEAM".into(), alice.clone());
        context.extend(other);

        // Exact spellings still win over the case-insensitive tie-break.
        assert_eq!(context.get("aws:PrincipalTag/team"), Some(&blocked));
        assert_eq!(context.get("aws:PrincipalTag/TEAM"), Some(&alice));

        // Any spelling that is not stored verbatim resolves by the total order.
        assert_eq!(context.get("aws:PrincipalTag/Team"), Some(&alice));
        assert_eq!(context.get("AWS:PRINCIPALTAG/team"), Some(&alice));
        assert_eq!(context.get("aws:principaltag/Team"), Some(&alice));
    }

    /// Whatever the insertion order and however the map was built, a lookup that
    /// matches several case-variants must return the same value every time.
    #[test]
    fn test_duplicate_case_variants_are_deterministic_across_copies() {
        let blocked = ContextValue::String("blocked".into());
        let alice = ContextValue::String("alice".into());
        let expected = Some(&alice);

        let build = || {
            let mut context = Context::new();
            context.insert("aws:PrincipalTag/team".into(), blocked.clone());
            let mut other = Context::new();
            other.insert("aws:PrincipalTag/TEAM".into(), alice.clone());
            context.extend(other);
            context
        };

        // Same map, different construction order.
        let mut reversed = Context::new();
        reversed.insert("aws:PrincipalTag/TEAM".into(), alice.clone());
        reversed.insert("aws:PrincipalTag/team".into(), blocked.clone());

        let base = build();
        let json = serde_json::to_string(&base).unwrap();

        // Every fresh `HashMap` gets a fresh `RandomState`, so rebuilding and
        // re-deserializing in-process exercises many different iteration orders.
        for _ in 0..100 {
            let mut fresh_reversed = Context::new();
            fresh_reversed.insert("aws:PrincipalTag/TEAM".into(), alice.clone());
            fresh_reversed.insert("aws:PrincipalTag/team".into(), blocked.clone());
            let decoded: Context = serde_json::from_str(&json).unwrap();
            let from_data = Context::with_data(base.data.clone());

            for context in [
                build(),
                fresh_reversed,
                decoded,
                from_data,
                base.clone(),
                reversed.clone(),
            ] {
                assert_eq!(context.get("aws:PrincipalTag/Team"), expected);
                assert_eq!(context.get("aws:principaltag/team"), expected);
                assert!(context.has_key("aws:PrincipalTag/Team"));
            }
        }
    }

    /// Guards the pre-existing precedence rule: an exact spelling beats a
    /// case-variant duplicate, even when the duplicate sorts first.
    #[test]
    fn test_get_exact_spelling_wins_over_case_variant_duplicate() {
        let blocked = ContextValue::String("blocked".into());
        let alice = ContextValue::String("alice".into());

        let mut context = Context::new();
        context.insert("aws:PrincipalTag/team".into(), blocked.clone());
        context.insert("aws:PrincipalTag/TEAM".into(), alice.clone());

        assert_eq!(context.get("aws:PrincipalTag/team"), Some(&blocked));
        assert_eq!(context.get("aws:PrincipalTag/TEAM"), Some(&alice));
        assert_eq!(context.get("aws:PrincipalTag/Team"), Some(&alice));
    }
}
