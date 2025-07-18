use crate::{
    OperatorType,
    core::Operator,
    validation::{Validate, ValidationContext, ValidationError, ValidationResult, helpers},
};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};

/// Represents a condition value that can be a boolean, number, string, or list of strings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ConditionValue {
    /// A boolean value (e.g., `true`, `false`)
    Boolean(bool),
    /// A numeric value (e.g., `42`, `3.14`)
    Number(i64),
    /// A single string value (e.g., `"us-east-1"`)
    String(String),
    /// Multiple string values (e.g., `["us-east-1", "us-west-2"]`)
    StringList(Vec<String>),
}

impl ConditionValue {
    /// Returns true if this is a string value
    #[must_use]
    pub fn is_string(&self) -> bool {
        matches!(self, ConditionValue::String(_))
    }

    /// Returns true if this is a boolean value
    #[must_use]
    pub fn is_boolean(&self) -> bool {
        matches!(self, ConditionValue::Boolean(_))
    }

    /// Returns true if this is a number value
    #[must_use]
    pub fn is_number(&self) -> bool {
        matches!(self, ConditionValue::Number(_))
    }

    /// Returns true if this is a string list value
    #[must_use]
    pub fn is_string_list(&self) -> bool {
        matches!(self, ConditionValue::StringList(_))
    }

    /// Returns true if this value represents multiple items (i.e., is a list)
    #[must_use]
    pub fn is_array(&self) -> bool {
        matches!(self, ConditionValue::StringList(_))
    }

    /// Returns the length of the value (1 for single values, list length for arrays)
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            ConditionValue::StringList(list) => list.len(),
            _ => 1,
        }
    }

    /// Returns true if this is an empty list
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            ConditionValue::StringList(list) => list.is_empty(),
            _ => false,
        }
    }

    /// Converts to a `serde_json::Value` for backward compatibility
    #[must_use]
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            ConditionValue::Boolean(b) => serde_json::Value::Bool(*b),
            ConditionValue::Number(n) => serde_json::Value::Number((*n).into()),
            ConditionValue::String(s) => serde_json::Value::String(s.clone()),
            ConditionValue::StringList(list) => serde_json::Value::Array(
                list.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        }
    }

    /// Creates a ConditionValue from a `serde_json::Value`
    pub fn from_json_value(value: serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Bool(b) => Ok(ConditionValue::Boolean(b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(ConditionValue::Number(i))
                } else {
                    Err(format!("Unsupported number format: {n}"))
                }
            }
            serde_json::Value::String(s) => Ok(ConditionValue::String(s)),
            serde_json::Value::Array(arr) => {
                let mut strings = Vec::new();
                for item in arr {
                    if let serde_json::Value::String(s) = item {
                        strings.push(s);
                    } else {
                        return Err(format!("Array must contain only strings, found: {item:?}"));
                    }
                }
                Ok(ConditionValue::StringList(strings))
            }
            _ => Err(format!("Unsupported JSON value type: {value:?}")),
        }
    }
}

/// Represents a single condition in an IAM policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Condition {
    /// The condition operator (e.g., `StringEquals`, `DateGreaterThan`)
    pub operator: Operator,
    /// The condition key (e.g., "aws:username", "s3:prefix")
    pub key: String,
    /// The condition value(s)
    pub value: ConditionValue,
}

/// Represents a condition block in an IAM policy
/// This is a collection of conditions grouped by operator
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ConditionBlock {
    /// Map of operators to their key-value pairs
    #[serde(flatten)]
    pub conditions: HashMap<Operator, HashMap<String, ConditionValue>>,
}

impl Serialize for ConditionBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the HashMap<Operator, ...> to BTreeMap<String, ...> for ordered serialization
        // Also, sort the keys within each condition (e.g., inside StringEquals)
        let ordered_map: BTreeMap<String, BTreeMap<String, &ConditionValue>> = self
            .conditions
            .iter()
            .map(|(op, conditions)| {
                let inner_ordered: BTreeMap<String, &ConditionValue> =
                    conditions.iter().map(|(k, v)| (k.clone(), v)).collect();
                (op.as_str().to_string(), inner_ordered)
            })
            .collect();

        ordered_map.serialize(serializer)
    }
}

impl Condition {
    /// Creates a new condition
    pub fn new<K: Into<String>>(operator: Operator, key: K, value: ConditionValue) -> Self {
        Self {
            operator,
            key: key.into(),
            value,
        }
    }

    /// Creates a condition with a string value
    pub fn string<K: Into<String>, V: Into<String>>(operator: Operator, key: K, value: V) -> Self {
        Self::new(operator, key, ConditionValue::String(value.into()))
    }

    /// Creates a condition with a boolean value
    pub fn boolean<K: Into<String>>(operator: Operator, key: K, value: bool) -> Self {
        Self::new(operator, key, ConditionValue::Boolean(value))
    }

    /// Creates a condition with a numeric value
    pub fn number<K: Into<String>>(operator: Operator, key: K, value: i64) -> Self {
        Self::new(operator, key, ConditionValue::Number(value))
    }

    /// Creates a condition with an array of string values
    pub fn string_array<K: Into<String>>(operator: Operator, key: K, values: Vec<String>) -> Self {
        Self::new(operator, key, ConditionValue::StringList(values))
    }
}

impl ConditionBlock {
    /// Creates a new empty condition block
    #[must_use]
    pub fn new() -> Self {
        Self {
            conditions: HashMap::new(),
        }
    }

    /// Adds a condition to the block
    pub fn add_condition(&mut self, condition: Condition) {
        let operator_map = self.conditions.entry(condition.operator).or_default();
        operator_map.insert(condition.key, condition.value);
    }

    /// Adds a condition using the builder pattern
    #[must_use]
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.add_condition(condition);
        self
    }

    /// Adds a condition directly with operator, key, and value
    #[must_use]
    pub fn with_condition_direct<K: Into<String>>(
        mut self,
        operator: Operator,
        key: K,
        value: ConditionValue,
    ) -> Self {
        let condition = Condition::new(operator, key, value);
        self.add_condition(condition);
        self
    }

    /// Gets all conditions for a specific operator
    #[must_use]
    pub fn get_conditions_for_operator(
        &self,
        operator: &Operator,
    ) -> Option<&HashMap<String, ConditionValue>> {
        self.conditions.get(operator)
    }

    /// Gets a specific condition value
    #[must_use]
    pub fn get_condition_value(&self, operator: &Operator, key: &str) -> Option<&ConditionValue> {
        self.conditions.get(operator)?.get(key)
    }

    /// Checks if a condition exists
    #[must_use]
    pub fn has_condition(&self, operator: &Operator, key: &str) -> bool {
        self.conditions
            .get(operator)
            .is_some_and(|map| map.contains_key(key))
    }

    /// Gets all operators used in this condition block
    #[must_use]
    pub fn operators(&self) -> Vec<&Operator> {
        self.conditions.keys().collect()
    }

    /// Checks if the condition block is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    /// Converts to the legacy `HashMap` format for backward compatibility
    #[must_use]
    pub fn to_legacy_format(&self) -> HashMap<String, HashMap<String, serde_json::Value>> {
        self.conditions
            .iter()
            .map(|(op, conditions)| {
                let json_conditions = conditions
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_json_value()))
                    .collect();
                (op.as_str().to_string(), json_conditions)
            })
            .collect()
    }

    /// Creates a condition block from the legacy `HashMap` format
    ///
    /// # Errors
    ///
    /// Returns an error if any operator string cannot be parsed into a valid `Operator`.
    pub fn from_legacy_format(
        legacy: HashMap<String, HashMap<String, serde_json::Value>>,
    ) -> Result<Self, String> {
        let mut conditions = HashMap::new();

        for (op_str, condition_map) in legacy {
            let operator = op_str
                .parse::<Operator>()
                .map_err(|e| format!("Invalid operator '{op_str}': {e}"))?;

            let mut converted_conditions = HashMap::new();
            for (key, value) in condition_map {
                let condition_value = ConditionValue::from_json_value(value)
                    .map_err(|e| format!("Invalid condition value for key '{key}': {e}"))?;
                converted_conditions.insert(key, condition_value);
            }

            conditions.insert(operator, converted_conditions);
        }

        Ok(Self { conditions })
    }
}

impl Default for ConditionBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl Validate for Condition {
    #[allow(clippy::too_many_lines)]
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Condition", |ctx| {
            let mut results = Vec::new();

            // Validate that key is not empty
            results.push(helpers::validate_non_empty(&self.key, "key", ctx));

            // Validate that the operator and value are compatible
            #[allow(clippy::single_match)]
            match &self.value {
                ConditionValue::StringList(arr) => {
                    if arr.is_empty() {
                        results.push(Err(ValidationError::InvalidCondition {
                            operator: self.operator.as_str().to_string(),
                            key: self.key.clone(),
                            reason: "Condition value array cannot be empty".to_string(),
                        }));
                    }

                    // Check if operator supports multiple values
                    if !self.operator.supports_multiple_values() && arr.len() > 1 {
                        results.push(Err(ValidationError::InvalidCondition {
                            operator: self.operator.as_str().to_string(),
                            key: self.key.clone(),
                            reason: format!("Operator {} does not support multiple values", self.operator.as_str()),
                        }));
                    }
                }
                _ => {} // Single values are generally OK
            }

            // Validate operator-specific rules
            match self.operator.category() {
                    OperatorType::String => {
                        // String operators should have string values
                        match &self.value {
                            ConditionValue::String(_) => {},
                            ConditionValue::StringList(arr) => {
                                if arr.is_empty() {
                                    results.push(Err(ValidationError::InvalidCondition {
                                        operator: self.operator.as_str().to_string(),
                                        key: self.key.clone(),
                                        reason: "String operator requires non-empty string array".to_string(),
                                    }));
                                }
                            },
                            _ => {
                                results.push(Err(ValidationError::InvalidCondition {
                                    operator: self.operator.as_str().to_string(),
                                    key: self.key.clone(),
                                    reason: "String operator requires string value(s)".to_string(),
                                }));
                            }
                        }
                    },
                    OperatorType::Numeric => {
                        // Numeric operators should have numeric values
                        #[allow(clippy::match_wildcard_for_single_variants)]
                        match &self.value {
                            ConditionValue::Number(_) => {},
                            ConditionValue::String(s) => {
                                // Allow string representation of numbers
                                if s.parse::<f64>().is_err() {
                                    results.push(Err(ValidationError::InvalidCondition {
                                        operator: self.operator.as_str().to_string(),
                                        key: self.key.clone(),
                                        reason: format!("Numeric operator requires numeric value, found non-numeric string: {s}"),
                                    }));
                                }
                            },
                            ConditionValue::StringList(arr) => {
                                for (i, s) in arr.iter().enumerate() {
                                    if s.parse::<f64>().is_err() {
                                        results.push(Err(ValidationError::InvalidCondition {
                                            operator: self.operator.as_str().to_string(),
                                            key: self.key.clone(),
                                            reason: format!("Numeric operator requires numeric values, found non-numeric string at index {i}: {s}"),
                                        }));
                                    }
                                }
                            },
                            _ => {
                                results.push(Err(ValidationError::InvalidCondition {
                                    operator: self.operator.as_str().to_string(),
                                    key: self.key.clone(),
                                    reason: "Numeric operator requires numeric value(s)".to_string(),
                                }));
                            }
                        }
                    },
                    OperatorType::Date => {
                        // Date operators should have valid date strings
                        match &self.value {
                            ConditionValue::String(s) => {
                                // Basic ISO 8601 format check
                                if !s.contains('T') && !s.contains('-') {
                                    results.push(Err(ValidationError::InvalidCondition {
                                        operator: self.operator.as_str().to_string(),
                                        key: self.key.clone(),
                                        reason: format!("Date operator requires ISO 8601 date format, found: {s}"),
                                    }));
                                }
                            },
                            _ => {
                                results.push(Err(ValidationError::InvalidCondition {
                                    operator: self.operator.as_str().to_string(),
                                    key: self.key.clone(),
                                    reason: "Date operator requires string date value".to_string(),
                                }));
                            }
                        }
                    },
                    OperatorType::Boolean => {
                        // Boolean operators should have boolean values
                        match &self.value {
                            ConditionValue::Boolean(_) => {},
                            ConditionValue::String(s) => {
                                if !matches!(s.as_str(), "true" | "false") {
                                    results.push(Err(ValidationError::InvalidCondition {
                                        operator: self.operator.as_str().to_string(),
                                        key: self.key.clone(),
                                        reason: format!("Boolean operator requires boolean value, found: {s}"),
                                    }));
                                }
                            },
                            _ => {
                                results.push(Err(ValidationError::InvalidCondition {
                                    operator: self.operator.as_str().to_string(),
                                    key: self.key.clone(),
                                    reason: "Boolean operator requires boolean value".to_string(),
                                }));
                            }
                        }
                    },
                    _ => {} // Other categories are more flexible
                }

            helpers::collect_errors(results)
        })
    }
}

impl Validate for ConditionBlock {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("ConditionBlock", |ctx| {
            if self.conditions.is_empty() {
                return Err(ValidationError::InvalidValue {
                    field: "Condition".to_string(),
                    value: "{}".to_string(),
                    reason: "Condition block cannot be empty".to_string(),
                });
            }

            let mut results = Vec::new();

            for (operator, condition_map) in &self.conditions {
                ctx.with_segment(operator.as_str(), |op_ctx| {
                    if condition_map.is_empty() {
                        results.push(Err(ValidationError::InvalidValue {
                            field: "Condition operator".to_string(),
                            value: operator.as_str().to_string(),
                            reason: "Condition operator cannot have empty condition map"
                                .to_string(),
                        }));
                        return;
                    }

                    for (key, value) in condition_map {
                        op_ctx.with_segment(key, |key_ctx| {
                            let condition = Condition {
                                operator: operator.clone(),
                                key: key.clone(),
                                value: value.clone(),
                            };
                            results.push(condition.validate(key_ctx));
                        });
                    }
                });
            }

            helpers::collect_errors(results)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_creation() {
        let condition = Condition::string(Operator::StringEquals, "aws:username", "john");

        assert_eq!(condition.operator, Operator::StringEquals);
        assert_eq!(condition.key, "aws:username");
        assert_eq!(condition.value, ConditionValue::String("john".to_string()));
    }

    #[test]
    fn test_condition_block() {
        let block = ConditionBlock::new()
            .with_condition(Condition::string(
                Operator::StringEquals,
                "aws:username",
                "john",
            ))
            .with_condition(Condition::boolean(
                Operator::Bool,
                "aws:SecureTransport",
                true,
            ));

        assert!(block.has_condition(&Operator::StringEquals, "aws:username"));
        assert!(block.has_condition(&Operator::Bool, "aws:SecureTransport"));
        assert!(!block.has_condition(&Operator::StringEquals, "nonexistent"));

        let username = block.get_condition_value(&Operator::StringEquals, "aws:username");
        assert_eq!(username, Some(&ConditionValue::String("john".to_string())));
    }

    #[test]
    fn test_legacy_format_conversion() {
        let mut legacy = HashMap::new();
        let mut string_conditions = HashMap::new();
        string_conditions.insert("aws:username".to_string(), serde_json::json!("john"));
        legacy.insert("StringEquals".to_string(), string_conditions);

        let block = ConditionBlock::from_legacy_format(legacy.clone()).unwrap();
        assert!(block.has_condition(&Operator::StringEquals, "aws:username"));

        let converted_back = block.to_legacy_format();
        assert_eq!(converted_back, legacy);
    }

    #[test]
    fn test_condition_serialization() {
        let condition = Condition::string(Operator::StringEquals, "aws:username", "john");

        let json = serde_json::to_string(&condition).unwrap();
        let deserialized: Condition = serde_json::from_str(&json).unwrap();

        assert_eq!(condition, deserialized);
    }

    #[test]
    fn test_condition_block_serialization() {
        let block = ConditionBlock::new()
            .with_condition(Condition::string_array(
                Operator::StringEquals,
                "aws:PrincipalTag/department",
                vec!["finance".to_string(), "hr".to_string(), "legal".to_string()],
            ))
            .with_condition(Condition::string_array(
                Operator::ArnLike,
                "aws:PrincipalArn",
                vec![
                    "arn:aws:iam::222222222222:user/Ana".to_string(),
                    "arn:aws:iam::222222222222:user/Mary".to_string(),
                ],
            ));

        let json = serde_json::to_string_pretty(&block).unwrap();
        println!("Current serialization:\n{}", json);

        // Test that it can be deserialized back
        let deserialized: ConditionBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, deserialized);
    }
}
