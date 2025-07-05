use crate::{
    core::Operator,
    validation::{Validate, ValidationContext, ValidationResult, ValidationError, helpers},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};

/// Represents a single condition in an IAM policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// The condition operator (e.g., StringEquals, DateGreaterThan)
    pub operator: Operator,
    /// The condition key (e.g., "aws:username", "s3:prefix")
    pub key: String,
    /// The condition value(s)
    pub value: serde_json::Value,
}

/// Represents a condition block in an IAM policy
/// This is a collection of conditions grouped by operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionBlock {
    /// Map of operators to their key-value pairs
    pub conditions: HashMap<Operator, HashMap<String, serde_json::Value>>,
}

impl Serialize for ConditionBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the HashMap<Operator, ...> to BTreeMap<String, ...> for ordered serialization
        // Also, sort the keys within each condition (e.g., inside StringEquals)
        let ordered_map: BTreeMap<String, BTreeMap<String, &serde_json::Value>> = self
            .conditions
            .iter()
            .map(|(op, conditions)| {
                let inner_ordered: BTreeMap<String, &serde_json::Value> = conditions
                    .iter()
                    .map(|(k, v)| (k.clone(), v))
                    .collect();
                (op.as_str().to_string(), inner_ordered)
            })
            .collect();

        ordered_map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConditionBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_map: HashMap<String, HashMap<String, serde_json::Value>> =
            HashMap::deserialize(deserializer)?;

        let mut conditions = HashMap::new();

        for (op_str, condition_map) in string_map {
            let operator = op_str.parse::<Operator>().map_err(|e| {
                serde::de::Error::custom(format!("Invalid operator '{}': {}", op_str, e))
            })?;
            conditions.insert(operator, condition_map);
        }

        Ok(ConditionBlock { conditions })
    }
}

impl Condition {
    /// Creates a new condition
    pub fn new<K: Into<String>>(operator: Operator, key: K, value: serde_json::Value) -> Self {
        Self {
            operator,
            key: key.into(),
            value,
        }
    }

    /// Creates a condition with a string value
    pub fn string<K: Into<String>, V: Into<String>>(operator: Operator, key: K, value: V) -> Self {
        Self::new(operator, key, serde_json::Value::String(value.into()))
    }

    /// Creates a condition with a boolean value
    pub fn boolean<K: Into<String>>(operator: Operator, key: K, value: bool) -> Self {
        Self::new(operator, key, serde_json::Value::Bool(value))
    }

    /// Creates a condition with a numeric value
    pub fn number<K: Into<String>>(operator: Operator, key: K, value: i64) -> Self {
        Self::new(
            operator,
            key,
            serde_json::Value::Number(serde_json::Number::from(value)),
        )
    }

    /// Creates a condition with an array of string values
    pub fn string_array<K: Into<String>>(operator: Operator, key: K, values: Vec<String>) -> Self {
        let json_values: Vec<serde_json::Value> =
            values.into_iter().map(serde_json::Value::String).collect();
        Self::new(operator, key, serde_json::Value::Array(json_values))
    }
}

impl ConditionBlock {
    /// Creates a new empty condition block
    pub fn new() -> Self {
        Self {
            conditions: HashMap::new(),
        }
    }

    /// Adds a condition to the block
    pub fn add_condition(&mut self, condition: Condition) {
        let operator_map = self
            .conditions
            .entry(condition.operator)
            .or_insert_with(HashMap::new);
        operator_map.insert(condition.key, condition.value);
    }

    /// Adds a condition using the builder pattern
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.add_condition(condition);
        self
    }

    /// Adds a condition directly with operator, key, and value
    pub fn with_condition_direct<K: Into<String>>(
        mut self,
        operator: Operator,
        key: K,
        value: serde_json::Value,
    ) -> Self {
        let condition = Condition::new(operator, key, value);
        self.add_condition(condition);
        self
    }

    /// Gets all conditions for a specific operator
    pub fn get_conditions_for_operator(
        &self,
        operator: &Operator,
    ) -> Option<&HashMap<String, serde_json::Value>> {
        self.conditions.get(operator)
    }

    /// Gets a specific condition value
    pub fn get_condition_value(
        &self,
        operator: &Operator,
        key: &str,
    ) -> Option<&serde_json::Value> {
        self.conditions.get(operator)?.get(key)
    }

    /// Checks if a condition exists
    pub fn has_condition(&self, operator: &Operator, key: &str) -> bool {
        self.conditions
            .get(operator)
            .map(|map| map.contains_key(key))
            .unwrap_or(false)
    }

    /// Gets all operators used in this condition block
    pub fn operators(&self) -> Vec<&Operator> {
        self.conditions.keys().collect()
    }

    /// Checks if the condition block is empty
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    /// Converts to the legacy HashMap format for backward compatibility
    pub fn to_legacy_format(&self) -> HashMap<String, HashMap<String, serde_json::Value>> {
        self.conditions
            .iter()
            .map(|(op, conditions)| (op.as_str().to_string(), conditions.clone()))
            .collect()
    }

    /// Creates a condition block from the legacy HashMap format
    pub fn from_legacy_format(
        legacy: HashMap<String, HashMap<String, serde_json::Value>>,
    ) -> Result<Self, String> {
        let mut conditions = HashMap::new();

        for (op_str, condition_map) in legacy {
            let operator = op_str
                .parse::<Operator>()
                .map_err(|e| format!("Invalid operator '{}': {}", op_str, e))?;
            conditions.insert(operator, condition_map);
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
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Condition", |ctx| {
            let mut results = Vec::new();

            // Validate that key is not empty
            results.push(helpers::validate_non_empty(&self.key, "key", ctx));

            // Validate that the operator and value are compatible
            match &self.value {
                serde_json::Value::Null => {
                    results.push(Err(ValidationError::InvalidCondition {
                        operator: self.operator.as_str().to_string(),
                        key: self.key.clone(),
                        reason: "Condition value cannot be null".to_string(),
                    }));
                }
                serde_json::Value::Array(arr) => {
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
                    "String" => {
                        // String operators should have string values
                        match &self.value {
                            serde_json::Value::String(_) => {},
                            serde_json::Value::Array(arr) => {
                                for (i, val) in arr.iter().enumerate() {
                                    if !val.is_string() {
                                        results.push(Err(ValidationError::InvalidCondition {
                                            operator: self.operator.as_str().to_string(),
                                            key: self.key.clone(),
                                            reason: format!("String operator requires string values, found {} at index {}", val, i),
                                        }));
                                    }
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
                    "Numeric" => {
                        // Numeric operators should have numeric values
                        match &self.value {
                            serde_json::Value::Number(_) => {},
                            serde_json::Value::String(s) => {
                                // Allow string representation of numbers
                                if s.parse::<f64>().is_err() {
                                    results.push(Err(ValidationError::InvalidCondition {
                                        operator: self.operator.as_str().to_string(),
                                        key: self.key.clone(),
                                        reason: format!("Numeric operator requires numeric value, found non-numeric string: {}", s),
                                    }));
                                }
                            },
                            serde_json::Value::Array(arr) => {
                                for (i, val) in arr.iter().enumerate() {
                                    match val {
                                        serde_json::Value::Number(_) => {},
                                        serde_json::Value::String(s) => {
                                            if s.parse::<f64>().is_err() {
                                                results.push(Err(ValidationError::InvalidCondition {
                                                    operator: self.operator.as_str().to_string(),
                                                    key: self.key.clone(),
                                                    reason: format!("Numeric operator requires numeric values, found non-numeric string at index {}: {}", i, s),
                                                }));
                                            }
                                        },
                                        _ => {
                                            results.push(Err(ValidationError::InvalidCondition {
                                                operator: self.operator.as_str().to_string(),
                                                key: self.key.clone(),
                                                reason: format!("Numeric operator requires numeric values, found {} at index {}", val, i),
                                            }));
                                        }
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
                    "Date" => {
                        // Date operators should have valid date strings
                        match &self.value {
                            serde_json::Value::String(s) => {
                                // Basic ISO 8601 format check
                                if !s.contains('T') && !s.contains('-') {
                                    results.push(Err(ValidationError::InvalidCondition {
                                        operator: self.operator.as_str().to_string(),
                                        key: self.key.clone(),
                                        reason: format!("Date operator requires ISO 8601 date format, found: {}", s),
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
                    "Boolean" => {
                        // Boolean operators should have boolean values
                        match &self.value {
                            serde_json::Value::Bool(_) => {},
                            serde_json::Value::String(s) => {
                                if !matches!(s.as_str(), "true" | "false") {
                                    results.push(Err(ValidationError::InvalidCondition {
                                        operator: self.operator.as_str().to_string(),
                                        key: self.key.clone(),
                                        reason: format!("Boolean operator requires boolean value, found: {}", s),
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
                ctx.with_segment(&operator.as_str(), |op_ctx| {
                    if condition_map.is_empty() {
                        results.push(Err(ValidationError::InvalidValue {
                            field: "Condition operator".to_string(),
                            value: operator.as_str().to_string(),
                            reason: "Condition operator cannot have empty condition map".to_string(),
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
    use serde_json::json;

    #[test]
    fn test_condition_creation() {
        let condition = Condition::string(Operator::StringEquals, "aws:username", "john");

        assert_eq!(condition.operator, Operator::StringEquals);
        assert_eq!(condition.key, "aws:username");
        assert_eq!(condition.value, json!("john"));
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
        assert_eq!(username, Some(&json!("john")));
    }

    #[test]
    fn test_legacy_format_conversion() {
        let mut legacy = HashMap::new();
        let mut string_conditions = HashMap::new();
        string_conditions.insert("aws:username".to_string(), json!("john"));
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
