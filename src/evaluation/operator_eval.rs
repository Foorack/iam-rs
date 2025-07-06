use crate::{Context, ContextValue, EvaluationError, Operator};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use chrono::{DateTime, Utc};

/// Evaluate a single condition
pub(super) fn evaluate_condition(
    operator: &Operator,
    key: &str,
    value: &serde_json::Value,
    context: &Context,
) -> Result<bool, EvaluationError> {
    // Get the context value for the key
    let context_value = context.get(key);

    match operator {
        // String conditions
        Operator::StringEquals => ev_single_string(context_value, value, |a, b| a == b),
        Operator::StringNotEquals => ev_single_string(context_value, value, |a, b| a != b),
        Operator::StringEqualsIgnoreCase => {
            ev_single_string(context_value, value, |a, b| a.eq_ignore_ascii_case(b))
        }
        Operator::StringNotEqualsIgnoreCase => {
            ev_single_string(context_value, value, |a, b| !a.eq_ignore_ascii_case(b))
        }
        Operator::StringLike => ev_single_string(context_value, value, |a, b| wildcard_match(a, b)),
        Operator::StringNotLike => {
            ev_single_string(context_value, value, |a, b| !wildcard_match(a, b))
        }

        // Numeric conditions
        Operator::NumericEquals => {
            evaluate_numeric_condition(context_value, value, |a, b| (a - b).abs() < f64::EPSILON)
        }
        Operator::NumericNotEquals => {
            evaluate_numeric_condition(context_value, value, |a, b| (a - b).abs() >= f64::EPSILON)
        }
        Operator::NumericLessThan => evaluate_numeric_condition(context_value, value, |a, b| a < b),
        Operator::NumericLessThanEquals => {
            evaluate_numeric_condition(context_value, value, |a, b| a <= b)
        }
        Operator::NumericGreaterThan => {
            evaluate_numeric_condition(context_value, value, |a, b| a > b)
        }
        Operator::NumericGreaterThanEquals => {
            evaluate_numeric_condition(context_value, value, |a, b| a >= b)
        }

        // Date conditions
        Operator::DateEquals => evaluate_date_condition(context_value, value, |a, b| a == b),
        Operator::DateNotEquals => evaluate_date_condition(context_value, value, |a, b| a != b),
        Operator::DateLessThan => evaluate_date_condition(context_value, value, |a, b| a < b),
        Operator::DateLessThanEquals => {
            evaluate_date_condition(context_value, value, |a, b| a <= b)
        }
        Operator::DateGreaterThan => evaluate_date_condition(context_value, value, |a, b| a > b),
        Operator::DateGreaterThanEquals => {
            evaluate_date_condition(context_value, value, |a, b| a >= b)
        }

        // Boolean conditions
        Operator::Bool => evaluate_boolean_condition(context_value, value),

        // Binary conditions
        Operator::BinaryEquals => evaluate_binary_condition(context_value, value),

        // IP address conditions
        Operator::IpAddress => evaluate_ip_condition(context_value, value, true),
        Operator::NotIpAddress => evaluate_ip_condition(context_value, value, false),

        // ARN conditions
        Operator::ArnEquals => evaluate_arn_condition(context_value, value, |a, b| a == b),
        Operator::ArnNotEquals => evaluate_arn_condition(context_value, value, |a, b| a != b),
        Operator::ArnLike => {
            evaluate_arn_condition(context_value, value, |a, b| wildcard_match(a, b))
        }
        Operator::ArnNotLike => {
            evaluate_arn_condition(context_value, value, |a, b| !wildcard_match(a, b))
        }

        // Null check
        Operator::Null => match value {
            serde_json::Value::Bool(should_be_null) => {
                let is_null = context_value.is_none();
                Ok(is_null == *should_be_null)
            }
            _ => Err(EvaluationError::ConditionError(
                "Null operator requires boolean value".to_string(),
            )),
        },

        // Set operators (for multivalued context)
        Operator::ForAnyValueStringEquals
        | Operator::ForAllValuesStringEquals
        | Operator::ForAnyValueStringLike
        | Operator::ForAllValuesStringLike => {
            // TODO: Treat these as regular string conditions for now. Full implementation should handle set logic.
            ev_single_string(context_value, value, |a, b| a == b)
        }

        Operator::ForAllValuesStringEqualsIgnoreCase => todo!(),
        Operator::ForAnyValueStringEqualsIgnoreCase => todo!(),
        Operator::ForAllValuesStringNotEquals => todo!(),
        Operator::ForAllValuesStringNotEqualsIgnoreCase => todo!(),
        Operator::ForAnyValueStringNotEquals => todo!(),
        Operator::ForAnyValueStringNotEqualsIgnoreCase => todo!(),
        Operator::ForAllValuesStringNotLike => todo!(),
        Operator::ForAnyValueStringNotLike => todo!(),
        Operator::ForAllValuesBool => todo!(),
        Operator::ForAnyValueBool => todo!(),
        Operator::ForAllValuesArnEquals => todo!(),
        Operator::ForAllValuesArnLike => todo!(),
        Operator::ForAnyValueArnEquals => todo!(),
        Operator::ForAnyValueArnLike => todo!(),
        Operator::ForAllValuesArnNotEquals => todo!(),
        Operator::ForAllValuesArnNotLike => todo!(),
        Operator::ForAnyValueArnNotEquals => todo!(),
        Operator::ForAnyValueArnNotLike => todo!(),
        Operator::StringEqualsIfExists => todo!(),
        Operator::StringNotEqualsIfExists => todo!(),
        Operator::StringEqualsIgnoreCaseIfExists => todo!(),
        Operator::StringNotEqualsIgnoreCaseIfExists => todo!(),
        Operator::StringLikeIfExists => todo!(),
        Operator::StringNotLikeIfExists => todo!(),
        Operator::NumericEqualsIfExists => todo!(),
        Operator::NumericNotEqualsIfExists => todo!(),
        Operator::NumericLessThanIfExists => todo!(),
        Operator::NumericLessThanEqualsIfExists => todo!(),
        Operator::NumericGreaterThanIfExists => todo!(),
        Operator::NumericGreaterThanEqualsIfExists => todo!(),
        Operator::DateEqualsIfExists => todo!(),
        Operator::DateNotEqualsIfExists => todo!(),
        Operator::DateLessThanIfExists => todo!(),
        Operator::DateLessThanEqualsIfExists => todo!(),
        Operator::DateGreaterThanIfExists => todo!(),
        Operator::DateGreaterThanEqualsIfExists => todo!(),
        Operator::BoolIfExists => todo!(),
        Operator::BinaryEqualsIfExists => todo!(),
        Operator::IpAddressIfExists => todo!(),
        Operator::NotIpAddressIfExists => todo!(),
        Operator::ArnEqualsIfExists => todo!(),
        Operator::ArnLikeIfExists => todo!(),
        Operator::ArnNotEqualsIfExists => todo!(),
        Operator::ArnNotLikeIfExists => todo!(),
    }
}

/// Helper for string condition evaluation
fn ev_single_string<F>(
    context_value: Option<&ContextValue>,
    condition_value: &serde_json::Value,
    predicate: F,
) -> Result<bool, EvaluationError>
where
    F: Fn(&str, &str) -> bool,
{
    let context_str = match context_value {
        Some(ContextValue::String(s)) => s,
        Some(_) => return Ok(false), // Type mismatch
        None => return Ok(false),    // Missing context
    };

    match condition_value {
        serde_json::Value::String(s) => Ok(predicate(context_str, s)),
        serde_json::Value::Array(arr) => {
            // Any value in the array can match
            for val in arr {
                if let serde_json::Value::String(s) = val {
                    if predicate(context_str, s) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        _ => Err(EvaluationError::ConditionError(
            "String condition requires string value".to_string(),
        )),
    }
}

/// Helper for numeric condition evaluation
fn evaluate_numeric_condition<F>(
    context_value: Option<&ContextValue>,
    condition_value: &serde_json::Value,
    predicate: F,
) -> Result<bool, EvaluationError>
where
    F: Fn(f64, f64) -> bool,
{
    let context_num = match context_value {
        Some(ContextValue::Number(n)) => *n,
        Some(ContextValue::String(s)) => s.parse::<f64>().map_err(|_| {
            EvaluationError::ConditionError("Invalid numeric context value".to_string())
        })?,
        Some(_) => return Ok(false),
        None => return Ok(false),
    };

    match condition_value {
        serde_json::Value::Number(n) => {
            let val = n.as_f64().ok_or_else(|| {
                EvaluationError::ConditionError("Invalid numeric condition value".to_string())
            })?;
            Ok(predicate(context_num, val))
        }
        serde_json::Value::String(s) => {
            let val = s.parse::<f64>().map_err(|_| {
                EvaluationError::ConditionError("Invalid numeric condition value".to_string())
            })?;
            Ok(predicate(context_num, val))
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                let num_val = match val {
                    serde_json::Value::Number(n) => n.as_f64().ok_or_else(|| {
                        EvaluationError::ConditionError(
                            "Invalid numeric value in array".to_string(),
                        )
                    })?,
                    serde_json::Value::String(s) => s.parse::<f64>().map_err(|_| {
                        EvaluationError::ConditionError(
                            "Invalid numeric value in array".to_string(),
                        )
                    })?,
                    _ => continue,
                };
                if predicate(context_num, num_val) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Err(EvaluationError::ConditionError(
            "Numeric condition requires numeric value".to_string(),
        )),
    }
}

/// Helper for date condition evaluation
fn evaluate_date_condition<F>(
    context_value: Option<&ContextValue>,
    condition_value: &serde_json::Value,
    predicate: F,
) -> Result<bool, EvaluationError>
where
    F: Fn(DateTime<Utc>, DateTime<Utc>) -> bool,
{
    let context_date = match context_value {
        Some(ContextValue::DateTime(dt)) => *dt,
        Some(ContextValue::String(s)) => DateTime::parse_from_rfc3339(s)
            .map_err(|_| EvaluationError::ConditionError("Invalid date format".to_string()))?
            .with_timezone(&Utc),
        Some(_) => return Ok(false),
        None => return Ok(false),
    };

    let condition_date = match condition_value {
        serde_json::Value::String(s) => DateTime::parse_from_rfc3339(s)
            .map_err(|_| EvaluationError::ConditionError("Invalid date format".to_string()))?
            .with_timezone(&Utc),
        _ => {
            return Err(EvaluationError::ConditionError(
                "Date condition requires string value".to_string(),
            ));
        }
    };

    Ok(predicate(context_date, condition_date))
}

/// Helper for boolean condition evaluation
fn evaluate_boolean_condition(
    context_value: Option<&ContextValue>,
    condition_value: &serde_json::Value,
) -> Result<bool, EvaluationError> {
    let context_bool = match context_value {
        Some(ContextValue::Boolean(b)) => *b,
        Some(ContextValue::String(s)) => s.parse::<bool>().map_err(|_| {
            EvaluationError::ConditionError("Invalid boolean context value".to_string())
        })?,
        Some(_) => return Ok(false),
        None => return Ok(false),
    };

    match condition_value {
        serde_json::Value::Bool(b) => Ok(context_bool == *b),
        serde_json::Value::String(s) => {
            let condition_bool = s.parse::<bool>().map_err(|_| {
                EvaluationError::ConditionError("Invalid boolean condition value".to_string())
            })?;
            Ok(context_bool == condition_bool)
        }
        _ => Err(EvaluationError::ConditionError(
            "Boolean condition requires boolean value".to_string(),
        )),
    }
}

/// Helper for binary condition evaluation
fn evaluate_binary_condition(
    context_value: Option<&ContextValue>,
    condition_value: &serde_json::Value,
) -> Result<bool, EvaluationError> {
    let context_bytes = match context_value {
        Some(ContextValue::String(s)) => {
            // Try to decode base64 string to bytes
            BASE64_STANDARD.decode(s.as_bytes()).map_err(|_| {
                EvaluationError::ConditionError("Invalid base64 context value".to_string())
            })?
        }
        Some(_) => return Ok(false), // Type mismatch
        None => return Ok(false),    // Missing context
    };

    match condition_value {
        serde_json::Value::String(s) => {
            // Decode base64 condition value to bytes
            let condition_bytes = BASE64_STANDARD.decode(s.as_bytes()).map_err(|_| {
                EvaluationError::ConditionError("Invalid base64 condition value".to_string())
            })?;
            Ok(context_bytes == condition_bytes)
        }
        serde_json::Value::Array(arr) => {
            // Any value in the array can match
            for val in arr {
                if let serde_json::Value::String(s) = val {
                    let condition_bytes = BASE64_STANDARD.decode(s.as_bytes()).map_err(|_| {
                        EvaluationError::ConditionError("Invalid base64 value in array".to_string())
                    })?;
                    if context_bytes == condition_bytes {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        _ => Err(EvaluationError::ConditionError(
            "Binary condition requires string value".to_string(),
        )),
    }
}

/// Helper for IP address condition evaluation
fn evaluate_ip_condition(
    context_value: Option<&ContextValue>,
    condition_value: &serde_json::Value,
    should_match: bool,
) -> Result<bool, EvaluationError> {
    // TODO: Simplified IP matching - real implementation would use IP parsing
    let result = ev_single_string(context_value, condition_value, |a, b| a == b)?;
    Ok(if should_match { result } else { !result })
}

/// Helper for ARN condition evaluation
fn evaluate_arn_condition<F>(
    context_value: Option<&ContextValue>,
    condition_value: &serde_json::Value,
    predicate: F,
) -> Result<bool, EvaluationError>
where
    F: Fn(&str, &str) -> bool,
{
    // Use the same logic as string conditions for ARN comparison
    ev_single_string(context_value, condition_value, predicate)
}

/// Simple wildcard matching for actions and strings
pub(super) fn wildcard_match(text: &str, pattern: &str) -> bool {
    // Use the ARN wildcard matching logic
    crate::Arn::wildcard_match(text, pattern)
}
