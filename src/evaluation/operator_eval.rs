use crate::{Arn, Context, ContextValue, EvaluationError, Operator, OperatorType};
use chrono::{DateTime, Utc};
use ipnet::IpNet;

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
enum SetOperatorType {
    ForAnyValue,
    ForAllValues,
    None,
}

/// Evaluate a single condition
///
///
/// Important!: If the key that you specify in a policy condition is not present in the request context,
///     the values do not match and the condition is false. If the policy condition requires that the key is
///     not matched, such as StringNotLike or ArnNotLike, and the right key is not present, the condition is true.
///     This logic applies to all condition operators except `...IfExists` and `Null` check.
///     These operators test whether the key is present (exists) in the request context.
///
/// ## Example:
///
/// ```json
/// "StringEquals": {
///   "aws:PrincipalTag/job-category": "iamuser-admin"
/// }
/// ```
///
/// ```text
/// aws:PrincipalTag/job-category:
///   – iamuser-admin
/// ```
///
/// Result: Match
///
pub(super) fn evaluate_condition(
    ctx: &Context,
    operator: &Operator,
    key: &str,
    value: &serde_json::Value,
) -> Result<bool, EvaluationError> {
    let if_exists = operator.is_if_exists_operator();
    let set_operator = if operator.to_string().starts_with("ForAnyValue:") {
        SetOperatorType::ForAnyValue
    } else if operator.to_string().starts_with("ForAllValues:") {
        SetOperatorType::ForAllValues
    } else {
        SetOperatorType::None
    };

    let mut predicate_str: Box<dyn Fn(&str, &str) -> bool> =
        Box::new(|_a, _b| panic!("Logic error, predicate not set before use"));
    let mut predicate_num: Box<dyn Fn(&f64, &f64) -> bool> =
        Box::new(|_a, _b| panic!("Logic error, predicate not set before use"));
    let mut predicate_date: Box<dyn Fn(&DateTime<Utc>, &DateTime<Utc>) -> bool> =
        Box::new(|_a, _b| panic!("Logic error, predicate not set before use"));
    let mut predicate_bool: Box<dyn Fn(bool, bool) -> bool> =
        Box::new(|_a, _b| panic!("Logic error, predicate not set before use"));
    let mut predicate_ip: Box<dyn Fn(&IpNet, &IpNet) -> bool> =
        Box::new(|_a, _b| panic!("Logic error, predicate not set before use"));

    type O = Operator;
    match operator {
        // String conditions
        O::StringEquals
        | O::ForAllValuesStringEquals
        | O::ForAnyValueStringEquals
        | O::StringEqualsIfExists
        | O::ArnEquals
        | O::ForAllValuesArnEquals
        | O::ForAnyValueArnEquals
        | O::ArnEqualsIfExists => predicate_str = Box::new(|a, b| a == b),
        O::StringNotEquals
        | O::ForAllValuesStringNotEquals
        | O::ForAnyValueStringNotEquals
        | O::StringNotEqualsIfExists
        | O::ArnNotEquals
        | O::ForAllValuesArnNotEquals
        | O::ForAnyValueArnNotEquals
        | O::ArnNotEqualsIfExists => predicate_str = Box::new(|a, b| a != b),
        O::StringEqualsIgnoreCase
        | O::ForAllValuesStringEqualsIgnoreCase
        | O::ForAnyValueStringEqualsIgnoreCase
        | O::StringEqualsIgnoreCaseIfExists => {
            predicate_str = Box::new(|a, b| a.eq_ignore_ascii_case(b))
        }
        O::StringNotEqualsIgnoreCase
        | O::ForAllValuesStringNotEqualsIgnoreCase
        | O::ForAnyValueStringNotEqualsIgnoreCase
        | O::StringNotEqualsIgnoreCaseIfExists => {
            predicate_str = Box::new(|a, b| !a.eq_ignore_ascii_case(b))
        }
        O::StringLike
        | O::ForAllValuesStringLike
        | O::ForAnyValueStringLike
        | O::StringLikeIfExists
        | O::ArnLike
        | O::ForAllValuesArnLike
        | O::ForAnyValueArnLike
        | O::ArnLikeIfExists => predicate_str = Box::new(|a, b| wildcard_match(a, b)),
        O::StringNotLike
        | O::ForAllValuesStringNotLike
        | O::ForAnyValueStringNotLike
        | O::StringNotLikeIfExists
        | O::ArnNotLike
        | O::ForAllValuesArnNotLike
        | O::ForAnyValueArnNotLike
        | O::ArnNotLikeIfExists => predicate_str = Box::new(|a, b| !wildcard_match(a, b)),

        // Numeric conditions
        O::NumericEquals | O::NumericEqualsIfExists => {
            predicate_num = Box::new(|a, b| (a - b).abs() < f64::EPSILON)
        }
        O::NumericNotEquals | O::NumericNotEqualsIfExists => {
            predicate_num = Box::new(|a, b| (a - b).abs() >= f64::EPSILON)
        }
        O::NumericLessThan | O::NumericLessThanIfExists => predicate_num = Box::new(|a, b| a < b),
        O::NumericLessThanEquals | O::NumericLessThanEqualsIfExists => {
            predicate_num = Box::new(|a, b| a <= b)
        }
        O::NumericGreaterThan | O::NumericGreaterThanIfExists => {
            predicate_num = Box::new(|a, b| a > b)
        }
        O::NumericGreaterThanEquals | O::NumericGreaterThanEqualsIfExists => {
            predicate_num = Box::new(|a, b| a >= b)
        }

        // Date conditions
        O::DateEquals | O::DateEqualsIfExists => predicate_date = Box::new(|a, b| a == b),
        O::DateNotEquals | O::DateNotEqualsIfExists => predicate_date = Box::new(|a, b| a != b),
        O::DateLessThan | O::DateLessThanIfExists => predicate_date = Box::new(|a, b| a < b),
        O::DateLessThanEquals | O::DateLessThanEqualsIfExists => {
            predicate_date = Box::new(|a, b| a <= b)
        }
        O::DateGreaterThan | O::DateGreaterThanIfExists => predicate_date = Box::new(|a, b| a > b),
        O::DateGreaterThanEquals | O::DateGreaterThanEqualsIfExists => {
            predicate_date = Box::new(|a, b| a >= b)
        }

        // Boolean conditions
        O::Bool | O::ForAllValuesBool | O::ForAnyValueBool | O::BoolIfExists => {
            predicate_bool = Box::new(|a, b| a == b)
        }

        // Binary conditions
        O::BinaryEquals | O::BinaryEqualsIfExists => {
            predicate_str = Box::new(|a, b| {
                a.to_lowercase().trim_end_matches('=') == b.to_lowercase().trim_end_matches('=')
            });
        }

        // IP address conditions
        O::IpAddress | O::IpAddressIfExists => predicate_ip = Box::new(|a, b| b.contains(a)),
        O::NotIpAddress | O::NotIpAddressIfExists => predicate_ip = Box::new(|a, b| !b.contains(a)),

        O::Null => {
            // None
        }
    };

    let values = match value {
        // Keep array as is
        serde_json::Value::Array(arr) => arr,
        // Convert single value to array for consistency
        _ => &{ vec![value.clone()] },
    };

    for value in values {
        let result = match operator.category() {
            OperatorType::String | OperatorType::Arn | OperatorType::Binary => {
                ev_str(ctx, key, value, &predicate_str, if_exists, set_operator)?
            }
            OperatorType::Numeric => ev_numeric(ctx, key, value, &predicate_num, if_exists)?,
            OperatorType::Date => ev_date(ctx, key, value, &predicate_date, if_exists)?,
            OperatorType::Boolean => {
                ev_bool(ctx, key, value, &predicate_bool, if_exists, set_operator)?
            }
            OperatorType::IpAddress => ev_ip(ctx, key, value, &predicate_ip, if_exists)?,
            OperatorType::Null => {
                // Null check
                match value {
                    serde_json::Value::Bool(should_be_null) => {
                        let is_null = ctx.get(key).is_none();
                        return Ok(is_null == *should_be_null);
                    }
                    _ => {
                        return Err(EvaluationError::ConditionError(
                            "Null operator requires boolean value".to_string(),
                        ));
                    }
                }
            }
        };
        if result {
            return Ok(true);
        }
    }

    return Ok(false);
}

/// Helper for single string condition evaluation
///
/// String condition operators let you construct Condition elements that restrict access based on comparing a key to a string value.
fn ev_str(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Box<dyn Fn(&str, &str) -> bool>,
    if_exists: bool,
    set_operator: SetOperatorType,
) -> Result<bool, EvaluationError> {
    let value = value.as_str().ok_or_else(|| {
        EvaluationError::ConditionError("String condition value must be a string".to_string())
    })?;

    match ctx.get(key) {
        Some(ContextValue::String(s)) => Ok(predicate(s, value)),
        Some(ContextValue::StringList(list)) => match set_operator {
            // ForAnyValue: return true if any value matches
            SetOperatorType::ForAnyValue => Ok(list.iter().any(|val| predicate(val, value))),
            // ForAllValues: return true only if all values match
            SetOperatorType::ForAllValues => Ok(list.iter().all(|val| predicate(val, value))),
            SetOperatorType::None => Err(EvaluationError::ConditionError(
                "Multivalued context keys require a condition set operator.".to_string(),
            )),
        },
        Some(_) => Ok(false),  // Type mismatch
        None => Ok(if_exists), // Missing context (return true if operator is IfExists)
    }
}

/// Helper for single numeric condition evaluation
///
/// Numeric condition operators let you construct Condition elements that restrict access based on comparing a key to an integer or decimal value.
fn ev_numeric(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Box<dyn Fn(&f64, &f64) -> bool>,
    if_exists: bool,
) -> Result<bool, EvaluationError> {
    let value = &value.as_f64().ok_or_else(|| {
        EvaluationError::ConditionError("Numeric condition value must be a number".to_string())
    })?;

    let context_value = match ctx.get(key) {
        Some(ContextValue::Number(n)) => n,
        Some(ContextValue::String(s)) => &s.parse::<f64>().map_err(|_| {
            EvaluationError::ConditionError("Invalid numeric context value".to_string())
        })?,
        Some(_) => return Ok(false),  // Type mismatch
        None => return Ok(if_exists), // Missing context (return true if operator is IfExists)
    };
    Ok(predicate(context_value, value))
}

// Parse either ISO 8601 or epoch
fn parse_date(value: &str) -> Result<DateTime<Utc>, EvaluationError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            value
                .parse::<i64>()
                .map_err(|_| EvaluationError::ConditionError("Invalid date value".to_string()))
                .and_then(|epoch| {
                    DateTime::<Utc>::from_timestamp(epoch, 0).ok_or_else(|| {
                        EvaluationError::ConditionError("Invalid epoch time".to_string())
                    })
                })
        })
}

/// Helper for single date condition evaluation
///
/// Date condition operators let you construct Condition elements that restrict access based on comparing a key to a date/time value.
/// You use these condition operators with aws:CurrentTime key or aws:EpochTime key.
/// You must specify date/time values with one of the W3C implementations of the ISO 8601 date formats or in epoch (UNIX) time.
fn ev_date(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Box<dyn Fn(&DateTime<Utc>, &DateTime<Utc>) -> bool>,
    if_exists: bool,
) -> Result<bool, EvaluationError> {
    let value = value.as_str().ok_or_else(|| {
        EvaluationError::ConditionError("Date condition value must be a string".to_string())
    })?;
    let value: DateTime<Utc> = parse_date(value)
        .map_err(|_| EvaluationError::ConditionError("Invalid date condition value".to_string()))?;

    let context_value: DateTime<Utc> = match ctx.get(key) {
        Some(ContextValue::DateTime(dt)) => *dt,
        Some(ContextValue::Number(epoch)) => parse_date(&epoch.to_string()).map_err(|_| {
            EvaluationError::ConditionError("Invalid epoch context value".to_string())
        })?,
        Some(ContextValue::String(s)) => parse_date(s).map_err(|_| {
            EvaluationError::ConditionError("Invalid date context value".to_string())
        })?,
        Some(_) => return Ok(false),  // Type mismatch
        None => return Ok(if_exists), // Missing context (return true if operator is IfExists)
    };
    Ok(predicate(&context_value, &value))
}

/// Helper for boolean condition evaluation
///
/// Boolean conditions let you construct Condition elements that restrict access based on comparing a key to true or false.
/// If a key contains multiple values, boolean operators can be qualified with set operators ForAllValues and ForAnyValue.
fn ev_bool(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Box<dyn Fn(bool, bool) -> bool>,
    if_exists: bool,
    set_operator: SetOperatorType,
) -> Result<bool, EvaluationError> {
    let value = value.as_bool().ok_or_else(|| {
        EvaluationError::ConditionError("Boolean condition value must be a boolean".to_string())
    })?;

    match ctx.get(key) {
        Some(ContextValue::Boolean(b)) => Ok(predicate(*b, value)),
        Some(ContextValue::BooleanList(list)) => match set_operator {
            // ForAnyValue: return true if any value matches
            SetOperatorType::ForAnyValue => Ok(list.iter().any(|&val| predicate(val, value))),
            // ForAllValues: return true only if all values match
            SetOperatorType::ForAllValues => Ok(list.iter().all(|&val| predicate(val, value))),
            SetOperatorType::None => Err(EvaluationError::ConditionError(
                "Multivalued context keys require a condition set operator.".to_string(),
            )),
        },
        Some(_) => Ok(false),  // Type mismatch
        None => Ok(if_exists), // Missing context (return true if operator is IfExists)
    }
}

/// Helper for IP address condition evaluation
///
/// IP address condition operators let you construct Condition elements that restrict access based on comparing a key to an IPv4 or IPv6 address or range of IP addresses.
/// You use these with the aws:SourceIp key. The value must be in the standard CIDR format (for example, 203.0.113.0/24 or 2001:DB8:1234:5678::/64).
/// If you specify an IP address without the associated routing prefix, IAM uses the default prefix value of /32.
///
/// Some AWS services support IPv6, using :: to represent a range of 0s.
/// To learn whether a service supports IPv6, see the documentation for that service.
fn ev_ip(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Box<dyn Fn(&IpNet, &IpNet) -> bool>,
    if_exists: bool,
) -> Result<bool, EvaluationError> {
    // "ipnet" crate is added to workspace.
    let value = value.as_str().ok_or_else(|| {
        EvaluationError::ConditionError("IP condition value must be a string".to_string())
    })?;
    let value: IpNet = value
        .parse()
        .map_err(|_| EvaluationError::ConditionError("Invalid IP condition value".to_string()))?;

    let context_value = match ctx.get(key) {
        Some(ContextValue::String(ip_addr)) => ip_addr
            .parse::<IpNet>()
            .map_err(|_| EvaluationError::ConditionError("Invalid IP context value".to_string()))?,
        Some(_) => return Ok(false),  // Type mismatch
        None => return Ok(if_exists), // Missing context (return true if operator is IfExists)
    };

    return Ok(predicate(&context_value, &value));
}

/// Simple wildcard matching for actions and strings
pub(super) fn wildcard_match(text: &str, pattern: &str) -> bool {
    // Use the ARN wildcard matching logic
    Arn::wildcard_match(text, pattern)
}
