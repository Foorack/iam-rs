use crate::{Arn, Context, ContextValue, EvaluationError, IAMOperator, OperatorType};
use chrono::{DateTime, Utc};
use ipnet::IpNet;

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
enum SetOperatorType {
    ForAnyValue,
    ForAllValues,
    None,
}

impl SetOperatorType {
    fn from_operator(operator: &IAMOperator) -> Self {
        match operator.to_string().as_str() {
            s if s.starts_with("ForAnyValue:") => SetOperatorType::ForAnyValue,
            s if s.starts_with("ForAllValues:") => SetOperatorType::ForAllValues,
            _ => SetOperatorType::None,
        }
    }
}

type Predicate<T> = Box<dyn Fn(T, T) -> bool>;
type DatePredicate<T> = Box<dyn for<'a, 'b> Fn(&'a T, &'b T) -> bool>;
type O = IAMOperator;

/// Evaluate a single condition
///
///
/// Important!: If the key that you specify in a policy condition is not present in the request context,
///     the values do not match and the condition is false. If the policy condition requires that the key is
///     not matched, such as `StringNotLike` or `ArnNotLike`, and the right key is not present, the condition is true.
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
// The numeric predicates below compare f64 values exactly (AWS uses decimal
// comparison), so clippy::float_cmp is allowed here intentionally.
#[allow(clippy::too_many_lines, clippy::float_cmp)]
pub(super) fn evaluate_condition(
    ctx: &Context,
    operator: &IAMOperator,
    key: &str,
    value: &serde_json::Value,
) -> Result<bool, EvaluationError> {
    let if_exists = operator.is_if_exists_operator();
    let set_operator = SetOperatorType::from_operator(operator);
    // AWS: for negated operators (StringNotLike, ArnNotLike, ...) the condition
    // is true when the key is absent from the request context.
    let is_negated = operator.is_negated_operator();

    let mut predicate_str: Predicate<String> =
        Box::new(|_a, _b| unreachable!("predicate_str invoked for non-string operator category"));
    let mut predicate_num: Predicate<f64> =
        Box::new(|_a, _b| unreachable!("predicate_num invoked for non-numeric operator category"));
    let mut predicate_date: DatePredicate<DateTime<Utc>> =
        Box::new(|_a, _b| unreachable!("predicate_date invoked for non-date operator category"));
    let mut predicate_bool: Predicate<bool> =
        Box::new(|_a, _b| unreachable!("predicate_bool invoked for non-boolean operator category"));
    let mut predicate_ip: Predicate<IpNet> =
        Box::new(|_a, _b| unreachable!("predicate_ip invoked for non-IP operator category"));

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
            predicate_str = Box::new(|a, b| a.eq_ignore_ascii_case(&b));
        }
        O::StringNotEqualsIgnoreCase
        | O::ForAllValuesStringNotEqualsIgnoreCase
        | O::ForAnyValueStringNotEqualsIgnoreCase
        | O::StringNotEqualsIgnoreCaseIfExists => {
            predicate_str = Box::new(|a, b| !a.eq_ignore_ascii_case(&b));
        }
        O::StringLike
        | O::ForAllValuesStringLike
        | O::ForAnyValueStringLike
        | O::StringLikeIfExists
        | O::ArnLike
        | O::ForAllValuesArnLike
        | O::ForAnyValueArnLike
        | O::ArnLikeIfExists => predicate_str = Box::new(|a, b| wildcard_match(&a, &b)),
        O::StringNotLike
        | O::ForAllValuesStringNotLike
        | O::ForAnyValueStringNotLike
        | O::StringNotLikeIfExists
        | O::ArnNotLike
        | O::ForAllValuesArnNotLike
        | O::ForAnyValueArnNotLike
        | O::ArnNotLikeIfExists => predicate_str = Box::new(|a, b| !wildcard_match(&a, &b)),

        // Numeric conditions
        // AWS compares numeric values exactly (decimal), so equality is exact.
        O::NumericEquals | O::NumericEqualsIfExists => {
            predicate_num = Box::new(|a, b| a == b);
        }
        O::NumericNotEquals | O::NumericNotEqualsIfExists => {
            predicate_num = Box::new(|a, b| a != b);
        }
        O::NumericLessThan | O::NumericLessThanIfExists => predicate_num = Box::new(|a, b| a < b),
        O::NumericLessThanEquals | O::NumericLessThanEqualsIfExists => {
            predicate_num = Box::new(|a, b| a <= b);
        }
        O::NumericGreaterThan | O::NumericGreaterThanIfExists => {
            predicate_num = Box::new(|a, b| a > b);
        }
        O::NumericGreaterThanEquals | O::NumericGreaterThanEqualsIfExists => {
            predicate_num = Box::new(|a, b| a >= b);
        }

        // Date conditions
        O::DateEquals | O::DateEqualsIfExists => predicate_date = Box::new(|a, b| a == b),
        O::DateNotEquals | O::DateNotEqualsIfExists => predicate_date = Box::new(|a, b| a != b),
        O::DateLessThan | O::DateLessThanIfExists => predicate_date = Box::new(|a, b| a < b),
        O::DateLessThanEquals | O::DateLessThanEqualsIfExists => {
            predicate_date = Box::new(|a, b| a <= b);
        }
        O::DateGreaterThan | O::DateGreaterThanIfExists => predicate_date = Box::new(|a, b| a > b),
        O::DateGreaterThanEquals | O::DateGreaterThanEqualsIfExists => {
            predicate_date = Box::new(|a, b| a >= b);
        }

        // Boolean conditions
        O::Bool | O::ForAllValuesBool | O::ForAnyValueBool | O::BoolIfExists => {
            predicate_bool = Box::new(|a, b| a == b);
        }

        // Binary conditions
        O::BinaryEquals | O::BinaryEqualsIfExists => {
            predicate_str = Box::new(|a, b| {
                a.to_lowercase().trim_end_matches('=') == b.to_lowercase().trim_end_matches('=')
            });
        }

        // IP address conditions
        O::IpAddress | O::IpAddressIfExists => predicate_ip = Box::new(|a, b| b.contains(&a)),
        O::NotIpAddress | O::NotIpAddressIfExists => {
            predicate_ip = Box::new(|a, b| !b.contains(&a));
        }

        O::Null => {
            // None
        }
    }

    // Convert value into Array if it isn't already
    let values = match value {
        serde_json::Value::Array(arr) => arr,
        _ => std::slice::from_ref(value),
    };

    // Set operators (ForAllValues / ForAnyValue) need the whole policy value
    // set to evaluate correctly, so handle them before the per-value loop.
    if set_operator != SetOperatorType::None {
        return evaluate_set_operator(ctx, operator, key, values, &predicate_str, &predicate_bool);
    }

    // Non-set operators aggregate across the policy values. AWS evaluates
    // multiple values with a logical OR, but negated operators with a logical
    // NOR (every value must satisfy the negated comparison).
    for value in values {
        let result = match operator.category() {
            OperatorType::String | OperatorType::Arn | OperatorType::Binary => {
                ev_str(ctx, key, value, &predicate_str, if_exists, is_negated)?
            }
            OperatorType::Numeric => {
                ev_numeric(ctx, key, value, &predicate_num, if_exists, is_negated)?
            }
            OperatorType::Date => ev_date(ctx, key, value, &predicate_date, if_exists, is_negated)?,
            OperatorType::Boolean => ev_bool(ctx, key, value, &predicate_bool, if_exists)?,
            OperatorType::IpAddress => {
                ev_ip(ctx, key, value, &predicate_ip, if_exists, is_negated)?
            }
            OperatorType::Null => {
                // Null check. AWS accepts both a JSON boolean and the string
                // forms "true"/"false" for the expected presence of the key.
                let should_be_null = match value {
                    serde_json::Value::Bool(b) => *b,
                    serde_json::Value::String(s) => s.parse::<bool>().map_err(|_| {
                        EvaluationError::ConditionError(
                            "Null operator value must be 'true' or 'false'".to_string(),
                        )
                    })?,
                    _ => {
                        return Err(EvaluationError::ConditionError(
                            "Null operator value must be a boolean or the string 'true'/'false'"
                                .to_string(),
                        ));
                    }
                };
                let is_null = ctx.get_ci(key).is_none();
                return Ok(is_null == should_be_null);
            }
        };
        if is_negated {
            // NOR: every policy value must satisfy the negated comparison.
            if !result {
                return Ok(false);
            }
        } else if result {
            return Ok(true);
        }
    }
    // Negated: every value matched -> true. Non-negated: none matched -> false.
    Ok(is_negated)
}

/// Evaluate a set-operator condition (`ForAllValues` / `ForAnyValue`) against
/// the full set of policy values.
///
/// AWS semantics (see "Conditions with multiple context keys or values"):
/// * `ForAllValues` is true iff EVERY request value satisfies the comparison.
/// * `ForAnyValue`  is true iff AT LEAST ONE request value satisfies it.
/// * For negated operators the pairwise predicate is already the negated
///   comparison, and AWS applies a logical NOR across the policy values
///   (every policy value must hold).
/// * `ForAllValues` with a missing or empty context resolves to true;
///   `ForAnyValue` with a missing or empty context resolves to false.
fn evaluate_set_operator(
    ctx: &Context,
    operator: &IAMOperator,
    key: &str,
    values: &[serde_json::Value],
    predicate_str: &Predicate<String>,
    predicate_bool: &Predicate<bool>,
) -> Result<bool, EvaluationError> {
    let all_policy_values = operator.is_negated_operator();
    let for_all_values = matches!(
        SetOperatorType::from_operator(operator),
        SetOperatorType::ForAllValues
    );

    match operator.category() {
        OperatorType::String | OperatorType::Arn | OperatorType::Binary => {
            let policy_values: Vec<&str> = values
                .iter()
                .map(|v| {
                    v.as_str().ok_or_else(|| {
                        EvaluationError::ConditionError(
                            "String condition value must be a string".to_string(),
                        )
                    })
                })
                .collect::<Result<_, _>>()?;

            let satisfies = |context_value: &String| {
                if all_policy_values {
                    policy_values
                        .iter()
                        .all(|&pv| predicate_str(context_value.clone(), pv.to_string()))
                } else {
                    policy_values
                        .iter()
                        .any(|&pv| predicate_str(context_value.clone(), pv.to_string()))
                }
            };

            match ctx.get_ci(key) {
                Some(ContextValue::StringList(list)) => {
                    if for_all_values {
                        Ok(list.iter().all(satisfies))
                    } else {
                        Ok(list.iter().any(satisfies))
                    }
                }
                // A scalar context behaves like a single-element set.
                Some(ContextValue::String(s)) => Ok(satisfies(s)),
                Some(_) => Ok(false),       // Type mismatch
                None => Ok(for_all_values), // ForAllValues: true, ForAnyValue: false
            }
        }
        OperatorType::Boolean => {
            let policy_values: Vec<bool> = values
                .iter()
                .map(|v| {
                    v.as_bool().ok_or_else(|| {
                        EvaluationError::ConditionError(format!(
                            "Boolean condition value must be a boolean, got {v}"
                        ))
                    })
                })
                .collect::<Result<_, _>>()?;

            let satisfies = |&context_value: &bool| {
                if all_policy_values {
                    policy_values
                        .iter()
                        .all(|&pv| predicate_bool(context_value, pv))
                } else {
                    policy_values
                        .iter()
                        .any(|&pv| predicate_bool(context_value, pv))
                }
            };

            match ctx.get_ci(key) {
                Some(ContextValue::BooleanList(list)) => {
                    if for_all_values {
                        Ok(list.iter().all(satisfies))
                    } else {
                        Ok(list.iter().any(satisfies))
                    }
                }
                Some(ContextValue::Boolean(b)) => Ok(satisfies(b)),
                Some(_) => Ok(false),       // Type mismatch
                None => Ok(for_all_values), // ForAllValues: true, ForAnyValue: false
            }
        }
        // Set operators are only defined for string/ARN/boolean operators.
        _ => Ok(false),
    }
}

/// Helper for single string condition evaluation
///
/// String condition operators let you construct Condition elements that restrict access based on comparing a key to a string value.
fn ev_str(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Predicate<String>,
    if_exists: bool,
    is_negated: bool,
) -> Result<bool, EvaluationError> {
    let value = value.as_str().ok_or_else(|| {
        EvaluationError::ConditionError("String condition value must be a string".to_string())
    })?;

    match ctx.get_ci(key) {
        Some(ContextValue::String(s)) => Ok(predicate(s.clone(), value.to_string())),
        // A multivalued context key with a plain operator matches if any value
        // matches (implicit ForAnyValue semantics).
        Some(ContextValue::StringList(list)) => Ok(list
            .iter()
            .any(|val| predicate(val.clone(), value.to_string()))),
        Some(_) => Ok(false), // Type mismatch
        // Missing context: true for IfExists and negated operators
        None => Ok(if_exists || is_negated),
    }
}

/// Helper for single numeric condition evaluation
///
/// Numeric condition operators let you construct Condition elements that restrict access based on comparing a key to an integer or decimal value.
fn ev_numeric(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Predicate<f64>,
    if_exists: bool,
    is_negated: bool,
) -> Result<bool, EvaluationError> {
    let value = value
        .to_string()
        .trim_matches('"') // Remove quotes if present
        .parse::<f64>()
        .map_err(|err| {
            EvaluationError::ConditionError(format!(
                "Numeric condition value must be a number, was {value}. ParseFloatError: {err}",
            ))
        })?;

    let context_value = match ctx.get_ci(key) {
        Some(ContextValue::Number(n)) => *n,
        Some(ContextValue::String(s)) => match s.parse::<f64>() {
            Ok(n) => n,
            // Present but not a parseable number: the value can't match under
            // the operator, so the condition is false (true for a negated
            // operator, which is the negation of "no match").
            Err(_) => return Ok(is_negated),
        },
        // Present but a non-numeric type: same as unparseable.
        Some(_) => return Ok(is_negated),
        // Missing context: true for IfExists and negated operators
        None => return Ok(if_exists || is_negated),
    };
    Ok(predicate(context_value, value))
}

// Parse either ISO 8601 or epoch
// The casts below are safe: epoch.floor() is far below i64::MAX for real
// epochs, and the fractional part is in [0, 1), so nanos stays < 1e9.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn parse_date(value: &str) -> Result<DateTime<Utc>, EvaluationError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            value
                .parse::<f64>()
                .map_err(|_| EvaluationError::ConditionError("Invalid date value".to_string()))
                .and_then(|epoch| {
                    if !epoch.is_finite() {
                        return Err(EvaluationError::ConditionError(
                            "Invalid epoch time".to_string(),
                        ));
                    }
                    let secs = epoch.floor() as i64;
                    let nanos = ((epoch - epoch.floor()) * 1e9) as u32;
                    DateTime::<Utc>::from_timestamp(secs, nanos).ok_or_else(|| {
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
    predicate: &DatePredicate<DateTime<Utc>>,
    if_exists: bool,
    is_negated: bool,
) -> Result<bool, EvaluationError> {
    // AWS accepts ISO 8601 date/time strings and Unix epoch time. Epoch may be
    // given as a string ("1704067200") or as a JSON number (1704067200).
    let value: DateTime<Utc> = match value {
        serde_json::Value::String(s) => parse_date(s),
        serde_json::Value::Number(n) => parse_date(&n.to_string()),
        other => Err(EvaluationError::ConditionError(format!(
            "Date condition value must be a string or number, got {other}"
        ))),
    }
    .map_err(|_| EvaluationError::ConditionError("Invalid date condition value".to_string()))?;

    let context_value: DateTime<Utc> = match ctx.get_ci(key) {
        Some(ContextValue::DateTime(dt)) => *dt,
        Some(ContextValue::Number(epoch)) => match parse_date(&epoch.to_string()) {
            Ok(dt) => dt,
            // Present but not a parseable epoch: non-comparable value.
            Err(_) => return Ok(is_negated),
        },
        Some(ContextValue::String(s)) => match parse_date(s) {
            Ok(dt) => dt,
            // Present but not a parseable date: non-comparable value.
            Err(_) => return Ok(is_negated),
        },
        // Present but a non-date type: same as unparseable.
        Some(_) => return Ok(is_negated),
        // Missing context: true for IfExists and negated operators
        None => return Ok(if_exists || is_negated),
    };
    Ok(predicate(&context_value, &value))
}

/// Helper for boolean condition evaluation
///
/// Boolean conditions let you construct Condition elements that restrict access based on comparing a key to true or false.
/// If a key contains multiple values, boolean operators can be qualified with set operators `ForAllValues` and `ForAnyValue`.
fn ev_bool(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Predicate<bool>,
    if_exists: bool,
) -> Result<bool, EvaluationError> {
    let value = value
        .to_string()
        .trim_matches('"') // Remove quotes if present
        .parse::<bool>()
        .map_err(|err| {
            EvaluationError::ConditionError(format!(
                "Boolean condition value must be a boolean, got {value}. Error: {err}",
            ))
        })?;

    match ctx.get_ci(key) {
        Some(ContextValue::Boolean(b)) => Ok(predicate(*b, value)),
        // A multivalued context key with a plain operator matches if any value
        // matches (implicit ForAnyValue semantics).
        Some(ContextValue::BooleanList(list)) => Ok(list.iter().any(|&val| predicate(val, value))),
        Some(_) => Ok(false),  // Type mismatch
        None => Ok(if_exists), // Missing context (return true if operator is IfExists)
    }
}

/// Helper for IP address condition evaluation
///
/// IP address condition operators let you construct Condition elements that restrict access based on comparing a key to an IPv4 or IPv6 address or range of IP addresses.
/// You use these with the aws:SourceIp key. The value must be in the standard CIDR format (for example, 203.0.113.0/24 or `2001:DB8:1234:5678::/64`).
/// If you specify an IP address without the associated routing prefix, IAM uses the default prefix value of /32.
///
/// Some AWS services support IPv6, using :: to represent a range of 0s.
/// To learn whether a service supports IPv6, see the documentation for that service.
fn ev_ip(
    ctx: &Context,
    key: &str,
    value: &serde_json::Value,
    predicate: &Predicate<IpNet>,
    if_exists: bool,
    is_negated: bool,
) -> Result<bool, EvaluationError> {
    /// Add default /32 prefix for IPv4 or /128 for IPv6 if none is specified
    fn ip_subnet(ip: &str) -> String {
        match ip {
            ip if ip.contains('/') => ip.to_string(),
            ip if ip.contains(':') => format!("{ip}/128"),
            ip => format!("{ip}/32"),
        }
    }

    let value = value.as_str().ok_or_else(|| {
        EvaluationError::ConditionError("IP condition value must be a string".to_string())
    })?;
    let value: IpNet = ip_subnet(value)
        .parse()
        .map_err(|_| EvaluationError::ConditionError("Invalid IP condition value".to_string()))?;

    let context_value = match ctx.get_ci(key) {
        Some(ContextValue::String(ip_addr)) => match ip_subnet(ip_addr).parse::<IpNet>() {
            Ok(net) => net,
            // Present but not a parseable IP: non-comparable value.
            Err(_) => return Ok(is_negated),
        },
        // Present but a non-string type: same as unparseable.
        Some(_) => return Ok(is_negated),
        // Missing context: true for IfExists and negated operators
        None => return Ok(if_exists || is_negated),
    };

    Ok(predicate(context_value, value))
}

/// Simple wildcard matching for actions and strings
#[must_use]
pub(super) fn wildcard_match(text: &str, pattern: &str) -> bool {
    // Use the ARN wildcard matching logic
    Arn::wildcard_match(text, pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    fn create_test_context() -> Context {
        let mut ctx = Context::new()
            .with_string("string_key", "test_value")
            .with_string("ip_key", "192.168.1.1")
            .with_string("date_key", "2024-01-01T00:00:00Z")
            .with_string("numeric_string", "42.5")
            .with_number("numeric_key", 42.0)
            .with_boolean("bool_key", true);

        // Add datetime context value manually
        ctx.insert(
            "datetime_key".to_string(),
            ContextValue::DateTime(
                DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        );

        // Add string list manually
        ctx.insert(
            "string_list".to_string(),
            ContextValue::StringList(vec![
                "value1".to_string(),
                "value2".to_string(),
                "value3".to_string(),
            ]),
        );

        // Add boolean list manually
        ctx.insert(
            "bool_list".to_string(),
            ContextValue::BooleanList(vec![true, false, true]),
        );

        ctx
    }

    #[test]
    fn test_evaluate_condition_string_equals() {
        let ctx = create_test_context();
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "string_key",
            &serde_json::Value::String("test_value".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "string_key",
            &serde_json::Value::String("different_value".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_string_not_equals() {
        let ctx = create_test_context();
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotEquals,
            "string_key",
            &serde_json::Value::String("different_value".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotEquals,
            "string_key",
            &serde_json::Value::String("test_value".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_missing_key_negated_operators() {
        // AWS: if the key is absent, non-negated conditions are false but
        // negated ones (StringNotEquals, StringNotLike, ...) are true.
        let ctx = Context::new();

        // Non-negated operators are false when the key is missing.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "missing_key",
            &serde_json::Value::String("x".to_string()),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringLike,
            "missing_key",
            &serde_json::Value::String("x*".to_string()),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "missing_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::IpAddress,
            "missing_key",
            &serde_json::Value::String("10.0.0.0/8".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Negated operators are true when the key is missing.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotEquals,
            "missing_key",
            &serde_json::Value::String("x".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotLike,
            "missing_key",
            &serde_json::Value::String("x*".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericNotEquals,
            "missing_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NotIpAddress,
            "missing_key",
            &serde_json::Value::String("10.0.0.0/8".to_string()),
        )
        .unwrap();
        assert!(result);

        // IfExists operators are true when the key is missing.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEqualsIfExists,
            "missing_key",
            &serde_json::Value::String("x".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotEqualsIfExists,
            "missing_key",
            &serde_json::Value::String("x".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_for_all_values_multiple_policy_values() {
        let mut ctx = Context::new();
        ctx.insert(
            "key".to_string(),
            ContextValue::StringList(vec!["a".to_string(), "b".to_string()]),
        );

        // Every context value matches at least one policy value -> true.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);

        // A policy value that matches nothing extra doesn't change the result.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a", "b", "c"]),
        )
        .unwrap();
        assert!(result);

        // A context value ("b") that matches no policy value -> false.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a"]),
        )
        .unwrap();
        assert!(!result);

        // Single policy value behaves the same as before: all context values
        // must match that one value.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);

        let mut scalar_ctx = Context::new();
        scalar_ctx.insert("key".to_string(), ContextValue::String("a".to_string()));
        let result = evaluate_condition(
            &scalar_ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_set_operator_negated_semantics() {
        // AWS: ForAllValues:StringNotEquals - "none of the request values can
        // match any of the policy values".
        let mut ctx = Context::new();
        ctx.insert(
            "region".to_string(),
            ContextValue::String("eu-central-1".to_string()),
        );

        // A request value inside the allowed set -> false (not denied).
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAllValuesStringNotEquals,
            "region",
            &serde_json::json!(["eu-central-1", "eu-west-1"]),
        )
        .unwrap();
        assert!(!result);

        // A request value outside the allowed set -> true (denied).
        let mut ctx_outside = Context::new();
        ctx_outside.insert(
            "region".to_string(),
            ContextValue::String("us-east-1".to_string()),
        );
        let result = evaluate_condition(
            &ctx_outside,
            &IAMOperator::ForAllValuesStringNotEquals,
            "region",
            &serde_json::json!(["eu-central-1", "eu-west-1"]),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_set_operator_missing_context() {
        let ctx = Context::new();

        // AWS: ForAllValues with no context key resolves to true.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "missing_key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);

        // ForAnyValue with no context key resolves to false.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueStringEquals,
            "missing_key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_negated_operator_multiple_values_nor() {
        // AWS: negated operators with multiple values use a logical NOR.
        let ctx = Context::new().with_string("key", "a");

        // "a" equals the first policy value, so NOR is false.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(!result);

        // "c" differs from every policy value, so NOR is true.
        let ctx_c = Context::new().with_string("key", "c");
        let result = evaluate_condition(
            &ctx_c,
            &IAMOperator::StringNotEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_for_any_value_negated() {
        // AWS: ForAnyValue:StringNotEquals - at least one request value must
        // not match any policy value.
        let mut ctx = Context::new();
        ctx.insert(
            "key".to_string(),
            ContextValue::StringList(vec!["a".to_string(), "b".to_string()]),
        );

        // "b" matches no policy value -> true.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueStringNotEquals,
            "key",
            &serde_json::json!(["a"]),
        )
        .unwrap();
        assert!(result);

        // Both request values match a policy value -> false.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueStringNotEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_aws_doc_examples() {
        // Locks in behavior against AWS's own documented examples.

        // ForAnyValue:StringEquals with aws:TagKeys = "environment".
        let mut ctx = Context::new();
        ctx.insert(
            "aws:TagKeys".to_string(),
            ContextValue::StringList(vec!["environment".to_string(), "costcenter".to_string()]),
        );
        // At least one tag key matches -> true.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueStringEquals,
            "aws:TagKeys",
            &serde_json::json!("environment"),
        )
        .unwrap();
        assert!(result);

        // Case-sensitive: "Environment" does not match "environment" -> false.
        let mut ctx_case = Context::new();
        ctx_case.insert(
            "aws:TagKeys".to_string(),
            ContextValue::StringList(vec!["Environment".to_string()]),
        );
        let result = evaluate_condition(
            &ctx_case,
            &IAMOperator::ForAnyValueStringEquals,
            "aws:TagKeys",
            &serde_json::json!("environment"),
        )
        .unwrap();
        assert!(!result);

        // ForAllValues:ArnLike with logs:LogGeneratingResourceArns.
        let mut ctx_arns = Context::new();
        ctx_arns.insert(
            "logs:LogGeneratingResourceArns".to_string(),
            ContextValue::StringList(vec![
                "arn:aws:cloudfront::123456789012:distribution/costcenter".to_string(),
                "arn:aws:cloudfront::123456789012:distribution/support2025".to_string(),
            ]),
        );
        // Every ARN matches at least one policy pattern -> true.
        let result = evaluate_condition(
            &ctx_arns,
            &IAMOperator::ForAllValuesArnLike,
            "logs:LogGeneratingResourceArns",
            &serde_json::json!([
                "arn:aws:cloudfront::123456789012:distribution/*",
                "arn:aws:cloudfront::123456789012:distribution/support*"
            ]),
        )
        .unwrap();
        assert!(result);

        // An ARN from a different account matches no pattern -> false.
        let mut ctx_arns_out = Context::new();
        ctx_arns_out.insert(
            "logs:LogGeneratingResourceArns".to_string(),
            ContextValue::StringList(vec![
                "arn:aws:cloudfront::777788889999:distribution/costcenter".to_string(),
            ]),
        );
        let result = evaluate_condition(
            &ctx_arns_out,
            &IAMOperator::ForAllValuesArnLike,
            "logs:LogGeneratingResourceArns",
            &serde_json::json!([
                "arn:aws:cloudfront::123456789012:distribution/*",
                "arn:aws:cloudfront::123456789012:distribution/support*"
            ]),
        )
        .unwrap();
        assert!(!result);

        // ArnNotLike with multiple values is a logical NOR (aws:PrincipalArn).
        let ctx_principal =
            Context::new().with_string("aws:PrincipalArn", "arn:aws:iam::222222222222:user/Nikki");
        let result = evaluate_condition(
            &ctx_principal,
            &IAMOperator::ArnNotLike,
            "aws:PrincipalArn",
            &serde_json::json!([
                "arn:aws:iam::222222222222:user/Ana",
                "arn:aws:iam::222222222222:user/Mary"
            ]),
        )
        .unwrap();
        assert!(result);

        let ctx_principal_mary =
            Context::new().with_string("aws:PrincipalArn", "arn:aws:iam::222222222222:user/Mary");
        let result = evaluate_condition(
            &ctx_principal_mary,
            &IAMOperator::ArnNotLike,
            "aws:PrincipalArn",
            &serde_json::json!([
                "arn:aws:iam::222222222222:user/Ana",
                "arn:aws:iam::222222222222:user/Mary"
            ]),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_string_equals_ignore_case() {
        let ctx = create_test_context();
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEqualsIgnoreCase,
            "string_key",
            &serde_json::Value::String("TEST_VALUE".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEqualsIgnoreCase,
            "string_key",
            &serde_json::Value::String("different_value".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_string_like() {
        let ctx = create_test_context();
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringLike,
            "string_key",
            &serde_json::Value::String("test_*".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringLike,
            "string_key",
            &serde_json::Value::String("other_*".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_numeric_operators() {
        let ctx = create_test_context();

        // NumericEquals
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "numeric_key",
            &serde_json::Value::Number(serde_json::Number::from_f64(42.0).unwrap()),
        )
        .unwrap();
        assert!(result);

        // NumericLessThan
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericLessThan,
            "numeric_key",
            &serde_json::Value::Number(serde_json::Number::from_f64(50.0).unwrap()),
        )
        .unwrap();
        assert!(result);

        // NumericGreaterThan
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericGreaterThan,
            "numeric_key",
            &serde_json::Value::Number(serde_json::Number::from_f64(30.0).unwrap()),
        )
        .unwrap();
        assert!(result);

        // Test with string that can be parsed as number
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "numeric_string",
            &serde_json::Value::Number(serde_json::Number::from_f64(42.5).unwrap()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_numeric_equals_exact() {
        // AWS compares numeric values exactly (decimal), not with an epsilon
        // tolerance, so tiny numbers that differ must NOT be considered equal.
        let mut ctx = Context::new();
        ctx.insert("key".to_string(), ContextValue::Number(1e-17));

        // 1e-17 != 2e-17.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "key",
            &serde_json::json!(2e-17),
        )
        .unwrap();
        assert!(!result);

        // Exact match still works.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "key",
            &serde_json::json!(1e-17),
        )
        .unwrap();
        assert!(result);

        // NumericNotEquals for the differing values.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericNotEquals,
            "key",
            &serde_json::json!(2e-17),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_unparseable_context_value_is_no_match() {
        // A present context value that can't be parsed for the operator's type
        // is non-comparable: the condition is false for non-negated operators
        // and true for negated operators (the negation of "no match"). AWS
        // treats such values as effectively null. Previously these errored.
        let ctx = Context::new().with_string("num_key", "not-a-number");

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "num_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericNotEquals,
            "num_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(result);

        // A wrong-typed context value (Boolean for a numeric operator) behaves
        // the same way.
        let ctx = Context::new().with_boolean("num_key", true);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "num_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericNotEquals,
            "num_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(result);

        // Date operators: unparseable string context.
        let ctx = Context::new().with_string("date_key", "not-a-date");

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "date_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateNotEquals,
            "date_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_boolean() {
        let ctx = create_test_context();
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Bool,
            "bool_key",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Bool,
            "bool_key",
            &serde_json::Value::Bool(false),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_date_operators() {
        let ctx = create_test_context();

        // DateEquals with ISO 8601 string
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "datetime_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(result);

        // DateLessThan
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateLessThan,
            "datetime_key",
            &serde_json::Value::String("2024-12-31T23:59:59Z".to_string()),
        )
        .unwrap();
        assert!(result);

        // Test with string context value
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "date_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(result);

        // Test with epoch time
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "datetime_key",
            &serde_json::Value::String("1704067200".to_string()), // 2024-01-01T00:00:00Z in epoch
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_ip_address() {
        let ctx = create_test_context();

        // IpAddress - check if IP is in CIDR range
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::IpAddress,
            "ip_key",
            &serde_json::Value::String("192.168.1.0/24".to_string()),
        )
        .unwrap();
        assert!(result);

        // NotIpAddress
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NotIpAddress,
            "ip_key",
            &serde_json::Value::String("10.0.0.0/8".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_null() {
        let ctx = create_test_context();

        // Key exists - should return false when checking if null
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(!result);

        // Key doesn't exist - should return true when checking if null
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "nonexistent_key",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(result);

        // Key exists - should return true when checking if not null
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::Bool(false),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_null_string_form() {
        let ctx = create_test_context();

        // AWS IAM policies commonly use the string form "true"/"false".
        // Key exists, checking "false" (key is not null) -> true.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::String("false".to_string()),
        )
        .unwrap();
        assert!(result);

        // Key exists, checking "true" (is null) -> false.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::String("true".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Missing key, checking "true" (is null) -> true.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "nonexistent_key",
            &serde_json::Value::String("true".to_string()),
        )
        .unwrap();
        assert!(result);

        // Missing key, checking "false" (is null) -> false.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "nonexistent_key",
            &serde_json::Value::String("false".to_string()),
        )
        .unwrap();
        assert!(!result);

        // A non-boolean string is still an error.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::String("not_a_bool".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_condition_if_exists_operators() {
        let ctx = create_test_context();

        // Key exists and matches
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEqualsIfExists,
            "string_key",
            &serde_json::Value::String("test_value".to_string()),
        )
        .unwrap();
        assert!(result);

        // Key doesn't exist - should return true for IfExists operators
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEqualsIfExists,
            "nonexistent_key",
            &serde_json::Value::String("any_value".to_string()),
        )
        .unwrap();
        assert!(result);

        // Key exists but doesn't match
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEqualsIfExists,
            "string_key",
            &serde_json::Value::String("different_value".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_for_any_value() {
        let ctx = create_test_context();

        // ForAnyValue:StringEquals - should return true if any value matches
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueStringEquals,
            "string_list",
            &serde_json::Value::String("value2".to_string()),
        )
        .unwrap();
        assert!(result);

        // ForAnyValue:StringEquals - should return false if no value matches
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueStringEquals,
            "string_list",
            &serde_json::Value::String("nonexistent".to_string()),
        )
        .unwrap();
        assert!(!result);

        // ForAnyValue:Bool
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueBool,
            "bool_list",
            &serde_json::Value::Bool(false),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_for_all_values() {
        let ctx = create_test_context();

        // Create context with all matching values
        let mut ctx_all_same = Context::new();
        ctx_all_same.insert(
            "all_same".to_string(),
            ContextValue::StringList(vec![
                "same".to_string(),
                "same".to_string(),
                "same".to_string(),
            ]),
        );

        // ForAllValues:StringEquals - should return true if all values match
        let result = evaluate_condition(
            &ctx_all_same,
            &IAMOperator::ForAllValuesStringEquals,
            "all_same",
            &serde_json::Value::String("same".to_string()),
        )
        .unwrap();
        assert!(result);

        // ForAllValues:StringEquals - should return false if not all values match
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "string_list",
            &serde_json::Value::String("value1".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_array_values() {
        let ctx = create_test_context();

        // Test with array of values in condition
        let array_value = serde_json::Value::Array(vec![
            serde_json::Value::String("test_value".to_string()),
            serde_json::Value::String("other_value".to_string()),
        ]);

        let result =
            evaluate_condition(&ctx, &IAMOperator::StringEquals, "string_key", &array_value)
                .unwrap();
        assert!(result); // Should return true because one of the values matches
    }

    #[test]
    fn test_plain_operator_multivalued_context() {
        let ctx = create_test_context(); // string_list = [value1, value2, value3]

        // A plain operator against a multivalued context key matches if any
        // value matches (implicit ForAnyValue semantics).
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "string_list",
            &serde_json::Value::String("value2".to_string()),
        )
        .unwrap();
        assert!(result);

        // No value matches -> false.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "string_list",
            &serde_json::Value::String("nonexistent".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Negated plain operator: any value not equal -> true.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotEquals,
            "string_list",
            &serde_json::Value::String("value1".to_string()),
        )
        .unwrap();
        assert!(result);

        // Boolean multivalued context.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Bool,
            "bool_list",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_context_key_case_insensitive() {
        // AWS: context key names are case-insensitive (aws:SourceIP == AWS:SourceIp).
        let ctx = Context::new().with_string("AWS:USERNAME", "alice");

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "aws:username",
            &serde_json::Value::String("alice".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_type_mismatches() {
        let ctx = create_test_context();

        // String operator with non-string context value
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "numeric_key",
            &serde_json::Value::String("test".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Numeric operator with string context value that can't be parsed as a
        // number: non-comparable, so the condition is false (no error).
        let ctx_with_unparseable = Context::new().with_string("unparseable_string", "not_a_number");

        let result = evaluate_condition(
            &ctx_with_unparseable,
            &IAMOperator::NumericEquals,
            "unparseable_string",
            &serde_json::Value::Number(serde_json::Number::from(42)),
        )
        .unwrap();
        assert!(!result);

        // Boolean operator with non-boolean context value
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Bool,
            "string_key",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_condition_errors() {
        let ctx = create_test_context();

        // String operator with non-string value
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "string_key",
            &serde_json::Value::Number(serde_json::Number::from(42)),
        );
        assert!(result.is_err());

        // Numeric operator with non-numeric value
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "numeric_key",
            &serde_json::Value::String("not_a_number".to_string()),
        );
        assert!(result.is_err());

        // Boolean operator with non-boolean value
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Bool,
            "bool_key",
            &serde_json::Value::String("not_a_bool".to_string()),
        );
        assert!(result.is_err());

        // Date operator with invalid date string
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "date_key",
            &serde_json::Value::String("invalid_date".to_string()),
        );
        assert!(result.is_err());

        // IP operator with invalid IP string
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::IpAddress,
            "ip_key",
            &serde_json::Value::String("invalid_ip".to_string()),
        );
        assert!(result.is_err());

        // Null operator with non-boolean value
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::String("not_a_bool".to_string()),
        );
        assert!(result.is_err());

        // Multivalued context without set operator matches if any value matches.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "string_list",
            &serde_json::Value::String("value1".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_binary_equals() {
        let ctx = Context::new().with_string("binary_key", "SGVsbG8gV29ybGQ="); // "Hello World" in base64

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::BinaryEquals,
            "binary_key",
            &serde_json::Value::String("SGVsbG8gV29ybGQ=".to_string()),
        )
        .unwrap();
        assert!(result);

        // Test case insensitive and padding removal
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::BinaryEquals,
            "binary_key",
            &serde_json::Value::String("sGVsbG8gV29ybGQ".to_string()), // Different case and no padding
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_parse_date() {
        // Test ISO 8601 parsing
        let result = parse_date("2024-01-01T00:00:00Z");
        assert!(result.is_ok());

        // Test epoch parsing
        let result = parse_date("1704067200"); // 2024-01-01T00:00:00Z
        assert!(result.is_ok());

        // Test invalid date
        let result = parse_date("invalid_date");
        assert!(result.is_err());

        // Fractional epoch seconds keep their sub-second precision.
        let result = parse_date("1704067200.5").unwrap();
        assert_eq!(result.timestamp_subsec_nanos(), 500_000_000);

        // Non-finite epoch values are rejected.
        let result = parse_date("NaN");
        assert!(result.is_err());
        let result = parse_date("inf");
        assert!(result.is_err());
    }

    #[test]
    fn test_date_fractional_epoch() {
        // A fractional epoch context value and condition value must match.
        let ctx = Context::new().with_number("epoch_key", 1_704_067_200.5);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "epoch_key",
            &serde_json::Value::String("1704067200.5".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_date_condition_numeric_epoch_policy_value() {
        // AWS accepts Unix epoch as a JSON number for date condition values,
        // e.g. "DateLessThan": {"aws:EpochTime": 1704067200}.
        let ctx = Context::new().with_number("epoch_key", 1_704_067_200.5);

        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "epoch_key",
            &serde_json::json!(1_704_067_200.5),
        )
        .unwrap();
        assert!(result);

        // A different numeric epoch must not match.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "epoch_key",
            &serde_json::json!(1_704_067_200),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("hello", "hello"));
        assert!(wildcard_match("hello", "h*"));
        assert!(wildcard_match("hello", "*llo"));
        assert!(wildcard_match("hello", "h*o"));
        assert!(!wildcard_match("hello", "world"));
        assert!(!wildcard_match("hello", "h*x"));
    }

    #[test]
    fn test_wildcard_match_many_stars_terminates() {
        // Adversarial patterns that were exponential (and stack-overflowing)
        // under the old recursive matcher must complete quickly and correctly.
        let text = "a".repeat(60);
        let pattern = "*a".repeat(30);
        assert!(wildcard_match(&text, &pattern));

        // A very long all-star pattern must not overflow the stack.
        let text = "x".repeat(100_000);
        let pattern = "*".repeat(100_000);
        assert!(wildcard_match(&text, &pattern));
    }

    #[test]
    fn test_set_operator_type_detection() {
        // This tests the internal set operator detection logic
        let ctx = create_test_context();

        // Test ForAnyValue prefix detection
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ForAnyValueStringEquals,
            "string_list",
            &serde_json::Value::String("value1".to_string()),
        )
        .unwrap();
        assert!(result);

        // Test ForAllValues prefix detection
        let mut ctx_all_same = Context::new();
        ctx_all_same.insert(
            "all_same".to_string(),
            ContextValue::StringList(vec!["same".to_string(), "same".to_string()]),
        );

        let result = evaluate_condition(
            &ctx_all_same,
            &IAMOperator::ForAllValuesStringEquals,
            "all_same",
            &serde_json::Value::String("same".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_arn_operators() {
        let ctx = Context::new().with_string("arn_key", "arn:aws:s3:::my-bucket/*");

        // ArnEquals
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ArnEquals,
            "arn_key",
            &serde_json::Value::String("arn:aws:s3:::my-bucket/*".to_string()),
        )
        .unwrap();
        assert!(result);

        // ArnLike with wildcard
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ArnLike,
            "arn_key",
            &serde_json::Value::String("arn:aws:s3:::my-bucket*".to_string()),
        )
        .unwrap();
        assert!(result);

        // ArnNotEquals
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::ArnNotEquals,
            "arn_key",
            &serde_json::Value::String("arn:aws:s3:::other-bucket/*".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_context_value_parsing_edge_cases() {
        let ctx = Context::new()
            .with_string("invalid_numeric", "not_a_number")
            .with_string("invalid_ip", "not_an_ip")
            .with_string("invalid_date", "not_a_date");

        // Unparseable numeric string context: non-comparable -> no match.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::NumericEquals,
            "invalid_numeric",
            &serde_json::Value::Number(serde_json::Number::from(42)),
        )
        .unwrap();
        assert!(!result);

        // Unparseable IP string context: non-comparable -> no match.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::IpAddress,
            "invalid_ip",
            &serde_json::Value::String("192.168.1.0/24".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Unparseable date string context: non-comparable -> no match.
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::DateEquals,
            "invalid_date",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_missing_context_keys_non_if_exists() {
        let ctx = Context::new(); // Empty context

        // Non-IfExists operators should return false for missing keys
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringEquals,
            "missing_key",
            &serde_json::Value::String("any_value".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Negated operators (e.g. StringNotEquals) return true for a missing
        // key: "NOT (key == value)" holds when the key is absent. Non-negated
        // operators return false instead (see test_missing_key_negated_operators).
        let result = evaluate_condition(
            &ctx,
            &IAMOperator::StringNotEquals,
            "missing_key",
            &serde_json::Value::String("any_value".to_string()),
        )
        .unwrap();
        assert!(result);
    }
}
