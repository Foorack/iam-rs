use crate::{
    Arn, ConditionValue, Context, ContextValue, EvaluationError, IAMOperator, OperatorType,
};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use std::fmt;

/// A borrowed, single element of a [`ConditionValue`].
///
/// `StringList` is the multivalued form: each of its elements is evaluated like
/// a single `String` value. The helpers take this view rather than an owned
/// `serde_json::Value`, which `ConditionValue::to_json_value` used to deep-clone
/// for every condition key of every statement.
#[derive(Debug, Clone, Copy)]
enum ValueRef<'a> {
    Boolean(bool),
    Number(&'a serde_json::Number),
    String(&'a str),
}

impl<'a> ValueRef<'a> {
    const fn as_str(self) -> Option<&'a str> {
        match self {
            ValueRef::String(s) => Some(s),
            ValueRef::Boolean(_) | ValueRef::Number(_) => None,
        }
    }

    const fn as_bool(self) -> Option<bool> {
        match self {
            ValueRef::Boolean(b) => Some(b),
            ValueRef::String(_) | ValueRef::Number(_) => None,
        }
    }
}

impl fmt::Display for ValueRef<'_> {
    /// Renders like `serde_json::Value`'s `Display` so condition error messages
    /// read the same as before.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueRef::Boolean(b) => b.fmt(f),
            ValueRef::Number(n) => n.fmt(f),
            ValueRef::String(s) => f.write_str(&serde_json::to_string(s).map_err(|_| fmt::Error)?),
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
enum SetOperatorType {
    ForAnyValue,
    ForAllValues,
    None,
}

impl SetOperatorType {
    fn from_operator(operator: &IAMOperator) -> Self {
        // Goes through `as_str` rather than `to_string`: this runs for every
        // condition key of every statement, so an allocation per call is waste.
        let name = operator.as_str();
        if name.starts_with("ForAnyValue:") {
            SetOperatorType::ForAnyValue
        } else if name.starts_with("ForAllValues:") {
            SetOperatorType::ForAllValues
        } else {
            SetOperatorType::None
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
    value: &ConditionValue,
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
        | O::StringEqualsIfExists => predicate_str = Box::new(|a, b| a == b),
        O::StringNotEquals
        | O::ForAllValuesStringNotEquals
        | O::ForAnyValueStringNotEquals
        | O::StringNotEqualsIfExists => predicate_str = Box::new(|a, b| a != b),
        // AWS: `ArnEquals` and `ArnNotEquals` behave identically to `ArnLike`
        // and `ArnNotLike`, and "each of the six colon-delimited components of
        // the ARN is checked separately and each can include multi-character
        // match wildcards (*) or single-character match wildcards (?)".
        O::ArnEquals
        | O::ForAllValuesArnEquals
        | O::ForAnyValueArnEquals
        | O::ArnEqualsIfExists => predicate_str = Box::new(|a, b| arn_matches(&a, &b)),
        O::ArnNotEquals
        | O::ForAllValuesArnNotEquals
        | O::ForAnyValueArnNotEquals
        | O::ArnNotEqualsIfExists => predicate_str = Box::new(|a, b| !arn_matches(&a, &b)),
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
        | O::StringLikeIfExists => predicate_str = Box::new(|a, b| wildcard_match(&a, &b)),
        O::StringNotLike
        | O::ForAllValuesStringNotLike
        | O::ForAnyValueStringNotLike
        | O::StringNotLikeIfExists => predicate_str = Box::new(|a, b| !wildcard_match(&a, &b)),
        O::ArnLike | O::ForAllValuesArnLike | O::ForAnyValueArnLike | O::ArnLikeIfExists => {
            predicate_str = Box::new(|a, b| arn_matches(&a, &b))
        }
        O::ArnNotLike
        | O::ForAllValuesArnNotLike
        | O::ForAnyValueArnNotLike
        | O::ArnNotLikeIfExists => predicate_str = Box::new(|a, b| !arn_matches(&a, &b)),

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
            // AWS: "compares the value of the specified key byte for byte against
            // a base-64 encoded representation". Base64 is case-sensitive and its
            // padding is significant, so decode both sides and compare the bytes
            // instead of the encoded text.
            validate_binary_values(value)?;
            predicate_str = Box::new(|a, b| match (decode_base64(&a), decode_base64(&b)) {
                (Some(a), Some(b)) => a == b,
                // A context value that is not canonical base64 cannot be a
                // byte-for-byte match for any valid policy value.
                _ => false,
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

    // A `StringList` is the multivalued form, where every element is evaluated
    // like a single `String`. A scalar value stays on the stack.
    let list_values: Vec<ValueRef<'_>>;
    let single_value: [ValueRef<'_>; 1];
    let values: &[ValueRef<'_>] = match value {
        ConditionValue::StringList(list) => {
            list_values = list.iter().map(|s| ValueRef::String(s)).collect();
            &list_values
        }
        ConditionValue::Boolean(b) => {
            single_value = [ValueRef::Boolean(*b)];
            &single_value
        }
        ConditionValue::Number(n) => {
            single_value = [ValueRef::Number(n)];
            &single_value
        }
        ConditionValue::String(s) => {
            single_value = [ValueRef::String(s)];
            &single_value
        }
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
                ev_str(ctx, key, *value, &predicate_str, if_exists, is_negated)?
            }
            OperatorType::Numeric => {
                ev_numeric(ctx, key, *value, &predicate_num, if_exists, is_negated)?
            }
            OperatorType::Date => {
                ev_date(ctx, key, *value, &predicate_date, if_exists, is_negated)?
            }
            OperatorType::Boolean => ev_bool(ctx, key, *value, &predicate_bool, if_exists)?,
            OperatorType::IpAddress => {
                ev_ip(ctx, key, *value, &predicate_ip, if_exists, is_negated)?
            }
            OperatorType::Null => {
                // Null check. AWS accepts both a JSON boolean and the string
                // forms "true"/"false" for the expected presence of the key.
                let should_be_null = match *value {
                    ValueRef::Boolean(b) => b,
                    ValueRef::String(s) => s.parse::<bool>().map_err(|_| {
                        EvaluationError::ConditionError(
                            "Null operator value must be 'true' or 'false'".to_string(),
                        )
                    })?,
                    ValueRef::Number(_) => {
                        return Err(EvaluationError::ConditionError(
                            "Null operator value must be a boolean or the string 'true'/'false'"
                                .to_string(),
                        ));
                    }
                };
                let is_null = ctx.get(key).is_none();
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
    values: &[ValueRef<'_>],
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

            match ctx.get(key) {
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

            match ctx.get(key) {
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
    value: ValueRef<'_>,
    predicate: &Predicate<String>,
    if_exists: bool,
    is_negated: bool,
) -> Result<bool, EvaluationError> {
    let value = value.as_str().ok_or_else(|| {
        EvaluationError::ConditionError("String condition value must be a string".to_string())
    })?;

    match ctx.get(key) {
        Some(ContextValue::String(s)) => Ok(predicate(s.clone(), value.to_string())),
        // A multivalued context key with a plain operator matches if any value
        // matches (implicit ForAnyValue semantics).
        Some(ContextValue::StringList(list)) => Ok(list
            .iter()
            .any(|val| predicate(val.clone(), value.to_string()))),
        // Present but a non-string type: non-comparable value, so the condition
        // is false (true for a negated operator, which is the negation of
        // "no match"). Consistent with the numeric/date/IP helpers.
        Some(_) => Ok(is_negated),
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
    value: ValueRef<'_>,
    predicate: &Predicate<f64>,
    if_exists: bool,
    is_negated: bool,
) -> Result<bool, EvaluationError> {
    // A JSON number is already numeric. Every other variant keeps the
    // historical text conversion, which is what makes a numeric string such as
    // `"42.5"` acceptable while `true` is rejected.
    let value = match value {
        ValueRef::Number(n) => n.as_f64().ok_or_else(|| {
            EvaluationError::ConditionError(format!(
                "Numeric condition value must be a number, was {n}"
            ))
        })?,
        other => other
            .to_string()
            .trim_matches('"') // Remove quotes if present
            .parse::<f64>()
            .map_err(|err| {
                EvaluationError::ConditionError(format!(
                    "Numeric condition value must be a number, was {other}. ParseFloatError: {err}",
                ))
            })?,
    };

    let context_value = match ctx.get(key) {
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
    value: ValueRef<'_>,
    predicate: &DatePredicate<DateTime<Utc>>,
    if_exists: bool,
    is_negated: bool,
) -> Result<bool, EvaluationError> {
    // AWS accepts ISO 8601 date/time strings and Unix epoch time. Epoch may be
    // given as a string ("1704067200") or as a JSON number (1704067200).
    let value: DateTime<Utc> = match value {
        ValueRef::String(s) => parse_date(s),
        ValueRef::Number(n) => parse_date(&n.to_string()),
        ValueRef::Boolean(_) => Err(EvaluationError::ConditionError(format!(
            "Date condition value must be a string or number, got {value}"
        ))),
    }
    .map_err(|_| EvaluationError::ConditionError("Invalid date condition value".to_string()))?;

    let context_value: DateTime<Utc> = match ctx.get(key) {
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
    value: ValueRef<'_>,
    predicate: &Predicate<bool>,
    if_exists: bool,
) -> Result<bool, EvaluationError> {
    let value = match value {
        ValueRef::Boolean(b) => b,
        // The string forms "true"/"false" are accepted, as AWS documents them.
        other => other
            .to_string()
            .trim_matches('"') // Remove quotes if present
            .parse::<bool>()
            .map_err(|err| {
                EvaluationError::ConditionError(format!(
                    "Boolean condition value must be a boolean, got {other}. Error: {err}",
                ))
            })?,
    };

    match ctx.get(key) {
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
    value: ValueRef<'_>,
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

    let context_value = match ctx.get(key) {
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

/// Matches an ARN condition value the way AWS's ARN operators do.
///
/// AWS checks each of the six colon-delimited components of the ARN separately,
/// so a `*` cannot cross a `:` separator. Matching the whole string instead let
/// a pattern like `arn:aws:s3:us*1234:5678:bucket/key` match
/// `arn:aws:s3:us-east-1:1234:5678:bucket/key`, because the `*` swallowed
/// `-east-1:` — which could both grant access and, under `ArnNotLike`, prevent a
/// `Deny` from firing.
///
/// When either side is not a well-formed ARN the comparison falls back to whole
/// string wildcard matching: such a policy would be rejected by AWS at save time,
/// and refusing to evaluate it here would turn a document error into a decision
/// error for every request that reaches the statement.
fn arn_matches(value: &str, pattern: &str) -> bool {
    match Arn::parse(value).and_then(|arn| arn.matches(pattern)) {
        Ok(matched) => matched,
        Err(_) => wildcard_match(value, pattern),
    }
}

/// Verifies that every policy value of a binary condition is valid base64.
///
/// AWS treats a `BinaryEquals` policy value that is not base64 as an invalid
/// policy, so this reports a [`EvaluationError::ConditionError`] instead of
/// silently failing to match.
fn validate_binary_values(value: &ConditionValue) -> Result<(), EvaluationError> {
    let check = |encoded: &str| {
        decode_base64(encoded).map(|_| ()).ok_or_else(|| {
            EvaluationError::ConditionError(format!(
                "Binary condition value must be valid base64, was {encoded:?}"
            ))
        })
    };

    match value {
        ConditionValue::String(encoded) => check(encoded),
        ConditionValue::StringList(list) => list.iter().try_for_each(|encoded| check(encoded)),
        ConditionValue::Boolean(b) => Err(EvaluationError::ConditionError(format!(
            "Binary condition value must be a base64-encoded string, was {b}"
        ))),
        ConditionValue::Number(n) => Err(EvaluationError::ConditionError(format!(
            "Binary condition value must be a base64-encoded string, was {n}"
        ))),
    }
}

/// Value of a standard base64 (`RFC 4648`) alphabet character, as a sextet.
const fn base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes canonical base64 into the bytes it represents.
///
/// Only the canonical encoding is accepted: the standard alphabet, padding
/// required to a multiple of four characters, and zero non-padding bits in the
/// final quantum. That keeps the encoding of a given byte sequence unique, so
/// alternate spellings such as `"YQ"`, `"YQ="` or `"YR=="` never decode to the
/// same bytes as `"YQ=="`.
fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(4) {
        return None;
    }

    let input = encoded.as_bytes();
    let mut out = Vec::with_capacity(encoded.len() / 4 * 3);
    let (chunks, _) = input.as_chunks::<4>();

    for (index, chunk) in chunks.iter().enumerate() {
        let is_last = index + 1 == chunks.len();
        let padding = match (chunk[2] == b'=', chunk[3] == b'=') {
            (false, false) => 0,
            (true, true) => 2,
            (false, true) => 1,
            // `=` may only follow another `=` in the final quantum.
            (true, false) => return None,
        };
        if padding > 0 && !is_last {
            return None;
        }

        let a = base64_sextet(chunk[0])?;
        let b = base64_sextet(chunk[1])?;
        match padding {
            0 => {
                let c = base64_sextet(chunk[2])?;
                let d = base64_sextet(chunk[3])?;
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
            1 => {
                let c = base64_sextet(chunk[2])?;
                if c & 0b11 != 0 {
                    return None;
                }
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
            _ => {
                if b & 0b1111 != 0 {
                    return None;
                }
                out.push((a << 2) | (b >> 4));
            }
        }
    }

    Some(out)
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

    /// Calls [`evaluate_condition`] with the JSON form a policy is parsed from.
    fn evaluate_condition_json(
        ctx: &Context,
        operator: &IAMOperator,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<bool, EvaluationError> {
        let value = ConditionValue::from_json_value(value.clone()).expect("convertible value");
        evaluate_condition(ctx, operator, key, &value)
    }

    #[test]
    fn test_evaluate_condition_string_equals() {
        let ctx = create_test_context();
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEquals,
            "string_key",
            &serde_json::Value::String("test_value".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringNotEquals,
            "string_key",
            &serde_json::Value::String("different_value".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEquals,
            "missing_key",
            &serde_json::Value::String("x".to_string()),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringLike,
            "missing_key",
            &serde_json::Value::String("x*".to_string()),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "missing_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::IpAddress,
            "missing_key",
            &serde_json::Value::String("10.0.0.0/8".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Negated operators are true when the key is missing.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringNotEquals,
            "missing_key",
            &serde_json::Value::String("x".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringNotLike,
            "missing_key",
            &serde_json::Value::String("x*".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericNotEquals,
            "missing_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NotIpAddress,
            "missing_key",
            &serde_json::Value::String("10.0.0.0/8".to_string()),
        )
        .unwrap();
        assert!(result);

        // IfExists operators are true when the key is missing.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEqualsIfExists,
            "missing_key",
            &serde_json::Value::String("x".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);

        // A policy value that matches nothing extra doesn't change the result.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a", "b", "c"]),
        )
        .unwrap();
        assert!(result);

        // A context value ("b") that matches no policy value -> false.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a"]),
        )
        .unwrap();
        assert!(!result);

        // Single policy value behaves the same as before: all context values
        // must match that one value.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);

        let mut scalar_ctx = Context::new();
        scalar_ctx.insert("key".to_string(), ContextValue::String("a".to_string()));
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAllValuesStringEquals,
            "missing_key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(result);

        // ForAnyValue with no context key resolves to false.
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringNotEquals,
            "key",
            &serde_json::json!(["a", "b"]),
        )
        .unwrap();
        assert!(!result);

        // "c" differs from every policy value, so NOR is true.
        let ctx_c = Context::new().with_string("key", "c");
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAnyValueStringNotEquals,
            "key",
            &serde_json::json!(["a"]),
        )
        .unwrap();
        assert!(result);

        // Both request values match a policy value -> false.
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEqualsIgnoreCase,
            "string_key",
            &serde_json::Value::String("TEST_VALUE".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringLike,
            "string_key",
            &serde_json::Value::String("test_*".to_string()),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "numeric_key",
            &serde_json::Value::Number(serde_json::Number::from_f64(42.0).unwrap()),
        )
        .unwrap();
        assert!(result);

        // NumericLessThan
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericLessThan,
            "numeric_key",
            &serde_json::Value::Number(serde_json::Number::from_f64(50.0).unwrap()),
        )
        .unwrap();
        assert!(result);

        // NumericGreaterThan
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericGreaterThan,
            "numeric_key",
            &serde_json::Value::Number(serde_json::Number::from_f64(30.0).unwrap()),
        )
        .unwrap();
        assert!(result);

        // Test with string that can be parsed as number
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "key",
            &serde_json::json!(2e-17),
        )
        .unwrap();
        assert!(!result);

        // Exact match still works.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "key",
            &serde_json::json!(1e-17),
        )
        .unwrap();
        assert!(result);

        // NumericNotEquals for the differing values.
        let result = evaluate_condition_json(
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

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "num_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition_json(
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

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "num_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericNotEquals,
            "num_key",
            &serde_json::json!(42),
        )
        .unwrap();
        assert!(result);

        // Date operators: unparseable string context.
        let ctx = Context::new().with_string("date_key", "not-a-date");

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::DateEquals,
            "date_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::DateNotEquals,
            "date_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(result);

        // String operators: a wrong-typed context value is non-comparable too.
        let ctx = Context::new().with_number("str_key", 42.0);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEquals,
            "str_key",
            &serde_json::Value::String("42".to_string()),
        )
        .unwrap();
        assert!(!result);

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringNotEquals,
            "str_key",
            &serde_json::Value::String("42".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_condition_boolean() {
        let ctx = create_test_context();
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Bool,
            "bool_key",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(result);

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::DateEquals,
            "datetime_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(result);

        // DateLessThan
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::DateLessThan,
            "datetime_key",
            &serde_json::Value::String("2024-12-31T23:59:59Z".to_string()),
        )
        .unwrap();
        assert!(result);

        // Test with string context value
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::DateEquals,
            "date_key",
            &serde_json::Value::String("2024-01-01T00:00:00Z".to_string()),
        )
        .unwrap();
        assert!(result);

        // Test with epoch time
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::IpAddress,
            "ip_key",
            &serde_json::Value::String("192.168.1.0/24".to_string()),
        )
        .unwrap();
        assert!(result);

        // NotIpAddress
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(!result);

        // Key doesn't exist - should return true when checking if null
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Null,
            "nonexistent_key",
            &serde_json::Value::Bool(true),
        )
        .unwrap();
        assert!(result);

        // Key exists - should return true when checking if not null
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::String("false".to_string()),
        )
        .unwrap();
        assert!(result);

        // Key exists, checking "true" (is null) -> false.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::String("true".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Missing key, checking "true" (is null) -> true.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Null,
            "nonexistent_key",
            &serde_json::Value::String("true".to_string()),
        )
        .unwrap();
        assert!(result);

        // Missing key, checking "false" (is null) -> false.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Null,
            "nonexistent_key",
            &serde_json::Value::String("false".to_string()),
        )
        .unwrap();
        assert!(!result);

        // A non-boolean string is still an error.
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEqualsIfExists,
            "string_key",
            &serde_json::Value::String("test_value".to_string()),
        )
        .unwrap();
        assert!(result);

        // Key doesn't exist - should return true for IfExists operators
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEqualsIfExists,
            "nonexistent_key",
            &serde_json::Value::String("any_value".to_string()),
        )
        .unwrap();
        assert!(result);

        // Key exists but doesn't match
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAnyValueStringEquals,
            "string_list",
            &serde_json::Value::String("value2".to_string()),
        )
        .unwrap();
        assert!(result);

        // ForAnyValue:StringEquals - should return false if no value matches
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ForAnyValueStringEquals,
            "string_list",
            &serde_json::Value::String("nonexistent".to_string()),
        )
        .unwrap();
        assert!(!result);

        // ForAnyValue:Bool
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx_all_same,
            &IAMOperator::ForAllValuesStringEquals,
            "all_same",
            &serde_json::Value::String("same".to_string()),
        )
        .unwrap();
        assert!(result);

        // ForAllValues:StringEquals - should return false if not all values match
        let result = evaluate_condition_json(
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
            evaluate_condition_json(&ctx, &IAMOperator::StringEquals, "string_key", &array_value)
                .unwrap();
        assert!(result); // Should return true because one of the values matches
    }

    #[test]
    fn test_plain_operator_multivalued_context() {
        let ctx = create_test_context(); // string_list = [value1, value2, value3]

        // A plain operator against a multivalued context key matches if any
        // value matches (implicit ForAnyValue semantics).
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEquals,
            "string_list",
            &serde_json::Value::String("value2".to_string()),
        )
        .unwrap();
        assert!(result);

        // No value matches -> false.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEquals,
            "string_list",
            &serde_json::Value::String("nonexistent".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Negated plain operator: any value not equal -> true.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringNotEquals,
            "string_list",
            &serde_json::Value::String("value1".to_string()),
        )
        .unwrap();
        assert!(result);

        // Boolean multivalued context.
        let result = evaluate_condition_json(
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

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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

        let result = evaluate_condition_json(
            &ctx_with_unparseable,
            &IAMOperator::NumericEquals,
            "unparseable_string",
            &serde_json::Value::Number(serde_json::Number::from(42)),
        )
        .unwrap();
        assert!(!result);

        // Boolean operator with non-boolean context value
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringEquals,
            "string_key",
            &serde_json::Value::Number(serde_json::Number::from(42)),
        );
        assert!(result.is_err());

        // Numeric operator with non-numeric value
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "numeric_key",
            &serde_json::Value::String("not_a_number".to_string()),
        );
        assert!(result.is_err());

        // Boolean operator with non-boolean value
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Bool,
            "bool_key",
            &serde_json::Value::String("not_a_bool".to_string()),
        );
        assert!(result.is_err());

        // Date operator with invalid date string
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::DateEquals,
            "date_key",
            &serde_json::Value::String("invalid_date".to_string()),
        );
        assert!(result.is_err());

        // IP operator with invalid IP string
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::IpAddress,
            "ip_key",
            &serde_json::Value::String("invalid_ip".to_string()),
        );
        assert!(result.is_err());

        // Null operator with non-boolean value
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::Null,
            "string_key",
            &serde_json::Value::String("not_a_bool".to_string()),
        );
        assert!(result.is_err());

        // Multivalued context without set operator matches if any value matches.
        let result = evaluate_condition_json(
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

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "binary_key",
            &serde_json::Value::String("SGVsbG8gV29ybGQ=".to_string()),
        )
        .unwrap();
        assert!(result);

        // Base64 is case-sensitive: the same text in a different case encodes
        // different bytes and must not match.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "binary_key",
            &serde_json::Value::String("sGVsbG8gV29ybGQ=".to_string()),
        )
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_binary_equals_compares_decoded_bytes() {
        // "yQ==" is byte 0xc9, "YQ==" is byte 0x61.
        let ctx = Context::new().with_string("k", "YQ==");
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "k",
            &serde_json::Value::String("yQ==".to_string()),
        )
        .unwrap();
        assert!(!result);

        // "QUJD" is "ABC", "quJd" is 0xaa 0xe2 0x5d.
        let ctx = Context::new().with_string("k", "quJd");
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "k",
            &serde_json::Value::String("QUJD".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Identical base64 still matches.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "k",
            &serde_json::Value::String("quJd".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_binary_equals_padding_is_significant() {
        // The policy side must be canonical, padded base64.
        let ctx = Context::new().with_string("k", "YQ==");
        for policy in ["YQ", "YQ=", "YR=="] {
            let result = evaluate_condition_json(
                &ctx,
                &IAMOperator::BinaryEquals,
                "k",
                &serde_json::Value::String(policy.to_string()),
            );
            assert!(result.is_err(), "policy {policy:?} should be rejected");
        }

        // A context value with different (or missing) padding is not a match.
        for context in ["YQ", "YQ=", "YR=="] {
            let ctx = Context::new().with_string("k", context);
            let result = evaluate_condition_json(
                &ctx,
                &IAMOperator::BinaryEquals,
                "k",
                &serde_json::Value::String("YQ==".to_string()),
            )
            .unwrap();
            assert!(!result, "context {context:?} should not match");
        }
    }

    #[test]
    fn test_binary_equals_rejects_non_base64_policy() {
        let ctx = Context::new().with_string("k", "hello");
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "k",
            &serde_json::Value::String("hello".to_string()),
        );
        assert!(matches!(result, Err(EvaluationError::ConditionError(_))));

        // A non-string policy value is a condition error too.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "k",
            &serde_json::Value::Bool(true),
        );
        assert!(matches!(result, Err(EvaluationError::ConditionError(_))));
    }

    #[test]
    fn test_binary_equals_if_exists_missing_key() {
        let ctx = Context::new().with_string("other", "YQ==");

        // AWS: `...IfExists` is true when the key is absent.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEqualsIfExists,
            "k",
            &serde_json::Value::String("YQ==".to_string()),
        )
        .unwrap();
        assert!(result);

        // Non-IfExists is false when the key is absent.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::BinaryEquals,
            "k",
            &serde_json::Value::String("YQ==".to_string()),
        )
        .unwrap();
        assert!(!result);

        // With the key present, both compare exactly.
        let ctx = Context::new().with_string("k", "YQ==");
        for (policy, expected) in [("YQ==", true), ("yQ==", false)] {
            let result = evaluate_condition_json(
                &ctx,
                &IAMOperator::BinaryEqualsIfExists,
                "k",
                &serde_json::Value::String(policy.to_string()),
            )
            .unwrap();
            assert_eq!(result, expected, "policy {policy:?}");
        }
    }

    #[test]
    fn test_decode_base64() {
        // No padding, one byte of padding, two bytes of padding.
        assert_eq!(decode_base64("QUJD").as_deref(), Some(&b"ABC"[..]));
        assert_eq!(
            decode_base64("SGVsbG8gV29ybGQ=").as_deref(),
            Some(&b"Hello World"[..])
        );
        assert_eq!(decode_base64("YQ==").as_deref(), Some(&[0x61][..]));
        // Both non-alphanumeric alphabet characters.
        assert_eq!(
            decode_base64("+/+/").as_deref(),
            Some(&[0xfb, 0xff, 0xbf][..])
        );
        // The empty input is valid base64 for zero bytes.
        assert_eq!(decode_base64("").as_deref(), Some(&[][..]));

        // Wrong lengths, misplaced padding and invalid characters.
        for invalid in [
            "YQ", "YQ=", "YQ===", "=AAA", "A===", "Y Q==", "YQ==\n", "YQ-_",
        ] {
            assert_eq!(decode_base64(invalid), None, "{invalid:?}");
        }
        // Non-canonical: padding must drop only zero bits.
        assert_eq!(decode_base64("YR=="), None);
        // Padding is only allowed in the final quantum.
        assert_eq!(decode_base64("YQ==QUJD"), None);
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

        let result = evaluate_condition_json(
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

        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::DateEquals,
            "epoch_key",
            &serde_json::json!(1_704_067_200.5),
        )
        .unwrap();
        assert!(result);

        // A different numeric epoch must not match.
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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

        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ArnEquals,
            "arn_key",
            &serde_json::Value::String("arn:aws:s3:::my-bucket/*".to_string()),
        )
        .unwrap();
        assert!(result);

        // ArnLike with wildcard
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ArnLike,
            "arn_key",
            &serde_json::Value::String("arn:aws:s3:::my-bucket*".to_string()),
        )
        .unwrap();
        assert!(result);

        // ArnNotEquals
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::ArnNotEquals,
            "arn_key",
            &serde_json::Value::String("arn:aws:s3:::other-bucket/*".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_arn_operators_match_each_component_separately() {
        // AWS: "Each of the six colon-delimited components of the ARN is checked
        // separately". A `*` must not be able to swallow a `:` and cross into the
        // next component.
        let ctx = Context::new()
            .with_string("aws:SourceArn", "arn:aws:s3:us-east-1:1234:5678:bucket/key");

        let matches = |operator: &IAMOperator, pattern: &str| {
            evaluate_condition_json(
                &ctx,
                operator,
                "aws:SourceArn",
                &serde_json::Value::String(pattern.to_string()),
            )
            .unwrap()
        };

        for operator in [IAMOperator::ArnLike, IAMOperator::ArnEquals] {
            // `us*1234` would match `us-east-1:1234` if the whole string were
            // matched at once, because the `*` could consume `-east-1:`.
            assert!(
                !matches(&operator, "arn:aws:s3:us*1234:5678:bucket/key"),
                "{operator:?} must not let a wildcard cross a component boundary"
            );
            assert!(
                !matches(&operator, "arn:aws:s3:us-east-1?1234:5678:bucket/key"),
                "{operator:?} must not let `?` match a different component"
            );
            // Wildcards inside a component still work.
            assert!(
                matches(&operator, "arn:aws:s3:us-east-*:1234:5678:bucket/*"),
                "{operator:?} must still match within each component"
            );
        }

        // The deny direction: `ArnNotLike` must be able to fire, which it could
        // not while the whole-string match reported a spurious match.
        assert!(matches(
            &IAMOperator::ArnNotLike,
            "arn:aws:s3:us*1234:5678:bucket/key"
        ));
        assert!(!matches(
            &IAMOperator::ArnNotLike,
            "arn:aws:s3:us-east-*:1234:5678:bucket/*"
        ));
    }

    #[test]
    fn test_arn_operators_fall_back_for_a_non_arn_value() {
        // AWS would reject such a policy at save time; matching it leniently is
        // better than turning it into a decision error.
        let ctx = Context::new().with_string("aws:SourceArn", "not-an-arn");
        let matched = evaluate_condition_json(
            &ctx,
            &IAMOperator::ArnLike,
            "aws:SourceArn",
            &serde_json::Value::String("not-*".to_string()),
        )
        .unwrap();
        assert!(matched);
    }

    #[test]
    fn test_arn_equals_matches_like_arn_like() {
        // AWS documents `ArnEquals` and `ArnNotEquals` as behaving identically to
        // `ArnLike` and `ArnNotLike`: each ARN component may contain `*` or `?`.
        let ctx = Context::new().with_string(
            "iam:PolicyARN",
            "arn:aws:iam::123456789012:policy/policy-name-1",
        );

        let evaluate = |operator: &IAMOperator, pattern: &str| {
            evaluate_condition_json(
                &ctx,
                operator,
                "iam:PolicyARN",
                &serde_json::Value::String(pattern.to_string()),
            )
            .unwrap()
        };

        // A wildcard account component, exactly as `tests/policies/52.json` writes it.
        assert!(evaluate(
            &IAMOperator::ArnEquals,
            "arn:aws:iam::*:policy/policy-name-1"
        ));
        // A single-character wildcard.
        assert!(evaluate(
            &IAMOperator::ArnEquals,
            "arn:aws:iam::123456789012:policy/policy-name-?"
        ));
        // Still an equality check: a different policy name does not match.
        assert!(!evaluate(
            &IAMOperator::ArnEquals,
            "arn:aws:iam::*:policy/other-name"
        ));

        // `ArnNotEquals` is the exact negation of the same matching.
        assert!(!evaluate(
            &IAMOperator::ArnNotEquals,
            "arn:aws:iam::*:policy/policy-name-1"
        ));
        assert!(evaluate(
            &IAMOperator::ArnNotEquals,
            "arn:aws:iam::*:policy/other-name"
        ));
    }

    #[test]
    fn test_context_value_parsing_edge_cases() {
        let ctx = Context::new()
            .with_string("invalid_numeric", "not_a_number")
            .with_string("invalid_ip", "not_an_ip")
            .with_string("invalid_date", "not_a_date");

        // Unparseable numeric string context: non-comparable -> no match.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::NumericEquals,
            "invalid_numeric",
            &serde_json::Value::Number(serde_json::Number::from(42)),
        )
        .unwrap();
        assert!(!result);

        // Unparseable IP string context: non-comparable -> no match.
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::IpAddress,
            "invalid_ip",
            &serde_json::Value::String("192.168.1.0/24".to_string()),
        )
        .unwrap();
        assert!(!result);

        // Unparseable date string context: non-comparable -> no match.
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
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
        let result = evaluate_condition_json(
            &ctx,
            &IAMOperator::StringNotEquals,
            "missing_key",
            &serde_json::Value::String("any_value".to_string()),
        )
        .unwrap();
        assert!(result);
    }

    /// The evaluator reads `ConditionValue` directly, so each variant must mean
    /// what the JSON form it came from meant.
    #[test]
    fn test_evaluate_condition_reads_condition_value_variants() {
        let ctx = create_test_context();

        // Numeric: a JSON number and a numeric string both compare as numbers,
        // an unparseable string is still an error.
        for value in [
            ConditionValue::Number(serde_json::Number::from(42)),
            ConditionValue::String("42".to_string()),
        ] {
            assert!(
                evaluate_condition(&ctx, &IAMOperator::NumericEquals, "numeric_key", &value)
                    .unwrap(),
                "{value:?} should equal 42"
            );
        }
        assert!(
            evaluate_condition(
                &ctx,
                &IAMOperator::NumericEquals,
                "numeric_key",
                &ConditionValue::String("not_a_number".to_string()),
            )
            .is_err()
        );

        // A list-valued condition matches when any element matches.
        assert!(
            evaluate_condition(
                &ctx,
                &IAMOperator::StringEquals,
                "string_key",
                &ConditionValue::StringList(vec!["other".to_string(), "test_value".to_string()]),
            )
            .unwrap()
        );
        assert!(
            !evaluate_condition(
                &ctx,
                &IAMOperator::StringEquals,
                "string_key",
                &ConditionValue::StringList(vec!["other".to_string()]),
            )
            .unwrap()
        );

        // Booleans: the JSON boolean and its string form both work.
        assert!(
            evaluate_condition(
                &ctx,
                &IAMOperator::Bool,
                "bool_key",
                &ConditionValue::Boolean(true),
            )
            .unwrap()
        );
        assert!(
            evaluate_condition(
                &ctx,
                &IAMOperator::Bool,
                "bool_key",
                &ConditionValue::String("true".to_string()),
            )
            .unwrap()
        );

        // Dates: ISO 8601, and Unix epoch as either a string or a number.
        for value in [
            ConditionValue::String("2024-01-01T00:00:00Z".to_string()),
            ConditionValue::String("1704067200".to_string()),
            ConditionValue::Number(serde_json::Number::from(1_704_067_200)),
        ] {
            assert!(
                evaluate_condition(&ctx, &IAMOperator::DateEquals, "date_key", &value).unwrap(),
                "{value:?} should equal the context date"
            );
        }
    }
}
