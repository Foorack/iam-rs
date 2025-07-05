use super::{
    context::{Context, ContextValue},
    matcher::ArnMatcher,
    request::IAMRequest,
};
use crate::{
    core::{Action, Effect, Operator, Principal, Resource},
    policy::{ConditionBlock, IAMPolicy, IAMStatement},
};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of policy evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Access is explicitly allowed
    Allow,
    /// Access is explicitly denied
    Deny,
    /// No applicable policy found (implicit deny)
    NotApplicable,
}

/// Error types for policy evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationError {
    /// Invalid request context
    InvalidContext(String),
    /// Policy parsing or validation error
    InvalidPolicy(String),
    /// ARN format error during evaluation
    InvalidArn(String),
    /// Condition evaluation error
    ConditionError(String),
    /// Internal evaluation error
    InternalError(String),
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationError::InvalidContext(msg) => write!(f, "Invalid context: {}", msg),
            EvaluationError::InvalidPolicy(msg) => write!(f, "Invalid policy: {}", msg),
            EvaluationError::InvalidArn(msg) => write!(f, "Invalid ARN: {}", msg),
            EvaluationError::ConditionError(msg) => write!(f, "Condition error: {}", msg),
            EvaluationError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for EvaluationError {}

/// Evaluation result with decision and metadata
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// The final decision
    pub decision: Decision,
    /// Statements that matched (for debugging/auditing)
    pub matched_statements: Vec<StatementMatch>,
    /// Evaluation context used
    pub context: IAMRequest,
}

/// Information about a statement that matched during evaluation
#[derive(Debug, Clone)]
pub struct StatementMatch {
    /// Statement ID if available
    pub sid: Option<String>,
    /// Effect of the statement
    pub effect: Effect,
    /// Whether all conditions were satisfied
    pub conditions_satisfied: bool,
    /// Reason for the match/non-match
    pub reason: String,
}

/// Policy evaluation engine
#[derive(Debug, Clone)]
pub struct PolicyEvaluator {
    /// Policies to evaluate
    policies: Vec<IAMPolicy>,
    /// Evaluation options
    options: EvaluationOptions,
}

/// Options for policy evaluation
#[derive(Debug, Clone)]
pub struct EvaluationOptions {
    /// Whether to continue evaluation after finding an explicit deny
    pub stop_on_explicit_deny: bool,
    /// Whether to collect detailed match information
    pub collect_match_details: bool,
    /// Maximum number of statements to evaluate (for safety)
    pub max_statements: usize,
}

impl Default for EvaluationOptions {
    fn default() -> Self {
        Self {
            stop_on_explicit_deny: true,
            collect_match_details: false,
            max_statements: 1000,
        }
    }
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            options: EvaluationOptions::default(),
        }
    }

    /// Create evaluator with policies
    pub fn with_policies(policies: Vec<IAMPolicy>) -> Self {
        Self {
            policies,
            options: EvaluationOptions::default(),
        }
    }

    /// Add a policy to the evaluator
    pub fn add_policy(&mut self, policy: IAMPolicy) {
        self.policies.push(policy);
    }

    /// Set evaluation options
    pub fn with_options(mut self, options: EvaluationOptions) -> Self {
        self.options = options;
        self
    }

    /// Evaluate an authorization request against all policies
    pub fn evaluate(&self, request: &IAMRequest) -> Result<EvaluationResult, EvaluationError> {
        let mut matched_statements = Vec::new();
        let mut has_explicit_allow = false;
        let mut has_explicit_deny = false;
        let mut statement_count = 0;

        // Evaluate each policy
        for policy in &self.policies {
            for statement in &policy.statement {
                statement_count += 1;
                if statement_count > self.options.max_statements {
                    return Err(EvaluationError::InternalError(
                        "Maximum statement evaluation limit exceeded".to_string(),
                    ));
                }

                let statement_result = self.evaluate_statement(statement, request)?;

                if self.options.collect_match_details {
                    matched_statements.push(statement_result.clone());
                }

                // Check if this statement applies to the request
                if statement_result.conditions_satisfied {
                    match statement.effect {
                        Effect::Allow => {
                            has_explicit_allow = true;
                            if self.options.collect_match_details {
                                matched_statements.push(statement_result);
                            }
                        }
                        Effect::Deny => {
                            has_explicit_deny = true;
                            if self.options.collect_match_details {
                                matched_statements.push(statement_result);
                            }
                            if self.options.stop_on_explicit_deny {
                                return Ok(EvaluationResult {
                                    decision: Decision::Deny,
                                    matched_statements,
                                    context: request.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Apply IAM evaluation logic: Explicit deny overrides everything,
        // then explicit allow, then implicit deny
        let decision = if has_explicit_deny {
            Decision::Deny
        } else if has_explicit_allow {
            Decision::Allow
        } else {
            Decision::NotApplicable
        };

        Ok(EvaluationResult {
            decision,
            matched_statements,
            context: request.clone(),
        })
    }

    /// Evaluate a single statement against a request
    fn evaluate_statement(
        &self,
        statement: &IAMStatement,
        request: &IAMRequest,
    ) -> Result<StatementMatch, EvaluationError> {
        // Check if principal matches (for resource-based policies)
        if let Some(ref principal) = statement.principal {
            if !self.principal_matches(principal, &request.principal)? {
                return Ok(StatementMatch {
                    sid: statement.sid.clone(),
                    effect: statement.effect,
                    conditions_satisfied: false,
                    reason: "Principal does not match".to_string(),
                });
            }
        }

        if let Some(ref not_principal) = statement.not_principal {
            if self.principal_matches(not_principal, &request.principal)? {
                return Ok(StatementMatch {
                    sid: statement.sid.clone(),
                    effect: statement.effect,
                    conditions_satisfied: false,
                    reason: "Principal matches NotPrincipal exclusion".to_string(),
                });
            }
        }

        // Check if action matches
        let action_matches = if let Some(ref action) = statement.action {
            self.action_matches(action, &request.action)?
        } else if let Some(ref not_action) = statement.not_action {
            !self.action_matches(not_action, &request.action)?
        } else {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "No action or not_action specified".to_string(),
            });
        };

        if !action_matches {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "Action does not match".to_string(),
            });
        }

        // Check if resource matches
        let resource_matches = if let Some(ref resource) = statement.resource {
            self.resource_matches(resource, &request.resource)?
        } else if let Some(ref not_resource) = statement.not_resource {
            !self.resource_matches(not_resource, &request.resource)?
        } else {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "No resource or not_resource specified".to_string(),
            });
        };

        if !resource_matches {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "Resource does not match".to_string(),
            });
        }

        // Check conditions
        if let Some(ref condition_block) = statement.condition {
            if !self.evaluate_conditions(condition_block, &request.context)? {
                return Ok(StatementMatch {
                    sid: statement.sid.clone(),
                    effect: statement.effect,
                    conditions_satisfied: false,
                    reason: "Conditions not satisfied".to_string(),
                });
            }
        }

        // All checks passed
        Ok(StatementMatch {
            sid: statement.sid.clone(),
            effect: statement.effect,
            conditions_satisfied: true,
            reason: "Statement fully matched".to_string(),
        })
    }

    /// Check if a principal matches the request principal
    fn principal_matches(
        &self,
        principal: &Principal,
        request_principal: &str,
    ) -> Result<bool, EvaluationError> {
        match principal {
            Principal::Wildcard => Ok(true),
            Principal::Mapped(map) => {
                // Handle mapped principals (e.g., {"AWS": "arn:aws:iam::123456789012:user/test"})
                for values in map.values() {
                    match values {
                        serde_json::Value::String(s) => {
                            if self.principal_string_matches(s, request_principal)? {
                                return Ok(true);
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for val in arr {
                                if let serde_json::Value::String(s) = val {
                                    if self.principal_string_matches(s, request_principal)? {
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(false)
            }
        }
    }

    /// Check if a principal string matches the request principal
    fn principal_string_matches(
        &self,
        principal_str: &str,
        request_principal: &str,
    ) -> Result<bool, EvaluationError> {
        if principal_str == "*" || principal_str == request_principal {
            Ok(true)
        } else if principal_str.starts_with("arn:") {
            // ARN-based principal matching
            let matcher = ArnMatcher::from_pattern(principal_str)
                .map_err(|e| EvaluationError::InvalidArn(e.to_string()))?;
            matcher
                .matches(request_principal)
                .map_err(|e| EvaluationError::InvalidArn(e.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Check if an action matches the request action
    fn action_matches(
        &self,
        action: &Action,
        request_action: &str,
    ) -> Result<bool, EvaluationError> {
        match action {
            Action::Single(a) => {
                Ok(a == "*" || a == request_action || self.wildcard_match(request_action, a))
            }
            Action::Multiple(actions) => {
                for a in actions {
                    if a == "*" || a == request_action || self.wildcard_match(request_action, a) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Check if a resource matches the request resource
    fn resource_matches(
        &self,
        resource: &Resource,
        request_resource: &str,
    ) -> Result<bool, EvaluationError> {
        match resource {
            Resource::Single(r) => {
                if r == "*" || r == request_resource {
                    Ok(true)
                } else {
                    // Use ARN matcher for resource patterns
                    let matcher = ArnMatcher::from_pattern(r)
                        .map_err(|e| EvaluationError::InvalidArn(e.to_string()))?;
                    matcher
                        .matches(request_resource)
                        .map_err(|e| EvaluationError::InvalidArn(e.to_string()))
                }
            }
            Resource::Multiple(resources) => {
                for r in resources {
                    if self.resource_matches(&Resource::Single(r.clone()), request_resource)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Evaluate condition block
    fn evaluate_conditions(
        &self,
        condition_block: &ConditionBlock,
        context: &Context,
    ) -> Result<bool, EvaluationError> {
        // All conditions in a block must be satisfied (AND logic)
        for (operator, condition_map) in &condition_block.conditions {
            for (key, value) in condition_map {
                if !self.evaluate_single_condition(operator, key, value, context)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Evaluate a single condition
    fn evaluate_single_condition(
        &self,
        operator: &Operator,
        key: &str,
        value: &serde_json::Value,
        context: &Context,
    ) -> Result<bool, EvaluationError> {
        // Get the context value for the key
        let context_value = context.get(key);

        match operator {
            // String conditions
            Operator::StringEquals => {
                self.evaluate_string_condition(context_value, value, |a, b| a == b)
            }
            Operator::StringNotEquals => {
                self.evaluate_string_condition(context_value, value, |a, b| a != b)
            }
            Operator::StringLike => self
                .evaluate_string_condition(context_value, value, |a, b| self.wildcard_match(a, b)),
            Operator::StringNotLike => {
                self.evaluate_string_condition(context_value, value, |a, b| {
                    !self.wildcard_match(a, b)
                })
            }

            // Numeric conditions
            Operator::NumericEquals => {
                self.evaluate_numeric_condition(context_value, value, |a, b| {
                    (a - b).abs() < f64::EPSILON
                })
            }
            Operator::NumericNotEquals => {
                self.evaluate_numeric_condition(context_value, value, |a, b| {
                    (a - b).abs() >= f64::EPSILON
                })
            }
            Operator::NumericLessThan => {
                self.evaluate_numeric_condition(context_value, value, |a, b| a < b)
            }
            Operator::NumericLessThanEquals => {
                self.evaluate_numeric_condition(context_value, value, |a, b| a <= b)
            }
            Operator::NumericGreaterThan => {
                self.evaluate_numeric_condition(context_value, value, |a, b| a > b)
            }
            Operator::NumericGreaterThanEquals => {
                self.evaluate_numeric_condition(context_value, value, |a, b| a >= b)
            }

            // Date conditions
            Operator::DateEquals => {
                self.evaluate_date_condition(context_value, value, |a, b| a == b)
            }
            Operator::DateNotEquals => {
                self.evaluate_date_condition(context_value, value, |a, b| a != b)
            }
            Operator::DateLessThan => {
                self.evaluate_date_condition(context_value, value, |a, b| a < b)
            }
            Operator::DateLessThanEquals => {
                self.evaluate_date_condition(context_value, value, |a, b| a <= b)
            }
            Operator::DateGreaterThan => {
                self.evaluate_date_condition(context_value, value, |a, b| a > b)
            }
            Operator::DateGreaterThanEquals => {
                self.evaluate_date_condition(context_value, value, |a, b| a >= b)
            }

            // Boolean conditions
            Operator::Bool => self.evaluate_boolean_condition(context_value, value),

            // Binary conditions
            Operator::BinaryEquals => self.evaluate_binary_condition(context_value, value),

            // IP address conditions
            Operator::IpAddress => self.evaluate_ip_condition(context_value, value, true),
            Operator::NotIpAddress => self.evaluate_ip_condition(context_value, value, false),

            // ARN conditions
            Operator::ArnEquals => self.evaluate_arn_condition(context_value, value, |a, b| a == b),
            Operator::ArnNotEquals => {
                self.evaluate_arn_condition(context_value, value, |a, b| a != b)
            }
            Operator::ArnLike => {
                self.evaluate_arn_condition(context_value, value, |a, b| self.wildcard_match(a, b))
            }
            Operator::ArnNotLike => {
                self.evaluate_arn_condition(context_value, value, |a, b| !self.wildcard_match(a, b))
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
                self.evaluate_string_condition(context_value, value, |a, b| a == b)
            }

            _ => Err(EvaluationError::ConditionError(format!(
                "Unsupported operator: {:?}",
                operator
            ))),
        }
    }

    /// Helper for string condition evaluation
    fn evaluate_string_condition<F>(
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
                        let condition_bytes =
                            BASE64_STANDARD.decode(s.as_bytes()).map_err(|_| {
                                EvaluationError::ConditionError(
                                    "Invalid base64 value in array".to_string(),
                                )
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
        &self,
        context_value: Option<&ContextValue>,
        condition_value: &serde_json::Value,
        should_match: bool,
    ) -> Result<bool, EvaluationError> {
        // TODO: Simplified IP matching - real implementation would use IP parsing
        let result =
            self.evaluate_string_condition(context_value, condition_value, |a, b| a == b)?;
        Ok(if should_match { result } else { !result })
    }

    /// Helper for ARN condition evaluation
    fn evaluate_arn_condition<F>(
        &self,
        context_value: Option<&ContextValue>,
        condition_value: &serde_json::Value,
        predicate: F,
    ) -> Result<bool, EvaluationError>
    where
        F: Fn(&str, &str) -> bool,
    {
        // Use the same logic as string conditions for ARN comparison
        self.evaluate_string_condition(context_value, condition_value, predicate)
    }

    /// Simple wildcard matching for actions and strings
    fn wildcard_match(&self, text: &str, pattern: &str) -> bool {
        // Use the ARN wildcard matching logic
        crate::Arn::wildcard_match(text, pattern)
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for simple policy evaluation
pub fn evaluate_policy(
    policy: &IAMPolicy,
    request: &IAMRequest,
) -> Result<Decision, EvaluationError> {
    let evaluator = PolicyEvaluator::with_policies(vec![policy.clone()]);
    let result = evaluator.evaluate(request)?;
    Ok(result.decision)
}

/// Convenience function for evaluating multiple policies
pub fn evaluate_policies(
    policies: &[IAMPolicy],
    request: &IAMRequest,
) -> Result<Decision, EvaluationError> {
    let evaluator = PolicyEvaluator::with_policies(policies.to_vec());
    let result = evaluator.evaluate(request)?;
    Ok(result.decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Effect, IAMStatement, Resource};
    use serde_json::json;

    #[test]
    fn test_simple_allow_policy() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            "arn:aws:iam::123456789012:user/test",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/file.txt",
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_simple_deny_policy() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Deny)
                .with_action(Action::Single("s3:DeleteObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            "arn:aws:iam::123456789012:user/test",
            "s3:DeleteObject",
            "arn:aws:s3:::my-bucket/file.txt",
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[test]
    fn test_not_applicable_policy() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::other-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            "arn:aws:iam::123456789012:user/test",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/file.txt",
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_wildcard_action_matching() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:*".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            "arn:aws:iam::123456789012:user/test",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/file.txt",
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_condition_evaluation() {
        use crate::Operator;

        let mut context = Context::new();
        context.insert(
            "aws:userid".to_string(),
            ContextValue::String("test-user".to_string()),
        );

        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
                .with_condition(
                    Operator::StringEquals,
                    "aws:userid".to_string(),
                    json!("test-user"),
                ),
        );

        let request = IAMRequest::new_with_context(
            "arn:aws:iam::123456789012:user/test",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/file.txt",
            context,
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_condition_evaluation_failure() {
        use crate::Operator;

        let mut context = Context::new();
        context.insert(
            "aws:userid".to_string(),
            ContextValue::String("other-user".to_string()),
        );

        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
                .with_condition(
                    Operator::StringEquals,
                    "aws:userid".to_string(),
                    json!("test-user"),
                ),
        );

        let request = IAMRequest::new_with_context(
            "arn:aws:iam::123456789012:user/test",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/file.txt",
            context,
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_explicit_deny_overrides_allow() {
        let policies = vec![
            IAMPolicy::new().add_statement(
                IAMStatement::new(Effect::Allow)
                    .with_action(Action::Single("s3:*".to_string()))
                    .with_resource(Resource::Single("*".to_string())),
            ),
            IAMPolicy::new().add_statement(
                IAMStatement::new(Effect::Deny)
                    .with_action(Action::Single("s3:DeleteObject".to_string()))
                    .with_resource(Resource::Single(
                        "arn:aws:s3:::protected-bucket/*".to_string(),
                    )),
            ),
        ];

        let request = IAMRequest::new(
            "arn:aws:iam::123456789012:user/test",
            "s3:DeleteObject",
            "arn:aws:s3:::protected-bucket/file.txt",
        );

        let result = evaluate_policies(&policies, &request).unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[test]
    fn test_numeric_condition() {
        let mut context = Context::new();
        context.insert("aws:RequestedRegion".to_string(), ContextValue::Number(5.0));

        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("*".to_string()))
                .with_condition(
                    Operator::NumericLessThan,
                    "aws:RequestedRegion".to_string(),
                    json!(10),
                ),
        );

        let request = IAMRequest::new_with_context(
            "arn:aws:iam::123456789012:user/test",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/file.txt",
            context,
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_evaluator_with_options() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_sid("AllowS3Read")
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            "arn:aws:iam::123456789012:user/test",
            "s3:GetObject",
            "arn:aws:s3:::my-bucket/file.txt",
        );

        let evaluator =
            PolicyEvaluator::with_policies(vec![policy]).with_options(EvaluationOptions {
                collect_match_details: true,
                ..Default::default()
            });

        let result = evaluator.evaluate(&request).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(!result.matched_statements.is_empty());
        assert_eq!(
            result.matched_statements[0].sid,
            Some("AllowS3Read".to_string())
        );
    }
}
