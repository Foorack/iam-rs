use super::{context::Context, matcher::ArnMatcher, request::IAMRequest};
use crate::{
    core::{Action, Effect, Principal, Resource},
    evaluation::{
        operator_eval::{evaluate_condition, wildcard_match},
        variable::interpolate_variables,
    },
    policy::{ConditionBlock, IAMPolicy, IAMStatement},
};
use serde::{Deserialize, Serialize};

/// Result of policy evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum EvaluationError {
    /// Invalid request context
    InvalidContext(String),
    /// Policy parsing or validation error
    InvalidPolicy(String),
    /// ARN format error during evaluation
    InvalidArn(String),
    /// Invalid variable reference
    InvalidVariable(String),
    /// Condition evaluation error
    ConditionError(String),
    /// Internal evaluation error
    InternalError(String),
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationError::InvalidContext(msg) => write!(f, "Invalid context: {msg}"),
            EvaluationError::InvalidPolicy(msg) => write!(f, "Invalid policy: {msg}"),
            EvaluationError::InvalidArn(msg) => write!(f, "Invalid ARN: {msg}"),
            EvaluationError::InvalidVariable(msg) => write!(f, "Invalid variable: {msg}"),
            EvaluationError::ConditionError(msg) => write!(f, "Condition error: {msg}"),
            EvaluationError::InternalError(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for EvaluationError {}

/// Evaluation result with decision and metadata
#[derive(Debug, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PolicyEvaluator {
    /// Policies to evaluate
    policies: Vec<IAMPolicy>,
    /// Evaluation options
    options: EvaluationOptions,
}

/// Options for policy evaluation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            options: EvaluationOptions::default(),
        }
    }

    /// Create evaluator with policies
    #[must_use]
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
    #[must_use]
    pub fn with_options(mut self, options: EvaluationOptions) -> Self {
        self.options = options;
        self
    }

    /// Evaluate an authorization request against all policies
    ///
    /// # Errors
    ///
    /// Returns `EvaluationError` if:
    /// - The request context is invalid
    /// - ARN format errors occur during evaluation
    /// - Variable interpolation fails
    /// - Condition evaluation fails
    /// - Maximum statement evaluation limit is exceeded
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

                let statement_result = Self::evaluate_statement(statement, request)?;

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
        statement: &IAMStatement,
        request: &IAMRequest,
    ) -> Result<StatementMatch, EvaluationError> {
        // Check if principal matches (for resource-based policies)
        if let Some(ref principal) = statement.principal {
            if !Self::principal_matches(principal, &request.principal)? {
                return Ok(StatementMatch {
                    sid: statement.sid.clone(),
                    effect: statement.effect,
                    conditions_satisfied: false,
                    reason: "Principal does not match".to_string(),
                });
            }
        }

        if let Some(ref not_principal) = statement.not_principal {
            if Self::principal_matches(not_principal, &request.principal)? {
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
            Self::action_matches(action, &request.action)
        } else if let Some(ref not_action) = statement.not_action {
            !Self::action_matches(not_action, &request.action)
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
            Self::resource_matches(resource, &request.resource, &request.context)?
        } else if let Some(ref not_resource) = statement.not_resource {
            !Self::resource_matches(not_resource, &request.resource, &request.context)?
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
            if !Self::evaluate_conditions(condition_block, &request.context)? {
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
                            if Self::principal_string_matches(s, request_principal)? {
                                return Ok(true);
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for val in arr {
                                if let serde_json::Value::String(s) = val {
                                    if Self::principal_string_matches(s, request_principal)? {
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
    fn action_matches(action: &Action, request_action: &str) -> bool {
        match action {
            Action::Single(a) => {
                a == "*" || a == request_action || wildcard_match(request_action, a)
            }
            Action::Multiple(actions) => {
                for a in actions {
                    if a == "*" || a == request_action || wildcard_match(request_action, a) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Check if a resource matches the request resource
    fn resource_matches(
        resource: &Resource,
        request_resource: &str,
        context: &Context,
    ) -> Result<bool, EvaluationError> {
        match resource {
            Resource::Single(r) => {
                if r == "*" || r == request_resource {
                    Ok(true)
                } else {
                    // First, interpolate variables
                    let interpolated = interpolate_variables(r, context)?;

                    // Then use ARN matcher for pattern matching
                    let matcher = ArnMatcher::from_pattern(&interpolated)
                        .map_err(|e| EvaluationError::InvalidArn(e.to_string()))?;
                    matcher
                        .matches(request_resource)
                        .map_err(|e| EvaluationError::InvalidArn(e.to_string()))
                }
            }
            Resource::Multiple(resources) => {
                for r in resources {
                    if Self::resource_matches(
                        &Resource::Single(r.clone()),
                        request_resource,
                        context,
                    )? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Evaluate condition block
    fn evaluate_conditions(
        condition_block: &ConditionBlock,
        context: &Context,
    ) -> Result<bool, EvaluationError> {
        // All conditions in a block must be satisfied (AND logic)
        for (operator, condition_map) in &condition_block.conditions {
            for (key, value) in condition_map {
                if !evaluate_condition(context, operator, key, value)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for simple policy evaluation
///
/// # Errors
///
/// Returns `EvaluationError` if the policy evaluation fails due to:
/// - Invalid request context
/// - ARN format errors
/// - Variable interpolation failures
/// - Condition evaluation errors
pub fn evaluate_policy(
    policy: &IAMPolicy,
    request: &IAMRequest,
) -> Result<Decision, EvaluationError> {
    let evaluator = PolicyEvaluator::with_policies(vec![policy.clone()]);
    let result = evaluator.evaluate(request)?;
    Ok(result.decision)
}

/// Convenience function for evaluating multiple policies
///
/// # Errors
///
/// Returns `EvaluationError` if the policy evaluation fails due to:
/// - Invalid request context
/// - ARN format errors
/// - Variable interpolation failures
/// - Condition evaluation errors
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
    use crate::{Action, ContextValue, Effect, IAMStatement, Operator, Resource};
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

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestCase {
        result: Decision,
        request: IAMRequest,
        policy: IAMPolicy,
    }

    #[test]
    fn test_requests_testset() {
        // List filenames in the tests/requests directory
        let request_dir = "tests/requests";
        let mut request_files = std::fs::read_dir(request_dir)
            .unwrap_or_else(|e| {
                panic!("Failed to read requests directory '{}': {}", request_dir, e)
            })
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()? == "json" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Verify we actually found request files to test
        assert!(
            !request_files.is_empty(),
            "No request JSON files found in {}/",
            request_dir
        );

        // Sort files by name for consistent test order
        // All files are called 1.json, 2.json, ..., 10.json, etc.
        request_files.sort_by_key(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.split(".").next().unwrap().parse::<u32>().unwrap())
                .map(|n| format!("{:010}", n))
        });

        println!(
            "Testing {} request files from {}/",
            request_files.len(),
            request_dir
        );

        for (index, request_file) in request_files.iter().enumerate() {
            let filename = request_file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            println!("Testing request #{}: {} ... ", index + 1, filename);

            // Read the JSON file
            let json_content = std::fs::read_to_string(&request_file).unwrap_or_else(|e| {
                panic!("Failed to read file '{}': {}", request_file.display(), e)
            });

            // Parse the test case from JSON
            let test: TestCase = serde_json::from_str(&json_content).unwrap_or_else(|e| {
                panic!(
                    "Failed to parse JSON from file '{}': {:?}",
                    request_file.display(),
                    e
                )
            });

            // Evaluate the policy against the request
            let result = evaluate_policy(&test.policy, &test.request).unwrap();
            assert_eq!(result, test.result);
        }
    }
}
