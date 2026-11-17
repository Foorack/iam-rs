use super::{context::Context, matcher::ArnMatcher, request::IAMRequest};
use crate::{
    Arn, Validate,
    core::{IAMAction, IAMEffect, IAMResource, Principal, PrincipalId},
    evaluation::{
        operator_eval::{evaluate_condition, wildcard_match},
        variable::interpolate_variables_checked,
    },
    policy::{ConditionBlock, ConditionValue, IAMPolicy, IAMStatement},
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Result of policy evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Decision {
    /// Access is explicitly allowed
    Allow,
    /// Access is explicitly denied
    Deny,
    /// No applicable policy found (implicit deny)
    NotApplicable,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        serde_json::to_string(self)
            .map_err(|_| std::fmt::Error)?
            .trim_matches('"')
            .fmt(f)
    }
}

/// Error types for policy evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum EvaluationError {
    /// Invalid request context
    InvalidRequest(String),
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
            EvaluationError::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct EvaluationResult {
    /// The final decision
    pub decision: Decision,
    /// Per-statement evaluation details, whether or not each statement matched.
    /// Populated only when [`EvaluationOptions::collect_match_details`] is
    /// enabled; otherwise empty.
    ///
    /// The list is truncated when [`EvaluationOptions::stop_on_explicit_deny`]
    /// is enabled and a statement with `Effect: Deny` matches: evaluation stops
    /// there, so statements after the denying one are never recorded. Disable
    /// `stop_on_explicit_deny` (and keep `collect_match_details` enabled) if you
    /// need the full list.
    pub statement_details: Vec<StatementMatch>,
    /// Evaluation context used
    pub context: IAMRequest,
}

/// Information about a statement's evaluation result (whether or not it matched)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct StatementMatch {
    /// Statement ID if available
    pub sid: Option<String>,
    /// Effect of the statement
    pub effect: IAMEffect,
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
    /// Resource patterns of `policies` compiled ahead of evaluation, parallel to
    /// `policies` → statement. Rebuilt/extended by every mutator of `policies`.
    #[cfg_attr(feature = "utoipa", schema(ignore))]
    resource_patterns: Vec<PolicyPatternCache>,
    /// Evaluation options
    options: EvaluationOptions,
}

/// Options for policy evaluation
///
/// Deserialising accepts a partial document: any field left out keeps its
/// [`Default`] value, so `{"max_statements": 50}` is a valid configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct EvaluationOptions {
    /// Whether to continue evaluation after finding an explicit deny
    pub stop_on_explicit_deny: bool,
    /// Whether to collect detailed match information
    pub collect_match_details: bool,
    /// Maximum number of statements to evaluate (for safety)
    pub max_statements: usize,
    /// Whether to ignore resource constraints
    pub ignore_resource_constraints: bool,
}

impl Default for EvaluationOptions {
    fn default() -> Self {
        Self {
            stop_on_explicit_deny: true,
            collect_match_details: false,
            max_statements: 1000,
            ignore_resource_constraints: false,
        }
    }
}

/// One resource pattern of a statement, with the request-invariant part parsed
/// ahead of evaluation.
///
/// Only patterns that interpolate a `${...}` variable vary per request; every
/// other pattern can be parsed once when the policy is added to the evaluator
/// rather than on every [`PolicyEvaluator::evaluate`] call.
#[derive(Debug, Clone)]
enum CompiledResourcePattern {
    /// `"*"`: matches every resource.
    Any,
    /// A pattern without variables, parsed once. The parse error is stored
    /// rather than returned so that adding a policy stays infallible while
    /// evaluation keeps reporting the same [`EvaluationError::InvalidArn`].
    Static(Result<ArnMatcher, String>),
    /// A pattern containing `${...}`, interpolated and parsed per request.
    Dynamic,
}

impl CompiledResourcePattern {
    /// Compile `pattern`, treating `${...}` as a variable only when the policy's
    /// `Version` is one that supports policy variables. Otherwise the braces are
    /// ordinary characters and the pattern is static.
    fn compile(pattern: &str, policy_variables: bool) -> Self {
        if pattern == "*" {
            Self::Any
        } else if policy_variables && pattern.contains("${") {
            Self::Dynamic
        } else {
            Self::Static(ArnMatcher::from_pattern(pattern).map_err(|e| e.to_string()))
        }
    }

    fn matches(
        &self,
        pattern: &str,
        request_resource: &Arn,
        context: &Context,
    ) -> Result<bool, EvaluationError> {
        match self {
            Self::Any => Ok(true),
            Self::Static(Ok(matcher)) => matcher
                .matches(request_resource)
                .map_err(|e| EvaluationError::InvalidArn(e.to_string())),
            Self::Static(Err(message)) => Err(EvaluationError::InvalidArn(message.clone())),
            Self::Dynamic => {
                let interpolation = interpolate_variables_checked(pattern, context)?;
                // AWS: "the resource that includes a policy variable with no
                // value will not match any resource". Substituting the empty
                // string instead would let `home/${aws:username}*` match every
                // user's prefix.
                if interpolation.unresolved {
                    return Ok(false);
                }
                let matcher = ArnMatcher::from_pattern(&interpolation.text)
                    .map_err(|e| EvaluationError::InvalidArn(e.to_string()))?;
                matcher
                    .matches(request_resource)
                    .map_err(|e| EvaluationError::InvalidArn(e.to_string()))
            }
        }
    }
}

/// Compiled resource patterns of one statement, parallel to its `resource` and
/// `not_resource` entries.
#[derive(Debug, Clone, Default)]
struct StatementPatternCache {
    resource: Option<Vec<CompiledResourcePattern>>,
    not_resource: Option<Vec<CompiledResourcePattern>>,
}

impl StatementPatternCache {
    fn build(statement: &IAMStatement, policy_variables: bool) -> Self {
        Self {
            resource: statement
                .resource
                .as_ref()
                .map(|resource| Self::compile_list(resource, policy_variables)),
            not_resource: statement
                .not_resource
                .as_ref()
                .map(|resource| Self::compile_list(resource, policy_variables)),
        }
    }

    fn compile_list(
        resource: &IAMResource,
        policy_variables: bool,
    ) -> Vec<CompiledResourcePattern> {
        match resource {
            IAMResource::Single(pattern) => {
                vec![CompiledResourcePattern::compile(pattern, policy_variables)]
            }
            IAMResource::Multiple(patterns) => patterns
                .iter()
                .map(|pattern| CompiledResourcePattern::compile(pattern, policy_variables))
                .collect(),
        }
    }
}

/// Compiled resource patterns of one policy, parallel to its statements.
#[derive(Debug, Clone, Default)]
struct PolicyPatternCache {
    statements: Vec<StatementPatternCache>,
}

impl PolicyPatternCache {
    fn build(policy: &IAMPolicy) -> Self {
        let policy_variables = policy.version.supports_policy_variables();
        Self {
            statements: policy
                .statement
                .iter()
                .map(|statement| StatementPatternCache::build(statement, policy_variables))
                .collect(),
        }
    }

    fn statement(&self, index: usize) -> Option<&StatementPatternCache> {
        self.statements.get(index)
    }
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            resource_patterns: Vec::new(),
            options: EvaluationOptions::default(),
        }
    }

    /// Create evaluator with policies
    #[must_use]
    pub fn with_policies(policies: Vec<IAMPolicy>) -> Self {
        let resource_patterns = policies.iter().map(PolicyPatternCache::build).collect();
        Self {
            policies,
            resource_patterns,
            options: EvaluationOptions::default(),
        }
    }

    /// Add a policy to the evaluator
    ///
    /// The policy is stored as given, without validation. A statement that cannot
    /// be evaluated — a resource pattern that is not a valid ARN, for instance —
    /// makes [`evaluate`](Self::evaluate) return `Err` for every request that
    /// reaches it, so use [`try_add_policy`](Self::try_add_policy) for policies
    /// that come from a user or a file.
    ///
    /// Unlike [`try_add_policy`](Self::try_add_policy), a policy whose `Version` is
    /// not `2012-10-17` is accepted here: evaluation then treats `${...}` as
    /// literal text, as AWS does for the policy language versions that predate
    /// policy variables.
    pub fn add_policy(&mut self, policy: IAMPolicy) {
        self.resource_patterns
            .push(PolicyPatternCache::build(&policy));
        self.policies.push(policy);
    }

    /// Validate a policy and add it only if it passes
    ///
    /// Validation is structural: it catches malformed documents, but a policy that
    /// passes can still fail to evaluate (an interpolated resource that is not an
    /// ARN, say), so `evaluate` can still return `Err`.
    ///
    /// # Errors
    ///
    /// Returns the validation errors in the policy, leaving the evaluator
    /// unchanged.
    pub fn try_add_policy(&mut self, policy: IAMPolicy) -> Result<(), crate::ValidationError> {
        policy.validate_result()?;
        self.resource_patterns
            .push(PolicyPatternCache::build(&policy));
        self.policies.push(policy);
        Ok(())
    }

    /// Build an evaluator from policies that must all validate
    ///
    /// # Errors
    ///
    /// Returns the validation errors found across the policies.
    pub fn try_with_policies(policies: Vec<IAMPolicy>) -> Result<Self, crate::ValidationError> {
        for policy in &policies {
            policy.validate_result()?;
        }
        Ok(Self::with_policies(policies))
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
        let (decision, statement_details) = self.decide(request)?;
        Ok(EvaluationResult {
            decision,
            statement_details,
            context: request.clone(),
        })
    }

    /// Evaluate an authorization request, taking ownership of it
    ///
    /// Same decision as [`evaluate`](Self::evaluate), but the request is moved
    /// into the result instead of being deep-cloned. Use this on the hot path
    /// when the caller does not need the request afterwards.
    ///
    /// # Errors
    ///
    /// See [`evaluate`](Self::evaluate).
    pub fn evaluate_owned(&self, request: IAMRequest) -> Result<EvaluationResult, EvaluationError> {
        let (decision, statement_details) = self.decide(&request)?;
        Ok(EvaluationResult {
            decision,
            statement_details,
            context: request,
        })
    }

    /// Run the evaluation and return everything except the echoed request
    fn decide(
        &self,
        request: &IAMRequest,
    ) -> Result<(Decision, Vec<StatementMatch>), EvaluationError> {
        if !request.principal.is_single() {
            return Err(EvaluationError::InvalidRequest(
                "Request principal must be a single entity".to_string(),
            ));
        }
        // A wildcard is not an authenticated identity. `{"AWS": "*"}` validates
        // as a policy principal, so reject it here rather than let it match.
        if request.principal.is_wildcard() {
            return Err(EvaluationError::InvalidRequest(
                "Request principal cannot be a wildcard".to_string(),
            ));
        }
        if !request.principal.is_valid() {
            return Err(EvaluationError::InvalidRequest(
                "Invalid principal".to_string(),
            ));
        }
        if request.action.is_empty() {
            return Err(EvaluationError::InvalidRequest(
                "Action cannot be empty".to_string(),
            ));
        }
        if !request.resource.is_valid() && !self.options.ignore_resource_constraints {
            return Err(EvaluationError::InvalidRequest(
                "Invalid resource ARN".to_string(),
            ));
        }

        let mut statement_details = Vec::new();
        let mut has_explicit_allow = false;
        let mut has_explicit_deny = false;
        let mut statement_count = 0;

        // Evaluate each policy
        for (policy_index, policy) in self.policies.iter().enumerate() {
            let policy_patterns = self.resource_patterns.get(policy_index);
            let policy_variables = policy.version.supports_policy_variables();
            for (statement_index, statement) in policy.statement.iter().enumerate() {
                statement_count += 1;
                if statement_count > self.options.max_statements {
                    return Err(EvaluationError::InternalError(
                        "Maximum statement evaluation limit exceeded".to_string(),
                    ));
                }

                let patterns = policy_patterns.and_then(|p| p.statement(statement_index));
                let statement_result = Self::evaluate_statement(
                    statement,
                    patterns,
                    request,
                    &self.options,
                    policy_variables,
                )?;

                if self.options.collect_match_details {
                    statement_details.push(statement_result.clone());
                }

                // Check if this statement applies to the request
                if statement_result.conditions_satisfied {
                    match statement.effect {
                        IAMEffect::Allow => {
                            has_explicit_allow = true;
                        }
                        IAMEffect::Deny => {
                            has_explicit_deny = true;
                            if self.options.stop_on_explicit_deny {
                                return Ok((Decision::Deny, statement_details));
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

        Ok((decision, statement_details))
    }

    /// Evaluate a single statement against a request
    ///
    /// `policy_variables` says whether the enclosing policy's `Version` resolves
    /// policy variables; when it does not, `${...}` is literal text in both
    /// resource patterns and condition values.
    fn evaluate_statement(
        statement: &IAMStatement,
        patterns: Option<&StatementPatternCache>,
        request: &IAMRequest,
        options: &EvaluationOptions,
        policy_variables: bool,
    ) -> Result<StatementMatch, EvaluationError> {
        // AWS only supports NotPrincipal with Effect: Deny, so an Allow statement
        // carrying one cannot exist as a policy. Treat it as never matching
        // rather than letting the exclusion logic below grant access.
        if statement.effect == IAMEffect::Allow && statement.not_principal.is_some() {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "Allow with NotPrincipal is invalid and never matches".to_string(),
            });
        }

        // Check if principal matches (for resource-based policies)
        if let Some(ref principal) = statement.principal
            && !Self::principal_matches(principal, &request.principal)?
        {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "Principal does not match".to_string(),
            });
        }

        if let Some(ref not_principal) = statement.not_principal
            && Self::principal_matches(not_principal, &request.principal)?
        {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "Principal matches NotPrincipal exclusion".to_string(),
            });
        }

        // Check if action matches
        let action_matches = if let Some(ref action) = statement.action {
            Self::action_matches(action, &request.action)
        } else if let Some(ref not_action) = statement.not_action {
            Self::not_action_matches(not_action, &request.action)
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
        let resource_matches = if options.ignore_resource_constraints {
            true
        } else if let Some(ref resource) = statement.resource {
            Self::resource_matches(
                resource,
                patterns.and_then(|p| p.resource.as_deref()),
                &request.resource,
                &request.context,
                policy_variables,
            )?
        } else if let Some(ref not_resource) = statement.not_resource {
            Self::not_resource_matches(
                not_resource,
                patterns.and_then(|p| p.not_resource.as_deref()),
                &request.resource,
                &request.context,
                policy_variables,
            )?
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
        if let Some(ref condition_block) = statement.condition
            && !Self::evaluate_conditions(condition_block, &request.context, policy_variables)?
        {
            return Ok(StatementMatch {
                sid: statement.sid.clone(),
                effect: statement.effect,
                conditions_satisfied: false,
                reason: "Conditions not satisfied".to_string(),
            });
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
        request_principal: &Principal,
    ) -> Result<bool, EvaluationError> {
        if !request_principal.is_single() {
            return Err(EvaluationError::InvalidRequest(
                "Request principal must be a single entity".to_string(),
            ));
        }

        // A policy wildcard — `"Principal": "*"` or the equivalent
        // `"Principal": {"AWS": "*"}` — matches any single request principal.
        // `decide` rejects wildcard and non-single request principals before
        // they reach this function.
        if principal.is_wildcard() {
            return Ok(true);
        }

        match (principal, request_principal) {
            //
            // Check: AWS
            //
            (
                Principal::Aws(principal_id),
                Principal::Aws(PrincipalId::String(request_principal_id)),
            ) => Self::principal_id_matches(principal_id, request_principal_id, |id| {
                // AWS principal can be an account ID, an ARN, or "*"
                // See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
                // "*" matches any principal
                if id == "*" || id == request_principal_id {
                    return Ok(true);
                }
                // Account ID (e.g., "123456789012")
                if id.len() == 12 && id.chars().all(|c| c.is_ascii_digit()) {
                    // Accept either the raw account ID or the root ARN. The
                    // root ARN's partition varies by region (aws, aws-cn,
                    // aws-us-gov, ...), so parse the request principal instead
                    // of hardcoding a single partition.
                    if request_principal_id == id {
                        return Ok(true);
                    }
                    if let Ok(request_arn) = Arn::parse(request_principal_id)
                        && request_arn.service == "iam"
                        && request_arn.account_id == id
                        && request_arn.resource == "root"
                    {
                        return Ok(true);
                    }
                }
                // If it's an ARN, match directly or with wildcard
                if id.starts_with("arn:") {
                    return Self::principal_string_matches(id, request_principal_id);
                }
                Ok(false)
            }),

            //
            // Check: Federated
            //
            (
                Principal::Federated(principal_id),
                Principal::Federated(PrincipalId::String(request_principal_id)),
            ) => Self::principal_id_matches(principal_id, request_principal_id, |id| {
                // Federated principal can be a provider name or ARN
                // e.g., "cognito-identity.amazonaws.com", "arn:aws:iam::account-id:oidc-provider/..."
                //
                // The comparison is exact. A prefix test would let a principal named
                // "cognito-identity.amazonaws.com.attacker.net" pass as
                // "cognito-identity.amazonaws.com", which is the classic
                // lookalike-domain escalation.
                Ok(id == request_principal_id)
            }),

            //
            // Check: Service
            //
            (
                Principal::Service(principal_id),
                Principal::Service(PrincipalId::String(request_principal_id)),
            ) => Self::principal_id_matches(principal_id, request_principal_id, |id| {
                // Service principal, e.g., "ec2.amazonaws.com"
                // Can also be regionalized, e.g., "s3.ap-east-1.amazonaws.com"
                Ok(id == request_principal_id)
            }),

            //
            // Check: CanonicalUser
            //
            (
                Principal::CanonicalUser(principal_id),
                Principal::CanonicalUser(PrincipalId::String(request_principal_id)),
            ) => Self::principal_id_matches(principal_id, request_principal_id, |id| {
                // Canonical user ID, e.g., "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
                Ok(id == request_principal_id)
            }),
            _ => {
                // If principal types don't match, they can't match
                Ok(false)
            }
        }
    }

    /// Helper function to handle `PrincipalId` enum matching
    fn principal_id_matches<F>(
        principal_id: &PrincipalId,
        _request_principal: &str,
        matcher: F,
    ) -> Result<bool, EvaluationError>
    where
        F: Fn(&str) -> Result<bool, EvaluationError>,
    {
        match principal_id {
            PrincipalId::String(id) => matcher(id),
            PrincipalId::Array(ids) => {
                // If any ID in the array matches, return true
                for id in ids {
                    if matcher(id)? {
                        return Ok(true);
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

            // A raw 12-digit account ID is the account's root principal. Build
            // the root ARN using the pattern's partition so the matcher can
            // compare the service/account/resource components (the raw ID
            // carries no partition, and account IDs are unique across
            // partitions).
            if request_principal.len() == 12
                && request_principal.chars().all(|c| c.is_ascii_digit())
            {
                let Ok(pattern_arn) = Arn::parse(principal_str) else {
                    return Ok(false);
                };
                let root_arn = Arn {
                    partition: pattern_arn.partition.clone(),
                    service: "iam".to_string(),
                    region: String::new(),
                    account_id: request_principal.to_string(),
                    resource: "root".to_string(),
                };
                return matcher
                    .matches(&root_arn)
                    .map_err(|e| EvaluationError::InvalidArn(e.to_string()));
            }

            // A request principal that isn't a valid ARN can't match an ARN pattern
            let Ok(request_arn) = Arn::parse(request_principal) else {
                return Ok(false);
            };
            matcher
                .matches(&request_arn)
                .map_err(|e| EvaluationError::InvalidArn(e.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Check if a request action falls outside a `NotAction` list
    ///
    /// An empty array is not valid IAM: AWS rejects the document with
    /// `MalformedPolicyDocument` because the grammar requires at least one
    /// value. A document that skipped [`IAMPolicy::validate`] must therefore not
    /// be treated as the negation of an empty list, which is "every action":
    /// that would silently turn a malformed `Allow` into allow-all and a
    /// malformed `Deny` into deny-all. An empty list matches nothing.
    fn not_action_matches(not_action: &IAMAction, request_action: &str) -> bool {
        match not_action {
            IAMAction::Multiple(actions) if actions.is_empty() => false,
            _ => !Self::action_matches(not_action, request_action),
        }
    }

    /// Check if an action matches the request action
    ///
    /// AWS treats action names as case-insensitive (e.g. `iam:ListAccessKeys`
    /// is the same as `IAM:listaccesskeys`), so both the request action and the
    /// policy pattern are compared lowercased.
    fn action_matches(action: &IAMAction, request_action: &str) -> bool {
        let request_action = request_action.to_ascii_lowercase();
        let pattern_matches =
            |a: &str| a == "*" || wildcard_match(&request_action, &a.to_ascii_lowercase());
        match action {
            IAMAction::Single(a) => pattern_matches(a),
            IAMAction::Multiple(actions) => actions.iter().any(|a| pattern_matches(a)),
        }
    }

    /// Check if a request resource falls outside a `NotResource` list
    ///
    /// Same reasoning as [`Self::not_action_matches`]: AWS rejects an empty array
    /// (`MalformedPolicyDocument`), so an unvalidated document must not have its
    /// empty `NotResource` inverted into "every resource". An empty list matches
    /// nothing.
    fn not_resource_matches(
        not_resource: &IAMResource,
        compiled: Option<&[CompiledResourcePattern]>,
        request_resource: &Arn,
        context: &Context,
        policy_variables: bool,
    ) -> Result<bool, EvaluationError> {
        match not_resource {
            IAMResource::Multiple(patterns) if patterns.is_empty() => Ok(false),
            _ => Self::resource_matches(
                not_resource,
                compiled,
                request_resource,
                context,
                policy_variables,
            )
            .map(|matches| !matches),
        }
    }

    /// Check if a resource matches the request resource
    ///
    /// `compiled` holds the patterns of `resource`, compiled when the policy was
    /// added to the evaluator. It is only a performance input: when it is absent
    /// (or shorter than the resource list) the affected entries are compiled on
    /// the fly, so the result and the error are the same either way.
    fn resource_matches(
        resource: &IAMResource,
        compiled: Option<&[CompiledResourcePattern]>,
        request_resource: &Arn,
        context: &Context,
        policy_variables: bool,
    ) -> Result<bool, EvaluationError> {
        match resource {
            IAMResource::Single(pattern) => Self::pattern_matches(
                compiled.and_then(|c| c.first()),
                pattern,
                request_resource,
                context,
                policy_variables,
            ),
            IAMResource::Multiple(patterns) => {
                for (index, pattern) in patterns.iter().enumerate() {
                    if Self::pattern_matches(
                        compiled.and_then(|c| c.get(index)),
                        pattern,
                        request_resource,
                        context,
                        policy_variables,
                    )? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Check if a single resource pattern matches the request resource
    fn pattern_matches(
        compiled: Option<&CompiledResourcePattern>,
        pattern: &str,
        request_resource: &Arn,
        context: &Context,
        policy_variables: bool,
    ) -> Result<bool, EvaluationError> {
        match compiled {
            Some(compiled) => compiled.matches(pattern, request_resource, context),
            None => CompiledResourcePattern::compile(pattern, policy_variables).matches(
                pattern,
                request_resource,
                context,
            ),
        }
    }

    /// Evaluate condition block
    fn evaluate_conditions(
        condition_block: &ConditionBlock,
        context: &Context,
        policy_variables: bool,
    ) -> Result<bool, EvaluationError> {
        // All conditions in a block must be satisfied (AND logic)
        for (operator, condition_map) in &condition_block.conditions {
            for (key, value) in condition_map {
                // A condition value may be a policy variable, as in
                // `"aws:ResourceTag/Owner": "${aws:username}"`. AWS resolves it
                // against the request context before comparing, for the string
                // and ARN operators — the same set this crate reports through
                // `supports_policy_variables` — but only from `Version`
                // 2012-10-17, which introduced policy variables. In an earlier
                // version the `${...}` is literal text.
                let interpolated = if policy_variables && operator.supports_policy_variables() {
                    interpolate_condition_value(value, context)?
                } else {
                    Interpolated::Resolved(Cow::Borrowed(value))
                };
                let value = match interpolated {
                    Interpolated::Resolved(value) => value,
                    Interpolated::Unresolved => {
                        // A variable with no value is null, so it equals nothing.
                        // When the condition key is itself absent there is nothing
                        // to compare either way, and the operator's own missing-key
                        // rule decides (`ForAllValues` true, `ForAnyValue` false,
                        // `...IfExists` true, negated true) — so let it decide,
                        // with a value that cannot be reached.
                        if context.get(key).is_none() {
                            let placeholder = ConditionValue::String(String::new());
                            if !evaluate_condition(context, operator, key, &placeholder)? {
                                return Ok(false);
                            }
                            continue;
                        }
                        // The key is present: a null policy value matches no
                        // positive operator, and therefore matches a negated one.
                        if !operator.is_negated_operator() {
                            return Ok(false);
                        }
                        continue;
                    }
                };
                if !evaluate_condition(context, operator, key, &value)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// A condition value after policy variables have been resolved.
enum Interpolated<'a> {
    /// Every variable had a value, or there was none to resolve.
    Resolved(Cow<'a, ConditionValue>),
    /// At least one variable had no value and no default, which AWS treats as
    /// null rather than as an empty string.
    Unresolved,
}

/// Resolve policy variables in a condition value against the request context.
///
/// Returns the value unchanged, without allocating, when it holds no `${...}`.
/// Only the string forms can carry a variable, so `Boolean` and `Number` are
/// always returned as they are.
fn interpolate_condition_value<'a>(
    value: &'a ConditionValue,
    context: &Context,
) -> Result<Interpolated<'a>, EvaluationError> {
    match value {
        ConditionValue::String(text) if text.contains("${") => {
            let interpolation = interpolate_variables_checked(text, context)?;
            if interpolation.unresolved {
                return Ok(Interpolated::Unresolved);
            }
            Ok(Interpolated::Resolved(Cow::Owned(ConditionValue::String(
                interpolation.text,
            ))))
        }
        ConditionValue::StringList(list) if list.iter().any(|item| item.contains("${")) => {
            let mut resolved = Vec::with_capacity(list.len());
            for item in list {
                let interpolation = interpolate_variables_checked(item, context)?;
                if interpolation.unresolved {
                    return Ok(Interpolated::Unresolved);
                }
                resolved.push(interpolation.text);
            }
            Ok(Interpolated::Resolved(Cow::Owned(
                ConditionValue::StringList(resolved),
            )))
        }
        _ => Ok(Interpolated::Resolved(Cow::Borrowed(value))),
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
    use crate::{
        Arn, ConditionValue, ContextValue, IAMAction, IAMEffect, IAMOperator, IAMResource,
        IAMStatement, IAMVersion,
    };

    #[test]
    fn test_simple_allow_policy() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_simple_deny_policy() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Deny)
                .with_action(IAMAction::Single("s3:DeleteObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:DeleteObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[test]
    fn test_not_applicable_policy() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single(
                    "arn:aws:s3:::other-bucket/*".to_string(),
                )),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_wildcard_action_matching() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:*".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_action_case_insensitive() {
        // AWS: action names are case-insensitive (iam:ListAccessKeys == IAM:listaccesskeys).
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "S3:getobject", // different case
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_action_multiple_case_insensitive() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Multiple(vec![
                    "s3:GetObject".to_string(),
                    "s3:PutObject".to_string(),
                ]))
                .with_resource(IAMResource::Single("*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "S3:PUTOBJECT",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_action_wildcard_case_insensitive() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("iam:*AccessKey*".to_string()))
                .with_resource(IAMResource::Single("*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "IAM:listaccesskeys",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_condition_evaluation() {
        use crate::IAMOperator;

        let mut context = Context::new();
        context.insert(
            "aws:userid".to_string(),
            ContextValue::String("test-user".to_string()),
        );

        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string()))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:userid".to_string(),
                    ConditionValue::String("test-user".to_string()),
                ),
        );

        let request = IAMRequest::new_with_context(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            context,
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_condition_evaluation_failure() {
        use crate::IAMOperator;

        let mut context = Context::new();
        context.insert(
            "aws:userid".to_string(),
            ContextValue::String("other-user".to_string()),
        );

        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string()))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:userid".to_string(),
                    ConditionValue::String("test-user".to_string()),
                ),
        );

        let request = IAMRequest::new_with_context(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            context,
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_deny_with_negated_condition_on_missing_key() {
        // AWS: a negated condition (StringNotEquals) with an absent context key
        // is true, so this Deny statement applies and denies access.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Deny)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::StringNotEquals,
                    "aws:SecureTransport".to_string(),
                    ConditionValue::String("true".to_string()),
                ),
        );

        // No context provided: aws:SecureTransport is absent.
        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[test]
    fn test_for_all_values_allow() {
        // AWS: ForAllValues is true when every request value matches at least
        // one policy value. Here each of the two TagKeys has a matching entry.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:TagKeys".to_string(),
            ContextValue::StringList(vec!["environment".to_string(), "cost-center".to_string()]),
        );

        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::ForAllValuesStringEquals,
                    "aws:TagKeys".to_string(),
                    ConditionValue::StringList(vec!["environment".into(), "cost-center".into()]),
                ),
        );

        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        request.context = ctx;

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_for_all_values_negated_deny_region() {
        // Classic AWS pattern: deny if the requested region is not in the
        // allowed set. A request to an allowed region must NOT be denied.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Deny)
                .with_action(IAMAction::Single("*".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::ForAllValuesStringNotEquals,
                    "aws:RequestedRegion".to_string(),
                    ConditionValue::StringList(vec!["eu-central-1".into(), "eu-west-1".into()]),
                ),
        );

        // Inside the allowed set -> not denied.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:RequestedRegion".to_string(),
            ContextValue::String("eu-central-1".to_string()),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);

        // Outside the allowed set -> denied.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:RequestedRegion".to_string(),
            ContextValue::String("us-east-1".to_string()),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[test]
    fn test_null_condition_string_form() {
        // AWS IAM policies commonly use the string form "true"/"false".
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::Null,
                    "aws:TokenIssueTime".to_string(),
                    ConditionValue::String("false".to_string()), // key must exist
                ),
        );

        // Key present -> condition true -> allowed.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:TokenIssueTime".to_string(),
            ContextValue::String("2024-01-01T00:00:00Z".to_string()),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);

        // Key absent -> condition false -> not applicable.
        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_float_numeric_condition() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"NumericLessThan": {"aws:multifactorAuthAge": 1234.5}}
            }]
        }"#;
        let policy = IAMPolicy::from_json(policy_json).unwrap();

        // Context value 500.0 < 1234.5 -> allowed.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:multifactorAuthAge".to_string(),
            ContextValue::Number(500.0),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);

        // Context value 2000.0 >= 1234.5 -> not applicable.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:multifactorAuthAge".to_string(),
            ContextValue::Number(2000.0),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_plain_operator_multivalued_context() {
        // A plain operator against a multivalued context key matches if any
        // value matches (implicit ForAnyValue semantics).
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("ec2:DeleteTags".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:TagKeys".to_string(),
                    ConditionValue::String("environment".to_string()),
                ),
        );

        // "environment" is among the request's tag keys -> allowed.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:TagKeys".to_string(),
            ContextValue::StringList(vec!["environment".to_string(), "dept".to_string()]),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "ec2:DeleteTags",
            Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-123").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);

        // No tag key matches -> not applicable.
        let mut ctx = Context::new();
        ctx.insert(
            "aws:TagKeys".to_string(),
            ContextValue::StringList(vec!["dept".to_string()]),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "ec2:DeleteTags",
            Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-123").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_context_key_case_insensitive() {
        // AWS: context key names are case-insensitive.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:username".to_string(),
                    ConditionValue::String("alice".to_string()),
                ),
        );

        // Context uses a different case for the key name.
        let mut ctx = Context::new();
        ctx.insert(
            "AWS:UserName".to_string(),
            ContextValue::String("alice".to_string()),
        );
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        request.context = ctx;
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_explicit_deny_overrides_allow() {
        let policies = vec![
            IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single("s3:*".to_string()))
                    .with_resource(IAMResource::Single("*".to_string())),
            ),
            IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Deny)
                    .with_action(IAMAction::Single("s3:DeleteObject".to_string()))
                    .with_resource(IAMResource::Single(
                        "arn:aws:s3:::protected-bucket/*".to_string(),
                    )),
            ),
        ];

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:DeleteObject",
            Arn::parse("arn:aws:s3:::protected-bucket/file.txt").unwrap(),
        );

        let result = evaluate_policies(&policies, &request).unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[test]
    fn test_non_arn_principal_does_not_panic() {
        // A request principal that is valid but not an ARN (e.g. a 12-digit
        // account ID) must not panic when matched against a wildcard ARN
        // principal. Previously this hit an unwrap on a failed ARN parse.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_principal(Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:role/*".to_string(),
                )))
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String("123456789012".to_string())),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        // Principal doesn't match the ARN pattern -> statement not applicable.
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_account_id_principal_matches_root_arn_any_partition() {
        // A policy-side 12-digit account ID must match the account's root ARN
        // in any partition (aws, aws-cn, aws-us-gov, ...), not just "aws".
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_principal(Principal::Aws(PrincipalId::String(
                    "123456789012".to_string(),
                )))
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        for root in [
            "arn:aws:iam::123456789012:root",
            "arn:aws-cn:iam::123456789012:root",
            "arn:aws-us-gov:iam::123456789012:root",
        ] {
            let request = IAMRequest::new(
                Principal::Aws(PrincipalId::String(root.to_string())),
                "s3:GetObject",
                Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            );
            let result = evaluate_policy(&policy, &request).unwrap();
            assert_eq!(
                result,
                Decision::Allow,
                "root principal {root} should match"
            );
        }

        // A root ARN for a different account must NOT match.
        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::999999999999:root".to_string(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_raw_account_id_request_principal_matches_root_arn() {
        // A request principal given as a raw 12-digit account ID is the
        // account's root principal, so ARN patterns that match the root must
        // match it.
        let root_policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_principal(Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:root".to_string(),
                )))
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String("123456789012".to_string())),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        let result = evaluate_policy(&root_policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);

        // A wildcard ARN that matches the root also matches the raw account ID.
        let wildcard_policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_principal(Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:*".to_string(),
                )))
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );
        let result = evaluate_policy(&wildcard_policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);

        // An ARN pattern that targets IAM users (not the account root) must NOT
        // match the raw account ID.
        let user_policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_principal(Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:user/jo*".to_string(),
                )))
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );
        let result = evaluate_policy(&user_policy, &request).unwrap();
        assert_eq!(result, Decision::NotApplicable);
    }

    #[test]
    fn test_numeric_condition() {
        let mut context = Context::new();
        context.insert("aws:RequestedRegion".to_string(), ContextValue::Number(5.0));

        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::NumericLessThan,
                    "aws:RequestedRegion".to_string(),
                    ConditionValue::Number(10.into()),
                ),
        );

        let request = IAMRequest::new_with_context(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            context,
        );

        let result = evaluate_policy(&policy, &request).unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[test]
    fn test_evaluator_with_options() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_sid("AllowS3Read")
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let evaluator =
            PolicyEvaluator::with_policies(vec![policy]).with_options(EvaluationOptions {
                collect_match_details: true,
                ..Default::default()
            });

        let result = evaluator.evaluate(&request).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_ne!(result.statement_details, Vec::new());
        assert_eq!(
            result.statement_details[0].sid,
            Some("AllowS3Read".to_string())
        );
    }

    /// One expected decision for a policy from `tests/policies/`.
    #[derive(Debug, Deserialize)]
    struct ExpectedCase {
        /// Why this decision is the right one, for whoever hits the failure.
        reason: String,
        request: IAMRequest,
        result: Decision,
    }

    #[derive(Debug, Deserialize)]
    struct ExpectedPolicy {
        policy_file: String,
        cases: Vec<ExpectedCase>,
    }

    #[test]
    fn test_policy_corpus_decisions() {
        // `test_policy_roundtrip_from_files` parses and re-serialises the corpus
        // without ever evaluating it, so nothing pinned what those documented AWS
        // example policies actually decide. This does.
        let path = "tests/expected-decisions.json";
        let json = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read '{path}': {e}"));
        let expectations: Vec<ExpectedPolicy> =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("Failed to parse '{path}': {e}"));
        assert!(
            !expectations.is_empty(),
            "expected at least one policy in {path}"
        );

        let mut case_count = 0;
        for expectation in &expectations {
            let policy_path = format!("tests/policies/{}", expectation.policy_file);
            let policy_json = std::fs::read_to_string(&policy_path)
                .unwrap_or_else(|e| panic!("Failed to read '{policy_path}': {e}"));
            let policy = IAMPolicy::from_json(&policy_json)
                .unwrap_or_else(|e| panic!("Failed to parse '{policy_path}': {e}"));
            assert!(policy.is_valid(), "'{policy_path}' should be valid IAM");
            assert!(
                !expectation.cases.is_empty(),
                "'{}' has no expected cases in {path}",
                expectation.policy_file
            );

            for case in &expectation.cases {
                case_count += 1;
                let decision = evaluate_policy(&policy, &case.request).unwrap_or_else(|e| {
                    panic!("Failed to evaluate '{policy_path}' ({}): {e}", case.reason)
                });
                assert_eq!(
                    decision, case.result,
                    "'{policy_path}': {} decided {decision:?}, expected {:?}",
                    case.reason, case.result
                );
            }
        }
        assert!(case_count > 0, "expected at least one case in {path}");
    }

    #[test]
    fn test_evaluate_owned_matches_evaluate() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );
        let evaluator = PolicyEvaluator::with_policies(vec![policy]);
        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let borrowed = evaluator.evaluate(&request).unwrap();
        let owned = evaluator.evaluate_owned(request).unwrap();
        assert_eq!(owned, borrowed);
    }

    // Patterns without `${...}` are compiled when the policy is added to the
    // evaluator. The cached matchers must match exactly what per-request
    // compilation matched, including entry-wise "*" and wildcard components.
    #[test]
    fn test_precompiled_patterns_match_same_resources() {
        let evaluator_for = |resource: IAMResource| {
            PolicyEvaluator::with_policies(vec![
                IAMPolicy::new().add_statement(
                    IAMStatement::new(IAMEffect::Allow)
                        .with_action(IAMAction::Single("s3:GetObject".to_string()))
                        .with_resource(resource),
                ),
            ])
        };
        let decision_for = |evaluator: &PolicyEvaluator, resource: &str| {
            let request = IAMRequest::new(
                Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:user/test".into(),
                )),
                "s3:GetObject",
                Arn::parse(resource).unwrap(),
            );
            evaluator.evaluate(&request).unwrap().decision
        };

        let patterns = evaluator_for(IAMResource::Multiple(vec![
            "arn:aws:s3:::other-bucket/*".to_string(),
            "arn:aws:s3:::my-*/*.txt".to_string(),
        ]));
        assert_eq!(
            decision_for(&patterns, "arn:aws:s3:::other-bucket/object.json"),
            Decision::Allow
        );
        assert_eq!(
            decision_for(&patterns, "arn:aws:s3:::my-bucket/file.txt"),
            Decision::Allow
        );
        // The wildcard components stay meaningful: another extension and another
        // bucket do not match.
        assert_eq!(
            decision_for(&patterns, "arn:aws:s3:::my-bucket/file.json"),
            Decision::NotApplicable
        );
        assert_eq!(
            decision_for(&patterns, "arn:aws:s3:::unrelated-bucket/file.txt"),
            Decision::NotApplicable
        );

        // "*" keeps its always-true short circuit when it is one entry of a list.
        let any = evaluator_for(IAMResource::Multiple(vec![
            "arn:aws:s3:::other-bucket/*".to_string(),
            "*".to_string(),
        ]));
        assert_eq!(
            decision_for(&any, "arn:aws:s3:::unrelated-bucket/file.txt"),
            Decision::Allow
        );
    }

    // A pattern with `${...}` is request-dependent: it must not be frozen at
    // add time, so the same evaluator resolves a different username per request.
    #[test]
    fn test_variable_resource_pattern_resolved_per_request() {
        let evaluator = PolicyEvaluator::with_policies(vec![
            IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single(
                        "arn:aws:s3:::home/${aws:username}/*".to_string(),
                    )),
            ),
        ]);

        let decision_for = |username: &str| {
            let request = IAMRequest::new_with_context(
                Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:user/test".into(),
                )),
                "s3:GetObject",
                Arn::parse("arn:aws:s3:::home/alice/notes.txt").unwrap(),
                Context::new().with_string("aws:username", username),
            );
            evaluator.evaluate(&request).unwrap().decision
        };

        assert_eq!(decision_for("alice"), Decision::Allow);
        assert_eq!(decision_for("bob"), Decision::NotApplicable);
    }

    // A malformed static pattern is only detected when the pattern is compiled.
    // `add_policy` is infallible, so the error must reach the caller from
    // `evaluate` exactly as the per-request compilation used to report it.
    #[test]
    fn test_malformed_static_pattern_fails_at_evaluation() {
        let mut evaluator = PolicyEvaluator::new();
        evaluator.add_policy(
            IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single("not-an-arn".to_string())),
            ),
        );

        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let error = evaluator
            .evaluate(&request)
            .expect_err("a malformed static resource pattern must fail evaluation");
        let expected = ArnMatcher::from_pattern("not-an-arn")
            .unwrap_err()
            .to_string();
        assert_eq!(error, EvaluationError::InvalidArn(expected));
    }

    // The compiled patterns are parallel to `policies`; a policy added after
    // construction must extend both, or evaluation would read bindings that do
    // not describe its statements.
    #[test]
    fn test_policies_added_after_construction_stay_in_sync() {
        let mut evaluator = PolicyEvaluator::new();
        assert_eq!(evaluator.resource_patterns.len(), evaluator.policies.len());

        evaluator.add_policy(
            IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string())),
            ),
        );
        assert_eq!(evaluator.resource_patterns.len(), evaluator.policies.len());

        evaluator
            .try_add_policy(
                IAMPolicy::new().add_statement(
                    IAMStatement::new(IAMEffect::Deny)
                        .with_action(IAMAction::Single("s3:GetObject".to_string()))
                        .with_resource(IAMResource::Single(
                            "arn:aws:s3:::my-bucket/secret/*".to_string(),
                        )),
                ),
            )
            .expect("valid policy must be accepted");
        assert_eq!(evaluator.resource_patterns.len(), evaluator.policies.len());

        let decision_for = |resource: &str| {
            let request = IAMRequest::new(
                Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:user/test".into(),
                )),
                "s3:GetObject",
                Arn::parse(resource).unwrap(),
            );
            evaluator.evaluate(&request).unwrap().decision
        };

        assert_eq!(
            decision_for("arn:aws:s3:::my-bucket/object.json"),
            Decision::Allow
        );
        assert_eq!(
            decision_for("arn:aws:s3:::my-bucket/secret/object.json"),
            Decision::Deny
        );
    }

    #[test]
    fn test_cloned_evaluator_evaluates_identically() {
        let evaluator = PolicyEvaluator::with_policies(vec![
            IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single(
                        "arn:aws:s3:::home/${aws:username}/*".to_string(),
                    )),
            ),
            IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Deny)
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single(
                        "arn:aws:s3:::home/*/private/*".to_string(),
                    )),
            ),
        ])
        .with_options(EvaluationOptions {
            collect_match_details: true,
            ..EvaluationOptions::default()
        });

        let cloned = evaluator.clone();
        let request = IAMRequest::new_with_context(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::home/alice/notes.txt").unwrap(),
            Context::new().with_string("aws:username", "alice"),
        );

        let original = evaluator.evaluate(&request).unwrap();
        assert_eq!(original.decision, Decision::Allow);
        assert_eq!(cloned.evaluate(&request).unwrap(), original);

        let denied = IAMRequest::new_with_context(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::home/alice/private/notes.txt").unwrap(),
            Context::new().with_string("aws:username", "alice"),
        );
        assert_eq!(
            cloned.evaluate(&denied).unwrap(),
            evaluator.evaluate(&denied).unwrap()
        );
        assert_eq!(cloned.evaluate(&denied).unwrap().decision, Decision::Deny);
    }

    #[test]
    fn test_try_add_policy_rejects_invalid_policies() {
        // An Allow statement carrying NotPrincipal is invalid IAM.
        let mut invalid = IAMStatement::new(IAMEffect::Allow);
        invalid.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        invalid.resource = Some(IAMResource::Single("*".to_string()));
        invalid.not_principal = Some(Principal::Aws(PrincipalId::String(
            "123456789012".to_string(),
        )));

        let mut evaluator = PolicyEvaluator::new();
        let error = evaluator
            .try_add_policy(IAMPolicy::new().add_statement(invalid))
            .expect_err("invalid policy must be rejected");
        assert!(
            error.to_string().contains("NotPrincipal"),
            "unexpected error: {error}"
        );

        let valid = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string())),
        );
        evaluator
            .try_add_policy(valid)
            .expect("valid policy must be accepted");
    }

    fn not_principal_policy(effect: IAMEffect) -> IAMPolicy {
        let mut statement = IAMStatement::new(effect)
            .with_action(IAMAction::Single("s3:GetObject".to_string()))
            .with_resource(IAMResource::Single("*".to_string()));
        statement.not_principal = Some(Principal::Aws(PrincipalId::String(
            "arn:aws:iam::123456789012:user/alice".to_string(),
        )));
        IAMPolicy::new().add_statement(statement)
    }

    fn s3_request_for(user: &str) -> IAMRequest {
        IAMRequest::new(
            Principal::Aws(PrincipalId::String(format!(
                "arn:aws:iam::123456789012:user/{user}"
            ))),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        )
    }

    // AWS does not support NotPrincipal with Effect: Allow, so no such policy can
    // exist. The evaluator treats the statement as never matching instead of
    // mirroring the exclusion and granting every principal outside the list.
    #[test]
    fn test_allow_with_not_principal_never_matches() {
        let policy = not_principal_policy(IAMEffect::Allow);
        let request = s3_request_for("bob");

        assert_eq!(
            evaluate_policy(&policy, &request).unwrap(),
            Decision::NotApplicable
        );

        // The decision comes from the statement not matching, not from an error.
        let evaluator =
            PolicyEvaluator::with_policies(vec![policy]).with_options(EvaluationOptions {
                collect_match_details: true,
                ..EvaluationOptions::default()
            });
        let result = evaluator.evaluate(&request).unwrap();
        assert_eq!(result.decision, Decision::NotApplicable);
        assert_eq!(result.statement_details.len(), 1);
        assert!(!result.statement_details[0].conditions_satisfied);
        assert!(
            result.statement_details[0].reason.contains("NotPrincipal"),
            "unexpected reason: {}",
            result.statement_details[0].reason
        );
    }

    #[test]
    fn test_allow_with_not_principal_does_not_match_the_listed_principal() {
        let policy = not_principal_policy(IAMEffect::Allow);

        assert_eq!(
            evaluate_policy(&policy, &s3_request_for("alice")).unwrap(),
            Decision::NotApplicable
        );
    }

    #[test]
    fn test_deny_with_not_principal_still_denies_other_principals() {
        let policy = not_principal_policy(IAMEffect::Deny);

        assert_eq!(
            evaluate_policy(&policy, &s3_request_for("bob")).unwrap(),
            Decision::Deny
        );
    }

    #[test]
    fn test_deny_with_not_principal_does_not_match_the_listed_principal() {
        let policy = not_principal_policy(IAMEffect::Deny);

        assert_eq!(
            evaluate_policy(&policy, &s3_request_for("alice")).unwrap(),
            Decision::NotApplicable
        );
    }

    fn principal_type_requests() -> Vec<Principal> {
        vec![
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/alice".into(),
            )),
            Principal::Service(PrincipalId::String("lambda.amazonaws.com".into())),
            Principal::Federated(PrincipalId::String("example.com".into())),
            Principal::CanonicalUser(PrincipalId::String(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
            )),
        ]
    }

    // AWS documents `{"AWS": "*"}` as another spelling of `"Principal": "*"`, so
    // the two must match exactly the same requests.
    #[test]
    fn test_aws_wildcard_principal_matches_every_principal_type() {
        let policy = IAMPolicy::from_json(
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }]
            }"#,
        )
        .unwrap();

        for principal in principal_type_requests() {
            let request = IAMRequest::new(
                principal.clone(),
                "s3:GetObject",
                Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            );
            assert_eq!(
                evaluate_policy(&policy, &request).unwrap(),
                Decision::Allow,
                "{{\"AWS\": \"*\"}} must allow {principal:?}"
            );
        }
    }

    #[test]
    fn test_bare_wildcard_principal_still_matches_every_principal_type() {
        let policy = IAMPolicy::from_json(
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }]
            }"#,
        )
        .unwrap();

        for principal in principal_type_requests() {
            let request = IAMRequest::new(
                principal.clone(),
                "s3:GetObject",
                Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            );
            assert_eq!(
                evaluate_policy(&policy, &request).unwrap(),
                Decision::Allow,
                "\"Principal\": \"*\" must allow {principal:?}"
            );
        }
    }

    // `NotPrincipal: {"AWS": "*"}` excludes everyone, so a Deny statement
    // carrying it never applies.
    #[test]
    fn test_deny_with_aws_wildcard_not_principal_excludes_everyone() {
        let policy = IAMPolicy::from_json(
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "NotPrincipal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }]
            }"#,
        )
        .unwrap();

        for principal in principal_type_requests() {
            let request = IAMRequest::new(
                principal.clone(),
                "s3:GetObject",
                Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            );
            assert_eq!(
                evaluate_policy(&policy, &request).unwrap(),
                Decision::NotApplicable,
                "NotPrincipal {{\"AWS\": \"*\"}} must exclude {principal:?}"
            );
        }
    }

    // A wildcard is not a valid request principal. `evaluate` rejects it before
    // any statement is matched, which is what makes the missing request-side
    // wildcard arm in `principal_matches` safe.
    #[test]
    fn test_wildcard_request_principal_is_rejected() {
        let evaluator = PolicyEvaluator::with_policies(vec![IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string())),
        )]);
        // `{"AWS": "*"}` validates as a policy principal, so the request side has
        // to reject it explicitly as well.
        for principal in [
            Principal::Wildcard,
            Principal::Aws(PrincipalId::String("*".into())),
        ] {
            let request = IAMRequest::new(
                principal.clone(),
                "s3:GetObject",
                Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            );

            assert!(
                matches!(
                    evaluator.evaluate(&request),
                    Err(EvaluationError::InvalidRequest(_))
                ),
                "{principal:?} must not be accepted as a request principal"
            );
        }
    }

    #[test]
    fn test_federated_principal_requires_exact_match() {
        let policy = IAMPolicy::from_json(
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }]
            }"#,
        )
        .unwrap();

        let trusted = IAMRequest::new(
            Principal::Federated(PrincipalId::String("cognito-identity.amazonaws.com".into())),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );
        assert_eq!(evaluate_policy(&policy, &trusted).unwrap(), Decision::Allow);

        // Merely starting with the trusted provider name must not be enough, and
        // neither must containing it.
        for lookalike in [
            "cognito-identity.amazonaws.com.attacker.net",
            "cognito-identity.amazonaws.com.evil",
            "evil.cognito-identity.amazonaws.com",
        ] {
            let request = IAMRequest::new(
                Principal::Federated(PrincipalId::String(lookalike.into())),
                "s3:GetObject",
                Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
            );
            assert_eq!(
                evaluate_policy(&policy, &request).unwrap(),
                Decision::NotApplicable,
                "{lookalike} must not match the trusted federated principal"
            );
        }
    }

    // `statement_details` stops at the statement that denies. `evaluate_owned` and
    // `evaluate` share `decide`, so this pins the contract both of them carry, and
    // the truncation the field documentation promises.
    #[test]
    fn test_statement_details_stops_at_the_denying_statement() {
        let policy = IAMPolicy::new()
            .add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_sid("AllowGet")
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single("*".to_string())),
            )
            .add_statement(
                IAMStatement::new(IAMEffect::Deny)
                    .with_sid("DenyAll")
                    .with_action(IAMAction::Single("s3:*".to_string()))
                    .with_resource(IAMResource::Single("*".to_string())),
            )
            .add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_sid("AllowPut")
                    .with_action(IAMAction::Single("s3:PutObject".to_string()))
                    .with_resource(IAMResource::Single("*".to_string())),
            );
        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            "s3:GetObject",
            Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap(),
        );

        let short_circuit = PolicyEvaluator::with_policies(vec![policy.clone()]).with_options(
            EvaluationOptions {
                collect_match_details: true,
                ..Default::default()
            },
        );
        let result = short_circuit.evaluate(&request).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.statement_details.len(),
            2,
            "the denying statement is recorded and nothing after it"
        );
        assert_eq!(result.statement_details[1].sid.as_deref(), Some("DenyAll"));

        let full = PolicyEvaluator::with_policies(vec![policy]).with_options(EvaluationOptions {
            collect_match_details: true,
            stop_on_explicit_deny: false,
            ..Default::default()
        });
        let result = full.evaluate(&request).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.statement_details.len(),
            3,
            "without the short circuit every statement is recorded"
        );
    }

    #[test]
    fn test_evaluation_options_accept_partial_json() {
        let options: EvaluationOptions =
            serde_json::from_str(r#"{"max_statements": 50}"#).expect("partial options must parse");

        assert_eq!(options.max_statements, 50);
        assert_eq!(
            options.stop_on_explicit_deny,
            EvaluationOptions::default().stop_on_explicit_deny
        );
        assert_eq!(
            options.collect_match_details,
            EvaluationOptions::default().collect_match_details
        );
        assert_eq!(
            options.ignore_resource_constraints,
            EvaluationOptions::default().ignore_resource_constraints
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
        let request_files = std::fs::read_dir(request_dir)
            .unwrap_or_else(|e| panic!("Failed to read requests directory '{request_dir}': {e}"))
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
            "No request JSON files found in {request_dir}/"
        );

        // Resolve the numeric prefix up front rather than inside the comparator:
        // `sort_by_key` is not obliged to call the key function for a directory
        // holding a single file, so a stray filename would otherwise go
        // unchecked, and a non-UTF-8 name would sort silently as `None`.
        let mut keyed: Vec<(u32, std::path::PathBuf)> = request_files
            .into_iter()
            .map(|path| {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_else(|| {
                        panic!(
                            "unexpected non-UTF-8 filename '{}' in {request_dir}/",
                            path.display()
                        )
                    });
                let number = name
                    .split('.')
                    .next()
                    .and_then(|stem| stem.parse::<u32>().ok())
                    .unwrap_or_else(|| {
                        panic!("unexpected file '{name}' in {request_dir}/: expected <number>.json")
                    });
                (number, path)
            })
            .collect();
        keyed.sort_by_key(|(number, _)| *number);
        let request_files: Vec<std::path::PathBuf> =
            keyed.into_iter().map(|(_, path)| path).collect();

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
            let json_content = std::fs::read_to_string(request_file).unwrap_or_else(|e| {
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

    fn request_with_context(action: &str, resource: &str, entries: &[(&str, &str)]) -> IAMRequest {
        let mut request = IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/alice".into(),
            )),
            action,
            Arn::parse(resource).unwrap(),
        );
        for (key, value) in entries {
            request.context.insert(
                (*key).to_string(),
                ContextValue::String((*value).to_string()),
            );
        }
        request
    }

    fn owner_tag_policy(operator: IAMOperator) -> IAMPolicy {
        // The shape AWS documents for "let users manage their own resources":
        // the condition value is a policy variable, resolved per request.
        IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("ec2:StartInstances".to_string()))
                .with_resource(IAMResource::Single(
                    "arn:aws:ec2:*:*:instance/*".to_string(),
                ))
                .with_condition(
                    operator,
                    "aws:ResourceTag/Owner".to_string(),
                    ConditionValue::String("${aws:username}".to_string()),
                ),
        )
    }

    #[test]
    fn test_condition_value_variable_resolves_against_the_request() {
        let policy = owner_tag_policy(IAMOperator::StringEquals);
        let resource = "arn:aws:ec2:us-east-1:123456789012:instance/i-1";

        // The tag names the caller, so the variable resolves to a match.
        let own = request_with_context(
            "ec2:StartInstances",
            resource,
            &[
                ("aws:ResourceTag/Owner", "alice"),
                ("aws:username", "alice"),
            ],
        );
        assert_eq!(evaluate_policy(&policy, &own).unwrap(), Decision::Allow);

        // Someone else's tag must not match: the variable is not a wildcard.
        let other = request_with_context(
            "ec2:StartInstances",
            resource,
            &[("aws:ResourceTag/Owner", "bob"), ("aws:username", "alice")],
        );
        assert_eq!(
            evaluate_policy(&policy, &other).unwrap(),
            Decision::NotApplicable
        );
    }

    #[test]
    fn test_condition_value_variable_is_interpolated_before_wildcard_matching() {
        // `home/${aws:username}/*` must become a pattern anchored on the caller,
        // not be compared as the literal text `home/${aws:username}/*`.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:ListBucket".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::bucket".to_string()))
                .with_condition(
                    IAMOperator::StringLike,
                    "s3:prefix".to_string(),
                    ConditionValue::String("home/${aws:username}/*".to_string()),
                ),
        );

        let own = request_with_context(
            "s3:ListBucket",
            "arn:aws:s3:::bucket",
            &[("s3:prefix", "home/alice/docs"), ("aws:username", "alice")],
        );
        assert_eq!(evaluate_policy(&policy, &own).unwrap(), Decision::Allow);

        let other = request_with_context(
            "s3:ListBucket",
            "arn:aws:s3:::bucket",
            &[("s3:prefix", "home/bob/docs"), ("aws:username", "alice")],
        );
        assert_eq!(
            evaluate_policy(&policy, &other).unwrap(),
            Decision::NotApplicable
        );
    }

    #[test]
    fn test_negated_condition_value_variable_stops_the_deny() {
        // `StringNotEquals` against `${aws:userid}` is how AWS documents
        // "deny everyone except the creator". Comparing the variable literally
        // would deny the creator too.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Deny)
                .with_action(IAMAction::Single(
                    "datapipeline:ActivatePipeline".to_string(),
                ))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::StringNotEquals,
                    "datapipeline:PipelineCreator".to_string(),
                    ConditionValue::String("${aws:userid}".to_string()),
                ),
        );
        let resource = "arn:aws:datapipeline:us-east-1:123456789012:pipeline/df-1";

        let creator = request_with_context(
            "datapipeline:ActivatePipeline",
            resource,
            &[
                ("datapipeline:PipelineCreator", "AIDAEXAMPLE:alice"),
                ("aws:userid", "AIDAEXAMPLE:alice"),
            ],
        );
        assert_eq!(
            evaluate_policy(&policy, &creator).unwrap(),
            Decision::NotApplicable,
            "the creator must not be denied"
        );

        let stranger = request_with_context(
            "datapipeline:ActivatePipeline",
            resource,
            &[
                ("datapipeline:PipelineCreator", "AIDAOTHER:bob"),
                ("aws:userid", "AIDAEXAMPLE:alice"),
            ],
        );
        assert_eq!(evaluate_policy(&policy, &stranger).unwrap(), Decision::Deny);
    }

    #[test]
    fn test_condition_value_variable_in_a_list_and_with_a_default() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:ListBucket".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::bucket".to_string()))
                .with_condition(
                    IAMOperator::StringLike,
                    "s3:prefix".to_string(),
                    ConditionValue::StringList(vec![
                        "shared/".to_string(),
                        "home/${aws:username}/*".to_string(),
                    ]),
                ),
        );
        let own = request_with_context(
            "s3:ListBucket",
            "arn:aws:s3:::bucket",
            &[("s3:prefix", "home/alice/"), ("aws:username", "alice")],
        );
        assert_eq!(evaluate_policy(&policy, &own).unwrap(), Decision::Allow);

        // A policy-authored default is used when the context key is absent.
        let with_default = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("ec2:StartInstances".to_string()))
                .with_resource(IAMResource::Single(
                    "arn:aws:ec2:*:*:instance/*".to_string(),
                ))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:ResourceTag/Owner".to_string(),
                    ConditionValue::String("${aws:username, 'anonymous'}".to_string()),
                ),
        );
        let anonymous = request_with_context(
            "ec2:StartInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1",
            &[("aws:ResourceTag/Owner", "anonymous")],
        );
        assert_eq!(
            evaluate_policy(&with_default, &anonymous).unwrap(),
            Decision::Allow
        );
    }

    #[test]
    fn test_condition_value_variable_refuses_a_wildcard_from_context() {
        // Same reasoning as for resource patterns: a context value of `*` must
        // not be spliced into a condition pattern.
        let policy = owner_tag_policy(IAMOperator::StringLike);
        let request = request_with_context(
            "ec2:StartInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1",
            &[("aws:ResourceTag/Owner", "anything"), ("aws:username", "*")],
        );
        let error = evaluate_policy(&policy, &request).unwrap_err();
        assert!(
            matches!(error, EvaluationError::InvalidVariable(_)),
            "expected InvalidVariable, got {error:?}"
        );
    }

    #[test]
    fn test_condition_value_without_a_variable_is_untouched() {
        // No `${...}` anywhere: the value must be compared exactly as written,
        // including text that looks vaguely variable-like.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("ec2:StartInstances".to_string()))
                .with_resource(IAMResource::Single(
                    "arn:aws:ec2:*:*:instance/*".to_string(),
                ))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:ResourceTag/Owner".to_string(),
                    ConditionValue::String("team alice".to_string()),
                ),
        );
        let request = request_with_context(
            "ec2:StartInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1",
            &[
                ("aws:ResourceTag/Owner", "team alice"),
                ("aws:username", "alice"),
            ],
        );
        assert_eq!(evaluate_policy(&policy, &request).unwrap(), Decision::Allow);
    }

    // AWS: "In order to use policy variables, you must include the `Version`
    // element ... set to a version that supports policy variables. Earlier
    // versions of the policy language don't support policy variables ... variables
    // like ${aws:username} are treated as literal strings."
    #[allow(deprecated)]
    fn version_without_policy_variables() -> IAMVersion {
        IAMVersion::V20081017
    }

    fn username_resource_policy(version: IAMVersion) -> IAMPolicy {
        IAMPolicy::with_version(version).add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:*".to_string()))
                .with_resource(IAMResource::Single(
                    "arn:aws:s3:::b/${aws:username}".to_string(),
                )),
        )
    }

    // Guard: 2012-10-17 is the version that introduced policy variables, so the
    // pattern resolves against the request context.
    #[test]
    fn test_policy_variables_resolve_in_2012_policy() {
        let policy = username_resource_policy(IAMVersion::V20121017);
        let request = request_with_context(
            "s3:GetObject",
            "arn:aws:s3:::b/test",
            &[("aws:username", "test")],
        );
        assert_eq!(evaluate_policy(&policy, &request).unwrap(), Decision::Allow);
    }

    #[test]
    fn test_policy_variables_are_literal_in_2008_policy() {
        // Same policy and request as the 2012 case, but the pattern stays the
        // literal text `arn:aws:s3:::b/${aws:username}` and matches nothing.
        let policy = username_resource_policy(version_without_policy_variables());
        let request = request_with_context(
            "s3:GetObject",
            "arn:aws:s3:::b/test",
            &[("aws:username", "test")],
        );
        assert_eq!(
            evaluate_policy(&policy, &request).unwrap(),
            Decision::NotApplicable
        );
    }

    #[test]
    fn test_condition_value_variable_is_literal_in_2008_policy() {
        let policy = IAMPolicy::with_version(version_without_policy_variables()).add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("ec2:StartInstances".to_string()))
                .with_resource(IAMResource::Single(
                    "arn:aws:ec2:*:*:instance/*".to_string(),
                ))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:ResourceTag/Owner".to_string(),
                    ConditionValue::String("${aws:username}".to_string()),
                ),
        );
        let resource = "arn:aws:ec2:us-east-1:123456789012:instance/i-1";

        // The caller's own tag does not match: the variable is not resolved.
        let own = request_with_context(
            "ec2:StartInstances",
            resource,
            &[
                ("aws:ResourceTag/Owner", "alice"),
                ("aws:username", "alice"),
            ],
        );
        assert_eq!(
            evaluate_policy(&policy, &own).unwrap(),
            Decision::NotApplicable
        );

        // Only the literal `${aws:username}` text matches the condition.
        let literal = request_with_context(
            "ec2:StartInstances",
            resource,
            &[
                ("aws:ResourceTag/Owner", "${aws:username}"),
                ("aws:username", "alice"),
            ],
        );
        assert_eq!(evaluate_policy(&policy, &literal).unwrap(), Decision::Allow);
    }

    // Guard: gating variables must not change anything else about a policy that
    // has no `${...}` in it.
    #[test]
    fn test_2008_policy_without_variables_evaluates_normally() {
        let policy = IAMPolicy::with_version(version_without_policy_variables()).add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::b/*".to_string()))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:RequestedRegion".to_string(),
                    ConditionValue::String("us-east-1".to_string()),
                ),
        );

        let matching = request_with_context(
            "s3:GetObject",
            "arn:aws:s3:::b/test",
            &[("aws:RequestedRegion", "us-east-1")],
        );
        assert_eq!(
            evaluate_policy(&policy, &matching).unwrap(),
            Decision::Allow
        );

        let other_region = request_with_context(
            "s3:GetObject",
            "arn:aws:s3:::b/test",
            &[("aws:RequestedRegion", "eu-west-1")],
        );
        assert_eq!(
            evaluate_policy(&policy, &other_region).unwrap(),
            Decision::NotApplicable
        );

        let other_resource = request_with_context(
            "s3:GetObject",
            "arn:aws:s3:::other-bucket/test",
            &[("aws:RequestedRegion", "us-east-1")],
        );
        assert_eq!(
            evaluate_policy(&policy, &other_resource).unwrap(),
            Decision::NotApplicable
        );
    }

    fn test_request(action: &str, resource: &str) -> IAMRequest {
        IAMRequest::new(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/test".into(),
            )),
            action,
            Arn::parse(resource).unwrap(),
        )
    }

    fn unresolved_variable_policy(resource: &str) -> IAMPolicy {
        IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single(resource.to_string())),
        )
    }

    #[test]
    fn test_unresolved_variable_matches_no_resource() {
        // AWS: "the resource that includes a policy variable with no value will
        // not match any resource". Substituting the empty string instead would
        // turn `home/${aws:username}*` into `home/*` and match every user.
        let policy = unresolved_variable_policy("arn:aws:s3:::home/${aws:username}*");
        let request = request_with_context("s3:GetObject", "arn:aws:s3:::home/bob/secret", &[]);
        assert_eq!(
            evaluate_policy(&policy, &request).unwrap(),
            Decision::NotApplicable
        );

        // With the key present the pattern resolves and matches as usual.
        let resolved = request_with_context(
            "s3:GetObject",
            "arn:aws:s3:::home/bob/secret",
            &[("aws:username", "bob")],
        );
        assert_eq!(
            evaluate_policy(&policy, &resolved).unwrap(),
            Decision::Allow
        );
    }

    #[test]
    fn test_unresolved_variable_matches_no_positive_condition() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:ListBucket".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::bucket".to_string()))
                .with_condition(
                    IAMOperator::StringLike,
                    "s3:prefix".to_string(),
                    ConditionValue::String("${aws:PrincipalTag/team}*".to_string()),
                ),
        );
        // A principal with no `team` tag must not get a `*` pattern.
        let request = request_with_context(
            "s3:ListBucket",
            "arn:aws:s3:::bucket",
            &[("s3:prefix", "anything")],
        );
        assert_eq!(
            evaluate_policy(&policy, &request).unwrap(),
            Decision::NotApplicable
        );
    }

    #[test]
    fn test_unresolved_variable_still_satisfies_a_negated_operator() {
        // A null value equals nothing, so `StringNotEquals` matches — which is
        // what makes the documented "deny everyone but the owner" pattern deny.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Deny)
                .with_action(IAMAction::Single("s3:*".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::StringNotEquals,
                    "s3:ExistingObjectTag/Team".to_string(),
                    ConditionValue::String("${aws:PrincipalTag/Team}".to_string()),
                ),
        );
        let request = request_with_context(
            "s3:GetObject",
            "arn:aws:s3:::bucket/object",
            &[("s3:ExistingObjectTag/Team", "media")],
        );
        assert_eq!(evaluate_policy(&policy, &request).unwrap(), Decision::Deny);
    }

    #[test]
    fn test_unresolved_variable_leaves_missing_key_rules_alone() {
        // The variable has no value *and* the condition key is absent. The
        // operator's missing-key rule decides: `ForAllValues` is true.
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("dynamodb:PutItem".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::ForAllValuesStringEquals,
                    "dynamodb:LeadingKeys".to_string(),
                    ConditionValue::String("${cognito-identity.amazonaws.com:sub}".to_string()),
                ),
        );
        let request = request_with_context(
            "dynamodb:PutItem",
            "arn:aws:dynamodb:us-east-1:123456789012:table/T",
            &[],
        );
        assert_eq!(evaluate_policy(&policy, &request).unwrap(), Decision::Allow);
    }

    #[test]
    fn test_unresolved_variable_keeps_policy_authored_defaults_working() {
        let policy = unresolved_variable_policy("arn:aws:s3:::home/${aws:username, 'anonymous'}/*");
        let request =
            request_with_context("s3:GetObject", "arn:aws:s3:::home/anonymous/report", &[]);
        assert_eq!(evaluate_policy(&policy, &request).unwrap(), Decision::Allow);
    }

    #[test]
    fn test_empty_not_action_matches_no_action() {
        // AWS rejects `"NotAction": []` with MalformedPolicyDocument: the array
        // grammar requires at least one value. Evaluating such a document without
        // validating it must not invert the empty list into "every action", which
        // would turn the Allow below into allow-all and the Deny into deny-all.
        for effect in [IAMEffect::Allow, IAMEffect::Deny] {
            let mut statement = IAMStatement::new(effect);
            statement.not_action = Some(IAMAction::Multiple(Vec::new()));
            statement.resource = Some(IAMResource::Single("*".to_string()));
            let policy = IAMPolicy::new().add_statement(statement);

            let request = test_request("s3:DeleteBucket", "arn:aws:s3:::my-bucket/file.txt");
            assert_eq!(
                evaluate_policy(&policy, &request).unwrap(),
                Decision::NotApplicable,
                "{effect:?} with an empty NotAction must not match any action"
            );
        }
    }

    #[test]
    fn test_empty_not_resource_matches_no_resource() {
        for effect in [IAMEffect::Allow, IAMEffect::Deny] {
            let mut statement = IAMStatement::new(effect);
            statement.action = Some(IAMAction::Single("ec2:*".to_string()));
            statement.not_resource = Some(IAMResource::Multiple(Vec::new()));
            let policy = IAMPolicy::new().add_statement(statement);

            let request = test_request(
                "ec2:TerminateInstances",
                "arn:aws:ec2:us-east-1:123456789012:instance/i-1",
            );
            assert_eq!(
                evaluate_policy(&policy, &request).unwrap(),
                Decision::NotApplicable,
                "{effect:?} with an empty NotResource must not match any resource"
            );
        }
    }

    #[test]
    fn test_non_empty_not_action_still_excludes() {
        // Guards against overcorrecting: a valid NotAction list must keep
        // excluding its entries and still apply to everything else.
        for (effect, matched) in [
            (IAMEffect::Allow, Decision::Allow),
            (IAMEffect::Deny, Decision::Deny),
        ] {
            let mut statement = IAMStatement::new(effect);
            statement.not_action = Some(IAMAction::Multiple(vec!["s3:GetObject".to_string()]));
            statement.resource = Some(IAMResource::Single("*".to_string()));
            let policy = IAMPolicy::new().add_statement(statement);

            let excluded = test_request("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt");
            assert_eq!(
                evaluate_policy(&policy, &excluded).unwrap(),
                Decision::NotApplicable,
                "{effect:?} with NotAction [s3:GetObject] must exclude s3:GetObject"
            );

            let other = test_request("s3:PutObject", "arn:aws:s3:::my-bucket/file.txt");
            assert_eq!(
                evaluate_policy(&policy, &other).unwrap(),
                matched,
                "{effect:?} with NotAction [s3:GetObject] must apply to s3:PutObject"
            );
        }
    }

    #[test]
    fn test_non_empty_not_resource_still_excludes() {
        for (effect, matched) in [
            (IAMEffect::Allow, Decision::Allow),
            (IAMEffect::Deny, Decision::Deny),
        ] {
            let mut statement = IAMStatement::new(effect);
            statement.action = Some(IAMAction::Single("s3:*".to_string()));
            statement.not_resource = Some(IAMResource::Multiple(vec![
                "arn:aws:s3:::sensitive/*".to_string(),
            ]));
            let policy = IAMPolicy::new().add_statement(statement);

            let excluded = test_request("s3:GetObject", "arn:aws:s3:::sensitive/secret.txt");
            assert_eq!(
                evaluate_policy(&policy, &excluded).unwrap(),
                Decision::NotApplicable,
                "{effect:?} with NotResource [sensitive/*] must exclude that ARN"
            );

            let other = test_request("s3:GetObject", "arn:aws:s3:::public/file.txt");
            assert_eq!(
                evaluate_policy(&policy, &other).unwrap(),
                matched,
                "{effect:?} with NotResource [sensitive/*] must apply elsewhere"
            );
        }
    }
}
