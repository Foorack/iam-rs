use std::fmt;

/// Validation error types for IAM policies
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ValidationError {
    /// Empty or missing required field
    MissingField { field: String, context: String },
    /// Invalid field value
    InvalidValue {
        field: String,
        value: String,
        reason: String,
    },
    /// Logical inconsistency in policy
    LogicalError { message: String },
    /// ARN format error
    InvalidArn { arn: String, reason: String },
    /// Condition operator/value mismatch
    InvalidCondition {
        operator: String,
        key: String,
        reason: String,
    },
    /// Principal format error
    InvalidPrincipal { principal: String, reason: String },
    /// Action format error
    InvalidAction { action: String, reason: String },
    /// Resource format error
    InvalidResource { resource: String, reason: String },
    /// Multiple validation errors
    Multiple(Vec<ValidationError>),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::MissingField { field, context } => {
                write!(f, "Missing required field '{field}' in {context}")
            }
            ValidationError::InvalidValue {
                field,
                value,
                reason,
            } => {
                write!(f, "Invalid value '{value}' for field '{field}': {reason}")
            }
            ValidationError::LogicalError { message } => {
                write!(f, "Logical error: {message}")
            }
            ValidationError::InvalidArn { arn, reason } => {
                write!(f, "Invalid ARN '{arn}': {reason}")
            }
            ValidationError::InvalidCondition {
                operator,
                key,
                reason,
            } => {
                write!(
                    f,
                    "Invalid condition '{operator}' for key '{key}': {reason}"
                )
            }
            ValidationError::InvalidPrincipal { principal, reason } => {
                write!(f, "Invalid principal '{principal}': {reason}")
            }
            ValidationError::InvalidAction { action, reason } => {
                write!(f, "Invalid action '{action}': {reason}")
            }
            ValidationError::InvalidResource { resource, reason } => {
                write!(f, "Invalid resource '{resource}': {reason}")
            }
            ValidationError::Multiple(errors) => {
                writeln!(f, "Multiple validation errors:")?;
                for (i, error) in errors.iter().enumerate() {
                    writeln!(f, "  {}: {error}", i + 1)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Result type for validation operations
pub type ValidationResult = Result<(), ValidationError>;

/// Validation context for tracking nested validation
#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub path: Vec<String>,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationContext {
    #[must_use]
    pub fn new() -> Self {
        Self { path: Vec::new() }
    }

    pub fn push(&mut self, segment: &str) {
        self.path.push(segment.to_string());
    }

    pub fn pop(&mut self) {
        self.path.pop();
    }

    #[must_use]
    pub fn current_path(&self) -> String {
        if self.path.is_empty() {
            "root".to_string()
        } else {
            self.path.join(".")
        }
    }

    pub fn with_segment<T>(&mut self, segment: &str, f: impl FnOnce(&mut Self) -> T) -> T {
        self.push(segment);
        let result = f(self);
        self.pop();
        result
    }
}

/// Trait for validating IAM policy components
/// All validation is strict and enforces high quality standards
pub trait Validate {
    /// Validate the component within the given context
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if the component is invalid
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult;

    /// Convenience method for basic validation
    fn is_valid(&self) -> bool {
        let mut context = ValidationContext::new();
        self.validate(&mut context).is_ok()
    }

    /// Validate with detailed errors (same as regular validation)
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if the component is invalid
    fn validate_result(&self) -> ValidationResult {
        let mut context = ValidationContext::new();
        self.validate(&mut context)
    }
}

/// Helper functions for common validation patterns
pub(crate) mod helpers {
    use super::{ValidationContext, ValidationError, ValidationResult};
    use crate::core::Arn;

    /// Validate that a string is not empty
    pub fn validate_non_empty(
        value: &str,
        field_name: &str,
        context: &ValidationContext,
    ) -> ValidationResult {
        if value.is_empty() {
            Err(ValidationError::MissingField {
                field: field_name.to_string(),
                context: context.current_path(),
            })
        } else {
            Ok(())
        }
    }

    /// Whether a segment carries an IAM wildcard
    fn has_wildcard(segment: &str) -> bool {
        segment.contains('*') || segment.contains('?')
    }

    /// The resource-type segment of an ARN's resource, if it has one.
    ///
    /// The type is the part that precedes the first `:` of the resource and the
    /// first `/`, so `arn:aws:lambda:r:a:function:my-function` has the type
    /// `function`. Resources written as `bucket/key` carry no `type:name` split
    /// at all, which is exactly an S3 resource: they have no type to check.
    fn resource_type(resource: &str) -> Option<&str> {
        let (head, _) = resource.split_once(':')?;
        Some(head.split('/').next().unwrap_or(head))
    }

    /// Validate action format (service:action)
    ///
    /// AWS's action grammar is "a service namespace, a colon, and the name of an
    /// action. Action names can include wildcards." The namespace itself cannot:
    /// a document such as `s3*:GetObject` is rejected with
    /// `MalformedPolicyDocument`. Accepting it here would also be unsafe at
    /// evaluation time, since the wildcard would cross the `:` boundary.
    pub fn validate_action(action: &str, _context: &ValidationContext) -> ValidationResult {
        if action == "*" {
            return Ok(());
        }

        let Some((namespace, name)) = action.split_once(':') else {
            return Err(ValidationError::InvalidAction {
                action: action.to_string(),
                reason: "Action must contain a colon separator or be '*'".to_string(),
            });
        };

        if namespace.is_empty() || name.is_empty() || name.contains(':') {
            return Err(ValidationError::InvalidAction {
                action: action.to_string(),
                reason: "Action must be in format 'service:action'".to_string(),
            });
        }

        if has_wildcard(namespace) {
            return Err(ValidationError::InvalidAction {
                action: action.to_string(),
                reason: "the service namespace must not contain wildcards".to_string(),
            });
        }

        Ok(())
    }

    /// Validate resource ARN or wildcard
    ///
    /// Wildcards are allowed in the region, account and resource-id parts of an
    /// ARN, but AWS forbids them in the partition, the service and the resource
    /// type ("you can't use a wildcard in the service segment that identifies the
    /// AWS product", "you cannot ... have a wildcard in the partition section of
    /// an ARN", "You cannot use a wildcard in the portion of the ARN that
    /// specifies the resource type"). Those are rejected here rather than in
    /// `Arn::matches`, so that a policy AWS refuses cannot pass as valid.
    ///
    /// A resource with no `type:name` split (`*`, `bucket`, `bucket/key`) has no
    /// type segment and is left alone, so an S3 pattern such as
    /// `arn:aws:s3:::my*bucket/*` stays valid.
    pub fn validate_resource(resource: &str, _context: &ValidationContext) -> ValidationResult {
        if resource == "*" {
            return Ok(());
        }

        if !resource.starts_with("arn:") {
            return Err(ValidationError::InvalidResource {
                resource: resource.to_string(),
                reason: "Resource must be an ARN or '*'".to_string(),
            });
        }

        // Use lenient parsing for resources with wildcards
        let arn = Arn::parse(resource).map_err(|e| ValidationError::InvalidResource {
            resource: resource.to_string(),
            reason: e.to_string(),
        })?;

        if has_wildcard(&arn.partition) {
            return Err(ValidationError::InvalidResource {
                resource: resource.to_string(),
                reason: "the ARN partition must not contain wildcards".to_string(),
            });
        }

        if has_wildcard(&arn.service) {
            return Err(ValidationError::InvalidResource {
                resource: resource.to_string(),
                reason: "the ARN service must not contain wildcards".to_string(),
            });
        }

        if resource_type(&arn.resource).is_some_and(has_wildcard) {
            return Err(ValidationError::InvalidResource {
                resource: resource.to_string(),
                reason: "the ARN resource type must not contain wildcards".to_string(),
            });
        }

        Ok(())
    }

    /// Collect multiple validation errors
    pub fn collect_errors(results: Vec<ValidationResult>) -> ValidationResult {
        let errors: Vec<ValidationError> = results
            .into_iter()
            .filter_map(std::result::Result::err)
            .collect();

        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.into_iter().next().unwrap())
        } else {
            Err(ValidationError::Multiple(errors))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ConditionValue;

    use super::*;

    #[test]
    fn test_validation_context() {
        let mut context = ValidationContext::new();
        assert_eq!(context.current_path(), "root");

        context.push("policy");
        context.push("statement");
        assert_eq!(context.current_path(), "policy.statement");

        context.pop();
        assert_eq!(context.current_path(), "policy");
    }

    #[test]
    fn test_validation_error_display() {
        let error = ValidationError::MissingField {
            field: "Effect".to_string(),
            context: "statement".to_string(),
        };
        assert!(
            error
                .to_string()
                .contains("Missing required field 'Effect'")
        );

        let multiple = ValidationError::Multiple(vec![
            ValidationError::MissingField {
                field: "Effect".to_string(),
                context: "statement".to_string(),
            },
            ValidationError::InvalidValue {
                field: "Action".to_string(),
                value: "invalid".to_string(),
                reason: "bad format".to_string(),
            },
        ]);
        let display = multiple.to_string();
        assert!(display.contains("Multiple validation errors"));
        assert!(display.contains("Missing required field"));
        assert!(display.contains("Invalid value"));
    }

    #[test]
    fn test_helper_validations() {
        let context = ValidationContext::new();

        // Test action validation
        assert!(helpers::validate_action("s3:GetObject", &context).is_ok());
        assert!(helpers::validate_action("*", &context).is_ok());
        assert!(helpers::validate_action("invalid-action", &context).is_err());

        // Test resource validation
        assert!(helpers::validate_resource("*", &context).is_ok());
        assert!(helpers::validate_resource("arn:aws:s3:::bucket/*", &context).is_ok());
        assert!(helpers::validate_resource("invalid-resource", &context).is_err());
        assert!(helpers::validate_resource("arn:aws:s3:::bucket/object", &context).is_ok());
    }

    #[test]
    fn test_wildcard_in_action_namespace_is_invalid() {
        use crate::{IAMAction, IAMEffect, IAMPolicy, IAMResource, IAMStatement};

        // AWS's grammar allows wildcards in the action name, not in the service
        // namespace: `s3*:GetObject` and `*:GetObject` are MalformedPolicyDocument.
        for action in [
            "s3*:GetObject",
            "*:GetObject",
            "s3?GetObject",
            "?3:GetObject",
        ] {
            let policy = IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single(action.to_string()))
                    .with_resource(IAMResource::Single("*".to_string())),
            );
            let error = policy
                .validate_result()
                .expect_err(&format!("'{action}' must not validate"));
            assert!(
                error.to_string().contains("Invalid action"),
                "unexpected error for '{action}': {error}"
            );
        }

        // `NotAction` goes through the same check.
        let mut statement = IAMStatement::new(IAMEffect::Deny);
        statement.not_action = Some(IAMAction::Multiple(vec!["*:GetObject".to_string()]));
        statement.resource = Some(IAMResource::Single("*".to_string()));
        assert!(
            IAMPolicy::new()
                .add_statement(statement)
                .validate_result()
                .is_err()
        );
    }

    #[test]
    fn test_wildcard_in_arn_partition_service_and_resource_type_is_invalid() {
        use crate::{IAMAction, IAMEffect, IAMPolicy, IAMResource, IAMStatement};

        for resource in [
            // partition
            "arn:*:s3:::bucket/*",
            "arn:aws-*:s3:::bucket/*",
            // service
            "arn:aws:*:::bucket/*",
            "arn:aws:s3*:::bucket/*",
            "arn:aws:s3?::bucket/*",
            // resource type, with a `type:name` resource
            "arn:aws:lambda:us-east-1:123456789012:functi*:my-function",
            "arn:aws:lambda:us-east-1:123456789012:function*:my-function",
            "arn:aws:ec2:us-east-1:123456789012:instanc?:i-1234567890abcdef0",
        ] {
            let policy = IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single(resource.to_string())),
            );
            let error = policy
                .validate_result()
                .expect_err(&format!("'{resource}' must not validate"));
            assert!(
                error.to_string().contains("Invalid resource"),
                "unexpected error for '{resource}': {error}"
            );
        }

        // `NotResource` goes through the same check.
        let mut statement = IAMStatement::new(IAMEffect::Deny);
        statement.action = Some(IAMAction::Single("s3:*".to_string()));
        statement.not_resource = Some(IAMResource::Single("arn:aws:*:::bucket/*".to_string()));
        assert!(
            IAMPolicy::new()
                .add_statement(statement)
                .validate_result()
                .is_err()
        );
    }

    #[test]
    fn test_wildcards_outside_action_namespace_and_arn_segments_still_validate() {
        use crate::{IAMAction, IAMEffect, IAMPolicy, IAMResource, IAMStatement};

        for action in ["*", "s3:*", "s3:GetObject", "s3:Get*", "iam:*AccessKey*"] {
            let policy = IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single(action.to_string()))
                    .with_resource(IAMResource::Single("*".to_string())),
            );
            assert!(policy.validate_result().is_ok(), "'{action}' must validate");
        }

        for resource in [
            "*",
            "arn:aws:s3:::bucket/*",
            "arn:aws:ec2:*:123456789012:vpc/*",
            "arn:aws:s3:::*",
            // An S3 resource is `bucket/key`: it has no resource type to reject.
            "arn:aws:s3:::bucket",
            "arn:aws:s3:::bucket/reports/2024/*",
            "arn:aws:iam::123456789012:role/*",
            "arn:aws:lambda:us-east-1:123456789012:function:my-function",
        ] {
            let policy = IAMPolicy::new().add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single(resource.to_string())),
            );
            assert!(
                policy.validate_result().is_ok(),
                "'{resource}' must validate"
            );
        }
    }

    #[test]
    fn test_policy_validation_integration() {
        use crate::{IAMAction, IAMEffect, IAMPolicy, IAMResource, IAMStatement};

        // Test valid policy with UUID-like ID
        let valid_policy = IAMPolicy::new()
            .with_id("550e8400-e29b-41d4-a716-446655440000") // UUID format
            .add_statement(
                IAMStatement::new(IAMEffect::Allow)
                    .with_sid("ValidStatement")
                    .with_action(IAMAction::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single("arn:aws:s3:::bucket/*".to_string())),
            );
        assert!(valid_policy.is_valid());

        // Test invalid policy - missing action
        let mut invalid_policy = IAMPolicy::new();
        invalid_policy
            .statement
            .push(IAMStatement::new(IAMEffect::Allow));
        assert!(!invalid_policy.is_valid());

        // Test policy with validation errors
        let complex_invalid_policy = IAMPolicy::new().add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("invalid-action".to_string()))
                .with_resource(IAMResource::Single("invalid-resource".to_string())),
        );

        assert!(!complex_invalid_policy.is_valid());

        let validation_result = complex_invalid_policy.validate_result();
        assert!(validation_result.is_err());

        let error = validation_result.unwrap_err();
        assert!(
            error.to_string().contains("Multiple validation errors")
                || error.to_string().contains("Invalid")
        );
    }

    #[test]
    fn test_condition_validation_integration() {
        use crate::{IAMAction, IAMEffect, IAMOperator, IAMResource, IAMStatement};

        // Valid condition
        let valid_statement = IAMStatement::new(IAMEffect::Allow)
            .with_action(IAMAction::Single("s3:GetObject".to_string()))
            .with_resource(IAMResource::Single("*".to_string()))
            .with_condition(
                IAMOperator::StringEquals,
                "aws:username".to_string(),
                ConditionValue::String("alice".to_string()),
            );

        assert!(valid_statement.is_valid());

        // Invalid condition - numeric operator with string value
        let invalid_condition_statement = IAMStatement::new(IAMEffect::Allow)
            .with_action(IAMAction::Single("s3:GetObject".to_string()))
            .with_resource(IAMResource::Single("*".to_string()))
            .with_condition(
                IAMOperator::NumericEquals,
                "aws:RequestedRegion".to_string(),
                ConditionValue::String("invalid-number".to_string()),
            );

        // Should fail validation due to type mismatch
        assert!(!invalid_condition_statement.is_valid());
        assert!(invalid_condition_statement.validate_result().is_err());
    }

    #[test]
    fn test_collect_errors() {
        let results = vec![
            Ok(()),
            Err(ValidationError::MissingField {
                field: "test".to_string(),
                context: "root".to_string(),
            }),
            Ok(()),
            Err(ValidationError::InvalidValue {
                field: "other".to_string(),
                value: "bad".to_string(),
                reason: "test".to_string(),
            }),
        ];

        let result = helpers::collect_errors(results);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::Multiple(errors) => assert_eq!(errors.len(), 2),
            _ => panic!("Expected Multiple error"),
        }
    }
}
