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

    /// Validate action format (service:action)
    pub fn validate_action(action: &str, _context: &ValidationContext) -> ValidationResult {
        if action == "*" {
            return Ok(());
        }

        if action.contains(':') {
            let parts: Vec<&str> = action.split(':').collect();
            if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                // Basic service:action format
                Ok(())
            } else {
                Err(ValidationError::InvalidAction {
                    action: action.to_string(),
                    reason: "Action must be in format 'service:action'".to_string(),
                })
            }
        } else {
            Err(ValidationError::InvalidAction {
                action: action.to_string(),
                reason: "Action must contain a colon separator or be '*'".to_string(),
            })
        }
    }

    /// Validate resource ARN or wildcard
    pub fn validate_resource(resource: &str, _context: &ValidationContext) -> ValidationResult {
        if resource == "*" {
            return Ok(());
        }

        // Resources should be ARNs, but may contain wildcards
        if resource.starts_with("arn:") {
            // Use lenient parsing for resources with wildcards
            match Arn::parse(resource) {
                Ok(_) => Ok(()),
                Err(e) => Err(ValidationError::InvalidResource {
                    resource: resource.to_string(),
                    reason: e.to_string(),
                }),
            }
        } else {
            Err(ValidationError::InvalidResource {
                resource: resource.to_string(),
                reason: "Resource must be an ARN or '*'".to_string(),
            })
        }
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
    fn test_policy_validation_integration() {
        use crate::{Action, Effect, IAMPolicy, IAMStatement, IAMResource};

        // Test valid policy with UUID-like ID
        let valid_policy = IAMPolicy::new()
            .with_id("550e8400-e29b-41d4-a716-446655440000") // UUID format
            .add_statement(
                IAMStatement::new(Effect::Allow)
                    .with_sid("ValidStatement")
                    .with_action(Action::Single("s3:GetObject".to_string()))
                    .with_resource(IAMResource::Single("arn:aws:s3:::bucket/*".to_string())),
            );
        assert!(valid_policy.is_valid());

        // Test invalid policy - missing action
        let mut invalid_policy = IAMPolicy::new();
        invalid_policy
            .statement
            .push(IAMStatement::new(Effect::Allow));
        assert!(!invalid_policy.is_valid());

        // Test policy with validation errors
        let complex_invalid_policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("invalid-action".to_string()))
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
        use crate::{Action, Effect, IAMStatement, IAMOperator, IAMResource};

        // Valid condition
        let valid_statement = IAMStatement::new(Effect::Allow)
            .with_action(Action::Single("s3:GetObject".to_string()))
            .with_resource(IAMResource::Single("*".to_string()))
            .with_condition(
                IAMOperator::StringEquals,
                "aws:username".to_string(),
                ConditionValue::String("alice".to_string()),
            );

        assert!(valid_statement.is_valid());

        // Invalid condition - numeric operator with string value
        let invalid_condition_statement = IAMStatement::new(Effect::Allow)
            .with_action(Action::Single("s3:GetObject".to_string()))
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
