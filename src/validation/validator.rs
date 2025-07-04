use std::fmt;

/// Validation error types for IAM policies
#[derive(Debug, Clone, PartialEq, Eq)]
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
                write!(f, "Missing required field '{}' in {}", field, context)
            }
            ValidationError::InvalidValue {
                field,
                value,
                reason,
            } => {
                write!(
                    f,
                    "Invalid value '{}' for field '{}': {}",
                    value, field, reason
                )
            }
            ValidationError::LogicalError { message } => {
                write!(f, "Logical error: {}", message)
            }
            ValidationError::InvalidArn { arn, reason } => {
                write!(f, "Invalid ARN '{}': {}", arn, reason)
            }
            ValidationError::InvalidCondition {
                operator,
                key,
                reason,
            } => {
                write!(
                    f,
                    "Invalid condition '{}' for key '{}': {}",
                    operator, key, reason
                )
            }
            ValidationError::InvalidPrincipal { principal, reason } => {
                write!(f, "Invalid principal '{}': {}", principal, reason)
            }
            ValidationError::InvalidAction { action, reason } => {
                write!(f, "Invalid action '{}': {}", action, reason)
            }
            ValidationError::InvalidResource { resource, reason } => {
                write!(f, "Invalid resource '{}': {}", resource, reason)
            }
            ValidationError::Multiple(errors) => {
                write!(f, "Multiple validation errors:\n")?;
                for (i, error) in errors.iter().enumerate() {
                    write!(f, "  {}: {}\n", i + 1, error)?;
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

impl ValidationContext {
    pub fn new() -> Self {
        Self { path: Vec::new() }
    }

    pub fn push(&mut self, segment: &str) {
        self.path.push(segment.to_string());
    }

    pub fn pop(&mut self) {
        self.path.pop();
    }

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
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult;

    /// Convenience method for basic validation
    fn is_valid(&self) -> bool {
        let mut context = ValidationContext::new();
        self.validate(&mut context).is_ok()
    }

    /// Validate with detailed errors (same as regular validation)
    fn validate_strict(&self) -> ValidationResult {
        let mut context = ValidationContext::new();
        self.validate(&mut context)
    }
}

/// Helper functions for common validation patterns
pub mod helpers {
    use super::*;
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

    /// Validate ARN format
    pub fn validate_arn(arn: &str, _context: &ValidationContext) -> ValidationResult {
        match Arn::parse(arn) {
            Ok(parsed_arn) => {
                if !parsed_arn.is_valid() {
                    Err(ValidationError::InvalidArn {
                        arn: arn.to_string(),
                        reason: "ARN format is valid but does not conform to AWS standards"
                            .to_string(),
                    })
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(ValidationError::InvalidArn {
                arn: arn.to_string(),
                reason: e.to_string(),
            }),
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

    /// Validate principal ARN or special values
    pub fn validate_principal(principal: &str, _context: &ValidationContext) -> ValidationResult {
        if principal == "*" || principal == "AWS" || principal == "Federated" {
            return Ok(());
        }

        // Check if it's an ARN
        if principal.starts_with("arn:") {
            return validate_arn(principal, _context);
        }

        // Check if it's an account ID
        if principal.len() == 12 && principal.chars().all(|c| c.is_ascii_digit()) {
            return Ok(());
        }

        // Check if it's a service principal (ends with .amazonaws.com or similar patterns)
        if principal.contains('.')
            && (principal.ends_with(".amazonaws.com")
                || principal.ends_with(".amazonaws.com.cn")
                || principal.ends_with(".aws.internal"))
        {
            return Ok(());
        }

        // Check if it's a federated identity provider URL
        if principal.starts_with("https://") || principal.starts_with("http://") {
            return Ok(());
        }

        // Check if it's a SAML provider ARN format
        if principal.starts_with("arn:aws:iam::") && principal.contains(":saml-provider/") {
            return Ok(());
        }

        // Reject anything else as invalid
        Err(ValidationError::InvalidPrincipal {
            principal: principal.to_string(),
            reason:
                "Principal must be an ARN, account ID, service principal, URL, or special value"
                    .to_string(),
        })
    }

    /// Validate resource ARN or wildcard
    pub fn validate_resource(resource: &str, _context: &ValidationContext) -> ValidationResult {
        if resource == "*" {
            return Ok(());
        }

        // Resources should be ARNs, but may contain wildcards
        if resource.starts_with("arn:") {
            // Use lenient parsing for resources with wildcards
            match Arn::parse_with_options(resource, true) {
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
        let errors: Vec<ValidationError> = results.into_iter().filter_map(|r| r.err()).collect();

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

        // Test ARN validation
        assert!(helpers::validate_arn("arn:aws:s3:::bucket/object", &context).is_ok());
        assert!(helpers::validate_arn("invalid-arn", &context).is_err());

        // Test action validation
        assert!(helpers::validate_action("s3:GetObject", &context).is_ok());
        assert!(helpers::validate_action("*", &context).is_ok());
        assert!(helpers::validate_action("invalid-action", &context).is_err());

        // Test principal validation
        assert!(helpers::validate_principal("*", &context).is_ok());
        assert!(helpers::validate_principal("123456789012", &context).is_ok());
        assert!(
            helpers::validate_principal("arn:aws:iam::123456789012:user/test", &context).is_ok()
        );
        assert!(helpers::validate_principal("invalid", &context).is_err());

        // Test resource validation
        assert!(helpers::validate_resource("*", &context).is_ok());
        assert!(helpers::validate_resource("arn:aws:s3:::bucket/*", &context).is_ok());
        assert!(helpers::validate_resource("invalid-resource", &context).is_err());
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
