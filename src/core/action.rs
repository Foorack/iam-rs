use crate::validation::{Validate, ValidationContext, ValidationResult, helpers};
use serde::{Deserialize, Serialize};

/// Represents an action in an IAM policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Action {
    /// A single action (e.g., "s3:GetObject")
    Single(String),
    /// Multiple actions
    Multiple(Vec<String>),
}

impl Validate for Action {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Action", |ctx| match self {
            Action::Single(action) => helpers::validate_action(action, ctx),
            Action::Multiple(actions) => {
                if actions.is_empty() {
                    return Err(crate::validation::ValidationError::InvalidValue {
                        field: "Action".to_string(),
                        value: "[]".to_string(),
                        reason: "Action list cannot be empty".to_string(),
                    });
                }

                let results: Vec<ValidationResult> = actions
                    .iter()
                    .enumerate()
                    .map(|(i, action)| {
                        ctx.with_segment(&format!("[{i}]"), |nested_ctx| {
                            helpers::validate_action(action, nested_ctx)
                        })
                    })
                    .collect();

                helpers::collect_errors(results)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_validation() {
        let valid_single = Action::Single("s3:GetObject".to_string());
        assert!(valid_single.is_valid());

        let valid_wildcard = Action::Single("*".to_string());
        assert!(valid_wildcard.is_valid());

        let valid_multiple =
            Action::Multiple(vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()]);
        assert!(valid_multiple.is_valid());

        let invalid_single = Action::Single("invalid-action".to_string());
        assert!(!invalid_single.is_valid());

        let empty_multiple = Action::Multiple(vec![]);
        assert!(!empty_multiple.is_valid());

        let invalid_multiple = Action::Multiple(vec![
            "s3:GetObject".to_string(),
            "invalid-action".to_string(),
        ]);
        assert!(!invalid_multiple.is_valid());
    }
}
