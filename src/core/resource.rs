use crate::validation::{Validate, ValidationContext, ValidationResult, helpers};
use serde::{Deserialize, Serialize};

/// Represents a resource in an IAM policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum IAMResource {
    /// A single resource (e.g., "`arn:aws:s3:::bucket/*`")
    Single(String),
    /// Multiple resources
    Multiple(Vec<String>),
}

impl Validate for IAMResource {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Resource", |ctx| match self {
            IAMResource::Single(resource) => helpers::validate_resource(resource, ctx),
            IAMResource::Multiple(resources) => {
                if resources.is_empty() {
                    return Err(crate::validation::ValidationError::InvalidValue {
                        field: "Resource".to_string(),
                        value: "[]".to_string(),
                        reason: "Resource list cannot be empty".to_string(),
                    });
                }

                let results: Vec<ValidationResult> = resources
                    .iter()
                    .enumerate()
                    .map(|(i, resource)| {
                        ctx.with_segment(&format!("[{i}]"), |nested_ctx| {
                            helpers::validate_resource(resource, nested_ctx)
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
    fn test_resource_validation() {
        let valid_single = IAMResource::Single("arn:aws:s3:::bucket/*".to_string());
        assert!(valid_single.is_valid());

        let valid_wildcard = IAMResource::Single("*".to_string());
        assert!(valid_wildcard.is_valid());

        let valid_multiple = IAMResource::Multiple(vec![
            "arn:aws:s3:::bucket/*".to_string(),
            "arn:aws:s3:::other-bucket/*".to_string(),
        ]);
        assert!(valid_multiple.is_valid());

        let invalid_single = IAMResource::Single("invalid-resource".to_string());
        assert!(!invalid_single.is_valid());

        let empty_multiple = IAMResource::Multiple(vec![]);
        assert!(!empty_multiple.is_valid());

        let invalid_multiple = IAMResource::Multiple(vec![
            "arn:aws:s3:::bucket/*".to_string(),
            "invalid-resource".to_string(),
        ]);
        assert!(!invalid_multiple.is_valid());
    }

    #[test]
    fn test_resource_with_wildcards() {
        let wildcard_resource = IAMResource::Single("arn:aws:s3:::*/*".to_string());
        assert!(wildcard_resource.is_valid());

        let complex_wildcard =
            IAMResource::Single("arn:aws:s3:::bucket/folder/*/file.txt".to_string());
        assert!(complex_wildcard.is_valid());
    }
}
