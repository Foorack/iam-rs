use crate::validation::{Validate, ValidationContext, ValidationResult, helpers};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a principal in an IAM policy
///
/// <principal_block> = ("Principal" | "NotPrincipal") : ("*" | <principal_map>)
/// <principal_map> = { <principal_map_entry>, <principal_map_entry>, ... }
/// <principal_map_entry> = ("AWS" | "Federated" | "Service" | "CanonicalUser") :
///     [<principal_id_string>, <principal_id_string>, ...]
///
/// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Principal {
    /// A single principal (e.g., "AWS:arn:aws:iam::123456789012:user/username")
    Single(String),
    /// Wildcard principal (*)
    Wildcard,
    /// Principal with service mapping (e.g., {"AWS": "arn:aws:iam::123456789012:user/username"})
    Mapped(HashMap<String, serde_json::Value>),
}

impl Validate for Principal {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Principal", |ctx| {
            match self {
                Principal::Single(principal) => helpers::validate_principal(principal, ctx),
                Principal::Wildcard => {
                    // Wildcard is always valid
                    Ok(())
                }
                Principal::Mapped(map) => {
                    if map.is_empty() {
                        return Err(crate::validation::ValidationError::InvalidValue {
                            field: "Principal".to_string(),
                            value: "{}".to_string(),
                            reason: "Principal mapping cannot be empty".to_string(),
                        });
                    }

                    let mut results = Vec::new();

                    for (key, value) in map {
                        ctx.with_segment(key, |nested_ctx| {
                            // Validate the principal type key
                            if !matches!(
                                key.as_str(),
                                "AWS" | "Federated" | "Service" | "CanonicalUser"
                            ) {
                                results.push(Err(
                                    crate::validation::ValidationError::InvalidValue {
                                        field: "Principal type".to_string(),
                                        value: key.clone(),
                                        reason:
                                            "Must be one of: AWS, Federated, Service, CanonicalUser"
                                                .to_string(),
                                    },
                                ));
                                return;
                            }

                            // Validate the principal values
                            match value {
                                serde_json::Value::String(s) => {
                                    results.push(helpers::validate_principal(s, nested_ctx));
                                }
                                serde_json::Value::Array(arr) => {
                                    for (i, item) in arr.iter().enumerate() {
                                        if let serde_json::Value::String(s) = item {
                                            nested_ctx.with_segment(
                                                &format!("[{}]", i),
                                                |item_ctx| {
                                                    results.push(helpers::validate_principal(
                                                        s, item_ctx,
                                                    ));
                                                },
                                            );
                                        } else {
                                            results.push(Err(
                                                crate::validation::ValidationError::InvalidValue {
                                                    field: "Principal value".to_string(),
                                                    value: item.to_string(),
                                                    reason: "Principal values must be strings"
                                                        .to_string(),
                                                },
                                            ));
                                        }
                                    }
                                }
                                _ => {
                                    results.push(Err(
                                        crate::validation::ValidationError::InvalidValue {
                                            field: "Principal value".to_string(),
                                            value: value.to_string(),
                                            reason:
                                                "Principal value must be string or array of strings"
                                                    .to_string(),
                                        },
                                    ));
                                }
                            }
                        });
                    }

                    helpers::collect_errors(results)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_principal_validation() {
        let valid_single = Principal::Single("arn:aws:iam::123456789012:user/alice".to_string());
        assert!(valid_single.is_valid());

        let valid_wildcard = Principal::Wildcard;
        assert!(valid_wildcard.is_valid());

        let mut valid_mapped = HashMap::new();
        valid_mapped.insert(
            "AWS".to_string(),
            json!("arn:aws:iam::123456789012:user/alice"),
        );
        let valid_mapped = Principal::Mapped(valid_mapped);
        assert!(valid_mapped.is_valid());

        let invalid_single = Principal::Single("invalid-principal".to_string());
        assert!(!invalid_single.is_valid());

        let empty_mapped = Principal::Mapped(HashMap::new());
        assert!(!empty_mapped.is_valid());
    }

    #[test]
    fn test_principal_mapped_validation() {
        // Valid service principal
        let mut service_map = HashMap::new();
        service_map.insert("Service".to_string(), json!("lambda.amazonaws.com"));
        let service_principal = Principal::Mapped(service_map);
        assert!(service_principal.is_valid());

        // Invalid principal type
        let mut invalid_map = HashMap::new();
        invalid_map.insert("InvalidType".to_string(), json!("test"));
        let invalid_principal = Principal::Mapped(invalid_map);
        assert!(!invalid_principal.is_valid());

        // Array of principals
        let mut array_map = HashMap::new();
        array_map.insert(
            "AWS".to_string(),
            json!([
                "arn:aws:iam::123456789012:user/alice",
                "arn:aws:iam::123456789012:user/bob"
            ]),
        );
        let array_principal = Principal::Mapped(array_map);
        assert!(array_principal.is_valid());
    }
}
