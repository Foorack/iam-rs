use crate::validation::{Validate, ValidationContext, ValidationResult, helpers};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Principal type for IAM policies
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum PrincipalType {
    /// AWS principals (users, roles, root accounts)
    #[serde(rename = "AWS")]
    Aws,
    /// Federated principals (SAML, OIDC providers)
    #[serde(rename = "Federated")]
    Federated,
    /// AWS service principals
    #[serde(rename = "Service")]
    Service,
    /// S3 canonical user principals
    #[serde(rename = "CanonicalUser")]
    CanonicalUser,
}

impl std::fmt::Display for PrincipalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrincipalType::Aws => write!(f, "AWS"),
            PrincipalType::Federated => write!(f, "Federated"),
            PrincipalType::Service => write!(f, "Service"),
            PrincipalType::CanonicalUser => write!(f, "CanonicalUser"),
        }
    }
}

/// Represents a principal in an IAM policy
///
/// `<principal_block>` = ("Principal" | "`NotPrincipal`") : ("*" | `<principal_map>`)
/// `<principal_map>` = { `<principal_map_entry>`, `<principal_map_entry>`, ... }
/// `<principal_map_entry>` = ("AWS" | "Federated" | "Service" | "`CanonicalUser`") :
///     [`<principal_id_string>`, `<principal_id_string>`, ...]
///
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Principal {
    /// Wildcard principal (*)
    Wildcard,
    /// Principal with service mapping (e.g., {"AWS": "`arn:aws:iam::123456789012:user/username`"})
    Mapped(HashMap<PrincipalType, serde_json::Value>),
}

impl Validate for Principal {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Principal", |ctx| {
            match self {
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
                        // Principal type key is guaranteed to be valid since it's an enum
                        ctx.with_segment(&key.to_string(), |nested_ctx| {
                            // Validate the principal values
                            match value {
                                serde_json::Value::String(s) => {
                                    results.push(helpers::validate_principal(s, nested_ctx));
                                }
                                serde_json::Value::Array(arr) => {
                                    for (i, item) in arr.iter().enumerate() {
                                        if let serde_json::Value::String(s) = item {
                                            nested_ctx.with_segment(
                                                &format!("[{i}]"),
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
        let mut valid_mapped = HashMap::new();
        valid_mapped.insert(
            PrincipalType::Aws,
            json!("arn:aws:iam::123456789012:user/alice"),
        );
        let valid_mapped = Principal::Mapped(valid_mapped);
        assert!(valid_mapped.is_valid());

        let valid_wildcard = Principal::Wildcard;
        assert!(valid_wildcard.is_valid());

        let mut another_valid_mapped = HashMap::new();
        another_valid_mapped.insert(
            PrincipalType::Aws,
            json!("arn:aws:iam::123456789012:user/alice"),
        );
        let another_valid_mapped = Principal::Mapped(another_valid_mapped);
        assert!(another_valid_mapped.is_valid());

        let mut invalid_mapped = HashMap::new();
        invalid_mapped.insert(PrincipalType::Aws, json!("invalid-principal"));
        let invalid_mapped = Principal::Mapped(invalid_mapped);
        assert!(!invalid_mapped.is_valid());

        let empty_mapped = Principal::Mapped(HashMap::new());
        assert!(!empty_mapped.is_valid());
    }

    #[test]
    fn test_principal_mapped_validation() {
        // Valid service principal
        let mut service_map = HashMap::new();
        service_map.insert(PrincipalType::Service, json!("lambda.amazonaws.com"));
        let service_principal = Principal::Mapped(service_map);
        assert!(service_principal.is_valid());

        // Test that we can no longer create invalid principal types
        // (This is now impossible at compile time with the enum)

        // Array of principals
        let mut array_map = HashMap::new();
        array_map.insert(
            PrincipalType::Aws,
            json!([
                "arn:aws:iam::123456789012:user/alice",
                "arn:aws:iam::123456789012:user/bob"
            ]),
        );
        let array_principal = Principal::Mapped(array_map);
        assert!(array_principal.is_valid());
    }
}
