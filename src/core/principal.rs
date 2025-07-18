use crate::validation::{Validate, ValidationContext, ValidationResult, helpers};
use serde::{Deserialize, Serialize};

/// Principal ID (can be either string or array of strings)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum PrincipalId {
    /// Single principal ID as a string
    String(String),
    /// Multiple principal IDs as an array of strings
    Array(Vec<String>),
}

impl Validate for PrincipalId {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("PrincipalId", |ctx| match self {
            PrincipalId::String(id) => helpers::validate_principal(id, ctx),
            PrincipalId::Array(ids) => {
                if ids.is_empty() {
                    return Err(crate::validation::ValidationError::InvalidValue {
                        field: "PrincipalId".to_string(),
                        value: "[]".to_string(),
                        reason: "PrincipalId array cannot be empty".to_string(),
                    });
                }

                let results: Vec<ValidationResult> = ids
                    .iter()
                    .enumerate()
                    .map(|(i, id)| {
                        ctx.with_segment(&format!("[{i}]"), |nested_ctx| {
                            helpers::validate_principal(id, nested_ctx)
                        })
                    })
                    .collect();

                helpers::collect_errors(results)
            }
        })
    }
}

/// Represents a principal in an IAM policy
///
/// `<principal_block>` = ("Principal" | "`NotPrincipal`") : ("*" | `<principal_map>`)
/// `<principal_map>` = { `<principal_map_entry>`, `<principal_map_entry>`, ... }
/// `<principal_map_entry>` = ("AWS" | "Federated" | "Service" | "`CanonicalUser`") :
///     [`<principal_id_string>`, `<principal_id_string>`, ...]
///
/// (e.g., {"AWS": "`arn:aws:iam::123456789012:user/username`"})
///
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Principal {
    /// AWS principals (users, roles, root accounts)
    #[serde(rename = "AWS")]
    Aws(PrincipalId),
    /// Federated principals (SAML, OIDC providers)
    #[serde(rename = "Federated")]
    Federated(PrincipalId),
    /// AWS service principals
    #[serde(rename = "Service")]
    Service(PrincipalId),
    /// Canonical user principals
    #[serde(rename = "CanonicalUser")]
    CanonicalUser(PrincipalId),
    /// Wildcard principal (matches all principals)
    #[serde(rename = "*")]
    Wildcard,
}

impl Validate for Principal {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Principal", |ctx| match self {
            Principal::Aws(id)
            | Principal::Federated(id)
            | Principal::Service(id)
            | Principal::CanonicalUser(id) => id.validate(ctx),
            Principal::Wildcard => Ok(()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_validation() {
        // Valid AWS principal
        assert!(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/alice".into()
            ))
            .is_valid()
        );

        // Invalid principal should be invalid
        assert!(!Principal::Federated(PrincipalId::String("invalid-principal".into())).is_valid());

        // Empty principal should be invalid
        assert!(!Principal::Federated(PrincipalId::String("".into())).is_valid());

        // Empty array principal should be invalid
        assert!(!Principal::Aws(PrincipalId::Array(vec![])).is_valid());

        // Two valid principals in an array
        let valid_array_principal = Principal::Aws(PrincipalId::Array(vec![
            "arn:aws:iam::123456789012:user/alice".into(),
            "arn:aws:iam::123456789012:user/bob".into(),
        ]));
        assert!(valid_array_principal.is_valid());
    }
}
