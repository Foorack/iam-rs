use crate::{
    Arn, ValidationError,
    validation::{Validate, ValidationContext, ValidationResult},
};
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

impl Principal {
    #[must_use]
    pub fn is_single(&self) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Principal::Aws(PrincipalId::String(_))
            | Principal::Federated(PrincipalId::String(_))
            | Principal::Service(PrincipalId::String(_))
            | Principal::CanonicalUser(PrincipalId::String(_)) => true,
            _ => false,
        }
    }
}

fn validate_domain(domain: &str) -> ValidationResult {
    // Domain, for now simple check if it contains dots, not uppercase, at ends with letter, and not empty
    if !domain.contains('.')
        || domain.to_lowercase() != domain
        || !domain.ends_with(|c: char| c.is_alphabetic())
        || domain.is_empty()
    {
        return Err(ValidationError::InvalidPrincipal {
            principal: domain.to_string(),
            reason: "Principal must be a valid domain".to_string(),
        });
    }
    Ok(())
}

impl Validate for Principal {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Principal", |ctx| match self {
            Principal::Wildcard => Ok(()),

            //
            // "Array" cases (compact)
            //
            Principal::Aws(PrincipalId::Array(ids))
            | Principal::Federated(PrincipalId::Array(ids))
            | Principal::Service(PrincipalId::Array(ids))
            | Principal::CanonicalUser(PrincipalId::Array(ids)) => {
                if ids.is_empty() {
                    return Err(ValidationError::InvalidPrincipal {
                        principal: "Empty principal array".to_string(),
                        reason: "Principal array cannot be empty".to_string(),
                    });
                }
                for id in ids {
                    let single = match self {
                        Principal::Aws(_) => Principal::Aws(PrincipalId::String(id.clone())),
                        Principal::Federated(_) => {
                            Principal::Federated(PrincipalId::String(id.clone()))
                        }
                        Principal::Service(_) => {
                            Principal::Service(PrincipalId::String(id.clone()))
                        }
                        Principal::CanonicalUser(_) => {
                            Principal::CanonicalUser(PrincipalId::String(id.clone()))
                        }
                        Principal::Wildcard => unreachable!(),
                    };
                    single.validate(ctx)?;
                }
                Ok(())
            }

            //
            // "Single" cases
            //

            // AWS means it is either account number or ARN
            Principal::Aws(PrincipalId::String(id)) => {
                if id.len() == 12 && id.chars().all(|c| c.is_ascii_digit()) {
                    // Account ID
                    return Ok(());
                }
                let arn = Arn::parse(id).map_err(|e| ValidationError::InvalidPrincipal {
                    principal: id.to_string(),
                    reason: e.to_string(),
                })?;
                arn.validate(ctx)
            }
            Principal::Federated(PrincipalId::String(id)) => {
                // If starts with "arn:", validate as ARN
                if id.starts_with("arn:") {
                    let arn = Arn::parse(id).map_err(|e| ValidationError::InvalidPrincipal {
                        principal: id.to_string(),
                        reason: e.to_string(),
                    })?;
                    arn.validate(ctx)?;
                } else {
                    validate_domain(id)?;
                }
                Ok(())
            }
            Principal::Service(PrincipalId::String(id)) => Ok(validate_domain(id)?),
            Principal::CanonicalUser(PrincipalId::String(id)) => {
                // Canonical user IDs are usually 64-character hexadecimal strings
                if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok(());
                }
                Err(ValidationError::InvalidPrincipal {
                    principal: id.to_string(),
                    reason: "Canonical user ID must be a 64-character hex string".to_string(),
                })
            }
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
        assert!(!Principal::Aws(PrincipalId::String("invalid-principal".into())).is_valid());

        // Empty principal should be invalid
        assert!(!Principal::Aws(PrincipalId::String("".into())).is_valid());

        // Empty array principal should be invalid
        assert!(!Principal::Aws(PrincipalId::Array(vec![])).is_valid());

        // Two valid principals in an array
        let valid_array_principal = Principal::Aws(PrincipalId::Array(vec![
            "arn:aws:iam::123456789012:user/alice".into(),
            "arn:aws:iam::123456789012:user/bob".into(),
        ]));
        assert!(valid_array_principal.is_valid());

        // Account ID as a valid principal
        assert!(Principal::Aws(PrincipalId::String("123456789012".into())).is_valid());

        // Valid service principal
        assert!(Principal::Service(PrincipalId::String("ec2.amazonaws.com".into())).is_valid());
        // Invalid service principal
        assert!(!Principal::Service(PrincipalId::String("invalid-service".into())).is_valid());

        // Valid federated principal
        assert!(
            Principal::Federated(PrincipalId::String(
                "arn:aws:iam::123456789012:saml-provider/MyProvider".into()
            ))
            .is_valid()
        );
        // Invalid federated principal
        assert!(!Principal::Federated(PrincipalId::String("invalid-federated".into())).is_valid());
        // Simple domain as federated principal
        assert!(Principal::Federated(PrincipalId::String("example.com".into())).is_valid());

        // Valid canonical user principal
        assert!(
            Principal::CanonicalUser(PrincipalId::String(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into()
            ))
            .is_valid()
        );
        // Invalid canonical user principal (wrong length)
        assert!(
            !Principal::CanonicalUser(PrincipalId::String("invalid-canonical".into())).is_valid()
        );
    }
}
