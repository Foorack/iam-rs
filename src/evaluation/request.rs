use super::context::Context;
use crate::{Arn, Principal};
use serde::{Deserialize, Serialize};

/// Core IAM request containing principal, action, and resource
///
/// ## Understanding the PARC model
///
/// The PARC model represents the request context based on the four JSON elements in the policy language:
///
/// * Principal – The entity making the request.
///   A principal represents a human user or programmatic workload that can be authenticated and
///   then authorized to perform actions in AWS accounts.
/// * Action – The operation being performed. Often the action will map to an API action.
/// * Resource – The AWS resource on which the action is being performed.
/// * Condition – Additional constraints that must be met for the request to be allowed.
///
/// The following shows an example of how the PARC model might represent a request context:
///
/// ```text
/// Principal: AIDA123456789EXAMPLE
/// Action: s3:CreateBucket
/// Resource: arn:aws:s3:::amzn-s3-demo-bucket1
/// Context:
/// - aws:UserId=AIDA123456789EXAMPLE:BobsSession
/// - aws:PrincipalAccount=123456789012
/// - aws:PrincipalOrgId=o-example
/// - aws:PrincipalARN=arn:aws:iam::AIDA123456789EXAMPLE:role/HR
/// - aws:MultiFactorAuthPresent=true
/// - aws:CurrentTime=...
/// - aws:EpochTime=...
/// - aws:SourceIp=...
/// - aws:PrincipalTag/dept=123
/// - aws:PrincipalTag/project=blue
/// - aws:RequestTag/dept=123
/// ```
///
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-reqcontext.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct IAMRequest {
    /// The principal making the request (e.g., AROA123456789EXAMPLE)
    #[serde(rename = "Principal")]
    pub principal: Principal,

    /// The action being requested (e.g., iam:DeactivateMFADevice)
    #[serde(rename = "Action")]
    pub action: String,

    /// The resource being accessed (e.g., `arn:aws:iam::user/martha`)
    #[serde(rename = "Resource")]
    pub resource: Arn,

    /// Additional context for condition evaluation
    #[serde(rename = "Context", default)]
    pub context: Context,
}

impl IAMRequest {
    /// Creates a new request
    #[must_use]
    pub fn new<S: Into<String>>(principal: Principal, action: S, resource: Arn) -> Self {
        let action = action.into();
        Self {
            principal,
            action,
            resource,
            context: Context::new(),
        }
    }

    /// Creates a request with context
    #[must_use]
    pub fn new_with_context<S: Into<String>>(
        principal: Principal,
        action: S,
        resource: Arn,
        context: Context,
    ) -> Self {
        let action = action.into();
        Self {
            principal,
            action,
            resource,
            context,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::PrincipalId;

    use super::*;

    #[test]
    fn test_parc_request_creation() {
        let request = IAMRequest::new(
            Principal::Aws(PrincipalId::String("AROA123456789EXAMPLE".into())),
            "iam:DeactivateMFADevice",
            Arn::parse("arn:aws:iam:::user/martha").unwrap(),
        );

        assert_eq!(
            request.principal,
            Principal::Aws(PrincipalId::String("AROA123456789EXAMPLE".into()))
        );
        assert_eq!(request.action, "iam:DeactivateMFADevice");
        assert_eq!(
            request.resource,
            Arn::parse("arn:aws:iam:::user/martha").unwrap()
        );
    }

    #[test]
    fn test_parc_request_with_context() {
        let context = Context::new()
            .with_string("aws:UserId", "AIDA123456789EXAMPLE:BobsSession")
            .with_boolean("aws:MultiFactorAuthPresent", true)
            .with_number("aws:EpochTime", 1633072800.0);
        let request = IAMRequest::new_with_context(
            Principal::Aws(PrincipalId::String("principal".into())),
            "action",
            Arn::parse("arn:aws:iam:::user/martha").unwrap(),
            context,
        );

        assert_eq!(
            request
                .context
                .get("aws:UserId")
                .unwrap()
                .as_string()
                .unwrap(),
            "AIDA123456789EXAMPLE:BobsSession"
        );
        assert_eq!(
            request
                .context
                .get("aws:MultiFactorAuthPresent")
                .unwrap()
                .as_boolean()
                .unwrap(),
            true
        );
        assert_eq!(
            request
                .context
                .get("aws:EpochTime")
                .unwrap()
                .as_number()
                .unwrap(),
            1633072800.0
        );
    }
}
