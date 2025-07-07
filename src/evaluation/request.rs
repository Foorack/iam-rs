use super::context::{Context, ContextValue};
use serde::{Deserialize, Serialize};

/// Core IAM request containing principal, action, and resource
///
/// ## Understanding the PARC model
///
/// The PARC model represents the request context based on the four JSON elements in the policy language:
///
/// * Principal – The entity making the request.
///         A principal represents a human user or programmatic workload that can be authenticated and
///         then authorized to perform actions in AWS accounts.
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
pub struct IAMRequest {
    /// The principal making the request (e.g., AROA123456789EXAMPLE)
    #[serde(rename = "Principal")]
    pub principal: String,

    /// The action being requested (e.g., iam:DeactivateMFADevice)
    #[serde(rename = "Action")]
    pub action: String,

    /// The resource being accessed (e.g., arn:aws:iam::user/martha)
    #[serde(rename = "Resource")]
    pub resource: String,

    /// Additional context for condition evaluation
    #[serde(rename = "Context", default)]
    pub context: Context,
}

impl IAMRequest {
    /// Creates a new request
    #[must_use]
    pub fn new<S: Into<String>>(principal: S, action: S, resource: S) -> Self {
        Self {
            principal: principal.into(),
            action: action.into(),
            resource: resource.into(),
            context: Context::new(),
        }
    }

    /// Creates a request with context
    #[must_use]
    pub fn new_with_context<S: Into<String>>(
        principal: S,
        action: S,
        resource: S,
        context: Context,
    ) -> Self {
        Self {
            principal: principal.into(),
            action: action.into(),
            resource: resource.into(),
            context,
        }
    }

    /// Adds all context key-value pairs from another context
    pub fn with_context(mut self, other_context: Context) -> Self {
        self.context.extend(other_context);
        self
    }

    /// Adds string context to the request
    pub fn with_string_context<K: Into<String>, V: Into<String>>(
        mut self,
        key: K,
        value: V,
    ) -> Self {
        self.context = self.context.with_string(key, value);
        self
    }

    /// Adds boolean context to the request
    pub fn with_boolean_context<K: Into<String>>(mut self, key: K, value: bool) -> Self {
        self.context = self.context.with_boolean(key, value);
        self
    }

    /// Adds numeric context to the request
    pub fn with_number_context<K: Into<String>>(mut self, key: K, value: f64) -> Self {
        self.context = self.context.with_number(key, value);
        self
    }

    /// Gets a context value by key
    #[must_use]
    pub fn get_context(&self, key: &str) -> Option<&ContextValue> {
        self.context.get(key)
    }

    /// Checks if a context key exists
    pub fn has_context(&self, key: &str) -> bool {
        self.context.has_key(key)
    }

    /// Gets all context keys
    pub fn context_keys(&self) -> Vec<&String> {
        self.context.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parc_request_creation() {
        let request = IAMRequest::new(
            "AROA123456789EXAMPLE",
            "iam:DeactivateMFADevice",
            "arn:aws:iam::user/martha",
        );

        assert_eq!(request.principal, "AROA123456789EXAMPLE");
        assert_eq!(request.action, "iam:DeactivateMFADevice");
        assert_eq!(request.resource, "arn:aws:iam::user/martha");
    }

    #[test]
    fn test_parc_request_with_context() {
        let request = IAMRequest::new("principal", "action", "resource")
            .with_string_context("string_key", "string_value")
            .with_boolean_context("bool_key", true)
            .with_number_context("number_key", 42.0);

        assert_eq!(
            request
                .get_context("string_key")
                .unwrap()
                .as_string()
                .unwrap(),
            "string_value"
        );
        assert_eq!(
            request
                .get_context("bool_key")
                .unwrap()
                .as_boolean()
                .unwrap(),
            true
        );
        assert_eq!(
            request
                .get_context("number_key")
                .unwrap()
                .as_number()
                .unwrap(),
            42.0
        );
    }

    #[test]
    fn test_parc_request_context_utilities() {
        let request = IAMRequest::new("principal", "action", "resource")
            .with_string_context("key1", "value1")
            .with_boolean_context("key2", false);

        assert!(request.has_context("key1"));
        assert!(request.has_context("key2"));
        assert!(!request.has_context("key3"));

        let keys = request.context_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&&"key1".to_string()));
        assert!(keys.contains(&&"key2".to_string()));
    }
}
