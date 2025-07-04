use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a principal in an IAM policy
///
/// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Principal {
    /// A single principal (e.g., "AWS:arn:aws:iam::123456789012:user/username")
    Single(String),
    /// Multiple principals
    Multiple(Vec<String>),
    /// Wildcard principal (*)
    Wildcard,
    /// Principal with service mapping (e.g., {"AWS": "arn:aws:iam::123456789012:user/username"})
    Mapped(HashMap<String, serde_json::Value>),
}
