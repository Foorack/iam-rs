use serde::{Deserialize, Serialize};

/// Represents a resource in an IAM policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Resource {
    /// A single resource (e.g., "arn:aws:s3:::bucket/*")
    Single(String),
    /// Multiple resources
    Multiple(Vec<String>),
}
