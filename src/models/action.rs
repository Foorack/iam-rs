use serde::{Deserialize, Serialize};

/// Represents an action in an IAM policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Action {
    /// A single action (e.g., "s3:GetObject")
    Single(String),
    /// Multiple actions
    Multiple(Vec<String>),
}
