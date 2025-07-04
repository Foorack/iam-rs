use serde::{Deserialize, Serialize};

/// Represents a condition in an IAM policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// The condition operator (e.g., "StringEquals", "DateGreaterThan")
    pub operator: String,
    /// The condition key (e.g., "aws:username", "s3:prefix")
    pub key: String,
    /// The condition value(s)
    pub value: serde_json::Value,
}
