use serde::{Deserialize, Serialize};

/// Represents the version of the IAM policy language
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IAMVersion {
    #[serde(rename = "2012-10-17")]
    V20121017,
    #[serde(rename = "2008-10-17")]
    V20081017,
}

impl Default for IAMVersion {
    fn default() -> Self {
        Self::V20121017
    }
}
