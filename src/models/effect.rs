use serde::{Deserialize, Serialize};

/// Represents the effect of an IAM statement
///
/// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}
