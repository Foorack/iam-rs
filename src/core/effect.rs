use serde::{Deserialize, Serialize};

/// Represents the effect of an IAM statement
///
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Effect {
    Allow,
    Deny,
}
