#![allow(deprecated)]

use serde::{Deserialize, Serialize};

/// Represents the version of the IAM policy language
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Default)]
pub enum IAMVersion {
    #[serde(rename = "2012-10-17")]
    #[default]
    V20121017,
    #[serde(rename = "2008-10-17")]
    #[allow(clippy::deprecated_semver)]
    #[deprecated(since = "2012-10-17", note = "Use V20121017 instead")]
    V20081017,
}

impl IAMVersion {
    /// Whether this language version resolves policy variables such as
    /// `${aws:username}`.
    ///
    /// AWS: "In order to use policy variables, you must include the `Version`
    /// element ... set to a version that supports policy variables. Earlier
    /// versions of the policy language don't support policy variables"; in a
    /// `2008-10-17` policy `${aws:username}` is the literal text.
    pub(crate) fn supports_policy_variables(&self) -> bool {
        matches!(self, Self::V20121017)
    }
}
