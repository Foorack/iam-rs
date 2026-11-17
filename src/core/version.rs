#![allow(deprecated)]

use serde::{Deserialize, Serialize};

/// Represents the version of the IAM policy language
///
/// AWS's grammar marks the version block optional (`<version_block?>`), and an
/// absent `Version` is not the same as one naming `2012-10-17`: such a document
/// is evaluated under the older policy language, where policy variables are
/// literal text. The `Unspecified` variant carries that distinction.
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
    /// The document carried no `Version` element at all.
    ///
    /// There is no JSON spelling for this: it is what
    /// [`IAMPolicy`](crate::IAMPolicy) deserialises to when the element is
    /// missing, and serialising it back leaves the element out again.
    #[serde(skip)]
    Unspecified,
}

impl IAMVersion {
    /// Whether this language version resolves policy variables such as
    /// `${aws:username}`.
    ///
    /// AWS: "In order to use policy variables, you must include the `Version`
    /// element ... set to a version that supports policy variables. Earlier
    /// versions of the policy language don't support policy variables"; in a
    /// `2008-10-17` policy `${aws:username}` is the literal text.
    ///
    /// A policy with no `Version` element at all is described by AWS as
    /// behaving like the older policy language, so it does not resolve
    /// variables either.
    pub(crate) fn supports_policy_variables(&self) -> bool {
        matches!(self, Self::V20121017)
    }

    /// The value of a policy that omitted the `Version` element.
    pub(crate) fn unspecified() -> Self {
        Self::Unspecified
    }

    /// Whether this policy carried no `Version` element.
    pub(crate) fn is_unspecified(&self) -> bool {
        matches!(self, Self::Unspecified)
    }
}
