//! Reject an explicit `null` where a policy element is expected.
//!
//! AWS's policy grammar is a closed set of elements and none of them admits
//! `null`: `"Action": null` is a `MalformedPolicyDocument`, not an omitted
//! element. A plain `Option<T>` cannot tell the two apart, so it accepts the
//! document and leaves the element out again when serialising. That silently
//! changes the policy — most visibly for `Condition`, where dropping the element
//! turns a conditional statement into an unconditional one.

use serde::Deserializer;
use serde::de::{DeserializeOwned, Error, Visitor};
use std::fmt;
use std::marker::PhantomData;

pub(super) fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    struct NonNull<T>(PhantomData<T>);

    impl<'de, T: DeserializeOwned> Visitor<'de> for NonNull<T> {
        type Value = Option<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a policy element value, which cannot be null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Err(E::custom(
                "a policy element cannot be null: omit the element instead",
            ))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_none()
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            T::deserialize(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(NonNull(PhantomData))
}
