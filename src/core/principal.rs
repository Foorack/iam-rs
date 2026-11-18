use crate::{
    Arn, ValidationError,
    validation::{Validate, ValidationContext, ValidationResult},
};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
};
use std::fmt;

/// Principal ID (can be either string or array of strings)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum PrincipalId {
    /// Single principal ID as a string
    String(String),
    /// Multiple principal IDs as an array of strings
    Array(Vec<String>),
}

/// Represents a principal in an IAM policy
///
/// `<principal_block>` = ("Principal" | "`NotPrincipal`") : ("*" | `<principal_map>`)
/// `<principal_map>` = { `<principal_map_entry>`, `<principal_map_entry>`, ... }
/// `<principal_map_entry>` = ("AWS" | "Federated" | "Service" | "`CanonicalUser`") :
///     [`<principal_id_string>`, `<principal_id_string>`, ...]
///
/// (e.g., {"AWS": "`arn:aws:iam::123456789012:user/username`"})
///
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// AWS principals (users, roles, root accounts)
    Aws(PrincipalId),
    /// Federated principals (SAML, OIDC providers)
    Federated(PrincipalId),
    /// AWS service principals
    Service(PrincipalId),
    /// Canonical user principals
    CanonicalUser(PrincipalId),
    /// Wildcard principal (matches all principals)
    Wildcard,
    /// Several principal types in one map, which AWS's grammar allows:
    /// `{"AWS": [...], "CanonicalUser": "..."}`.
    ///
    /// A request matches when any entry matches. The map entries are never
    /// flattened into a list: each keeps its own type, because the type is part
    /// of what a principal means (`Service` vs `AWS` must not be confused).
    Multiple(Vec<Principal>),
}

// The wire shape is one of two things, which an enum derive cannot express:
//
//     "Principal": "*"
//     "Principal": {"AWS": [...], "CanonicalUser": "..."}
//
// so the schema is written by hand to match what `Serialize` actually emits.
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for Principal {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::{
            Ref, RefOr,
            schema::{AdditionalProperties, ObjectBuilder, OneOfBuilder, Schema, SchemaType, Type},
        };

        let wildcard = ObjectBuilder::new()
            .schema_type(SchemaType::Type(Type::String))
            .enum_values(Some(["*"]))
            .description(Some(
                "All principals. The only principal block that is not a map.",
            ))
            .build();

        let map = ObjectBuilder::new()
            .property("AWS", Ref::from_schema_name("PrincipalId"))
            .property("Federated", Ref::from_schema_name("PrincipalId"))
            .property("Service", Ref::from_schema_name("PrincipalId"))
            .property("CanonicalUser", Ref::from_schema_name("PrincipalId"))
            .additional_properties(Some(AdditionalProperties::FreeForm(false)))
            .description(Some(
                "A principal map: one or more of AWS, Federated, Service and CanonicalUser, each \
                 holding an id or a list of ids. Any entry may match.",
            ))
            .build();

        RefOr::T(Schema::OneOf(
            OneOfBuilder::new().item(wildcard).item(map).build(),
        ))
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for Principal {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Principal")
    }

    // The schema above refers to `PrincipalId` by name, which a `Ref` does not register by
    // itself. The derive used to collect it; the hand-written schema does not, so a document
    // whose only holder of `Principal` was this type had a dangling `$ref`. `Context` does the
    // same for `ContextValue`.
    fn schemas(
        schemas: &mut Vec<(
            String,
            utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
        )>,
    ) {
        schemas.push((
            <PrincipalId as utoipa::ToSchema>::name().into_owned(),
            <PrincipalId as utoipa::PartialSchema>::schema(),
        ));
        <PrincipalId as utoipa::ToSchema>::schemas(schemas);
    }
}

/// The four map keys a principal block may use.
///
/// AWS's `<principal_map_entry>` is one of these; the key carries the type of
/// every id under it, and the type is part of what the id means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrincipalKind {
    Aws,
    Federated,
    Service,
    CanonicalUser,
}

const PRINCIPAL_KINDS: &[&str] = &["AWS", "Federated", "Service", "CanonicalUser"];

impl PrincipalKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "AWS",
            Self::Federated => "Federated",
            Self::Service => "Service",
            Self::CanonicalUser => "CanonicalUser",
        }
    }

    fn parse(key: &str) -> Option<Self> {
        match key {
            "AWS" => Some(Self::Aws),
            "Federated" => Some(Self::Federated),
            "Service" => Some(Self::Service),
            "CanonicalUser" => Some(Self::CanonicalUser),
            _ => None,
        }
    }

    const fn of(principal: &Principal) -> Option<Self> {
        match principal {
            Principal::Aws(_) => Some(Self::Aws),
            Principal::Federated(_) => Some(Self::Federated),
            Principal::Service(_) => Some(Self::Service),
            Principal::CanonicalUser(_) => Some(Self::CanonicalUser),
            Principal::Wildcard | Principal::Multiple(_) => None,
        }
    }

    fn wrap(self, id: PrincipalId) -> Principal {
        match self {
            Self::Aws => Principal::Aws(id),
            Self::Federated => Principal::Federated(id),
            Self::Service => Principal::Service(id),
            Self::CanonicalUser => Principal::CanonicalUser(id),
        }
    }
}

/// Combine two ids of the same type into one, as AWS does when the same map key
/// is given twice.
fn merge_principal_ids(first: &PrincipalId, second: &PrincipalId) -> PrincipalId {
    let mut ids = Vec::new();
    for id in [first, second] {
        match id {
            PrincipalId::String(one) => ids.push(one.clone()),
            PrincipalId::Array(many) => ids.extend(many.iter().cloned()),
        }
    }
    PrincipalId::Array(ids)
}

impl Principal {
    /// The id this principal carries, if it is a single-type entry.
    const fn id(&self) -> Option<&PrincipalId> {
        match self {
            Principal::Aws(id)
            | Principal::Federated(id)
            | Principal::Service(id)
            | Principal::CanonicalUser(id) => Some(id),
            Principal::Wildcard | Principal::Multiple(_) => None,
        }
    }
}

// A principal block is either the bare string `"*"`, or a **map** that AWS's
// grammar allows to hold several entries:
//
//     {"AWS": [...], "CanonicalUser": "..."}
//
// An externally tagged enum can only write one key per value, so this is
// hand-written. Single-entry output is unchanged, byte for byte, which is what
// keeps the corpus round-trip identical.
impl Serialize for Principal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Principal::Wildcard = self {
            return serializer.serialize_str("*");
        }

        // Group by key, preserving the order each key first appears, so a
        // multi-entry map round-trips in its own order.
        let mut grouped: Vec<(PrincipalKind, Vec<&PrincipalId>)> = Vec::new();
        match self {
            Principal::Multiple(entries) => {
                for entry in entries {
                    let (Some(kind), Some(id)) = (PrincipalKind::of(entry), entry.id()) else {
                        // A wildcard cannot sit beside other entries in the same
                        // map; the grammar has no key for it.
                        continue;
                    };
                    match grouped.iter_mut().find(|(seen, _)| *seen == kind) {
                        Some((_, ids)) => ids.push(id),
                        None => grouped.push((kind, vec![id])),
                    }
                }
            }
            single => {
                let (Some(kind), Some(id)) = (PrincipalKind::of(single), single.id()) else {
                    return serializer.serialize_str("*");
                };
                grouped.push((kind, vec![id]));
            }
        }

        let mut map = serializer.serialize_map(Some(grouped.len()))?;
        for (kind, ids) in &grouped {
            let merged = if ids.len() == 1 {
                (*ids[0]).clone()
            } else {
                let mut all = Vec::new();
                for id in ids {
                    match id {
                        PrincipalId::String(one) => all.push(one.clone()),
                        PrincipalId::Array(many) => all.extend(many.iter().cloned()),
                    }
                }
                PrincipalId::Array(all)
            };
            map.serialize_entry(kind.as_str(), &merged)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(PrincipalVisitor)
    }
}

struct PrincipalVisitor;

impl<'de> Visitor<'de> for PrincipalVisitor {
    type Value = Principal;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"*\" or a principal map such as {\"AWS\": \"...\"}")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Principal, E> {
        if value == "*" {
            Ok(Principal::Wildcard)
        } else {
            Err(E::custom(format!(
                "unknown principal `{value}`, expected \"*\" or a principal map"
            )))
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Principal, A::Error> {
        let mut entries: Vec<(PrincipalKind, PrincipalId)> = Vec::new();

        while let Some(key) = map.next_key::<String>()? {
            let kind = PrincipalKind::parse(&key)
                .ok_or_else(|| de::Error::unknown_field(&key, PRINCIPAL_KINDS))?;
            let id = map.next_value::<PrincipalId>()?;

            // A map cannot repeat a key in JSON, but a deserializer may hand us
            // the same key twice; AWS merges the ids, so do the same.
            match entries.iter_mut().find(|(seen, _)| *seen == kind) {
                Some((_, existing)) => *existing = merge_principal_ids(existing, &id),
                None => entries.push((kind, id)),
            }
        }

        if entries.is_empty() {
            return Err(de::Error::custom("principal map cannot be empty"));
        }
        if entries.len() == 1 {
            let (kind, id) = entries.pop().expect("one entry");
            return Ok(kind.wrap(id));
        }
        Ok(Principal::Multiple(
            entries
                .into_iter()
                .map(|(kind, id)| kind.wrap(id))
                .collect(),
        ))
    }
}

impl Principal {
    #[must_use]
    pub fn is_single(&self) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Principal::Aws(PrincipalId::String(_))
            | Principal::Federated(PrincipalId::String(_))
            | Principal::Service(PrincipalId::String(_))
            | Principal::CanonicalUser(PrincipalId::String(_)) => true,
            _ => false,
        }
    }

    /// Returns `true` when this principal matches every request principal.
    ///
    /// AWS documents `{"AWS": "*"}` as a valid synonym of `"Principal": "*"`,
    /// so both spellings have to validate and match identically.
    #[must_use]
    pub(crate) fn is_wildcard(&self) -> bool {
        match self {
            Principal::Wildcard => true,
            Principal::Aws(PrincipalId::String(id)) => id == "*",
            Principal::Aws(PrincipalId::Array(ids)) => ids.iter().any(|id| id == "*"),
            Principal::Multiple(entries) => entries.iter().any(Principal::is_wildcard),
            _ => false,
        }
    }
}

fn validate_domain(domain: &str) -> ValidationResult {
    if domain.is_empty() || !domain.contains('.') || !domain.ends_with(|c: char| c.is_alphabetic())
    {
        return Err(ValidationError::InvalidPrincipal {
            principal: domain.to_string(),
            reason: "Principal must be a valid domain".to_string(),
        });
    }
    Ok(())
}

impl Validate for Principal {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Principal", |ctx| match self {
            Principal::Wildcard => Ok(()),

            //
            // "Array" cases (compact)
            //
            Principal::Aws(PrincipalId::Array(ids))
            | Principal::Federated(PrincipalId::Array(ids))
            | Principal::Service(PrincipalId::Array(ids))
            | Principal::CanonicalUser(PrincipalId::Array(ids)) => {
                if ids.is_empty() {
                    return Err(ValidationError::InvalidPrincipal {
                        principal: "Empty principal array".to_string(),
                        reason: "Principal array cannot be empty".to_string(),
                    });
                }
                for id in ids {
                    let single = match self {
                        Principal::Aws(_) => Principal::Aws(PrincipalId::String(id.clone())),
                        Principal::Federated(_) => {
                            Principal::Federated(PrincipalId::String(id.clone()))
                        }
                        Principal::Service(_) => {
                            Principal::Service(PrincipalId::String(id.clone()))
                        }
                        Principal::CanonicalUser(_) => {
                            Principal::CanonicalUser(PrincipalId::String(id.clone()))
                        }
                        Principal::Wildcard | Principal::Multiple(_) => unreachable!(),
                    };
                    single.validate(ctx)?;
                }
                Ok(())
            }

            //
            // Several entries in one map: every entry has to be individually
            // valid, and the map has to hold at least one.
            //
            Principal::Multiple(entries) => {
                if entries.is_empty() {
                    return Err(ValidationError::InvalidPrincipal {
                        principal: "Empty principal map".to_string(),
                        reason: "Principal map cannot be empty".to_string(),
                    });
                }
                for entry in entries {
                    // The grammar has no nested map, so this cannot be built from
                    // a document; a hand-built one is rejected rather than
                    // serialised into something that reads differently.
                    if matches!(entry, Principal::Multiple(_)) {
                        return Err(ValidationError::InvalidPrincipal {
                            principal: "Nested principal map".to_string(),
                            reason: "A principal map cannot contain another map".to_string(),
                        });
                    }
                    entry.validate(ctx)?;
                }
                Ok(())
            }

            //
            // "Single" cases
            //

            // AWS means it is either "*", account number or ARN
            Principal::Aws(PrincipalId::String(id)) => {
                // `{"AWS": "*"}` is an accepted spelling of `"Principal": "*"`,
                // so the bare wildcard is not parsed as an ARN.
                if id == "*" {
                    return Ok(());
                }
                if id.len() == 12 && id.chars().all(|c| c.is_ascii_digit()) {
                    // Account ID
                    return Ok(());
                }
                let arn = Arn::parse(id).map_err(|e| ValidationError::InvalidPrincipal {
                    principal: id.clone(),
                    reason: e.to_string(),
                })?;
                arn.validate(ctx)
            }
            Principal::Federated(PrincipalId::String(id)) => {
                // If starts with "arn:", validate as ARN
                if id.starts_with("arn:") {
                    let arn = Arn::parse(id).map_err(|e| ValidationError::InvalidPrincipal {
                        principal: id.clone(),
                        reason: e.to_string(),
                    })?;
                    arn.validate(ctx)?;
                } else {
                    validate_domain(id)?;
                }
                Ok(())
            }
            Principal::Service(PrincipalId::String(id)) => Ok(validate_domain(id)?),
            Principal::CanonicalUser(PrincipalId::String(id)) => {
                // Canonical user IDs are usually 64-character hexadecimal strings
                if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok(());
                }
                Err(ValidationError::InvalidPrincipal {
                    principal: id.clone(),
                    reason: "Canonical user ID must be a 64-character hex string".to_string(),
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_validation() {
        // Valid AWS principal
        assert!(
            Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/alice".into()
            ))
            .is_valid()
        );

        // Invalid principal should be invalid
        assert!(!Principal::Aws(PrincipalId::String("invalid-principal".into())).is_valid());

        // Empty principal should be invalid
        assert!(!Principal::Aws(PrincipalId::String(String::new())).is_valid());

        // Empty array principal should be invalid
        assert!(!Principal::Aws(PrincipalId::Array(vec![])).is_valid());

        // Two valid principals in an array
        let valid_array_principal = Principal::Aws(PrincipalId::Array(vec![
            "arn:aws:iam::123456789012:user/alice".into(),
            "arn:aws:iam::123456789012:user/bob".into(),
        ]));
        assert!(valid_array_principal.is_valid());

        // Account ID as a valid principal
        assert!(Principal::Aws(PrincipalId::String("123456789012".into())).is_valid());

        // `{"AWS": "*"}` is an accepted spelling of the wildcard principal
        assert!(Principal::Aws(PrincipalId::String("*".into())).is_valid());
        assert!(Principal::Aws(PrincipalId::Array(vec!["*".into()])).is_valid());
        // ... but only the bare "*" is exempt from ARN validation
        assert!(!Principal::Aws(PrincipalId::String("arn:*".into())).is_valid());

        // Valid service principal
        assert!(Principal::Service(PrincipalId::String("ec2.amazonaws.com".into())).is_valid());
        // Invalid service principal
        assert!(!Principal::Service(PrincipalId::String("invalid-service".into())).is_valid());

        // Valid federated principal
        assert!(
            Principal::Federated(PrincipalId::String(
                "arn:aws:iam::123456789012:saml-provider/MyProvider".into()
            ))
            .is_valid()
        );
        // Invalid federated principal
        assert!(!Principal::Federated(PrincipalId::String("invalid-federated".into())).is_valid());
        // Simple domain as federated principal
        assert!(Principal::Federated(PrincipalId::String("example.com".into())).is_valid());

        // Valid canonical user principal
        assert!(
            Principal::CanonicalUser(PrincipalId::String(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into()
            ))
            .is_valid()
        );
        // Invalid canonical user principal (wrong length)
        assert!(
            !Principal::CanonicalUser(PrincipalId::String("invalid-canonical".into())).is_valid()
        );
    }

    #[test]
    fn test_wildcard_principal_spellings_are_equivalent() {
        assert!(Principal::Wildcard.is_wildcard());
        assert!(Principal::Aws(PrincipalId::String("*".into())).is_wildcard());
        assert!(Principal::Aws(PrincipalId::Array(vec!["*".into()])).is_wildcard());
        assert!(
            Principal::Aws(PrincipalId::Array(vec![
                "*".into(),
                "arn:aws:iam::123456789012:user/alice".into()
            ]))
            .is_wildcard()
        );

        // A wildcard in another principal type, or an ARN-shaped id, is not the
        // wildcard principal.
        assert!(!Principal::Service(PrincipalId::String("*".into())).is_wildcard());
        assert!(!Principal::Federated(PrincipalId::String("*".into())).is_wildcard());
        assert!(
            !Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/alice".into()
            ))
            .is_wildcard()
        );
    }

    fn canonical_user() -> &'static str {
        "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
    }

    #[test]
    fn test_multi_entry_principal_map_is_parsed() {
        // AWS's grammar allows several entries in one map.
        let json = format!(
            r#"{{"AWS":["arn:aws:iam::111122223333:root","999999999999"],"CanonicalUser":"{}"}}"#,
            canonical_user()
        );
        let principal: Principal = serde_json::from_str(&json).unwrap();
        let Principal::Multiple(entries) = &principal else {
            panic!("expected a multi-entry principal, got {principal:?}");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            Principal::Aws(PrincipalId::Array(vec![
                "arn:aws:iam::111122223333:root".into(),
                "999999999999".into()
            ]))
        );
        assert_eq!(
            entries[1],
            Principal::CanonicalUser(PrincipalId::String(canonical_user().into()))
        );
        assert!(principal.is_valid());
    }

    #[test]
    fn test_multi_entry_principal_map_round_trips_in_order() {
        let json = format!(
            r#"{{"AWS":["a:b","c:d"],"CanonicalUser":"{}"}}"#,
            canonical_user()
        );
        let principal: Principal = serde_json::from_str(&json).unwrap();
        let written = serde_json::to_value(&principal).unwrap();
        assert_eq!(
            written,
            serde_json::from_str::<serde_json::Value>(&json).unwrap()
        );
        // ... and reading the written form gives the same value back.
        assert_eq!(
            serde_json::from_value::<Principal>(written).unwrap(),
            principal
        );
    }

    #[test]
    fn test_single_entry_principal_map_is_unchanged() {
        // Every single-entry spelling must serialise exactly as before, which is
        // what keeps the corpus round-trip byte-identical.
        for (json, expected) in [
            (
                r#"{"AWS":"arn:aws:iam::123456789012:root"}"#,
                r#"{"AWS":"arn:aws:iam::123456789012:root"}"#,
            ),
            (r#"{"AWS":"*"}"#, r#"{"AWS":"*"}"#),
            (
                r#"{"Service":"ec2.amazonaws.com"}"#,
                r#"{"Service":"ec2.amazonaws.com"}"#,
            ),
            (r#"{"AWS":["a:b"]}"#, r#"{"AWS":["a:b"]}"#),
        ] {
            let principal: Principal = serde_json::from_str(json).unwrap();
            assert!(
                !matches!(principal, Principal::Multiple(_)),
                "{json} should stay a single entry"
            );
            assert_eq!(
                serde_json::to_value(&principal).unwrap(),
                serde_json::from_str::<serde_json::Value>(expected).unwrap(),
                "{json}"
            );
        }

        // The bare string form is the wildcard, not a map.
        let wildcard: Principal = serde_json::from_str(r#""*""#).unwrap();
        assert_eq!(wildcard, Principal::Wildcard);
        assert_eq!(
            serde_json::to_value(&wildcard).unwrap(),
            serde_json::json!("*")
        );
    }

    #[test]
    fn test_principal_map_rejects_unknown_and_empty() {
        assert!(serde_json::from_str::<Principal>(r#"{"Aws":"a:b"}"#).is_err());
        assert!(serde_json::from_str::<Principal>("{}").is_err());
        assert!(serde_json::from_str::<Principal>(r#"{"*":null}"#).is_err());
    }

    #[test]
    fn test_repeated_principal_key_merges_the_ids() {
        // A map cannot repeat a key in JSON, but the merge rule is exercised
        // directly: AWS combines the ids of a repeated key.
        assert_eq!(
            merge_principal_ids(
                &PrincipalId::String("a:b".into()),
                &PrincipalId::Array(vec!["c:d".into()])
            ),
            PrincipalId::Array(vec!["a:b".into(), "c:d".into()])
        );
    }

    #[test]
    fn test_multi_entry_principal_validation() {
        // Nested maps are not in the grammar, and an empty map is invalid.
        assert!(!Principal::Multiple(Vec::new()).is_valid());
        assert!(
            !Principal::Multiple(vec![Principal::Multiple(vec![Principal::Aws(
                PrincipalId::String("arn:aws:iam::123456789012:root".into())
            )])])
            .is_valid()
        );
        // A wildcard entry makes the whole block a wildcard.
        assert!(
            Principal::Multiple(vec![
                Principal::Aws(PrincipalId::String("*".into())),
                Principal::Service(PrincipalId::String("ec2.amazonaws.com".into())),
            ])
            .is_wildcard()
        );
    }
}
