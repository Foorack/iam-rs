#![allow(clippy::missing_errors_doc)]

// Module organization
mod core;
mod evaluation;
mod policy;
mod validation;

// Re-export all the main types for easy access
pub use core::*;
pub use evaluation::*;
pub use policy::*;
pub use validation::*;

#[cfg(all(feature = "utoipa", test))]
#[allow(clippy::needless_for_each)]
mod openapi_tests {
    use utoipa::OpenApi;

    #[derive(OpenApi)]
    #[openapi(components(schemas(
        crate::Arn,
        crate::ArnError,
        crate::IAMAction,
        crate::IAMEffect,
        crate::IAMOperator,
        crate::IAMResource,
        crate::IAMVersion,
        crate::OperatorType,
        crate::Principal,
        crate::PrincipalId,
        crate::Condition,
        crate::ConditionBlock,
        crate::ConditionValue,
        crate::IAMPolicy,
        crate::IAMStatement,
        crate::Context,
        crate::ContextValue,
        crate::Decision,
        crate::EvaluationError,
        crate::EvaluationOptions,
        crate::EvaluationResult,
        crate::IAMRequest,
        crate::PolicyEvaluator,
        crate::PolicyVariable,
        crate::StatementMatch,
    )))]
    struct IamApiDoc;

    #[test]
    fn test_generate_openapi_spec() {
        let spec = IamApiDoc::openapi().to_pretty_json().unwrap();
        assert_ne!(spec, "");
        println!("{spec}");
    }

    #[test]
    fn test_openapi_spec_matches_snapshot() {
        let current = IamApiDoc::openapi().to_pretty_json().unwrap();

        let snapshot_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/spec.json");
        let snapshot = std::fs::read_to_string(snapshot_path)
            .expect("could not read tests/spec.json — run `cargo test --features utoipa test_generate_openapi_spec -- --nocapture` and save the output to regenerate it");

        let mut current_value: serde_json::Value =
            serde_json::from_str(&current).expect("current spec is not valid JSON");
        let mut snapshot_value: serde_json::Value =
            serde_json::from_str(&snapshot).expect("tests/spec.json is not valid JSON");

        // `info.version` is filled from `CARGO_PKG_VERSION`, so it is true by construction and
        // changes on every release. Comparing it here made every version bump fail this test,
        // which is how 0.9.1 was tagged onto a tree whose own suite was red. It is checked on its
        // own below, and the snapshot carries the rest of the document.
        assert_eq!(
            current_value["info"]["version"],
            serde_json::json!(env!("CARGO_PKG_VERSION")),
            "the spec's version should be the crate's version"
        );
        if let serde_json::Value::Object(info) = &mut current_value["info"] {
            info.remove("version");
        }
        if let serde_json::Value::Object(info) = &mut snapshot_value["info"] {
            info.remove("version");
        }

        assert_eq!(
            current_value, snapshot_value,
            "OpenAPI spec has changed — update tests/spec.json if this is intentional"
        );
    }

    /// Every `$ref` a type emits has to resolve to a component in the same document.
    ///
    /// `IamApiDoc` registers every type in this crate by hand, so a hand-written `ToSchema` that
    /// forgets to collect its own dependencies still produces a complete document here: the
    /// component is present because the list says so, not because anything registered it. A
    /// downstream application has no such list — its derive collects whatever the holder's
    /// `schemas()` returns — so the omission only shows up there, as a dangling `$ref` and an
    /// invalid document. That is how the missing `PrincipalId` reached 0.15.2 with a green suite.
    ///
    /// Each type is therefore registered **on its own**, so nothing can cover for anything else.
    /// The names that yields are then compared against `IamApiDoc`'s components, so a type added
    /// to one and not the other fails here instead of being silently uncovered.
    #[test]
    fn test_every_schema_is_self_contained() {
        let mut covered: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        macro_rules! check_alone {
            ($($ty:ty),* $(,)?) => {
                $(
                    {
                        #[derive(OpenApi)]
                        #[openapi(components(schemas($ty)))]
                        struct Only;

                        let doc = serde_json::to_value(Only::openapi())
                            .expect("the document does not serialise");

                        let mut refs = Vec::new();
                        collect_refs(&doc, &mut refs);
                        let dangling: Vec<&String> = refs
                            .iter()
                            .filter(|reference| !resolves(&doc, reference))
                            .collect();
                        assert!(
                            dangling.is_empty(),
                            "{} on its own emits references that do not resolve to a \
                             component: {dangling:?}",
                            stringify!($ty),
                        );

                        covered.extend(component_names(&doc));
                    }
                )*
            };
        }

        check_alone!(
            crate::Arn,
            crate::ArnError,
            crate::IAMAction,
            crate::IAMEffect,
            crate::IAMOperator,
            crate::IAMResource,
            crate::IAMVersion,
            crate::OperatorType,
            crate::Principal,
            crate::PrincipalId,
            crate::Condition,
            crate::ConditionBlock,
            crate::ConditionValue,
            crate::IAMPolicy,
            crate::IAMStatement,
            crate::Context,
            crate::ContextValue,
            crate::Decision,
            crate::EvaluationError,
            crate::EvaluationOptions,
            crate::EvaluationResult,
            crate::IAMRequest,
            crate::PolicyEvaluator,
            crate::PolicyVariable,
            crate::StatementMatch,
        );

        let whole =
            serde_json::to_value(IamApiDoc::openapi()).expect("the document does not serialise");
        assert_eq!(
            covered,
            component_names(&whole),
            "a type is registered by one of these tests and not the other; add it to both",
        );
    }

    /// No policy element that the parser rejects as `null` may be described as nullable.
    ///
    /// `non_null::deserialize` refuses an explicit `null` for these elements, because AWS treats
    /// it as a malformed document rather than an omitted element. The derive only sees
    /// `Option<T>`, so it writes `null` into the schema unless the field says otherwise, and a
    /// client generated from that schema can send exactly what the parser refuses: with
    /// `typescript-fetch` the field comes out as `IAMAction | Null`, and `Null` is not a type
    /// anything defines.
    ///
    /// Each such field therefore carries `schema(nullable = false)`. This checks the result
    /// rather than the attribute, so a new element that is deserialised with `non_null` and
    /// declared without it fails here instead of downstream.
    ///
    /// The walk covers the whole document, not just the two structs that carry `non_null`
    /// today: a `non_null` field added to a third struct would otherwise sit outside it and
    /// pass. Every nullable property that remains has to be named below, which makes it a
    /// decision rather than an oversight, and a named one that stops being nullable fails too
    /// so the list cannot go stale.
    #[test]
    fn test_only_named_properties_are_nullable() {
        // `StatementMatch` is a readable result, not a document that is parsed back in, so
        // `null` there is a value it genuinely accepts.
        //
        // `PolicyVariable` derives no `Serialize`/`Deserialize` at all, so it has no wire form
        // and accepts nothing, `null` included. There is no parser to disagree with the schema;
        // the derive writes the `Option` out as-is.
        const NULLABLE: &[&str] = &["PolicyVariable.default_value", "StatementMatch.sid"];

        let doc =
            serde_json::to_value(IamApiDoc::openapi()).expect("the document does not serialise");
        let schemas = &doc["components"]["schemas"];

        let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (holder, component) in schemas.as_object().expect("no components in the spec") {
            let Some(properties) = component["properties"].as_object() else {
                continue;
            };
            for (name, schema) in properties {
                if admits_null(schema) {
                    found.insert(format!("{holder}.{name}"));
                }
            }
        }

        let expected: std::collections::BTreeSet<String> =
            NULLABLE.iter().map(|name| (*name).to_owned()).collect();

        let unexpected: Vec<&String> = found.difference(&expected).collect();
        assert!(
            unexpected.is_empty(),
            "these properties are described as nullable but are not in the allowlist: \
             {unexpected:?}. If the parser rejects null for one, put \
             #[cfg_attr(feature = \"utoipa\", schema(nullable = false))] on the field; if it \
             genuinely accepts null, add it to NULLABLE.",
        );

        let stale: Vec<&String> = expected.difference(&found).collect();
        assert!(
            stale.is_empty(),
            "these properties are in the allowlist but are no longer nullable: {stale:?}. \
             Remove them from NULLABLE.",
        );
    }

    /// Whether a schema permits the JSON value `null`, in either the 3.1 form
    /// (`"type": ["string", "null"]`) or the 3.0 one (`"nullable": true`).
    ///
    /// A `$ref` is not followed: this asks about the schema object in front of it, and no
    /// component in this crate admits `null`, so a reference to one cannot either. If a
    /// nullable component ever appears, this helper needs to resolve references before the
    /// answer means anything.
    fn admits_null(schema: &serde_json::Value) -> bool {
        if schema["nullable"] == serde_json::Value::Bool(true) {
            return true;
        }
        match &schema["type"] {
            serde_json::Value::String(kind) if kind == "null" => return true,
            serde_json::Value::Array(kinds) if kinds.iter().any(|k| k == "null") => return true,
            _ => {}
        }
        ["oneOf", "anyOf", "allOf"].iter().any(|key| {
            schema[key]
                .as_array()
                .is_some_and(|members| members.iter().any(admits_null))
        })
    }

    fn component_names(doc: &serde_json::Value) -> std::collections::BTreeSet<String> {
        doc["components"]["schemas"]
            .as_object()
            .map_or_else(std::collections::BTreeSet::new, |schemas| {
                schemas.keys().cloned().collect()
            })
    }

    fn collect_refs(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if key == "$ref" {
                        if let Some(reference) = child.as_str() {
                            out.push(reference.to_owned());
                        }
                    } else {
                        collect_refs(child, out);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_refs(item, out);
                }
            }
            _ => {}
        }
    }

    /// A `#/a/b/c` reference resolves when the document has that path. Anything else does not
    /// resolve *within* this document: this crate emits no external references, so one appearing
    /// here is a change that should be looked at rather than waved through.
    fn resolves(doc: &serde_json::Value, reference: &str) -> bool {
        let Some(path) = reference.strip_prefix("#/") else {
            return false;
        };
        let mut node = doc;
        for segment in path.split('/') {
            let Some(child) = node.get(segment) else {
                return false;
            };
            node = child;
        }
        true
    }
}
