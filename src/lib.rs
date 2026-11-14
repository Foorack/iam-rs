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
}
