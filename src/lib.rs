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
        assert!(!spec.is_empty());
        println!("{spec}");
    }

    #[test]
    fn test_openapi_spec_matches_snapshot() {
        let current = IamApiDoc::openapi().to_pretty_json().unwrap();

        let snapshot_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/spec.json");
        let snapshot = std::fs::read_to_string(snapshot_path)
            .expect("could not read tests/spec.json — run `cargo test --features utoipa test_generate_openapi_spec -- --nocapture` and save the output to regenerate it");

        let current_value: serde_json::Value =
            serde_json::from_str(&current).expect("current spec is not valid JSON");
        let snapshot_value: serde_json::Value =
            serde_json::from_str(&snapshot).expect("tests/spec.json is not valid JSON");

        assert_eq!(
            current_value, snapshot_value,
            "OpenAPI spec has changed — update tests/spec.json if this is intentional"
        );
    }
}
