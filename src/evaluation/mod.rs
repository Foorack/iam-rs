/// Policy evaluation engine and authorization logic
mod context;
mod engine;
mod matcher;
mod operator_eval;
mod request;
mod variable;

// Re-export evaluation types
pub use context::{Context, ContextValue};
pub use engine::{
    Decision, EvaluationError, EvaluationOptions, EvaluationResult, PolicyEvaluator,
    StatementMatch, evaluate_policies, evaluate_policy,
};
pub use matcher::{ArnBuilder, ArnMatcher, ArnSet};
pub use request::IAMRequest;
pub use variable::{PolicyVariable, interpolate_variables};

// Shared by the condition validator so validation and evaluation agree on
// which date values are valid (ISO 8601 or Unix epoch).
pub(crate) use operator_eval::parse_date;
