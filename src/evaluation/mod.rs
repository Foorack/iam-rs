/// Policy evaluation engine and authorization logic
pub mod context;
pub mod engine;
pub mod matcher;

// Re-export evaluation types
pub use context::{ContextValue, RequestContext};
pub use engine::{
    AuthorizationRequest, Decision, EvaluationError, EvaluationOptions, EvaluationResult,
    PolicyEvaluator, evaluate_policies, evaluate_policy,
};
pub use matcher::{ArnBuilder, ArnMatcher, ArnSet};
