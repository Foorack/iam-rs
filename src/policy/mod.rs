/// IAM policy definition and document structure
mod condition;
#[allow(clippy::module_inception)]
mod policy;
mod statement;

// Re-export policy types
pub use condition::{Condition, ConditionBlock, ConditionValue};
pub use policy::IAMPolicy;
pub use statement::IAMStatement;
