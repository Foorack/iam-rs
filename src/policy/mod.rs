/// IAM policy definition and document structure
mod condition;
mod policy;
mod statement;

// Re-export policy types
pub use condition::{Condition, ConditionBlock};
pub use policy::IAMPolicy;
pub use statement::IAMStatement;
