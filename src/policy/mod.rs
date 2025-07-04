/// IAM policy definition and document structure
pub mod condition;
pub mod policy;
pub mod statement;

// Re-export policy types
pub use condition::{Condition, ConditionBlock};
pub use policy::IAMPolicy;
pub use statement::IAMStatement;
