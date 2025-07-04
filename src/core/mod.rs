/// Core IAM types and fundamental data structures
pub mod action;
pub mod arn;
pub mod effect;
pub mod operator;
pub mod principal;
pub mod resource;
pub mod version;

// Re-export core types
pub use action::Action;
pub use arn::{Arn, ArnError};
pub use effect::Effect;
pub use operator::Operator;
pub use principal::Principal;
pub use resource::Resource;
pub use version::IAMVersion;
