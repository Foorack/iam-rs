/// Core IAM types and fundamental data structures
mod action;
mod arn;
mod effect;
mod operator;
mod principal;
mod resource;
mod version;

// Re-export core types
pub use action::Action;
pub use arn::{Arn, ArnError};
pub use effect::Effect;
pub use operator::{Operator, OperatorType};
pub use principal::{Principal, PrincipalId};
pub use resource::Resource;
pub use version::IAMVersion;
