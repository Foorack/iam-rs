/// Core IAM types and fundamental data structures
mod action;
mod arn;
mod effect;
mod operator;
mod principal;
mod resource;
mod version;

// Re-export core types
pub use action::IAMAction;
pub use arn::{Arn, ArnError};
pub use effect::IAMEffect;
pub use operator::{IAMOperator, OperatorType};
pub use principal::{Principal, PrincipalId};
pub use resource::IAMResource;
pub use version::IAMVersion;
