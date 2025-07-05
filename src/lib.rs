// Module organization
pub mod core;
pub mod evaluation;
pub mod policy;
pub mod validation;

// Re-export all the main types for easy access
pub use core::*;
pub use evaluation::*;
pub use policy::*;
pub use validation::*;
