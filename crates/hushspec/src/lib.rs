pub mod evaluate;
pub mod extensions;
mod generated_contract;
mod generated_models;
pub mod merge;
pub mod resolve;
pub mod rules;
pub mod schema;
pub mod validate;
pub mod version;

pub use evaluate::{
    Decision, EvaluationAction, EvaluationResult, OriginContext, PostureContext, PostureResult,
    evaluate,
};
pub use extensions::Extensions;
pub use merge::merge;
pub use resolve::{LoadedSpec, ResolveError, resolve_from_path, resolve_with_loader};
pub use rules::*;
pub use schema::HushSpec;
pub use validate::{ValidationError, ValidationResult, validate};
pub use version::HUSHSPEC_VERSION;
