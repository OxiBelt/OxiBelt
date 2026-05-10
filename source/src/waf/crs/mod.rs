mod actions;
mod compatibility;
mod config;
mod engine;
mod model;
mod operators;
mod parser;
mod syntax;
mod transforms;
mod utils;
mod variables;

pub use compatibility::{CrsCompatibilityMatrix, compatibility_matrix};
pub use config::WafCrsConfig;
pub(crate) use config::validate_config as validate_crs_config;
#[allow(unused_imports)]
pub use config::{WafCrsRuleOverrideMode, WafCrsUnsupportedDirectivePolicy};
#[allow(unused_imports)]
pub(crate) use engine::{CrsDecision, CrsEngine, CrsHitKey};
