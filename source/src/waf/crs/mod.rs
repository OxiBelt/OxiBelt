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

#[cfg(feature = "fuzzing")]
use model::CrsEntry;
#[cfg(feature = "fuzzing")]
use parser::CrsParser;

pub use compatibility::{CrsCompatibilityMatrix, compatibility_matrix};
pub use config::WafCrsConfig;
pub(crate) use config::validate_config as validate_crs_config;
#[allow(unused_imports)]
pub use config::{WafCrsRuleOverrideMode, WafCrsUnsupportedDirectivePolicy};
#[allow(unused_imports)]
pub(crate) use engine::{CrsDecision, CrsEngine, CrsHitKey};

/// Exercise CRS syntax and transform processing without loading rule files.
///
/// The caller supplies a size-bounded source and derived request text.  Parsing
/// and transform application are repeated from the same inputs so fuzzing can
/// detect nondeterminism without imposing idempotence on transformations whose
/// current semantics intentionally permit a second pass to change the value.
#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_parse_and_process(source: &str, value: &str) {
  fn parse(source: &str) -> anyhow::Result<CrsParser> {
    let mut parser = CrsParser::new();
    parser.load_str(source)?;
    Ok(parser)
  }

  let first = parse(source);
  let second = parse(source);
  match (first, second) {
    (Ok(first), Ok(second)) => {
      let first = processed_values(&first, value);
      let second = processed_values(&second, value);
      assert_eq!(
        first, second,
        "in-memory CRS parsing or transform processing was not deterministic"
      );
    }
    (Err(first), Err(second)) => assert_eq!(
      first.to_string(),
      second.to_string(),
      "in-memory CRS parse errors were not deterministic"
    ),
    _ => panic!("in-memory CRS parsing changed result for identical input"),
  }
}

#[cfg(feature = "fuzzing")]
fn processed_values(parser: &CrsParser, value: &str) -> Vec<String> {
  parser
    .entries
    .iter()
    .filter_map(|entry| match entry {
      CrsEntry::Rule(rule) => {
        Some(transforms::apply_transforms(value, &rule.transforms).into_owned())
      }
      CrsEntry::Marker(_) => None,
    })
    .collect()
}
