use regex::Regex;

use super::CompiledPatternSet;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct BodyScanResult {
  pub(crate) matched: bool,
  pub(crate) pattern: Option<String>,
  pub(crate) offset: Option<usize>,
  pub(crate) matched_text: Option<String>,
  pub(crate) is_truncated: bool,
}

impl BodyScanResult {
  pub(crate) fn no_match(is_truncated: bool) -> Self {
    Self {
      matched: false,
      pattern: None,
      offset: None,
      matched_text: None,
      is_truncated,
    }
  }
}

pub(crate) fn body_text(bytes: &[u8]) -> String {
  String::from_utf8_lossy(bytes).into_owned()
}

pub(crate) fn contains(bytes: &[u8], needle: &str) -> bool {
  body_text(bytes).contains(needle)
}

pub(crate) fn matches(bytes: &[u8], pattern: &str) -> anyhow::Result<bool> {
  Ok(Regex::new(pattern)?.is_match(&body_text(bytes)))
}

pub(crate) fn scan_pattern_set(
  bytes: &[u8],
  is_truncated: bool,
  pattern_set: &CompiledPatternSet,
) -> BodyScanResult {
  let text = body_text(bytes);
  match pattern_set {
    CompiledPatternSet::Contains(patterns) => {
      for pattern in patterns {
        if let Some(offset) = text.find(pattern) {
          return BodyScanResult {
            matched: true,
            pattern: Some(pattern.clone()),
            offset: Some(offset),
            matched_text: Some(pattern.clone()),
            is_truncated,
          };
        }
      }
      BodyScanResult::no_match(is_truncated)
    }
    CompiledPatternSet::Regex(patterns) => {
      for pattern in patterns {
        if let Some(found) = pattern.find(&text) {
          return BodyScanResult {
            matched: true,
            pattern: Some(pattern.as_str().to_string()),
            offset: Some(found.start()),
            matched_text: Some(found.as_str().to_string()),
            is_truncated,
          };
        }
      }
      BodyScanResult::no_match(is_truncated)
    }
  }
}
