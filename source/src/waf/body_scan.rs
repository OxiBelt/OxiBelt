//! Body inspection planning and scan execution.
//! The scanner treats all decoded body text as untrusted rule input.

use std::sync::Arc;

use regex::Regex;
use tokio::runtime::{Handle, RuntimeFlavor};

use crate::runtime_health::{RuntimeSubsystem, RuntimeSubsystemError};

use super::CompiledPatternSet;

const BLOCKING_TEXT_SCAN_MIN_BYTES: usize = 64 * 1024;

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

pub(crate) fn contains_text_maybe_offloaded(text: Arc<str>, needle: &str) -> bool {
  if let Some(handle) = blocking_scan_handle(text.len()) {
    let needle = needle.to_string();
    return run_on_blocking_pool(handle, move || text.contains(&needle)).unwrap_or_else(|error| {
      tracing::error!(error = %error, "failing WAF text match closed");
      true
    });
  }
  text.contains(needle)
}

pub(crate) fn matches_text(text: &str, pattern: &str) -> anyhow::Result<bool> {
  Ok(Regex::new(pattern)?.is_match(text))
}

pub(crate) fn matches_text_maybe_offloaded(text: Arc<str>, pattern: &str) -> anyhow::Result<bool> {
  if let Some(handle) = blocking_scan_handle(text.len()) {
    let pattern = pattern.to_string();
    return run_on_blocking_pool(handle, move || matches_text(&text, &pattern))
      .map_err(anyhow::Error::new)?;
  }
  matches_text(&text, pattern)
}

pub(crate) fn matches_regex_text_maybe_offloaded(text: Arc<str>, regex: &Regex) -> bool {
  if let Some(handle) = blocking_scan_handle(text.len()) {
    let regex = regex.clone();
    return run_on_blocking_pool(handle, move || regex.is_match(&text)).unwrap_or_else(|error| {
      tracing::error!(error = %error, "failing WAF regex match closed");
      true
    });
  }
  regex.is_match(&text)
}

pub(crate) fn scan_pattern_set_text(
  text: &str,
  is_truncated: bool,
  pattern_set: &CompiledPatternSet,
) -> BodyScanResult {
  match pattern_set {
    CompiledPatternSet::Contains(patterns) => patterns.scan(text, is_truncated),
    CompiledPatternSet::Regex(patterns) => patterns.scan(text, is_truncated),
  }
}

pub(crate) fn scan_pattern_set_text_maybe_offloaded(
  text: Arc<str>,
  is_truncated: bool,
  pattern_set: &CompiledPatternSet,
) -> BodyScanResult {
  if let Some(handle) = blocking_scan_handle(text.len()) {
    let pattern_set = pattern_set.clone();
    return run_on_blocking_pool(handle, move || {
      scan_pattern_set_text(&text, is_truncated, &pattern_set)
    })
    .unwrap_or_else(|error| {
      tracing::error!(error = %error, "failing WAF pattern-set scan closed");
      BodyScanResult {
        matched: true,
        pattern: Some("runtime-subsystem-unavailable".to_string()),
        offset: None,
        matched_text: None,
        is_truncated,
      }
    });
  }
  scan_pattern_set_text(&text, is_truncated, pattern_set)
}

fn blocking_scan_handle(text_len: usize) -> Option<Handle> {
  if text_len < BLOCKING_TEXT_SCAN_MIN_BYTES {
    return None;
  }
  let handle = Handle::try_current().ok()?;
  (handle.runtime_flavor() == RuntimeFlavor::MultiThread).then_some(handle)
}

fn run_on_blocking_pool<T, F>(handle: Handle, work: F) -> Result<T, RuntimeSubsystemError>
where
  T: Send + 'static,
  F: FnOnce() -> T + Send + 'static,
{
  tokio::task::block_in_place(|| handle.block_on(tokio::task::spawn_blocking(work)))
    .map_err(|_| RuntimeSubsystemError::CriticalStateUnavailable(RuntimeSubsystem::Waf))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sync_scan_still_works_without_tokio_runtime() {
    let result = contains_text_maybe_offloaded(Arc::<str>::from("a".repeat(70 * 1024)), "aaa");
    assert!(result);
  }
}
