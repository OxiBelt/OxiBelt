use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::{CompiledPatternSet, WafBodyInput, body_scan};

#[derive(Default)]
pub(super) struct BodyTextCaches {
  request: OnceLock<String>,
  response: OnceLock<String>,
  stream: OnceLock<String>,
  scan_results: RefCell<HashMap<(BodyTextSlot, String), body_scan::BodyScanResult>>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(super) enum BodyTextSlot {
  Request,
  Response,
  Stream,
}

impl BodyTextCaches {
  pub(super) fn text(&self, slot: BodyTextSlot, body: WafBodyInput<'_>) -> &str {
    self
      .cell(slot)
      .get_or_init(|| body_scan::body_text(body.bytes))
      .as_str()
  }

  fn cell(&self, slot: BodyTextSlot) -> &OnceLock<String> {
    match slot {
      BodyTextSlot::Request => &self.request,
      BodyTextSlot::Response => &self.response,
      BodyTextSlot::Stream => &self.stream,
    }
  }

  pub(super) fn scan_pattern_set(
    &self,
    slot: BodyTextSlot,
    body: WafBodyInput<'_>,
    pattern_set_name: &str,
    pattern_set: &CompiledPatternSet,
  ) -> body_scan::BodyScanResult {
    let key = (slot, pattern_set_name.to_string());
    if let Some(result) = self.scan_results.borrow().get(&key).cloned() {
      return result;
    }

    let result =
      body_scan::scan_pattern_set_text(self.text(slot, body), body.is_truncated, pattern_set);
    self.scan_results.borrow_mut().insert(key, result.clone());
    result
  }
}
