use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use super::{CompiledPatternSet, WafBodyInput, body_scan};

#[derive(Default)]
pub(super) struct BodyTextCaches {
  request: OnceLock<Arc<str>>,
  response: OnceLock<Arc<str>>,
  stream: OnceLock<Arc<str>>,
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
      .get_or_init(|| Arc::from(body_scan::body_text(body.bytes)))
      .as_ref()
  }

  pub(super) fn text_arc(&self, slot: BodyTextSlot, body: WafBodyInput<'_>) -> Arc<str> {
    self
      .cell(slot)
      .get_or_init(|| Arc::from(body_scan::body_text(body.bytes)))
      .clone()
  }

  fn cell(&self, slot: BodyTextSlot) -> &OnceLock<Arc<str>> {
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

    let result = body_scan::scan_pattern_set_text_maybe_offloaded(
      self.text_arc(slot, body),
      body.is_truncated,
      pattern_set,
    );
    self.scan_results.borrow_mut().insert(key, result.clone());
    result
  }
}
