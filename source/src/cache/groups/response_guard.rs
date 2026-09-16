//! Fail-closed protection for unsafe origin responses that cannot finish
//! cache-group invalidation processing.

use http::Method;

use crate::cache::ResponseCache;

/// Arms after an unsafe origin response has been received. Unless disarmed
/// after its authoritative cache-group update, dropping the guard fences the
/// policy so that no representation can be reused on uncertain coherence.
pub(crate) struct CacheGroupOriginResponseGuard<'a> {
  cache: &'a ResponseCache,
  policy: Option<String>,
}

impl CacheGroupOriginResponseGuard<'_> {
  pub(crate) fn disarm(&mut self) {
    self.policy = None;
  }
}

impl Drop for CacheGroupOriginResponseGuard<'_> {
  fn drop(&mut self) {
    if let Some(policy) = self.policy.take() {
      self.cache.groups.fence(&policy);
    }
  }
}

impl ResponseCache {
  pub(crate) fn group_origin_response_guard(
    &self,
    policy_name: Option<&str>,
    method: &Method,
  ) -> CacheGroupOriginResponseGuard<'_> {
    let policy = policy_name.unwrap_or("default");
    let policy =
      (self.groups_enabled(policy) && unsafe_origin_method(method)).then(|| policy.to_string());
    CacheGroupOriginResponseGuard {
      cache: self,
      policy,
    }
  }
}

fn unsafe_origin_method(method: &Method) -> bool {
  !matches!(
    *method,
    Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
  ) && method.as_str() != "QUERY"
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dropped_unsafe_origin_guard_fences_the_policy() {
    let cache = super::super::tests::cache(true);
    assert!(!cache.groups.fenced("default"));
    drop(cache.group_origin_response_guard(None, &Method::POST));
    assert!(cache.groups.fenced("default"));
  }

  #[test]
  fn safe_origin_guards_leave_the_policy_reusable() {
    let cache = super::super::tests::cache(true);
    for method in [
      Method::GET,
      Method::HEAD,
      Method::OPTIONS,
      Method::TRACE,
      Method::from_bytes(b"QUERY").expect("QUERY is a valid method"),
    ] {
      drop(cache.group_origin_response_guard(None, &method));
      assert!(!cache.groups.fenced("default"), "{method}");
    }
  }

  #[test]
  fn disarmed_unsafe_origin_guard_preserves_the_policy() {
    let cache = super::super::tests::cache(true);
    let mut guard = cache.group_origin_response_guard(None, &Method::POST);
    guard.disarm();
    drop(guard);
    assert!(!cache.groups.fenced("default"));
  }
}
