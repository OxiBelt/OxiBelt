use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;

#[derive(Debug, Default)]
pub struct Metrics {
  requests_total: AtomicU64,
  responses_total: AtomicU64,
  upstream_errors_total: AtomicU64,
  cache_hits_total: AtomicU64,
  cache_misses_total: AtomicU64,
}

impl Metrics {
  pub fn new() -> Arc<Self> {
    Arc::new(Self::default())
  }

  pub fn record_request(&self) {
    self.requests_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_response(&self, status: StatusCode) {
    self.responses_total.fetch_add(1, Ordering::Relaxed);
    if status.is_server_error() {
      self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
    }
  }

  pub fn record_cache_hit(&self) {
    self.cache_hits_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_miss(&self) {
    self.cache_misses_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn prometheus(&self) -> String {
    format!(
      "# TYPE oxibelt_requests_total counter\noxibelt_requests_total {}\n# TYPE oxibelt_responses_total counter\noxibelt_responses_total {}\n# TYPE oxibelt_upstream_errors_total counter\noxibelt_upstream_errors_total {}\n# TYPE oxibelt_cache_hits_total counter\noxibelt_cache_hits_total {}\n# TYPE oxibelt_cache_misses_total counter\noxibelt_cache_misses_total {}\n",
      self.requests_total.load(Ordering::Relaxed),
      self.responses_total.load(Ordering::Relaxed),
      self.upstream_errors_total.load(Ordering::Relaxed),
      self.cache_hits_total.load(Ordering::Relaxed),
      self.cache_misses_total.load(Ordering::Relaxed),
    )
  }
}
