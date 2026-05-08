use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;

use crate::cache::CacheStats;
use crate::waf::WafRuleHitSnapshot;

#[derive(Debug, Default)]
pub struct Metrics {
  requests_total: AtomicU64,
  responses_total: AtomicU64,
  upstream_errors_total: AtomicU64,
  cache_hits_total: AtomicU64,
  cache_misses_total: AtomicU64,
  cache_revalidations_total: AtomicU64,
  cache_stale_served_total: AtomicU64,
  cache_purges_total: AtomicU64,
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

  pub fn record_cache_revalidation(&self) {
    self
      .cache_revalidations_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_stale(&self) {
    self
      .cache_stale_served_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_purge(&self) {
    self.cache_purges_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn prometheus(&self, cache: CacheStats, waf_rule_hits: &[WafRuleHitSnapshot]) -> String {
    let mut output = format!(
      "# TYPE oxibelt_requests_total counter\noxibelt_requests_total {}\n# TYPE oxibelt_responses_total counter\noxibelt_responses_total {}\n# TYPE oxibelt_upstream_errors_total counter\noxibelt_upstream_errors_total {}\n# TYPE oxibelt_cache_hits_total counter\noxibelt_cache_hits_total {}\n# TYPE oxibelt_cache_misses_total counter\noxibelt_cache_misses_total {}\n# TYPE oxibelt_cache_revalidations_total counter\noxibelt_cache_revalidations_total {}\n# TYPE oxibelt_cache_stale_served_total counter\noxibelt_cache_stale_served_total {}\n# TYPE oxibelt_cache_purges_total counter\noxibelt_cache_purges_total {}\n# TYPE oxibelt_cache_memory_entries gauge\noxibelt_cache_memory_entries {}\n# TYPE oxibelt_cache_disk_entries gauge\noxibelt_cache_disk_entries {}\n# TYPE oxibelt_cache_tmpfs_entries gauge\noxibelt_cache_tmpfs_entries {}\n# TYPE oxibelt_cache_memory_bytes gauge\noxibelt_cache_memory_bytes {}\n# TYPE oxibelt_cache_disk_bytes gauge\noxibelt_cache_disk_bytes {}\n# TYPE oxibelt_cache_tmpfs_bytes gauge\noxibelt_cache_tmpfs_bytes {}\n",
      self.requests_total.load(Ordering::Relaxed),
      self.responses_total.load(Ordering::Relaxed),
      self.upstream_errors_total.load(Ordering::Relaxed),
      self.cache_hits_total.load(Ordering::Relaxed),
      self.cache_misses_total.load(Ordering::Relaxed),
      self.cache_revalidations_total.load(Ordering::Relaxed),
      self.cache_stale_served_total.load(Ordering::Relaxed),
      self.cache_purges_total.load(Ordering::Relaxed),
      cache.memory_entries,
      cache.disk_entries,
      cache.tmpfs_entries,
      cache.memory_bytes,
      cache.disk_bytes,
      cache.tmpfs_bytes,
    );
    output.push_str("# TYPE oxibelt_waf_rule_hits_total counter\n");
    for hit in waf_rule_hits {
      let route = hit.route.as_deref().unwrap_or_default();
      let id = hit.id.as_deref().unwrap_or_default();
      let _ = writeln!(
        output,
        "oxibelt_waf_rule_hits_total{{scope=\"{}\",route=\"{}\",phase=\"{}\",mode=\"{}\",rule_name=\"{}\",rule_id=\"{}\"}} {}",
        prometheus_label_value(&hit.scope),
        prometheus_label_value(route),
        prometheus_label_value(&hit.phase),
        prometheus_label_value(&hit.effective_mode),
        prometheus_label_value(&hit.name),
        prometheus_label_value(id),
        hit.hits
      );
    }
    output
  }
}

fn prometheus_label_value(value: &str) -> String {
  value
    .chars()
    .flat_map(|ch| match ch {
      '\\' => "\\\\".chars().collect::<Vec<_>>(),
      '"' => "\\\"".chars().collect::<Vec<_>>(),
      '\n' => "\\n".chars().collect::<Vec<_>>(),
      ch => vec![ch],
    })
    .collect()
}
