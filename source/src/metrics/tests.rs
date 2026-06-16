use http::StatusCode;

use super::*;

#[test]
fn prometheus_output_omits_waf_rule_metadata() {
  let metrics = Metrics::new();
  let config = MetricsConfig::default();
  let body = metrics.prometheus(
    &config,
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains("oxibelt_requests_total"));
  assert!(body.contains("oxibelt_cache_tag_purges_total"));
  assert!(body.contains("oxibelt_cache_background_refresh_success_total"));
  assert!(body.contains("oxibelt_cache_disk_recovered_entries_total"));
  assert!(body.contains("oxibelt_tls_server_session_storage_put_total"));
  assert!(!body.contains("oxibelt_waf_rule_hits_total"));
  assert!(!body.contains("rule_name"));
  assert!(!body.contains("rule_id"));
}

#[test]
fn prometheus_output_includes_tls_session_storage_diagnostics() {
  let metrics = Metrics::new();
  let config = MetricsConfig::default();
  let body = metrics.prometheus(
    &config,
    CacheStats::default(),
    TlsServerSessionStorageStats {
      put_count: 11,
      get_count: 13,
      take_count: 17,
      lock_wait_ns: 19,
      put_duration_ns: 23,
    },
  );

  assert!(body.contains("oxibelt_tls_server_session_storage_put_total 11"));
  assert!(body.contains("oxibelt_tls_server_session_storage_get_total 13"));
  assert!(body.contains("oxibelt_tls_server_session_storage_take_total 17"));
  assert!(body.contains("oxibelt_tls_server_session_storage_lock_wait_ns_total 19"));
  assert!(body.contains("oxibelt_tls_server_session_storage_put_duration_ns_total 23"));
}

#[test]
fn prometheus_output_includes_plain_proxy_fast_path_decisions() {
  let metrics = Metrics::new();
  metrics.record_plain_proxy_fast_path_decision("h1", "hit", "eligible");
  metrics.record_plain_proxy_fast_path_decision("h1", "miss", "cache_policy");
  metrics.record_plain_proxy_fast_path_decision("h1", "miss", "unknown");

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains(
    "oxibelt_http_fast_path_decisions_total{path=\"plain_proxy\",protocol=\"h1\",outcome=\"hit\",reason=\"eligible\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_fast_path_decisions_total{path=\"plain_proxy\",protocol=\"h1\",outcome=\"miss\",reason=\"cache_policy\"} 1"
  ));
  assert!(!body.contains("unknown"));
}

#[test]
fn prometheus_output_includes_upstream_pool_health_metrics() {
  let metrics = Metrics::new();
  let config = MetricsConfig::default();
  metrics.set_upstream_pool_server_counts(vec![(
    "app-pool".to_string(),
    "nomad".to_string(),
    "ready".to_string(),
    "outlier_ejected".to_string(),
    2,
  )]);
  metrics.record_upstream_pool_health_report("app-pool", "nomad", "failure", "passive_failure");
  metrics.record_upstream_pool_outlier_ejection("app-pool", "nomad", "outlier_ejected");

  let body = metrics.prometheus(
    &config,
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains("oxibelt_upstream_pool_servers"));
  assert!(body.contains("source=\"nomad\""));
  assert!(body.contains("reason=\"outlier_ejected\""));
  assert!(body.contains("oxibelt_upstream_pool_health_reports_total"));
  assert!(body.contains("outcome=\"failure\""));
  assert!(body.contains("oxibelt_upstream_pool_outlier_ejections_total"));
  assert!(!body.contains("http://"));
  assert!(!body.contains("secret"));
}

#[test]
fn striped_counters_sum_all_increments() {
  let metrics = Metrics::new();
  for _ in 0..7 {
    metrics.record_request();
  }
  for status in [
    StatusCode::OK,
    StatusCode::CREATED,
    StatusCode::BAD_GATEWAY,
    StatusCode::GATEWAY_TIMEOUT,
  ] {
    metrics.record_response(status);
  }

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );
  assert!(body.contains("oxibelt_requests_total 7\n"));
  assert!(body.contains("oxibelt_responses_total 4\n"));
  assert!(body.contains("oxibelt_upstream_errors_total 2\n"));
}
