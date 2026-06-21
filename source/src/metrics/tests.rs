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
  assert!(!body.contains("reason=\"unknown\""));
}

#[test]
fn prometheus_output_includes_fast_path_response_body_dispositions() {
  let metrics = Metrics::new();
  metrics.record_fast_path_response_body("h1", "inlined", "known_small");
  metrics.record_fast_path_response_body("h1", "streamed", "unknown_length");
  metrics.record_fast_path_response_body("h1", "error", "read_timeout");
  metrics.record_fast_path_response_body("h1", "streamed", "unknown");

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains(
    "oxibelt_http_fast_path_response_bodies_total{protocol=\"h1\",disposition=\"inlined\",reason=\"known_small\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_fast_path_response_bodies_total{protocol=\"h1\",disposition=\"streamed\",reason=\"unknown_length\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_fast_path_response_bodies_total{protocol=\"h1\",disposition=\"error\",reason=\"read_timeout\"} 1"
  ));
  assert!(!body.contains("unknown\"} 1"));
}

#[test]
fn prometheus_output_includes_direct_h1_pool_events() {
  let metrics = Metrics::new();
  metrics.record_direct_h1_pool_event("hit");
  metrics.record_direct_h1_pool_event("reconnect");
  metrics.record_direct_h1_pool_event("unknown");

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains("oxibelt_http_direct_h1_pool_events_total{event=\"hit\"} 1"));
  assert!(body.contains("oxibelt_http_direct_h1_pool_events_total{event=\"reconnect\"} 1"));
  assert!(!body.contains("event=\"unknown\""));
}

#[test]
fn prometheus_output_includes_direct_h2_pool_events() {
  let metrics = Metrics::new();
  metrics.record_direct_h2_pool_event("hit");
  metrics.record_direct_h2_pool_event("miss_saturated");
  metrics.record_direct_h2_pool_event("connect");
  metrics.record_direct_h2_pool_event("unknown");

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains("oxibelt_http_direct_h2_pool_events_total{event=\"hit\"} 1"));
  assert!(body.contains("oxibelt_http_direct_h2_pool_events_total{event=\"miss_saturated\"} 1"));
  assert!(body.contains("oxibelt_http_direct_h2_pool_events_total{event=\"connect\"} 1"));
  assert!(!body.contains("event=\"unknown\""));
}

#[test]
fn prometheus_output_includes_static_fast_path_responses() {
  let metrics = Metrics::new();
  metrics.record_static_fast_path_response("hot_object", "served");
  metrics.record_static_fast_path_response("sendfile", "fallback");
  metrics.record_static_fast_path_response("bytes", "served");

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains(
    "oxibelt_http_static_fast_path_responses_total{source=\"hot_object\",outcome=\"served\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_static_fast_path_responses_total{source=\"sendfile\",outcome=\"fallback\"} 1"
  ));
  assert!(!body.contains("source=\"bytes\""));
}

#[test]
fn prometheus_output_includes_upstream_client_reuse_metrics() {
  let metrics = Metrics::new();
  metrics.record_http_upstream_client_request("h1", "http", "primary");
  metrics.record_http_upstream_client_request("h1", "http", "primary");
  metrics.record_http_upstream_client_pool_miss("h1", "http", "primary");
  metrics.record_http_upstream_client_connection_created("h1", "http", "primary");
  metrics.record_http_upstream_client_request("h3", "https", "primary");
  metrics.record_http_upstream_client_pool_miss("h3", "https", "primary");
  metrics.record_http_upstream_client_connection_created("h3", "https", "primary");

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(body.contains(
    "oxibelt_http_upstream_client_requests_total{version=\"h1\",scheme=\"http\",pool=\"primary\"} 2"
  ));
  assert!(body.contains(
    "oxibelt_http_upstream_client_pool_misses_total{version=\"h1\",scheme=\"http\",pool=\"primary\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_upstream_client_connections_created_total{version=\"h1\",scheme=\"http\",pool=\"primary\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_upstream_client_reuse_estimate{version=\"h1\",scheme=\"http\",pool=\"primary\"} 0.500000"
  ));
  assert!(body.contains(
    "oxibelt_http_upstream_client_requests_total{version=\"h3\",scheme=\"https\",pool=\"primary\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_upstream_client_pool_misses_total{version=\"h3\",scheme=\"https\",pool=\"primary\"} 1"
  ));
  assert!(body.contains(
    "oxibelt_http_upstream_client_connections_created_total{version=\"h3\",scheme=\"https\",pool=\"primary\"} 1"
  ));
}

#[test]
fn prometheus_output_includes_downstream_h1_flush_metrics() {
  let metrics = Metrics::new();
  metrics.record_http_downstream_write_flush("h1", "tls");
  metrics.record_http_downstream_write_flush("h2", "tls");

  let body = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );

  assert!(
    body
      .contains("oxibelt_http_downstream_write_flushes_total{protocol=\"h1\",transport=\"tls\"} 1")
  );
  assert!(!body.contains("oxibelt_http_downstream_write_flushes_total{protocol=\"h2\""));
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
