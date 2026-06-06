//! Support bundle assembly and redacted runtime snapshots.
//! Bundle fields must be useful for debugging without exposing credentials or private URLs.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::cache::CacheStats;
use crate::pools::PoolRuntimeSnapshot;
use crate::state::AppSnapshot;
use crate::tls::TlsServerSessionStorageStats;

use super::{DiagnosticReport, DoctorOptions, diagnose_config};

mod process;
mod tls;
pub use process::ProcessSnapshot;
use process::process_snapshot;
pub use tls::TlsRuntimeSnapshot;

const SUPPORT_BUNDLE_FORMAT_VERSION: u32 = 1;
const WAF_RULE_LIMIT: usize = 50;

/// Redacted support bundle assembled from runtime, config, and system snapshots.
#[derive(Debug, Serialize)]
pub struct SupportBundle {
  pub metadata: SupportBundleMetadata,
  pub config: SupportBundleConfig,
  pub doctor: DiagnosticReport,
  pub runtime_snapshot: RuntimeSnapshot,
  pub waf: WafSnapshot,
  pub dynamic_policy: DynamicPolicySnapshot,
  pub metrics: String,
}

#[derive(Debug, Serialize)]
pub struct SupportBundleMetadata {
  pub format_version: u32,
  pub generated_at_unix_ms: u64,
  pub package_version: &'static str,
  pub target_os: &'static str,
  pub target_arch: &'static str,
  pub process_id: u32,
  pub redacted: bool,
}

#[derive(Debug, Serialize)]
pub struct SupportBundleConfig {
  pub status: Value,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub effective_toml: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeSnapshot {
  pub lifecycle: LifecycleSnapshot,
  pub listeners: ListenerSnapshot,
  pub admin: AdminRuntimeSnapshot,
  pub metrics: MetricsRuntimeSnapshot,
  pub health: HealthRuntimeSnapshot,
  pub tls: TlsRuntimeSnapshot,
  pub inventory: InventorySnapshot,
  pub upstreams: Vec<UpstreamSnapshot>,
  pub upstream_pools: Vec<PoolSnapshot>,
  pub cache: CacheStatsSnapshot,
  pub tls_resumption: TlsSessionStorageSnapshot,
  pub ipm: IpmSnapshot,
  pub shared_state: SharedStateSnapshot,
  pub dynamic_policy: DynamicPolicyRuntimeSnapshot,
  pub remote_signer: RemoteSignerSnapshot,
  pub process: ProcessSnapshot,
}

#[derive(Debug, Serialize)]
pub struct LifecycleSnapshot {
  pub draining: bool,
  pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ListenerSnapshot {
  pub https_bind: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub http_bind: Option<String>,
  pub http_mode: String,
  pub http1: bool,
  pub http2: bool,
  pub http3: bool,
  pub proxy_protocol_enabled: bool,
  pub stream_listener_count: usize,
  pub webrtc_turn_listener_count: usize,
}

#[derive(Debug, Serialize)]
pub struct AdminRuntimeSnapshot {
  pub enabled: bool,
  pub bind: String,
  pub transport: String,
  pub tls_enabled: bool,
  pub cache_purge_signing_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct MetricsRuntimeSnapshot {
  pub enabled: bool,
  pub bind: String,
  pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct HealthRuntimeSnapshot {
  pub enabled: bool,
  pub bind: String,
  pub ready_path: String,
  pub live_path: String,
}

#[derive(Debug, Serialize)]
pub struct InventorySnapshot {
  pub routes: usize,
  pub upstreams: usize,
  pub upstream_pools: usize,
  pub upstream_pool_servers: usize,
  pub turn_upstream_pools: usize,
  pub turn_upstream_pool_servers: usize,
  pub cache_policies: usize,
  pub rate_limits: usize,
  pub connection_limits: usize,
}

#[derive(Debug, Serialize)]
pub struct UpstreamSnapshot {
  pub name: String,
  pub origin: String,
  pub max_http_version: String,
  pub preserve_host: bool,
}

#[derive(Debug, Serialize)]
pub struct PoolSnapshot {
  pub name: String,
  pub algorithm: String,
  pub servers: Vec<PoolServerSnapshot>,
}

#[derive(Debug, Serialize)]
pub struct PoolServerSnapshot {
  pub id: String,
  pub upstream_name: String,
  pub origin: String,
  pub source: String,
  pub state: String,
  pub weight: u32,
  pub max_conns: usize,
  pub backup: bool,
  pub active: usize,
  pub healthy: bool,
  pub health_reason: String,
  pub last_health_check_ms: Option<u64>,
  pub ejected_until_ms: Option<u64>,
  pub ejection_count: u32,
  pub slow_start_remaining_ms: Option<u64>,
  pub effective_weight_percent: u32,
}

#[derive(Debug, Serialize)]
pub struct CacheStatsSnapshot {
  pub memory_entries: usize,
  pub disk_entries: usize,
  pub tmpfs_entries: usize,
  pub memory_bytes: usize,
  pub disk_bytes: usize,
  pub tmpfs_bytes: usize,
  pub disk_recovered_entries_total: u64,
  pub disk_recovery_errors_total: u64,
  pub disk_recovery_removed_files_total: u64,
}

#[derive(Debug, Serialize)]
pub struct TlsSessionStorageSnapshot {
  pub put_count: u64,
  pub get_count: u64,
  pub take_count: u64,
  pub lock_wait_ns: u64,
  pub put_duration_ns: u64,
}

#[derive(Debug, Serialize)]
pub struct IpmSnapshot {
  pub enabled: bool,
  pub principal_count: usize,
  pub credential_count: usize,
  pub policy_count: usize,
  pub binding_count: usize,
}

#[derive(Debug, Serialize)]
pub struct SharedStateSnapshot {
  pub enabled: bool,
  pub namespace: String,
  pub backend_count: usize,
  pub default_backend: Option<String>,
  pub feature_backends: BTreeMap<String, Option<String>>,
  pub runtime_connected: bool,
}

#[derive(Debug, Serialize)]
pub struct DynamicPolicyRuntimeSnapshot {
  pub enabled: bool,
  pub automation_api_enabled: bool,
  pub backend: Option<String>,
  pub max_policies: usize,
  pub require_ttl: bool,
}

#[derive(Debug, Serialize)]
pub struct RemoteSignerSnapshot {
  pub enabled: bool,
  pub socket_path_configured: bool,
  pub key_id_configured: bool,
}

#[derive(Debug, Serialize)]
pub struct WafSnapshot {
  pub enabled: bool,
  pub mode: String,
  pub crs_compatibility: Value,
  pub top_rule_hits: Value,
  pub top_rule_costs: Value,
}

#[derive(Debug, Serialize)]
pub struct DynamicPolicySnapshot {
  pub enabled: bool,
  pub automation_api_enabled: bool,
  pub active_policy_count: Option<usize>,
  pub policies: Vec<RedactedDynamicPolicyRecord>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RedactedDynamicPolicyRecord {
  pub id: i64,
  pub enabled: bool,
  pub priority: i32,
  pub source: String,
  pub action: String,
  pub subject_type: String,
  pub subject_redacted: bool,
  pub mode: String,
  pub rate_configured: bool,
  pub burst_configured: bool,
  pub status: Option<i32>,
  pub body_configured: bool,
  pub reason_configured: bool,
  pub signature_present: bool,
  pub expires_at: Option<String>,
}

pub async fn build_support_bundle(
  snapshot: &AppSnapshot,
  config_status: Value,
  effective_toml: Option<String>,
  options: &DoctorOptions,
) -> SupportBundle {
  let doctor = diagnose_config(snapshot.config.clone(), options).await;
  let runtime_snapshot = build_runtime_snapshot(snapshot);
  let waf = build_waf_snapshot(snapshot);
  let dynamic_policy = build_dynamic_policy_snapshot(snapshot).await;
  let metrics = snapshot.metrics.prometheus(
    &snapshot.config.metrics,
    snapshot.cache.stats(),
    snapshot.tls_resumption.server_session_storage_stats(),
  );
  SupportBundle {
    metadata: SupportBundleMetadata {
      format_version: SUPPORT_BUNDLE_FORMAT_VERSION,
      generated_at_unix_ms: now_unix_ms(),
      package_version: env!("CARGO_PKG_VERSION"),
      target_os: std::env::consts::OS,
      target_arch: std::env::consts::ARCH,
      process_id: std::process::id(),
      redacted: true,
    },
    config: SupportBundleConfig {
      status: config_status,
      effective_toml,
    },
    doctor,
    runtime_snapshot,
    waf,
    dynamic_policy,
    metrics,
  }
}

pub fn build_runtime_snapshot(snapshot: &AppSnapshot) -> RuntimeSnapshot {
  RuntimeSnapshot {
    lifecycle: LifecycleSnapshot {
      draining: snapshot.lifecycle.is_draining(),
      reason: snapshot.lifecycle.reason().to_string(),
    },
    listeners: ListenerSnapshot {
      https_bind: snapshot.config.listeners.https_bind.to_string(),
      http_bind: snapshot
        .config
        .listeners
        .http_bind
        .map(|bind| bind.to_string()),
      http_mode: format!("{:?}", snapshot.config.listeners.http_mode),
      http1: snapshot.config.listeners.http1,
      http2: snapshot.config.listeners.http2,
      http3: snapshot.config.listeners.http3,
      proxy_protocol_enabled: snapshot.config.listeners.proxy_protocol.enabled,
      stream_listener_count: snapshot.config.stream_listeners.len(),
      webrtc_turn_listener_count: snapshot.config.webrtc_turn_listeners.len(),
    },
    admin: AdminRuntimeSnapshot {
      enabled: snapshot.config.admin.enabled,
      bind: snapshot.config.admin.bind.to_string(),
      transport: format!("{:?}", snapshot.config.admin.transport),
      tls_enabled: snapshot.config.admin.tls.enabled,
      cache_purge_signing_enabled: snapshot.config.admin.cache_purge_signing.enabled,
    },
    metrics: MetricsRuntimeSnapshot {
      enabled: snapshot.config.metrics.enabled,
      bind: snapshot.config.metrics.bind.to_string(),
      detail: format!("{:?}", snapshot.config.metrics.detail),
    },
    health: HealthRuntimeSnapshot {
      enabled: snapshot.config.health.enabled,
      bind: snapshot.config.health.bind.to_string(),
      ready_path: snapshot.config.health.ready_path.clone(),
      live_path: snapshot.config.health.live_path.clone(),
    },
    tls: TlsRuntimeSnapshot {
      downstream_cert_chain_configured: snapshot
        .config
        .source_paths
        .downstream_tls_cert_chain
        .is_some(),
      downstream_private_key_configured: snapshot
        .config
        .source_paths
        .downstream_tls_private_key
        .is_some(),
      crlite_mode: snapshot.config.tls.crlite.mode.as_str().to_string(),
      crlite_filter_file_configured: snapshot
        .config
        .source_paths
        .downstream_tls_crlite_filter_file
        .is_some(),
      crlite: snapshot.crlite.status(),
      ocsp_mode: format!("{:?}", snapshot.config.tls.ocsp.mode),
      ocsp_response_file_configured: snapshot
        .config
        .source_paths
        .downstream_tls_ocsp_response_file
        .is_some(),
      ocsp: snapshot.ocsp_staple.status(),
      quic_host_key_configured: snapshot.config.source_paths.quic_host_key_file.is_some(),
      remote_signer_enabled: snapshot.config.tls.remote_signer.enabled,
      admin_tls_configured: snapshot.admin_tls_server_config.is_some(),
    },
    inventory: InventorySnapshot {
      routes: snapshot.config.routes.len(),
      upstreams: snapshot.config.upstreams.len(),
      upstream_pools: snapshot.config.upstream_pools.len(),
      upstream_pool_servers: snapshot
        .config
        .upstream_pools
        .iter()
        .map(|pool| pool.servers.len())
        .sum(),
      turn_upstream_pools: snapshot.config.turn_upstream_pools.len(),
      turn_upstream_pool_servers: snapshot
        .config
        .turn_upstream_pools
        .iter()
        .map(|pool| pool.servers.len())
        .sum(),
      cache_policies: snapshot.config.cache.policies.len(),
      rate_limits: snapshot.config.rate_limits.len(),
      connection_limits: snapshot.config.connection_limits.len(),
    },
    upstreams: snapshot
      .config
      .upstreams
      .iter()
      .map(|upstream| UpstreamSnapshot {
        name: upstream.name.clone(),
        origin: sanitize_url(upstream.origin.as_str()),
        max_http_version: format!("{:?}", upstream.max_http_version),
        preserve_host: upstream.preserve_host,
      })
      .collect(),
    upstream_pools: snapshot
      .pools
      .snapshots()
      .into_iter()
      .map(redact_pool_snapshot)
      .collect(),
    cache: cache_stats_snapshot(snapshot.cache.stats()),
    tls_resumption: tls_stats_snapshot(snapshot.tls_resumption.server_session_storage_stats()),
    ipm: IpmSnapshot {
      enabled: snapshot.config.ipm.enabled,
      principal_count: snapshot.ipm.list_principals().len(),
      credential_count: snapshot.ipm.list_credentials().len(),
      policy_count: snapshot.ipm.list_policies().len(),
      binding_count: snapshot.config.ipm.bindings.len(),
    },
    shared_state: SharedStateSnapshot {
      enabled: snapshot.config.shared_state.enabled,
      namespace: snapshot.config.shared_state.namespace.clone(),
      backend_count: snapshot.config.shared_state.backends.len(),
      default_backend: snapshot.config.shared_state.default_backend.clone(),
      feature_backends: shared_state_feature_backends(snapshot),
      runtime_connected: snapshot.shared_state.is_some(),
    },
    dynamic_policy: DynamicPolicyRuntimeSnapshot {
      enabled: snapshot.config.dynamic_policy.enabled,
      automation_api_enabled: snapshot.config.dynamic_policy.automation_api.enabled,
      backend: snapshot
        .config
        .dynamic_policy_backend_name()
        .map(str::to_string),
      max_policies: snapshot.config.dynamic_policy.max_policies,
      require_ttl: snapshot.config.dynamic_policy.automation_api.require_ttl,
    },
    remote_signer: RemoteSignerSnapshot {
      enabled: snapshot.config.tls.remote_signer.enabled,
      socket_path_configured: !snapshot
        .config
        .tls
        .remote_signer
        .socket_path
        .as_os_str()
        .is_empty(),
      key_id_configured: !snapshot.config.tls.remote_signer.key_id.trim().is_empty(),
    },
    process: process_snapshot(),
  }
}

fn build_waf_snapshot(snapshot: &AppSnapshot) -> WafSnapshot {
  let mut hits = snapshot.waf.rule_hit_snapshots();
  let mut costs = snapshot.waf.rule_cost_snapshots();
  hits.truncate(WAF_RULE_LIMIT);
  costs.truncate(WAF_RULE_LIMIT);
  WafSnapshot {
    enabled: snapshot.config.waf.enabled,
    mode: format!("{:?}", snapshot.config.waf.mode),
    crs_compatibility: serde_json::to_value(crate::waf::crs_compatibility_matrix())
      .unwrap_or(Value::Null),
    top_rule_hits: serde_json::to_value(hits).unwrap_or(Value::Null),
    top_rule_costs: serde_json::to_value(costs).unwrap_or(Value::Null),
  }
}

async fn build_dynamic_policy_snapshot(snapshot: &AppSnapshot) -> DynamicPolicySnapshot {
  if !snapshot.config.dynamic_policy.enabled {
    return DynamicPolicySnapshot {
      enabled: false,
      automation_api_enabled: snapshot.config.dynamic_policy.automation_api.enabled,
      active_policy_count: Some(0),
      policies: Vec::new(),
      error: None,
    };
  }
  if !snapshot.config.dynamic_policy.automation_api.enabled {
    return DynamicPolicySnapshot {
      enabled: true,
      automation_api_enabled: false,
      active_policy_count: None,
      policies: Vec::new(),
      error: None,
    };
  }
  match snapshot.dynamic_policy.admin_list().await {
    Ok(records) => {
      let policies = records
        .iter()
        .map(|record| RedactedDynamicPolicyRecord {
          id: record.id,
          enabled: record.enabled,
          priority: record.priority,
          source: record.source.clone(),
          action: record.action.clone(),
          subject_type: record.subject_type.clone(),
          subject_redacted: true,
          mode: record.mode.clone(),
          rate_configured: record.rate.is_some(),
          burst_configured: record.burst.is_some(),
          status: record.status,
          body_configured: record.body.is_some(),
          reason_configured: record.reason.is_some(),
          signature_present: record.row_signature.is_some(),
          expires_at: record.expires_at.clone(),
        })
        .collect::<Vec<_>>();
      DynamicPolicySnapshot {
        enabled: true,
        automation_api_enabled: true,
        active_policy_count: Some(policies.iter().filter(|policy| policy.enabled).count()),
        policies,
        error: None,
      }
    }
    Err(error) => DynamicPolicySnapshot {
      enabled: true,
      automation_api_enabled: true,
      active_policy_count: None,
      policies: Vec::new(),
      error: Some(error.to_string()),
    },
  }
}

fn redact_pool_snapshot(pool: PoolRuntimeSnapshot) -> PoolSnapshot {
  PoolSnapshot {
    name: pool.name,
    algorithm: pool.algorithm,
    servers: pool
      .servers
      .into_iter()
      .map(|server| PoolServerSnapshot {
        id: server.id,
        upstream_name: server.upstream_name,
        origin: sanitize_url(&server.origin),
        source: server.source,
        state: server.state,
        weight: server.weight,
        max_conns: server.max_conns,
        backup: server.backup,
        active: server.active,
        healthy: server.healthy,
        health_reason: server.health_reason,
        last_health_check_ms: server.last_health_check_ms,
        ejected_until_ms: server.ejected_until_ms,
        ejection_count: server.ejection_count,
        slow_start_remaining_ms: server.slow_start_remaining_ms,
        effective_weight_percent: server.effective_weight_percent,
      })
      .collect(),
  }
}

fn cache_stats_snapshot(stats: CacheStats) -> CacheStatsSnapshot {
  CacheStatsSnapshot {
    memory_entries: stats.memory_entries,
    disk_entries: stats.disk_entries,
    tmpfs_entries: stats.tmpfs_entries,
    memory_bytes: stats.memory_bytes,
    disk_bytes: stats.disk_bytes,
    tmpfs_bytes: stats.tmpfs_bytes,
    disk_recovered_entries_total: stats.disk_recovered_entries_total,
    disk_recovery_errors_total: stats.disk_recovery_errors_total,
    disk_recovery_removed_files_total: stats.disk_recovery_removed_files_total,
  }
}

fn tls_stats_snapshot(stats: TlsServerSessionStorageStats) -> TlsSessionStorageSnapshot {
  TlsSessionStorageSnapshot {
    put_count: stats.put_count,
    get_count: stats.get_count,
    take_count: stats.take_count,
    lock_wait_ns: stats.lock_wait_ns,
    put_duration_ns: stats.put_duration_ns,
  }
}

fn shared_state_feature_backends(snapshot: &AppSnapshot) -> BTreeMap<String, Option<String>> {
  let shared = &snapshot.config.shared_state;
  BTreeMap::from([
    (
      "rate_limits".to_string(),
      shared
        .rate_limits_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
    (
      "connection_limits".to_string(),
      shared
        .connection_limits_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
    (
      "person_proof".to_string(),
      shared
        .person_proof_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
    (
      "upstream_health".to_string(),
      shared
        .upstream_health_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
    (
      "sticky_sessions".to_string(),
      shared
        .sticky_sessions_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
    (
      "cache".to_string(),
      shared
        .cache_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
    (
      "reload".to_string(),
      shared
        .reload_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
    (
      "dynamic_policy".to_string(),
      shared
        .dynamic_policy_backend
        .clone()
        .or(shared.default_backend.clone()),
    ),
  ])
}

fn now_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(u128::from(u64::MAX)) as u64
}

fn sanitize_url(raw: &str) -> String {
  match Url::parse(raw) {
    Ok(mut url) => {
      let _ = url.set_username("");
      let _ = url.set_password(None);
      url.set_query(None);
      url.set_fragment(None);
      url.to_string()
    }
    Err(_) => raw
      .split_once('?')
      .map_or(raw, |(before_query, _)| before_query)
      .split_once('#')
      .map_or_else(
        || {
          raw
            .split_once('?')
            .map_or(raw, |(before_query, _)| before_query)
            .to_string()
        },
        |(before_fragment, _)| before_fragment.to_string(),
      ),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::Config;
  use crate::state::AppSnapshot;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[test]
  fn sanitize_url_removes_userinfo_query_and_fragment() {
    let redacted = sanitize_url("https://user:secret@example.test/private?token=secret#frag");
    assert_eq!(redacted, "https://example.test/private");
  }

  #[tokio::test]
  async fn runtime_snapshot_redacts_upstream_origin_credentials_and_queries() {
    let temp_dir = common::TempDir::new("support-bundle-redacted-upstream");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "support-bundle-redacted-upstream");
    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
      "origin = \"https://app.internal.example\"",
      "origin = \"https://user:secret@app.internal.example/private?token=secret#frag\"",
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let snapshot = AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize");
    let value = serde_json::to_string(&build_runtime_snapshot(&snapshot))
      .expect("runtime snapshot should serialize");

    assert!(value.contains("https://app.internal.example/private"));
    assert!(value.contains("\"failure_policy\":\"drop_stale\""));
    assert!(!value.contains("user:secret"));
    assert!(!value.contains("token=secret"));
  }

  #[test]
  fn redacted_dynamic_policy_record_omits_subject_body_reason_and_signature_values() {
    let record = RedactedDynamicPolicyRecord {
      id: 7,
      enabled: true,
      priority: 100,
      source: "automation".to_string(),
      action: "reject".to_string(),
      subject_type: "client_ip".to_string(),
      subject_redacted: true,
      mode: "enforce".to_string(),
      rate_configured: false,
      burst_configured: false,
      status: Some(403),
      body_configured: true,
      reason_configured: true,
      signature_present: true,
      expires_at: Some("2026-05-25T00:00:00Z".to_string()),
    };
    let value = serde_json::to_string(&record).expect("record should serialize");

    assert!(value.contains("\"subject_redacted\":true"));
    assert!(value.contains("\"body_configured\":true"));
    assert!(value.contains("\"signature_present\":true"));
    assert!(!value.contains("203.0.113.10"));
    assert!(!value.contains("row_signature"));
    assert!(!value.contains("blocked because"));
    assert!(!value.contains("secret response body"));
  }
}
