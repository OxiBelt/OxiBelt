use std::path::PathBuf;
use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::*;

impl AuditAnchorRuntime {
  pub(crate) fn test_health_only(health: Arc<RuntimeHealth>, required: bool) -> Self {
    let options = PgConnectOptions::from_str("postgres://oxibelt@localhost/oxibelt")
      .expect("lazy PostgreSQL options should parse");
    let local_pool = PgPoolOptions::new().connect_lazy_with(options.clone());
    let sink_pool = PgPoolOptions::new().connect_lazy_with(options);
    let sink = Arc::new(PostgresAnchorSink::new(
      sink_pool,
      "test-authority".to_string(),
      Duration::from_secs(1),
    ));
    Self {
      inner: Some(Arc::new(AuditAnchorInner {
        identity: AnchorStreamIdentity {
          namespace: "oxibelt".to_string(),
          stream_id: "test-stream".to_string(),
          instance_id: "test-instance".to_string(),
          cluster_id: None,
          membership_epoch: "single_instance".to_string(),
          deployment_epoch: "test-deployment".to_string(),
          signing_key_id: "test-key".to_string(),
          record_interval: 1,
          time_interval_ms: 1_000,
          max_pending_checkpoints: 2,
          max_pending_bytes: 128 * 1024,
        },
        local_pool,
        sink,
        signer: tokio::sync::Mutex::new(None),
        signer_config: AuditCheckpointSignerConfig {
          socket_path: PathBuf::from("test-audit-signer.sock"),
          key_id: "test-key".to_string(),
          token_env: "OXIBELT_TEST_AUDIT_SIGNER_TOKEN".to_string(),
          token_file: None,
          token_file_reload_base_dir: None,
          token_reload_interval: Duration::from_secs(1),
          connect_timeout: Duration::from_secs(1),
          sign_timeout: Duration::from_secs(1),
        },
        pinned_public_key: [0; 32],
        required,
        metrics: Arc::new(Metrics::default()),
        health,
        health_generation: std::sync::Mutex::new(None),
        state: AtomicU8::new(STATE_HEALTHY),
        last_observed_sequence: AtomicU64::new(u64::MAX),
        last_anchored_sequence: AtomicU64::new(u64::MAX),
        last_observed_chain: std::sync::Mutex::new(None),
        last_anchored_chain: std::sync::Mutex::new(None),
        pending_checkpoints: AtomicU64::new(0),
        pending_bytes: AtomicU64::new(0),
        submission_lock: tokio::sync::Mutex::new(()),
      })),
    }
  }

  pub(crate) fn test_fail(&self) {
    self
      .inner
      .as_ref()
      .expect("test anchor should be enabled")
      .failure("continuity_failure", false);
  }

  pub(crate) fn test_healthy(&self) {
    self
      .inner
      .as_ref()
      .expect("test anchor should be enabled")
      .healthy();
  }
}

#[test]
fn stream_identity_is_domain_separated_and_cluster_scoped() {
  let standalone = stream_id("oxibelt", None, "edge-0");
  let clustered = stream_id("oxibelt", Some("edge"), "edge-0");
  assert!(standalone.starts_with("sha256:"));
  assert_ne!(standalone, clustered);
  assert_eq!(standalone, stream_id("oxibelt", None, "edge-0"));
}

#[test]
fn an_old_chain_position_never_covers_a_restarted_chain() {
  let old = Some(("old-chain".to_string(), 99));
  assert!(anchor_position_covers(old.as_ref(), "old-chain", 0));
  assert!(!anchor_position_covers(old.as_ref(), "new-chain", 0));
}
