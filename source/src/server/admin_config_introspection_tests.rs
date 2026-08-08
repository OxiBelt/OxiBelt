use ::http::StatusCode;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::activation_plan::{
  ConfinementActivationPlan, ConfinementFit, ResolvedActivationOperation,
};
use crate::config::{
  AdminMutationRolloutMode, Config, ConfigOriginKind, ConfigValueOrigin, IpmPolicyConfig,
  IpmPolicyEffect, IpmPolicyStatementConfig, RuntimeOverrides,
};
use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};
use crate::state::{AppHandle, AppSnapshot};

use super::ListenerSupervisor;
use super::admin_auth::{AdminActor, AdminAuthorization};
use super::admin_control::{
  self, AdminControlCommand, AdminControlHandle, AdminControlResponse,
  ControlPlaneConfigPermissions, RollbackSnapshot,
};
use super::admin_ops::admin_config_response;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn actor_and_ipm(action: &str) -> (AdminActor, IpmRuntime) {
  let actor = IpmActor {
    name: "deployer-token".to_string(),
    principal: "deployer".to_string(),
    subject: "deployer@example.com".to_string(),
    groups: vec!["ops".to_string()],
  };
  let policy = IpmPolicyConfig {
    name: "test".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: vec![action.to_string()],
      resources: vec!["*".to_string()],
      conditions: Vec::new(),
    }],
  };
  let ipm = IpmRuntime::test_with_actor_policy("oxibelt", actor.clone(), policy);
  (actor, ipm)
}

async fn test_state(name: &str) -> (common::TempDir, AppHandle, String, String) {
  test_state_with_options(name, None, None, false).await
}

async fn test_state_with_options(
  name: &str,
  listener_bind: Option<SocketAddr>,
  reuse_port: Option<bool>,
  immutable_rollout: bool,
) -> (common::TempDir, AppHandle, String, String) {
  let temp_dir = common::TempDir::new(name);
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
  let mut candidate = common::minimal_config_toml_with_paths(
    cert_path.file_name().unwrap().to_str().unwrap(),
    key_path.file_name().unwrap().to_str().unwrap(),
  );
  let mut effective = common::minimal_config_toml(&cert_path, &key_path);
  if let Some(bind) = listener_bind {
    let bind = bind.to_string();
    candidate = candidate.replacen("127.0.0.1:8443", &bind, 1);
    effective = effective.replacen("127.0.0.1:8443", &bind, 1);
  }
  if let Some(reuse_port) = reuse_port {
    let replacement = format!("reuse_port = {reuse_port}");
    candidate = candidate.replacen("reuse_port = true", &replacement, 1);
    effective = effective.replacen("reuse_port = true", &replacement, 1);
    candidate = candidate.replacen("workers = \"auto\"", "workers = 1", 1);
    effective = effective.replacen("workers = \"auto\"", "workers = 1", 1);
  }
  let config_path = temp_dir.path().join("oxibelt.toml");
  std::fs::write(&config_path, &candidate).expect("config should be written");
  let mut config: Config = toml::from_str(&effective).expect("config should decode");
  config.validate().expect("config should validate");
  config.source_paths.config_entry = Some(config_path.clone());
  config.source_paths.config_dir = Some(temp_dir.path().to_path_buf());
  config.source_paths.cert_dir = Some(temp_dir.path().to_path_buf());
  config.source_paths.oxirule_dir = Some(temp_dir.path().to_path_buf());
  config.source_paths.config_files = vec![config_path.clone()];
  for field_path in ["logging.level", "tls.private_key"] {
    config.source_paths.field_origins.insert(
      field_path.to_string(),
      ConfigValueOrigin {
        kind: ConfigOriginKind::Entry,
        file: Some(config_path.clone()),
        line: None,
        column: None,
      },
    );
  }
  if immutable_rollout {
    config.rollout = crate::config::ConfigRolloutIdentity::validated_immutable_for_planning_test(
      "edge",
      "Deployment",
      "oxibelt",
      &config_path,
    );
  }
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  (temp_dir, AppHandle::new(snapshot), candidate, effective)
}

async fn unused_loopback_address() -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("ephemeral listener should bind");
  listener
    .local_addr()
    .expect("ephemeral listener address should be available")
}

async fn online_activation_plan(
  state: AppHandle,
  control: AdminControlHandle,
  candidate: &str,
) -> serde_json::Value {
  let (actor, ipm) = actor_and_ipm("config:DiffSecrets");
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let request = hyper::Request::builder()
    .method(::http::Method::POST)
    .uri("/admin/v1/config/diff")
    .body(Full::new(Bytes::from(
      serde_json::to_vec(&json!({ "format": "toml", "config": candidate }))
        .expect("planner request should serialize"),
    )))
    .expect("planner request should build");
  let response = admin_config_response(
    request,
    state,
    control,
    &authorization,
    &::http::Method::POST,
    "/admin/v1/config/diff",
  )
  .await;
  let status = response.status();
  let body = response
    .into_body()
    .collect()
    .await
    .expect("planner response should collect")
    .to_bytes();
  assert_eq!(
    status,
    StatusCode::OK,
    "planner response failed: {}",
    String::from_utf8_lossy(&body)
  );
  serde_json::from_slice(&body).expect("planner response should be JSON")
}

async fn drive_config_load(
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  receiver: &mut mpsc::UnboundedReceiver<AdminControlCommand>,
  candidate: String,
) -> AdminControlResponse {
  let if_match = control.status().await["etag"]
    .as_str()
    .expect("Admin control status should expose an ETag")
    .to_string();
  let request = tokio::spawn({
    let control = control.clone();
    async move {
      control
        .load_config(
          "planner-executor-test".to_string(),
          ControlPlaneConfigPermissions {
            admin_update_config: false,
            ipm_update_config: false,
          },
          Some(if_match),
          candidate,
        )
        .await
    }
  });
  let command = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
    .await
    .expect("config-load command should arrive before the test deadline")
    .expect("config-load command channel should remain open");
  let mut rollback: Option<RollbackSnapshot> = None;
  admin_control::handle_admin_control_command(
    command,
    state,
    listeners,
    control,
    &RuntimeOverrides::default(),
    &mut rollback,
  )
  .await;
  request
    .await
    .expect("config-load request task should not panic")
}

#[derive(Debug, Clone, Copy)]
enum ObservedExecutorOutcome {
  SnapshotApplied,
  SameAddressPreparationRejected,
  RestartOnlyRejected,
  ImmutableEndpointRejected,
  AdminClusterDispatchAdmitted,
}

impl ObservedExecutorOutcome {
  const fn required_operation(self) -> ResolvedActivationOperation {
    match self {
      Self::SnapshotApplied => ResolvedActivationOperation::FullSnapshotReload,
      Self::SameAddressPreparationRejected | Self::RestartOnlyRejected => {
        ResolvedActivationOperation::ProcessRestart
      }
      Self::ImmutableEndpointRejected => ResolvedActivationOperation::KubernetesImmutableRollout,
      Self::AdminClusterDispatchAdmitted => ResolvedActivationOperation::AdminClusterRollout,
    }
  }
}

fn assert_plan_covers_observed_executor(
  label: &str,
  plan: &serde_json::Value,
  observed: ObservedExecutorOutcome,
) {
  let minimum: ResolvedActivationOperation =
    serde_json::from_value(plan["activation_plan"]["minimum_required_operation"].clone())
      .expect("minimum operation should use the public vocabulary");
  let selected: ResolvedActivationOperation =
    serde_json::from_value(plan["activation_plan"]["selected_operation"].clone())
      .expect("selected operation should use the public vocabulary");
  let required = observed.required_operation();
  assert!(
    minimum.strength() >= required.strength(),
    "{label} minimum {minimum:?} is weaker than observed executor outcome {observed:?}"
  );
  assert!(
    selected.strength() >= required.strength(),
    "{label} selection {selected:?} is weaker than observed executor outcome {observed:?}"
  );
  assert!(
    selected.strength() >= minimum.strength(),
    "{label} selection is weaker than its published minimum"
  );
  let confinement: ConfinementActivationPlan =
    serde_json::from_value(plan["activation_plan"]["confinement"].clone())
      .expect("production confinement enrichment should use its public schema");
  for (surface, fit) in [
    ("filesystem", confinement.filesystem),
    ("landlock", confinement.landlock),
    ("seccomp", confinement.seccomp),
  ] {
    assert_ne!(
      fit,
      ConfinementFit::Unknown,
      "{label} did not resolve the active {surface} confinement boundary"
    );
  }
}

fn assert_rejected_load_preserves_revision(before: &serde_json::Value, after: &serde_json::Value) {
  for field in ["revision", "etag", "rollback_available"] {
    assert_eq!(after[field], before[field], "rejected load changed {field}");
  }
  assert_eq!(after["last_operation"]["outcome"], "rejected");
}

#[tokio::test]
async fn activation_planner_tracks_live_config_load_listener_restart_and_immutable_boundaries() {
  let bind = unused_loopback_address().await;
  let (_temp_dir, state, current, effective) =
    test_state_with_options("planner-live-full-reload", Some(bind), Some(true), false).await;
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, mut receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut listeners = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    control.clone(),
    super::test_admin_operations(),
  )
  .await
  .expect("live planner listener supervisor should start");
  let candidate = current.replacen(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
    1,
  );
  let plan = online_activation_plan(state.clone(), control.clone(), &candidate).await;
  let before_status = control.status().await;
  let before_snapshot = state.snapshot();
  let response =
    drive_config_load(&state, &mut listeners, &control, &mut receiver, candidate).await;
  assert_eq!(response.status, StatusCode::OK, "{:#}", response.body);
  let after_status = control.status().await;
  let after_snapshot = state.snapshot();
  assert!(
    after_status["revision"].as_u64() > before_status["revision"].as_u64(),
    "successful config load must advance the observed revision"
  );
  assert!(
    !Arc::ptr_eq(&before_snapshot, &after_snapshot),
    "successful config load must publish a new snapshot"
  );
  assert!(!after_snapshot.config.compression.enabled);
  assert_plan_covers_observed_executor(
    "full snapshot reload",
    &plan,
    ObservedExecutorOutcome::SnapshotApplied,
  );
  listeners.shutdown(after_snapshot.as_ref()).await;

  let bind = unused_loopback_address().await;
  let (_temp_dir, state, current, effective) = test_state_with_options(
    "planner-live-listener-conflict",
    Some(bind),
    Some(false),
    false,
  )
  .await;
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, mut receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut listeners = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    control.clone(),
    super::test_admin_operations(),
  )
  .await
  .expect("same-address listener supervisor should start");
  let candidate = current.replacen("backlog = 8192", "backlog = 8193", 1);
  let plan = online_activation_plan(state.clone(), control.clone(), &candidate).await;
  let before_status = control.status().await;
  let before_snapshot = state.snapshot();
  let response =
    drive_config_load(&state, &mut listeners, &control, &mut receiver, candidate).await;
  assert_eq!(response.status, StatusCode::BAD_REQUEST);
  assert!(
    response
      .body
      .get("error")
      .and_then(serde_json::Value::as_str)
      .is_some_and(|error| error.contains("failed to bind downstream listener")),
    "actual same-address preparation failure was not observed: {:#}",
    response.body
  );
  assert_rejected_load_preserves_revision(&before_status, &control.status().await);
  assert!(Arc::ptr_eq(&before_snapshot, &state.snapshot()));
  assert_plan_covers_observed_executor(
    "same-address listener preparation",
    &plan,
    ObservedExecutorOutcome::SameAddressPreparationRejected,
  );
  listeners.shutdown(before_snapshot.as_ref()).await;

  let bind = unused_loopback_address().await;
  let (_temp_dir, state, current, effective) = test_state_with_options(
    "planner-live-restart-rejection",
    Some(bind),
    Some(true),
    false,
  )
  .await;
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, mut receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut listeners = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    control.clone(),
    super::test_admin_operations(),
  )
  .await
  .expect("restart-rejection listener supervisor should start");
  let candidate = current.replacen("worker_threads = \"auto\"", "worker_threads = 997", 1);
  let plan = online_activation_plan(state.clone(), control.clone(), &candidate).await;
  let before_status = control.status().await;
  let before_snapshot = state.snapshot();
  let response =
    drive_config_load(&state, &mut listeners, &control, &mut receiver, candidate).await;
  assert_eq!(response.status, StatusCode::BAD_REQUEST);
  assert!(
    response
      .body
      .get("error")
      .and_then(serde_json::Value::as_str)
      .is_some_and(|error| error.contains("restart OxiBelt")),
    "actual restart-only rejection was not observed: {:#}",
    response.body
  );
  assert_rejected_load_preserves_revision(&before_status, &control.status().await);
  assert!(Arc::ptr_eq(&before_snapshot, &state.snapshot()));
  assert_plan_covers_observed_executor(
    "restart-only config load",
    &plan,
    ObservedExecutorOutcome::RestartOnlyRejected,
  );
  listeners.shutdown(before_snapshot.as_ref()).await;

  let (_temp_dir, state, current, effective) =
    test_state_with_options("planner-live-immutable-rejection", None, None, true).await;
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, _receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let candidate = current.replacen(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
    1,
  );
  let plan = online_activation_plan(state.clone(), control.clone(), &candidate).await;
  let (actor, ipm) = actor_and_ipm("config:Load");
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let request = hyper::Request::builder()
    .method(::http::Method::POST)
    .uri("/admin/v1/config/load")
    .body(Full::new(Bytes::from(
      serde_json::to_vec(&json!({ "format": "toml", "config": candidate }))
        .expect("immutable load request should serialize"),
    )))
    .expect("immutable load request should build");
  let response = admin_config_response(
    request,
    state.clone(),
    control.clone(),
    &authorization,
    &::http::Method::POST,
    "/admin/v1/config/load",
  )
  .await;
  assert_eq!(response.status(), StatusCode::CONFLICT);
  let body = response
    .into_body()
    .collect()
    .await
    .expect("immutable rejection should collect")
    .to_bytes();
  assert_eq!(
    body.as_ref(),
    b"per-Pod configuration mutation is disabled in kubernetes_immutable rollout mode"
  );
  assert_plan_covers_observed_executor(
    "Kubernetes immutable config load",
    &plan,
    ObservedExecutorOutcome::ImmutableEndpointRejected,
  );

  let (_temp_dir, state, current, effective) = test_state("planner-live-admin-cluster").await;
  let mut cluster_snapshot = state.snapshot().as_ref().clone();
  cluster_snapshot.config.rollout =
    crate::config::ConfigRolloutIdentity::admin_cluster_for_planning_test("node-a");
  cluster_snapshot.config.admin.mutations.rollout.mode = AdminMutationRolloutMode::AdminCluster;
  cluster_snapshot.config.admin.mutations.rollout.cluster_id = "edge".to_string();
  cluster_snapshot.config.admin.mutations.rollout.members =
    vec!["node-b".to_string(), "node-a".to_string()];
  let state = AppHandle::new(cluster_snapshot);
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, _receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let candidate = current.replacen(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
    1,
  );
  let candidate_activation: toml::Value =
    toml::from_str(&candidate).expect("cluster candidate TOML should parse");
  let mut report = control
    .activation_plan(&candidate_activation)
    .await
    .expect("active activation projection should be available");
  let active = state.snapshot();
  let mut candidate_config = active.config.clone();
  candidate_config.compression.enabled = false;
  let (actor, ipm) = actor_and_ipm("config:DiffSecrets");
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  super::admin_config_diff::enrich_activation_plan(
    &mut report,
    &active.config,
    &candidate_config,
    Some(&active.hardening),
    &authorization,
  );
  let plan = serde_json::to_value(report).expect("cluster activation report should serialize");
  assert_eq!(
    plan["activation_plan"]["deployment"]["mode"],
    "admin_cluster"
  );
  assert_eq!(plan["activation_plan"]["deployment"]["target_count"], 2);
  assert_plan_covers_observed_executor(
    "Admin cluster durable dispatch",
    &plan,
    ObservedExecutorOutcome::AdminClusterDispatchAdmitted,
  );
}

#[tokio::test]
async fn config_explain_reads_the_redacted_active_config_and_source_origin() {
  let (_temp_dir, state, _raw, effective) = test_state("admin-config-explain").await;
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, _receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let (actor, ipm) = actor_and_ipm("config:GetEffective");
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let request = hyper::Request::builder()
    .method(::http::Method::GET)
    .uri("/admin/v1/config/explain?field_path=logging.level")
    .body(Full::new(Bytes::new()))
    .expect("request should build");

  let response = admin_config_response(
    request,
    state.clone(),
    control.clone(),
    &authorization,
    &::http::Method::GET,
    "/admin/v1/config/explain",
  )
  .await;

  assert_eq!(response.status(), StatusCode::OK);
  let body = response
    .into_body()
    .collect()
    .await
    .expect("response should collect")
    .to_bytes();
  let body: serde_json::Value = serde_json::from_slice(&body).expect("response should be JSON");
  assert_eq!(body["field_path"], "logging.level");
  assert_eq!(body["effective_value"], "info");
  assert_eq!(body["source"]["kind"], "entry");
  assert_eq!(body["source"]["file"], "oxibelt.toml");
  assert_eq!(body["constraints"]["secret_class"], "none");
  assert_eq!(body["runtime_resolution"]["basis"], "active");
  assert_eq!(body["runtime_resolution"]["activated"], true);
  assert_eq!(
    body["runtime_resolution"]["topology"]["resolved_preset"],
    "external"
  );
  assert!(!body["source"]["file"].as_str().unwrap().starts_with('/'));

  let request = hyper::Request::builder()
    .method(::http::Method::GET)
    .uri("/admin/v1/config/explain?field_path=tls.private_key")
    .body(Full::new(Bytes::new()))
    .expect("request should build");
  let response = admin_config_response(
    request,
    state,
    control,
    &authorization,
    &::http::Method::GET,
    "/admin/v1/config/explain",
  )
  .await;
  let status = response.status();
  let body = response
    .into_body()
    .collect()
    .await
    .expect("response should collect")
    .to_bytes();
  assert_eq!(
    status,
    StatusCode::OK,
    "unexpected explain response: {}",
    String::from_utf8_lossy(&body)
  );
  let body: serde_json::Value = serde_json::from_slice(&body).expect("response should be JSON");
  assert_eq!(body["redacted"], true);
  assert!(body.get("effective_value").is_none());
  assert_eq!(body["constraints"]["secret_class"], "file_reference");
}

#[tokio::test]
async fn config_explain_requires_get_effective_permission() {
  let (_temp_dir, state, _raw, effective) = test_state("admin-config-explain-auth").await;
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, _receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let (actor, ipm) = actor_and_ipm("config:GetStatus");
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let request = hyper::Request::builder()
    .method(::http::Method::GET)
    .uri("/admin/v1/config/explain?field_path=logging.level")
    .body(Full::new(Bytes::new()))
    .expect("request should build");

  let response = admin_config_response(
    request,
    state,
    control,
    &authorization,
    &::http::Method::GET,
    "/admin/v1/config/explain",
  )
  .await;

  assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn config_validate_returns_stable_reports_and_redacts_parse_source() {
  let (_temp_dir, state, candidate, _effective) = test_state("admin-config-validate-report").await;
  let (control, _receiver) =
    admin_control::AdminControlHandle::new(None, None).expect("Admin control should initialize");
  let (actor, ipm) = actor_and_ipm("config:Validate");
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);

  let body = serde_json::to_vec(&json!({ "format": "toml", "config": candidate }))
    .expect("request should serialize");
  let request = hyper::Request::builder()
    .method(::http::Method::POST)
    .uri("/admin/v1/config/validate")
    .body(Full::new(Bytes::from(body)))
    .expect("request should build");
  let response = admin_config_response(
    request,
    state.clone(),
    control.clone(),
    &authorization,
    &::http::Method::POST,
    "/admin/v1/config/validate",
  )
  .await;
  let status = response.status();
  let body = response
    .into_body()
    .collect()
    .await
    .expect("response should collect")
    .to_bytes();
  assert_eq!(
    status,
    StatusCode::OK,
    "unexpected validation response: {}",
    String::from_utf8_lossy(&body)
  );
  let body: serde_json::Value = serde_json::from_slice(&body).expect("response should be JSON");
  assert_eq!(body["report_schema_version"], 3);
  assert_eq!(body["ok"], true);
  assert_eq!(body["diagnostics"], json!([]));

  let secret = "do-not-return-this-secret";
  let invalid = format!("[logging]\nlevel = \"{secret}\" trailing\n");
  let body = serde_json::to_vec(&json!({ "format": "toml", "config": invalid }))
    .expect("request should serialize");
  let request = hyper::Request::builder()
    .method(::http::Method::POST)
    .uri("/admin/v1/config/validate")
    .body(Full::new(Bytes::from(body)))
    .expect("request should build");
  let response = admin_config_response(
    request,
    state,
    control,
    &authorization,
    &::http::Method::POST,
    "/admin/v1/config/validate",
  )
  .await;
  assert_eq!(response.status(), StatusCode::BAD_REQUEST);
  let body = response
    .into_body()
    .collect()
    .await
    .expect("response should collect")
    .to_bytes();
  let encoded = String::from_utf8(body.to_vec()).expect("response should be UTF-8");
  assert!(!encoded.contains(secret));
  let body: serde_json::Value = serde_json::from_str(&encoded).expect("response should be JSON");
  assert_eq!(body["details"]["config_report"]["report_schema_version"], 3);
  assert_eq!(body["details"]["config_report"]["ok"], false);
  assert_eq!(
    body["details"]["config_report"]["diagnostics"][0]["severity"],
    "fatal"
  );
}

#[tokio::test]
async fn config_diff_is_secret_safe_side_effect_free_and_permission_scoped() {
  let (temp_dir, state, candidate, effective) = test_state("admin-config-diff-plan").await;
  let current: toml::Value = toml::from_str(&candidate).expect("current TOML should parse");
  let (control, _receiver) = AdminControlHandle::new(Some(effective), Some(&current))
    .expect("Admin control should initialize");
  let before = control.status().await;

  let mut candidate_value = current.clone();
  let matching_secret_candidate =
    toml::to_string(&current).expect("matching candidate should encode");
  candidate_value["logging"]["level"] = toml::Value::String("debug".to_string());
  let current_key = candidate_value["tls"]["private_key"]
    .as_str()
    .expect("test config should include a private-key reference");
  let alternate_key = "alternate-private-key.pem";
  std::fs::copy(
    temp_dir.path().join(current_key),
    temp_dir.path().join(alternate_key),
  )
  .expect("alternate private key should be copied");
  candidate_value["tls"]["private_key"] = toml::Value::String(alternate_key.to_string());
  let candidate = toml::to_string(&candidate_value).expect("candidate should encode");

  let (actor, ipm) = actor_and_ipm("config:DiffSecrets");
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let request = hyper::Request::builder()
    .method(::http::Method::POST)
    .uri("/admin/v1/config/diff")
    .body(Full::new(Bytes::from(
      serde_json::to_vec(&json!({ "format": "toml", "config": candidate }))
        .expect("request should serialize"),
    )))
    .expect("request should build");
  let response = admin_config_response(
    request,
    state.clone(),
    control.clone(),
    &authorization,
    &::http::Method::POST,
    "/admin/v1/config/diff",
  )
  .await;
  let status = response.status();
  let body = response
    .into_body()
    .collect()
    .await
    .expect("response should collect")
    .to_bytes();
  assert_eq!(
    status,
    StatusCode::OK,
    "unexpected diff response: {}",
    String::from_utf8_lossy(&body)
  );
  let encoded = String::from_utf8(body.to_vec()).expect("response should be UTF-8");
  assert!(!encoded.contains(alternate_key));
  assert!(!encoded.contains(&temp_dir.path().display().to_string()));
  let body: serde_json::Value = serde_json::from_str(&encoded).expect("response should be JSON");
  assert_eq!(body["activation_plan_schema_version"], 3);
  assert_eq!(body["native_schema_epoch"], 1);
  assert_eq!(body["ok"], true);
  assert_eq!(body["basis"], "online_active");
  assert!(body["changes"].as_array().is_some_and(|changes| {
    changes.iter().any(|change| {
      change["path"] == "tls.private_key"
        && change["secret"] == true
        && change.get("current_value").is_none()
        && change.get("candidate_value").is_none()
    })
  }));
  assert_eq!(control.status().await, before);

  let (actor, ipm) = actor_and_ipm("config:Diff");
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let mut legacy_responses = Vec::new();
  for legacy_candidate in [&matching_secret_candidate, &candidate] {
    let request = hyper::Request::builder()
      .method(::http::Method::POST)
      .uri("/admin/v1/config/diff")
      .body(Full::new(Bytes::from(
        serde_json::to_vec(&json!({ "format": "toml", "config": legacy_candidate }))
          .expect("request should serialize"),
      )))
      .expect("request should build");
    let response = admin_config_response(
      request,
      state.clone(),
      control.clone(),
      &authorization,
      &::http::Method::POST,
      "/admin/v1/config/diff",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    legacy_responses.push(
      response
        .into_body()
        .collect()
        .await
        .expect("response should collect")
        .to_bytes(),
    );
  }
  let request = hyper::Request::builder()
    .method(::http::Method::POST)
    .uri("/admin/v1/config/diff")
    .body(Full::new(Bytes::from_static(b"{")))
    .expect("request should build");
  let response = admin_config_response(
    request,
    state.clone(),
    control.clone(),
    &authorization,
    &::http::Method::POST,
    "/admin/v1/config/diff",
  )
  .await;
  assert_eq!(response.status(), StatusCode::FORBIDDEN);
  legacy_responses.push(
    response
      .into_body()
      .collect()
      .await
      .expect("response should collect")
      .to_bytes(),
  );
  assert_eq!(legacy_responses[0], legacy_responses[1]);
  assert_eq!(legacy_responses[0], legacy_responses[2]);
  assert_eq!(legacy_responses[0].as_ref(), b"forbidden");
  assert_eq!(control.status().await, before);

  let (actor, ipm) = actor_and_ipm("config:Load");
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let request = hyper::Request::builder()
    .method(::http::Method::POST)
    .uri("/admin/v1/config/diff")
    .body(Full::new(Bytes::from(
      serde_json::to_vec(&json!({ "format": "toml", "config": candidate }))
        .expect("request should serialize"),
    )))
    .expect("request should build");
  let response = admin_config_response(
    request,
    state,
    control,
    &authorization,
    &::http::Method::POST,
    "/admin/v1/config/diff",
  )
  .await;
  assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
