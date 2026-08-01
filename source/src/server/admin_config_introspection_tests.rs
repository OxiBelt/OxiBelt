use ::http::StatusCode;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::json;

use crate::config::{
  Config, ConfigOriginKind, ConfigValueOrigin, IpmPolicyConfig, IpmPolicyEffect,
  IpmPolicyStatementConfig,
};
use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};
use crate::state::{AppHandle, AppSnapshot};

use super::admin_auth::{AdminActor, AdminAuthorization};
use super::admin_control::{self, AdminControlHandle};
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
  let temp_dir = common::TempDir::new(name);
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
  let candidate = common::minimal_config_toml_with_paths(
    cert_path.file_name().unwrap().to_str().unwrap(),
    key_path.file_name().unwrap().to_str().unwrap(),
  );
  let effective = common::minimal_config_toml(&cert_path, &key_path);
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
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  (temp_dir, AppHandle::new(snapshot), candidate, effective)
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
  assert_eq!(body["report_schema_version"], 2);
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
  assert_eq!(body["details"]["config_report"]["report_schema_version"], 2);
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
  assert_eq!(body["activation_plan_schema_version"], 1);
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
