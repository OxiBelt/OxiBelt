use std::net::SocketAddr;

use ::http::{HeaderMap, Method, Response, StatusCode, Uri};
use serde::Deserialize;
use serde_json::json;

use crate::admin_audit::AdminAuditHandle;
use crate::proxy::http;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::{AppHandle, AppSnapshot};

use super::super::super::{AdminAuthorization, admin_operations};
use super::super::{collect_admin_json, json_response};
use super::{authorize_cache_target, effective_warm_policy, header_map_from_strings};

#[derive(Debug, Clone, Deserialize)]
struct AdminCacheWarmRequest {
  items: Vec<AdminCacheWarmItem>,
}

#[derive(Debug, Clone, Deserialize)]
struct AdminCacheWarmItem {
  #[serde(default)]
  policy: Option<String>,
  #[serde(default)]
  method: Option<String>,
  scheme: String,
  host: String,
  uri: String,
  #[serde(default)]
  headers: std::collections::HashMap<String, String>,
}

#[derive(Clone)]
struct PreparedCacheWarmItem {
  policy: Option<String>,
  authorized_policy: String,
  scheme: String,
  host: String,
  uri: String,
  method: Method,
  headers: HeaderMap,
}

#[derive(Clone)]
enum CacheWarmPlanItem {
  Ready(Box<PreparedCacheWarmItem>),
  ValidationError(serde_json::Value),
}

pub(in crate::server) async fn cache_warm_response(
  request: hyper::Request<hyper::body::Incoming>,
  state: AppHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  peer_addr: SocketAddr,
) -> Response<ProxyBody> {
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let respond_async = admin_operations::prefer_respond_async(&request);
  let request_id = AdminAuditHandle::from_request(&request)
    .map(|audit| audit.request_id())
    .unwrap_or_else(|| "unknown".to_string());
  let body = match collect_admin_json::<AdminCacheWarmRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  let plan = match prepare_cache_warm_plan(body, &state, authorization, peer_addr) {
    Ok(plan) => plan,
    Err(response) => return *response,
  };
  if respond_async {
    return match operations
      .enqueue(
        admin_operations::AdminOperationKind::CacheWarm,
        authorization.actor,
        request_id,
        move |context| async move {
          execute_cache_warm_plan(plan, state, peer_addr, Some(context)).await
        },
      )
      .await
    {
      Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
      Err(error) => operation_enqueue_error_response(error),
    };
  }
  match execute_cache_warm_plan(plan, state, peer_addr, None).await {
    Ok(value) => json_response(StatusCode::OK, &value),
    Err(error) => text_response(StatusCode::BAD_REQUEST, &error),
  }
}

pub(in crate::server) async fn enqueue_cache_warm_operation(
  request: serde_json::Value,
  state: AppHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
  peer_addr: SocketAddr,
) -> Response<ProxyBody> {
  let body = match serde_json::from_value::<AdminCacheWarmRequest>(request) {
    Ok(body) => body,
    Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid cache_warm request"),
  };
  let plan = match prepare_cache_warm_plan(body, &state, authorization, peer_addr) {
    Ok(plan) => plan,
    Err(response) => return *response,
  };
  match operations
    .enqueue(
      admin_operations::AdminOperationKind::CacheWarm,
      authorization.actor,
      request_id,
      move |context| async move {
        execute_cache_warm_plan(plan, state, peer_addr, Some(context)).await
      },
    )
    .await
  {
    Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
    Err(error) => admin_operations::enqueue_error_response(error),
  }
}

fn prepare_cache_warm_plan(
  body: AdminCacheWarmRequest,
  state: &AppHandle,
  authorization: &AdminAuthorization<'_>,
  peer_addr: SocketAddr,
) -> Result<Vec<CacheWarmPlanItem>, Box<Response<ProxyBody>>> {
  if body.items.is_empty() || body.items.len() > 128 {
    return Err(Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "items must contain 1 to 128 entries",
    )));
  }
  let snapshot = state.snapshot();
  let mut plan = Vec::new();
  for item in body.items {
    let method = item.method.unwrap_or_else(|| "GET".to_string());
    if method != "GET" && method != "HEAD" {
      plan.push(CacheWarmPlanItem::ValidationError(
        json!({ "uri": item.uri, "result": "validation_error" }),
      ));
      continue;
    }
    let request_method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let uri = match item.uri.parse::<Uri>() {
      Ok(uri) if !uri.path().is_empty() && uri.path().starts_with('/') => uri,
      _ => {
        plan.push(CacheWarmPlanItem::ValidationError(
          json!({ "uri": item.uri, "result": "validation_error" }),
        ));
        continue;
      }
    };
    let headers = match header_map_from_strings(item.headers) {
      Ok(headers) => headers,
      Err(_) => {
        plan.push(CacheWarmPlanItem::ValidationError(
          json!({ "uri": item.uri, "result": "validation_error" }),
        ));
        continue;
      }
    };
    let effective_policy = effective_warm_policy(
      &snapshot,
      &item.host,
      item.policy.as_deref(),
      &uri,
      &request_method,
      &headers,
      Some(peer_addr.ip()),
    );
    if !authorize_cache_target(
      authorization,
      "cache:Warm",
      &effective_policy,
      Some(&item.host),
    ) {
      return Err(Box::new(text_response(StatusCode::FORBIDDEN, "forbidden")));
    }
    plan.push(CacheWarmPlanItem::Ready(Box::new(PreparedCacheWarmItem {
      policy: item.policy,
      authorized_policy: effective_policy,
      scheme: item.scheme,
      host: item.host,
      uri: item.uri,
      method: request_method,
      headers,
    })));
  }
  Ok(plan)
}

async fn execute_cache_warm_plan(
  plan: Vec<CacheWarmPlanItem>,
  state: AppHandle,
  peer_addr: SocketAddr,
  context: Option<admin_operations::AdminOperationContext>,
) -> admin_operations::AdminOperationWorkResult {
  let total = plan.len() as u64;
  let mut results = Vec::new();
  for (index, item) in plan.into_iter().enumerate() {
    if let Some(context) = &context {
      context.ensure_not_cancelled()?;
      context
        .progress("warming", Some(index as u64), Some(total))
        .await;
    }
    let item = match item {
      CacheWarmPlanItem::Ready(item) => *item,
      CacheWarmPlanItem::ValidationError(result) => {
        results.push(result);
        continue;
      }
    };
    ensure_cache_warm_policy_is_current(&state.snapshot(), &item, peer_addr)?;
    match http::warm_cache_request(
      state.clone(),
      peer_addr,
      &item.scheme,
      &item.host,
      &item.uri,
      item.method,
      item.headers,
    )
    .await
    {
      Ok(result) => results.push(json!({
        "policy": item.policy,
        "uri": item.uri,
        "status": result.status,
        "result": result.result,
      })),
      Err(error) => results.push(json!({
        "policy": item.policy,
        "uri": item.uri,
        "result": "validation_error",
        "error": error.to_string(),
      })),
    }
  }
  if let Some(context) = &context {
    context.progress("warming", Some(total), Some(total)).await;
  }
  Ok(json!({ "items": results }))
}

fn ensure_cache_warm_policy_is_current(
  snapshot: &AppSnapshot,
  item: &PreparedCacheWarmItem,
  peer_addr: SocketAddr,
) -> Result<(), String> {
  let uri = item
    .uri
    .parse::<Uri>()
    .map_err(|_| "cache warm authorization is stale; retry request".to_string())?;
  let current_policy = effective_warm_policy(
    snapshot,
    &item.host,
    item.policy.as_deref(),
    &uri,
    &item.method,
    &item.headers,
    Some(peer_addr.ip()),
  );
  if current_policy == item.authorized_policy {
    return Ok(());
  }
  Err("cache warm authorization is stale; retry request".to_string())
}

fn operation_enqueue_error_response(
  error: admin_operations::AdminOperationError,
) -> Response<ProxyBody> {
  let status = match error {
    admin_operations::AdminOperationError::Disabled => StatusCode::CONFLICT,
    admin_operations::AdminOperationError::QueueFull
    | admin_operations::AdminOperationError::StoreFull => StatusCode::SERVICE_UNAVAILABLE,
    admin_operations::AdminOperationError::NotFound => StatusCode::NOT_FOUND,
    admin_operations::AdminOperationError::AlreadyTerminal => StatusCode::CONFLICT,
  };
  text_response(status, &error.to_string())
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::path::Path;

  use crate::config::Config;
  use crate::ipm::IpmRequestContext;
  use crate::server::AdminActor;
  use crate::state::AppSnapshot;

  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[tokio::test]
  async fn cache_warm_plan_rejects_stale_effective_policy() {
    let temp_dir = common::TempDir::new("cache-warm-stale-policy");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "cache-warm-stale-policy");
    let state = cache_warm_state(&cert_path, &key_path, "policy-a").await;
    let plan = {
      let snapshot = state.snapshot();
      let actor = bootstrap_actor();
      let context = IpmRequestContext::default();
      let authorization = AdminAuthorization::new(&actor, &snapshot.ipm, &context);
      let peer_addr = "127.0.0.1:12345".parse().expect("peer address");
      prepare_cache_warm_plan(
        AdminCacheWarmRequest {
          items: vec![AdminCacheWarmItem {
            policy: None,
            method: None,
            scheme: "http".to_string(),
            host: "example.com".to_string(),
            uri: "/cached".to_string(),
            headers: HashMap::new(),
          }],
        },
        &state,
        &authorization,
        peer_addr,
      )
      .unwrap_or_else(|_| panic!("cache warm plan should prepare"))
    };
    let replacement = cache_warm_snapshot(&cert_path, &key_path, "policy-b").await;
    state.replace(replacement);

    let result = execute_cache_warm_plan(
      plan,
      state,
      "127.0.0.1:12345".parse().expect("peer address"),
      None,
    )
    .await;

    assert_eq!(
      result.expect_err("stale cache warm policy should fail"),
      "cache warm authorization is stale; retry request"
    );
  }

  async fn cache_warm_state(cert_path: &Path, key_path: &Path, policy: &str) -> AppHandle {
    AppHandle::new(cache_warm_snapshot(cert_path, key_path, policy).await)
  }

  async fn cache_warm_snapshot(cert_path: &Path, key_path: &Path, policy: &str) -> AppSnapshot {
    AppSnapshot::new(cache_warm_config(cert_path, key_path, policy))
      .await
      .expect("snapshot should initialize")
  }

  fn cache_warm_config(cert_path: &Path, key_path: &Path, policy: &str) -> Config {
    let mut raw = common::minimal_config_toml(cert_path, key_path)
      .replace("unprivileged_mode = true", "unprivileged_mode = false")
      .replace(
        "https_bind = \"127.0.0.1:8443\"",
        "https_bind = \"127.0.0.1:0\"",
      )
      .replace(
        "upstream = \"app\"",
        &format!("upstream = \"app\"\ncache = \"{policy}\""),
      );
    raw.push_str(
      r#"

[cache]
enabled = true
store = "memory"
cache_methods = ["GET"]

[[cache.policies]]
name = "policy-a"

[[cache.policies]]
name = "policy-b"
"#,
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  fn bootstrap_actor() -> AdminActor {
    AdminActor {
      name: "bootstrap-admin".to_string(),
      principal: "bootstrap-admin".to_string(),
      subject: "bootstrap-admin".to_string(),
      groups: vec!["ipm-admin".to_string()],
    }
  }
}
