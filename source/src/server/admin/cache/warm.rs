use std::net::SocketAddr;

use ::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admin_audit::AdminAuditHandle;
use crate::ipm::IpmRequestContext;
use crate::proxy::http;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::routes::{RouteMatchContext, RouteRequestProtocol, normalize_host};
use crate::state::{AppHandle, AppSnapshot};

use super::super::super::{AdminAuthorization, admin_operations};
use super::super::{collect_admin_json, json_response};
use super::{
  AdminBase64Header, CacheWarmPolicyInput, authorize_cache_target, decode_base64_bounded,
  effective_warm_policy, header_map_from_base64, header_map_from_strings,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AdminCacheWarmRequest {
  items: Vec<AdminCacheWarmItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
  /// QUERY content is encoded rather than copied into logs, audit records,
  /// progress events, or result values. It is sealed only for resumable work.
  #[serde(default)]
  query_body_base64: Option<String>,
  #[serde(default)]
  query_trailers: Vec<AdminBase64Header>,
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
  body: Bytes,
  trailers: Option<HeaderMap>,
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
  let idempotency_key = if respond_async {
    match admin_operations::idempotency_key(&request) {
      Ok(key) => key,
      Err(response) => return *response,
    }
  } else {
    None
  };
  let request_id = AdminAuditHandle::from_request(&request)
    .map(|audit| audit.request_id())
    .unwrap_or_else(|| "unknown".to_string());
  let body = match collect_admin_json::<AdminCacheWarmRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  let envelope = durable_envelope(
    &body,
    peer_addr,
    authorization.context(),
    &authorization.actor.principal,
  );
  let command = durable_command(&envelope);
  let plan = match prepare_cache_warm_plan(body, &state, authorization, peer_addr) {
    Ok(plan) => plan,
    Err(response) => return *response,
  };
  if respond_async {
    let submission = durable_submission(command, idempotency_key);
    return match operations
      .enqueue_with_submission(
        submission,
        authorization.actor,
        request_id,
        move |context| async move {
          execute_cache_warm_plan(
            plan,
            state,
            peer_addr,
            Some(context),
            Some(&envelope),
            0,
            Vec::new(),
          )
          .await
        },
      )
      .await
    {
      Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
      Err(error) => operation_enqueue_error_response(error),
    };
  }
  match execute_cache_warm_plan(plan, state, peer_addr, None, Some(&envelope), 0, Vec::new()).await
  {
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
  idempotency_key: Option<String>,
) -> Response<ProxyBody> {
  if serde_json::to_vec(&request)
    .map(|bytes| bytes.len() > super::super::ADMIN_JSON_BODY_LIMIT)
    .unwrap_or(true)
  {
    return text_response(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large");
  }
  let body = match serde_json::from_value::<AdminCacheWarmRequest>(request) {
    Ok(body) => body,
    Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid cache_warm request"),
  };
  let envelope = durable_envelope(
    &body,
    peer_addr,
    authorization.context(),
    &authorization.actor.principal,
  );
  let command = durable_command(&envelope);
  let plan = match prepare_cache_warm_plan(body, &state, authorization, peer_addr) {
    Ok(plan) => plan,
    Err(response) => return *response,
  };
  let submission = durable_submission(command, idempotency_key);
  match operations
    .enqueue_with_submission(
      submission,
      authorization.actor,
      request_id,
      move |context| async move {
        execute_cache_warm_plan(
          plan,
          state,
          peer_addr,
          Some(context),
          Some(&envelope),
          0,
          Vec::new(),
        )
        .await
      },
    )
    .await
  {
    Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
    Err(error) => admin_operations::enqueue_error_response(error),
  }
}

fn durable_submission(
  command: serde_json::Value,
  idempotency_key: Option<String>,
) -> admin_operations::AdminOperationSubmission {
  let submission = admin_operations::AdminOperationSubmission::new(
    admin_operations::AdminOperationKind::CacheWarm,
    "cache:Warm",
    Some("cache/warm".to_string()),
    admin_operations::AdminOperationRecoveryClass::Resumable,
  )
  .with_command(command);
  match idempotency_key {
    Some(key) => submission.with_idempotency_key(key),
    None => submission,
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheWarmRecoveryEnvelope {
  version: u8,
  request: AdminCacheWarmRequest,
  submitting_peer_addr: SocketAddr,
  /// These values are authenticated Admin request facts, captured before the
  /// command is sealed. Recovery reuses them for policy conditions but never
  /// treats them as fresh credential evidence.
  request_context: IpmRequestContext,
  #[serde(skip)]
  request_context_principal: String,
}

fn durable_envelope(
  request: &AdminCacheWarmRequest,
  submitting_peer_addr: SocketAddr,
  request_context: &IpmRequestContext,
  principal: &str,
) -> CacheWarmRecoveryEnvelope {
  CacheWarmRecoveryEnvelope {
    version: 1,
    request: request.clone(),
    submitting_peer_addr,
    request_context: request_context.clone(),
    request_context_principal: principal.to_string(),
  }
}

fn durable_command(envelope: &CacheWarmRecoveryEnvelope) -> serde_json::Value {
  serde_json::to_value(envelope).unwrap_or(serde_json::Value::Null)
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
    if method != "GET" && method != "HEAD" && method != "QUERY" {
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
    let (body, trailers) = if method == "QUERY" {
      if crate::proxy::http::query::validate_content_type(&request_method, &headers).is_err() {
        return Err(Box::new(text_response(
          StatusCode::BAD_REQUEST,
          "invalid QUERY Content-Type",
        )));
      }
      let Some(encoded_body) = item.query_body_base64.as_deref() else {
        return Err(Box::new(text_response(
          StatusCode::BAD_REQUEST,
          "QUERY requires query_body_base64",
        )));
      };
      let body = match decode_base64_bounded(encoded_body) {
        Ok(body) => Bytes::from(body),
        Err(message) => return Err(Box::new(text_response(StatusCode::BAD_REQUEST, message))),
      };
      let trailers = match header_map_from_base64(&item.query_trailers) {
        Ok(trailers) => trailers,
        Err(message) => return Err(Box::new(text_response(StatusCode::BAD_REQUEST, message))),
      };
      (body, Some(trailers))
    } else {
      if item.query_body_base64.is_some() || !item.query_trailers.is_empty() {
        plan.push(CacheWarmPlanItem::ValidationError(
          json!({ "uri": item.uri, "result": "validation_error" }),
        ));
        continue;
      }
      (Bytes::new(), None)
    };
    let effective_policy = effective_warm_policy(
      &snapshot,
      CacheWarmPolicyInput {
        host: &item.host,
        requested_policy: item.policy.as_deref(),
        scheme: &item.scheme,
        uri: &uri,
        method: &request_method,
        headers: &headers,
        peer_addr,
      },
    );
    let effective_policy = match effective_policy {
      Ok(policy) => policy,
      Err(_) => {
        plan.push(CacheWarmPlanItem::ValidationError(
          json!({ "uri": item.uri, "result": "validation_error" }),
        ));
        continue;
      }
    };
    if method == "QUERY"
      && warm_target_uses_unsupported_trusted_partition(
        &snapshot,
        &item.scheme,
        &item.host,
        &uri,
        &request_method,
        &headers,
        peer_addr,
      )
      .map_err(|message| Box::new(text_response(StatusCode::BAD_REQUEST, message)))?
    {
      return Err(Box::new(text_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "QUERY warm does not support trusted cache partitions",
      )));
    }
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
      body,
      trailers,
    })));
  }
  Ok(plan)
}

fn warm_target_uses_unsupported_trusted_partition(
  snapshot: &AppSnapshot,
  scheme: &str,
  host: &str,
  uri: &Uri,
  method: &Method,
  headers: &HeaderMap,
  peer_addr: SocketAddr,
) -> Result<bool, &'static str> {
  let mut headers = headers.clone();
  headers.insert(
    ::http::header::HOST,
    HeaderValue::from_str(host).map_err(|_| "invalid warm host")?,
  );
  let tls = crate::proxy::http::cache_warm_tls_metadata(scheme, host);
  let normalized_host = normalize_host(host);
  let client_addr = snapshot
    .resolve_client_addr(
      &headers,
      peer_addr,
      &normalized_host,
      tls.sni.as_deref().filter(|_| tls.enabled),
    )
    .map_err(|_| "invalid real IP metadata")?;
  Ok(
    snapshot
      .route_table
      .resolve_normalized_host_with_context(
        &normalized_host,
        RouteMatchContext {
          path: uri.path(),
          method: Some(method),
          headers: Some(&headers),
          query: uri.query(),
          source_ip: Some(client_addr.ip()),
          protocol: Some(RouteRequestProtocol::Http1),
          tls: Some(&tls),
        },
        &snapshot.upstreams,
      )
      .and_then(|resolved| resolved.upstream)
      .is_some_and(|upstream| upstream.proxy_protocol_tls.is_some()),
  )
}

async fn execute_cache_warm_plan(
  plan: Vec<CacheWarmPlanItem>,
  state: AppHandle,
  peer_addr: SocketAddr,
  context: Option<admin_operations::AdminOperationContext>,
  recovery: Option<&CacheWarmRecoveryEnvelope>,
  resume_from: usize,
  mut results: Vec<serde_json::Value>,
) -> admin_operations::AdminOperationWorkResult {
  let total = plan.len() as u64;
  if results.len() != resume_from {
    return Err("cache warm checkpoint is invalid".to_string());
  }
  for (index, item) in plan.into_iter().enumerate().skip(resume_from) {
    if let Some(context) = &context {
      context.ensure_not_cancelled()?;
      context
        .progress("warming", Some(index as u64), Some(total))
        .await;
      context.ensure_not_cancelled()?;
    }
    let item = match item {
      CacheWarmPlanItem::Ready(item) => *item,
      CacheWarmPlanItem::ValidationError(result) => {
        results.push(result);
        if let Some(context) = &context {
          context
            .checkpoint(
              "warming",
              (index + 1) as u64,
              total,
              json!({ "version": 1, "next_index": index + 1, "results": results }),
            )
            .await;
          context.ensure_not_cancelled()?;
        }
        continue;
      }
    };
    let snapshot = state.snapshot();
    if let Some(recovery) = recovery
      && snapshot.config.ipm.enabled
    {
      let Some(actor) = snapshot
        .ipm
        .current_enabled_actor(&recovery.request_context_principal)
      else {
        return Err("cache warm authorization is stale; retry request".to_string());
      };
      let authorization = AdminAuthorization::new(&actor, &snapshot.ipm, &recovery.request_context);
      if !authorize_cache_target(
        &authorization,
        "cache:Warm",
        &item.authorized_policy,
        Some(&item.host),
      ) {
        return Err("cache warm authorization is stale; retry request".to_string());
      }
    }
    ensure_cache_warm_policy_is_current(&snapshot, &item, peer_addr)?;
    match http::warm_cache_request(
      snapshot,
      peer_addr,
      http::WarmRequest {
        scheme: item.scheme.clone(),
        host: item.host.clone(),
        uri: item.uri.clone(),
        method: item.method,
        headers: item.headers,
        body: item.body,
        trailers: item.trailers,
      },
    )
    .await
    {
      Ok(result) => results.push(json!({
        "policy": item.policy,
        "uri": item.uri,
        "status": result.status,
        "result": result.result,
      })),
      Err(_) => results.push(json!({
        "policy": item.policy,
        "uri": item.uri,
        "result": "validation_error",
      })),
    }
    if let Some(context) = &context {
      context
        .checkpoint(
          "warming",
          (index + 1) as u64,
          total,
          json!({ "version": 1, "next_index": index + 1, "results": results }),
        )
        .await;
      context.ensure_not_cancelled()?;
    }
  }
  if let Some(context) = &context {
    context.progress("warming", Some(total), Some(total)).await;
  }
  Ok(json!({ "items": results }))
}

/// Replays only a cache-warm command whose sealed, versioned envelope is
/// revalidated by the durable-operation runtime. Submitted credentials never
/// enter this path: each item resolves the current canonical principal and
/// reapplies its policy and host permissions.
pub(in crate::server) async fn recover_cache_warm_command(
  command: serde_json::Value,
  state: AppHandle,
  principal: String,
  context: admin_operations::AdminOperationContext,
  checkpoint: serde_json::Value,
) -> admin_operations::AdminOperationWorkResult {
  let mut envelope = serde_json::from_value::<CacheWarmRecoveryEnvelope>(command)
    .map_err(|_| "cache warm recovery command is invalid".to_string())?;
  if envelope.version != 1 {
    return Err("cache warm recovery command is invalid".to_string());
  }
  envelope.request_context_principal = principal;
  let snapshot = state.snapshot();
  let actor = snapshot
    .ipm
    .current_enabled_actor(&envelope.request_context_principal)
    .ok_or_else(|| "cache warm authorization is stale; retry request".to_string())?;
  let authorization = AdminAuthorization::new(&actor, &snapshot.ipm, &envelope.request_context);
  let plan = prepare_cache_warm_plan(
    envelope.request.clone(),
    &state,
    &authorization,
    envelope.submitting_peer_addr,
  )
  .map_err(|_| "cache warm authorization is stale; retry request".to_string())?;
  let checkpoint = serde_json::from_value::<CacheWarmRecoveryCheckpoint>(checkpoint)
    .map_err(|_| "cache warm checkpoint is invalid".to_string())?;
  if checkpoint.version != 1
    || checkpoint.next_index > plan.len()
    || checkpoint.results.len() != checkpoint.next_index
  {
    return Err("cache warm checkpoint is invalid".to_string());
  }
  execute_cache_warm_plan(
    plan,
    state,
    envelope.submitting_peer_addr,
    Some(context),
    Some(&envelope),
    checkpoint.next_index,
    checkpoint.results,
  )
  .await
}

#[derive(Deserialize)]
struct CacheWarmRecoveryCheckpoint {
  version: u8,
  next_index: usize,
  results: Vec<serde_json::Value>,
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
    CacheWarmPolicyInput {
      host: &item.host,
      requested_policy: item.policy.as_deref(),
      scheme: &item.scheme,
      uri: &uri,
      method: &item.method,
      headers: &item.headers,
      peer_addr,
    },
  )
  .map_err(|_| "cache warm authorization is stale; retry request".to_string())?;
  if current_policy == item.authorized_policy {
    return Ok(());
  }
  Err("cache warm authorization is stale; retry request".to_string())
}

fn operation_enqueue_error_response(
  error: admin_operations::AdminOperationError,
) -> Response<ProxyBody> {
  admin_operations::enqueue_error_response(error)
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
            query_body_base64: None,
            query_trailers: Vec::new(),
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
      None,
      0,
      Vec::new(),
    )
    .await;

    assert_eq!(
      result.expect_err("stale cache warm policy should fail"),
      "cache warm authorization is stale; retry request"
    );
  }

  #[tokio::test]
  async fn cache_warm_execution_rechecks_current_principal_permissions() {
    let temp_dir = common::TempDir::new("cache-warm-current-principal");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "cache-warm-current-principal");
    let state =
      cache_warm_state_from_config(cache_warm_real_ip_config(&cert_path, &key_path)).await;
    let peer_addr = "127.0.0.1:12345".parse().expect("peer address");
    let context = IpmRequestContext::default();
    let request = AdminCacheWarmRequest {
      items: vec![AdminCacheWarmItem {
        policy: None,
        method: None,
        scheme: "http".to_string(),
        host: "example.com".to_string(),
        uri: "/cached".to_string(),
        headers: HashMap::new(),
        query_body_base64: None,
        query_trailers: Vec::new(),
      }],
    };
    let plan = {
      let snapshot = state.snapshot();
      let actor = scoped_actor();
      let authorization = AdminAuthorization::new(&actor, &snapshot.ipm, &context);
      prepare_cache_warm_plan(request.clone(), &state, &authorization, peer_addr)
        .expect("initial cache warm authorization")
    };
    let envelope = durable_envelope(&request, peer_addr, &context, "operator");
    let mut revoked = state.snapshot().config.clone();
    revoked.ipm.bindings.clear();
    state.replace(
      AppSnapshot::new(revoked)
        .await
        .expect("revoked snapshot must build"),
    );

    let result =
      execute_cache_warm_plan(plan, state, peer_addr, None, Some(&envelope), 0, Vec::new()).await;
    assert_eq!(
      result.expect_err("revoked current permission must stop pending work"),
      "cache warm authorization is stale; retry request"
    );
  }

  #[tokio::test]
  async fn cache_warm_authorization_uses_trusted_real_ip_route_context() {
    let temp_dir = common::TempDir::new("cache-warm-real-ip-policy");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "cache-warm-real-ip-policy");
    let state =
      cache_warm_state_from_config(cache_warm_real_ip_config(&cert_path, &key_path)).await;
    let snapshot = state.snapshot();
    let actor = scoped_actor();
    let context = IpmRequestContext::default();
    let authorization = AdminAuthorization::new(&actor, &snapshot.ipm, &context);
    let peer_addr = "127.0.0.1:12345".parse().expect("peer address");
    let mut headers = HashMap::new();
    headers.insert("X-Forwarded-For".to_string(), "203.0.113.9".to_string());

    let error = match prepare_cache_warm_plan(
      AdminCacheWarmRequest {
        items: vec![AdminCacheWarmItem {
          policy: None,
          method: None,
          scheme: "http".to_string(),
          host: "example.com".to_string(),
          uri: "/cached".to_string(),
          headers,
          query_body_base64: None,
          query_trailers: Vec::new(),
        }],
      },
      &state,
      &authorization,
      peer_addr,
    ) {
      Ok(_) => panic!("warm plan should require the forwarded-IP selected policy"),
      Err(error) => error,
    };

    assert_eq!(error.status(), StatusCode::FORBIDDEN);
  }

  #[tokio::test]
  async fn cache_warm_scoped_real_ip_uses_target_sni_only_for_https() {
    let temp_dir = common::TempDir::new("cache-warm-scoped-real-ip");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "cache-warm-scoped-real-ip");
    let mut config = cache_warm_real_ip_config(&cert_path, &key_path);
    config.proxy.real_ip = toml::from_str(
      r#"
[[rules]]
name = "target-sni"
server_names = ["example.com"]
enabled = true
trusted_proxies = ["127.0.0.1/32"]
"#,
    )
    .expect("scoped policy");
    let state = cache_warm_state_from_config(config).await;
    let snapshot = state.snapshot();
    let actor = scoped_actor();
    let context = IpmRequestContext::default();
    let authorization = AdminAuthorization::new(&actor, &snapshot.ipm, &context);
    for (scheme, host, denied) in [
      ("https", "example.com", true),
      ("https", "example.com:8443", true),
      ("http", "example.com", false),
    ] {
      let result = prepare_cache_warm_plan(
        AdminCacheWarmRequest {
          items: vec![AdminCacheWarmItem {
            policy: None,
            method: None,
            scheme: scheme.to_string(),
            host: host.to_string(),
            uri: "/cached".to_string(),
            headers: HashMap::from([("X-Forwarded-For".to_string(), "203.0.113.9".to_string())]),
            query_body_base64: None,
            query_trailers: Vec::new(),
          }],
        },
        &state,
        &authorization,
        "127.0.0.1:12345".parse().unwrap(),
      );
      if denied {
        assert_eq!(
          result
            .err()
            .expect("HTTPS target policy needs separate authority")
            .status(),
          StatusCode::FORBIDDEN
        );
      } else {
        assert!(result.is_ok(), "plaintext warm must not match SNI rules");
      }
    }
  }

  #[tokio::test]
  async fn cache_warm_authorization_uses_synthesized_host_header() {
    let temp_dir = common::TempDir::new("cache-warm-host-policy");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "cache-warm-host-policy");
    let state =
      cache_warm_state_from_config(cache_warm_host_header_config(&cert_path, &key_path)).await;
    let snapshot = state.snapshot();
    let actor = scoped_actor();
    let context = IpmRequestContext::default();
    let authorization = AdminAuthorization::new(&actor, &snapshot.ipm, &context);

    let error = match prepare_cache_warm_plan(
      AdminCacheWarmRequest {
        items: vec![AdminCacheWarmItem {
          policy: None,
          method: None,
          scheme: "http".to_string(),
          host: "example.com".to_string(),
          uri: "/cached".to_string(),
          headers: HashMap::new(),
          query_body_base64: None,
          query_trailers: Vec::new(),
        }],
      },
      &state,
      &authorization,
      "127.0.0.1:12345".parse().expect("peer address"),
    ) {
      Ok(_) => panic!("warm plan should require the host-header selected policy"),
      Err(error) => error,
    };

    assert_eq!(error.status(), StatusCode::FORBIDDEN);
  }

  async fn cache_warm_state(cert_path: &Path, key_path: &Path, policy: &str) -> AppHandle {
    AppHandle::new(cache_warm_snapshot(cert_path, key_path, policy).await)
  }

  async fn cache_warm_state_from_config(config: Config) -> AppHandle {
    AppHandle::new(
      AppSnapshot::new(config)
        .await
        .expect("snapshot should initialize"),
    )
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

  fn cache_warm_real_ip_config(cert_path: &Path, key_path: &Path) -> Config {
    let raw = common::minimal_config_toml(cert_path, key_path)
      .replace("unprivileged_mode = true", "unprivileged_mode = false")
      .replace(
        "https_bind = \"127.0.0.1:8443\"",
        "https_bind = \"127.0.0.1:0\"",
      )
      .replace(
        "upstream = \"app\"",
        r#"upstream = "app"
cache = "policy-a"

[routes.match]
source_cidrs = ["127.0.0.1/32"]"#,
      );
    parse_cache_warm_config_with_extra_routes(
      raw,
      r#"
[proxy.real_ip]
enabled = true
trusted_proxies = ["127.0.0.1/32"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = false

[[routes]]
name = "forwarded-client"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
cache = "policy-b"

[routes.match]
source_cidrs = ["203.0.113.0/24"]
"#,
    )
  }

  fn cache_warm_host_header_config(cert_path: &Path, key_path: &Path) -> Config {
    let raw = common::minimal_config_toml(cert_path, key_path)
      .replace("unprivileged_mode = true", "unprivileged_mode = false")
      .replace(
        "https_bind = \"127.0.0.1:8443\"",
        "https_bind = \"127.0.0.1:0\"",
      )
      .replace(
        "upstream = \"app\"",
        r#"upstream = "app"
cache = "policy-a""#,
      );
    parse_cache_warm_config_with_extra_routes(
      raw,
      r#"
[[routes]]
name = "host-header"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
cache = "policy-b"

[[routes.match.headers]]
name = "host"
exact = "example.com"
"#,
    )
  }

  fn parse_cache_warm_config_with_extra_routes(mut raw: String, extra: &str) -> Config {
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
    raw.push_str(extra);
    raw.push_str(
      r#"

[ipm]
enabled = true
namespace = "oxibelt"

[[ipm.principals]]
id = "operator"
subject = "operator@example.com"

[[ipm.credentials]]
name = "operator-token"
principal = "operator"
bearer_token_env = "PATH"

[[ipm.policies]]
name = "scoped-cache-warm"

[[ipm.policies.statements]]
effect = "allow"
actions = ["cache:Warm"]
resources = [
  "oxibelt:oxibelt:cache:policy/policy-a",
  "oxibelt:oxibelt:cache:host/example.com",
]

[[ipm.bindings]]
principal = "operator"
policy = "scoped-cache-warm"
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

  fn scoped_actor() -> AdminActor {
    AdminActor {
      name: "operator-token".to_string(),
      principal: "operator".to_string(),
      subject: "operator@example.com".to_string(),
      groups: Vec::new(),
    }
  }
}
