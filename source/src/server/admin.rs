use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use ::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri};
use anyhow::bail;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::dynamic_policy::{
  DynamicPolicyAdminCreate, DynamicPolicyAdminImport, DynamicPolicyAdminPatch,
};
use crate::proxy::http;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::{AppHandle, AppSnapshot};

use super::{AdminActor, AdminAuthorization};

mod dynamic_policy_query;

pub(super) const ADMIN_JSON_BODY_LIMIT: usize = 64 * 1024;

fn allowed(authorization: &AdminAuthorization<'_>, action: &str, resource_name: &str) -> bool {
  authorization.is_allowed(action, resource_name)
}

#[derive(Debug, Deserialize)]
struct AdminCacheKeyExplainRequest {
  #[serde(default)]
  policy: Option<String>,
  method: String,
  scheme: String,
  host: String,
  uri: String,
  #[serde(default)]
  headers: std::collections::HashMap<String, String>,
  #[serde(default)]
  response_headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct AdminCacheWarmRequest {
  items: Vec<AdminCacheWarmItem>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct AdminCachePurgeJsonRequest {
  #[serde(rename = "type")]
  purge_type: String,
  #[serde(default)]
  policy: Option<String>,
  #[serde(default)]
  scheme: Option<String>,
  #[serde(default)]
  host: Option<String>,
  #[serde(default)]
  uri: Option<String>,
  #[serde(default)]
  path_prefix: Option<String>,
  #[serde(default)]
  tag: Option<String>,
  #[serde(default)]
  partition: Option<String>,
}

pub(super) fn signed_cache_purge_actor(
  request: &hyper::Request<Incoming>,
  snapshot: &AppSnapshot,
  method: &::http::Method,
) -> anyhow::Result<AdminActor> {
  let content_length = request
    .headers()
    .get(::http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or(0);
  if content_length != 0 {
    bail!("signed cache purge requests must not include a body");
  }
  let path_and_query = request
    .uri()
    .path_and_query()
    .map(|value| value.as_str())
    .unwrap_or_else(|| request.uri().path());
  let verified = crate::cache::signing::verify_cache_purge_signature(
    request.headers(),
    method,
    path_and_query,
    b"",
    &snapshot.config.admin.cache_purge_signing,
    SystemTime::now(),
  )?;
  let nonce_ttl = Duration::from_secs(snapshot.config.admin.cache_purge_signing.nonce_ttl_seconds);
  if !snapshot
    .cache
    .remember_purge_nonce(&verified.nonce, nonce_ttl)
  {
    bail!("cache purge signature nonce was already used");
  }
  Ok(AdminActor {
    name: "signed-cache-purge".to_string(),
    principal: "signed-cache-purge".to_string(),
    subject: "signed-cache-purge".to_string(),
    groups: vec!["ipm-admin".to_string()],
  })
}

pub(super) async fn cache_key_explain_response(
  request: hyper::Request<Incoming>,
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
) -> Response<ProxyBody> {
  if !allowed(authorization, "cache:ExplainKey", "policy/*") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let body = match collect_admin_json::<AdminCacheKeyExplainRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  let method = match Method::from_bytes(body.method.as_bytes()) {
    Ok(method) => method,
    Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid method"),
  };
  let uri = match body.uri.parse::<Uri>() {
    Ok(uri) => uri,
    Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid uri"),
  };
  let headers = match header_map_from_strings(body.headers) {
    Ok(headers) => headers,
    Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
  };
  let response_headers = match header_map_from_strings(body.response_headers) {
    Ok(headers) => headers,
    Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
  };
  let explain = snapshot.cache.explain_key(
    crate::cache::CacheLookupContext {
      policy_name: body.policy.as_deref(),
      scheme: &body.scheme,
      host: &body.host,
      method: &method,
      uri: &uri,
      request_headers: &headers,
    },
    (!response_headers.is_empty()).then_some(&response_headers),
  );
  json_response(StatusCode::OK, &explain)
}

pub(super) async fn cache_warm_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  peer_addr: SocketAddr,
) -> Response<ProxyBody> {
  if !allowed(authorization, "cache:Warm", "policy/*") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let body = match collect_admin_json::<AdminCacheWarmRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  if body.items.is_empty() || body.items.len() > 128 {
    return text_response(
      StatusCode::BAD_REQUEST,
      "items must contain 1 to 128 entries",
    );
  }
  let mut results = Vec::new();
  for item in body.items {
    let method = item.method.unwrap_or_else(|| "GET".to_string());
    if method != "GET" && method != "HEAD" {
      results.push(json!({ "uri": item.uri, "result": "validation_error" }));
      continue;
    }
    let request_method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let headers = match header_map_from_strings(item.headers) {
      Ok(headers) => headers,
      Err(_) => {
        results.push(json!({ "uri": item.uri, "result": "validation_error" }));
        continue;
      }
    };
    match http::warm_cache_request(
      state.clone(),
      peer_addr,
      &item.scheme,
      &item.host,
      &item.uri,
      request_method,
      headers,
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
  json_response(StatusCode::OK, &json!({ "items": results }))
}

pub(super) async fn cache_purge_json_response(
  request: hyper::Request<Incoming>,
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  default_scheme: &'static str,
  peer_addr: SocketAddr,
) -> Response<ProxyBody> {
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let body = match collect_admin_json::<AdminCachePurgeJsonRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  let policy = body.policy.as_deref().unwrap_or("default");
  let partition = body.partition.as_deref();
  let scheme = body.scheme.as_deref().unwrap_or(default_scheme);
  let action = match body.purge_type.as_str() {
    "exact" => "cache:PurgeObject",
    "prefix" => "cache:PurgePrefix",
    "tag" => "cache:PurgeTag",
    _ => "cache:PurgeObject",
  };
  if !allowed(authorization, action, &format!("policy/{policy}")) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }

  let purged = match body.purge_type.as_str() {
    "exact" => {
      let Some(host) = body.host.as_deref() else {
        audit_rejected_cache_purge(
          peer_addr,
          authorization.actor,
          "cache_purge_json",
          "missing host",
        );
        return text_response(StatusCode::BAD_REQUEST, "missing host");
      };
      let Some(uri) = body.uri.as_deref() else {
        audit_rejected_cache_purge(
          peer_addr,
          authorization.actor,
          "cache_purge_json",
          "missing uri",
        );
        return text_response(StatusCode::BAD_REQUEST, "missing uri");
      };
      snapshot
        .cache
        .purge_exact_partition(policy, scheme, host, uri, partition)
    }
    "prefix" => {
      let Some(host) = body.host.as_deref() else {
        audit_rejected_cache_purge(
          peer_addr,
          authorization.actor,
          "cache_purge_prefix_json",
          "missing host",
        );
        return text_response(StatusCode::BAD_REQUEST, "missing host");
      };
      let Some(path_prefix) = body.path_prefix.as_deref() else {
        audit_rejected_cache_purge(
          peer_addr,
          authorization.actor,
          "cache_purge_prefix_json",
          "missing path_prefix",
        );
        return text_response(StatusCode::BAD_REQUEST, "missing path_prefix");
      };
      snapshot
        .cache
        .purge_prefix_partition(policy, scheme, host, path_prefix, partition)
    }
    "tag" => {
      let Some(tag) = body.tag.as_deref() else {
        audit_rejected_cache_purge(
          peer_addr,
          authorization.actor,
          "cache_purge_tag_json",
          "missing tag",
        );
        return text_response(StatusCode::BAD_REQUEST, "missing tag");
      };
      snapshot.cache.purge_tag_partition(
        policy,
        tag,
        body.scheme.as_deref(),
        body.host.as_deref(),
        partition,
      )
    }
    _ => {
      audit_rejected_cache_purge(
        peer_addr,
        authorization.actor,
        "cache_purge_json",
        "invalid type",
      );
      return text_response(StatusCode::BAD_REQUEST, "invalid type");
    }
  };

  if body.purge_type == "tag" {
    snapshot.metrics.record_cache_tag_purge();
  } else {
    snapshot.metrics.record_cache_purge();
  }
  super::admin_audit(
    peer_addr,
    authorization.actor,
    match body.purge_type.as_str() {
      "exact" => "cache_purge_json",
      "prefix" => "cache_purge_prefix_json",
      "tag" => "cache_purge_tag_json",
      _ => "cache_purge_json",
    },
    None,
    None,
    super::AdminAuditOutcome::Applied,
    None,
  );
  info!(
    peer = %peer_addr,
    actor = %authorization.actor.name,
    policy,
    purged,
    purge_type = %body.purge_type,
    "admin JSON cache purge completed"
  );
  json_response(StatusCode::OK, &json!({ "purged": purged }))
}

fn audit_rejected_cache_purge(
  peer_addr: SocketAddr,
  actor: &AdminActor,
  operation: &'static str,
  reason: &'static str,
) {
  super::admin_audit(
    peer_addr,
    actor,
    operation,
    None,
    None,
    super::AdminAuditOutcome::Rejected,
    Some(reason),
  );
}

fn header_map_from_strings(
  headers: std::collections::HashMap<String, String>,
) -> Result<HeaderMap, &'static str> {
  let mut map = HeaderMap::new();
  for (name, value) in headers {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid header name")?;
    let value = HeaderValue::from_str(&value).map_err(|_| "invalid header value")?;
    map.append(name, value);
  }
  Ok(map)
}

pub(super) fn cache_purge_response(
  snapshot: &AppSnapshot,
  params: &std::collections::HashMap<String, String>,
  path: &str,
  scheme: &'static str,
  peer_addr: SocketAddr,
  authorization: &AdminAuthorization<'_>,
) -> Response<ProxyBody> {
  let policy = params
    .get("policy")
    .map(String::as_str)
    .unwrap_or("default");
  let (action, operation) = match path {
    "/cache/purge" => ("cache:PurgeObject", "cache_purge"),
    "/cache/purge-prefix" => ("cache:PurgePrefix", "cache_purge_prefix"),
    "/cache/purge-tag" => ("cache:PurgeTag", "cache_purge_tag"),
    _ => return text_response(StatusCode::NOT_FOUND, "not found"),
  };
  if !allowed(authorization, action, &format!("policy/{policy}")) {
    super::admin_audit(
      peer_addr,
      authorization.actor,
      operation,
      None,
      None,
      super::AdminAuditOutcome::Rejected,
      Some("permission denied"),
    );
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  let partition = params.get("partition").map(String::as_str);
  let purge_scheme = params.get("scheme").map(String::as_str).unwrap_or(scheme);
  let host = params.get("host").map(String::as_str);
  let purged = match path {
    "/cache/purge" => {
      let Some(host) = host else {
        super::admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge",
          None,
          None,
          super::AdminAuditOutcome::Rejected,
          Some("missing host"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing host");
      };
      let Some(uri) = params.get("uri").map(String::as_str) else {
        super::admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge",
          None,
          None,
          super::AdminAuditOutcome::Rejected,
          Some("missing uri"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing uri");
      };
      snapshot
        .cache
        .purge_exact_partition(policy, purge_scheme, host, uri, partition)
    }
    "/cache/purge-prefix" => {
      let Some(host) = host else {
        super::admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge_prefix",
          None,
          None,
          super::AdminAuditOutcome::Rejected,
          Some("missing host"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing host");
      };
      let Some(path_prefix) = params.get("path_prefix").map(String::as_str) else {
        super::admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge_prefix",
          None,
          None,
          super::AdminAuditOutcome::Rejected,
          Some("missing path_prefix"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing path_prefix");
      };
      snapshot
        .cache
        .purge_prefix_partition(policy, purge_scheme, host, path_prefix, partition)
    }
    "/cache/purge-tag" => {
      let Some(tag) = params.get("tag").map(String::as_str) else {
        super::admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge_tag",
          None,
          None,
          super::AdminAuditOutcome::Rejected,
          Some("missing tag"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing tag");
      };
      snapshot.cache.purge_tag_partition(
        policy,
        tag,
        params.get("scheme").map(String::as_str),
        host,
        partition,
      )
    }
    _ => unreachable!("admin cache purge path checked before dispatch"),
  };
  if path == "/cache/purge-tag" {
    snapshot.metrics.record_cache_tag_purge();
  } else {
    snapshot.metrics.record_cache_purge();
  }
  super::admin_audit(
    peer_addr,
    authorization.actor,
    operation,
    None,
    None,
    super::AdminAuditOutcome::Applied,
    None,
  );
  info!(peer = %peer_addr, actor = %authorization.actor.name, policy, purged, "admin cache purge completed");
  text_response(StatusCode::OK, &format!("purged={purged}\n"))
}

pub(super) async fn dynamic_policy_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path != "/admin/v1/dynamic-policies"
    && path != "/admin/v1/dynamic-policies/apply"
    && path != "/admin/v1/dynamic-policies/audit"
    && path != "/admin/v1/dynamic-policies/export"
    && path != "/admin/v1/dynamic-policies/import"
    && !path.starts_with("/admin/v1/dynamic-policies/")
  {
    return None;
  }
  let query = request.uri().query().map(str::to_string);
  match (method, path) {
    (&::http::Method::GET, "/admin/v1/dynamic-policies") => {
      if !allowed(authorization, "dynamic-policy:List", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(match state.snapshot().dynamic_policy.admin_list().await {
        Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      });
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies") => {
      if !allowed(authorization, "dynamic-policy:Create", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let body = match collect_admin_json::<DynamicPolicyAdminCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_create(&authorization.actor.name, body)
          .await
        {
          Ok(policy) => json_response(StatusCode::CREATED, &policy),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      );
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies/apply") => {
      if !allowed(authorization, "dynamic-policy:Apply", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let body = match collect_admin_json::<DynamicPolicyAdminCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_apply(&authorization.actor.name, body)
          .await
        {
          Ok(policy) => json_response(StatusCode::OK, &policy),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/dynamic-policies/audit") => {
      if !allowed(authorization, "dynamic-policy:ReadAudit", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let (policy_id, limit) = match dynamic_policy_query::audit_query(query.as_deref()) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_audit(policy_id, limit)
          .await
        {
          Ok(audit) => json_response(StatusCode::OK, &json!({ "audit": audit })),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/dynamic-policies/export") => {
      if !allowed(authorization, "dynamic-policy:Export", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(match state.snapshot().dynamic_policy.admin_export().await {
        Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      });
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies/import") => {
      if !allowed(authorization, "dynamic-policy:Import", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let body = match collect_admin_json::<DynamicPolicyAdminImport>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_import(&authorization.actor.name, body)
          .await
        {
          Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      );
    }
    _ => {}
  }

  let Some(id) = dynamic_policy_query::policy_id_from_path(path) else {
    return Some(text_response(StatusCode::NOT_FOUND, "not found"));
  };
  Some(match *method {
    ::http::Method::GET => {
      if !allowed(authorization, "dynamic-policy:Get", &id.to_string()) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      match state.snapshot().dynamic_policy.admin_get(id).await {
        Ok(Some(policy)) => json_response(StatusCode::OK, &policy),
        Ok(None) => text_response(StatusCode::NOT_FOUND, "not found"),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      }
    }
    ::http::Method::PATCH => {
      if !allowed(authorization, "dynamic-policy:Update", &id.to_string()) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let body = match collect_admin_json::<DynamicPolicyAdminPatch>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      match state
        .snapshot()
        .dynamic_policy
        .admin_patch(&authorization.actor.name, id, body)
        .await
      {
        Ok(Some(policy)) => json_response(StatusCode::OK, &policy),
        Ok(None) => text_response(StatusCode::NOT_FOUND, "not found"),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      }
    }
    ::http::Method::DELETE => {
      if !allowed(authorization, "dynamic-policy:Delete", &id.to_string()) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      match state
        .snapshot()
        .dynamic_policy
        .admin_delete(&authorization.actor.name, id)
        .await
      {
        Ok(true) => json_response(StatusCode::OK, &json!({ "ok": true })),
        Ok(false) => text_response(StatusCode::NOT_FOUND, "not found"),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      }
    }
    _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
  })
}

async fn collect_admin_json<T>(request: hyper::Request<Incoming>) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> serde::Deserialize<'de>,
{
  let bytes = Limited::new(request.into_body(), ADMIN_JSON_BODY_LIMIT)
    .collect()
    .await
    .map_err(|error| {
      if error.downcast_ref::<LengthLimitError>().is_some() {
        super::admin_error::error_response(
          StatusCode::PAYLOAD_TOO_LARGE,
          "request body is too large",
        )
      } else {
        super::admin_error::error_response(StatusCode::BAD_REQUEST, "failed to read request body")
      }
    })?
    .to_bytes();
  serde_json::from_slice(&bytes).map_err(|_| {
    super::admin_error::error_response(StatusCode::BAD_REQUEST, "invalid JSON request body")
  })
}

pub(super) fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<ProxyBody> {
  match serde_json::to_vec(value) {
    Ok(bytes) => {
      let body = http_body_util::Full::new(bytes::Bytes::from(bytes))
        .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
        .boxed();
      let mut response = Response::new(body);
      *response.status_mut() = status;
      response.headers_mut().insert(
        ::http::header::CONTENT_TYPE,
        ::http::HeaderValue::from_static("application/json"),
      );
      response
    }
    Err(error) => text_response(
      StatusCode::INTERNAL_SERVER_ERROR,
      &format!("failed to encode JSON response: {error}"),
    ),
  }
}
