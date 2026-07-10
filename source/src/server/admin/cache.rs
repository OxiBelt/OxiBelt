use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use ::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri};
use anyhow::bail;
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::routes::{RouteMatchContext, RouteRequestProtocol, normalize_host};
use crate::state::AppSnapshot;

use super::super::{
  AdminActor, AdminAuditOutcome, AdminAuthorization, admin_audit, admin_resource,
};
use super::{collect_admin_json, json_response};

mod warm;
pub(in crate::server) use warm::{cache_warm_response, enqueue_cache_warm_operation};

fn allowed(authorization: &AdminAuthorization<'_>, action: &str, resource_name: &str) -> bool {
  authorization.is_allowed(action, resource_name)
}

fn authorize_cache_target(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  policy: &str,
  host: Option<&str>,
) -> bool {
  let policy_resource = admin_resource::cache_policy(policy);
  if !allowed(authorization, action, &policy_resource) {
    return false;
  }
  let host_resource = host
    .map(admin_resource::cache_host)
    .unwrap_or_else(|| "host/*".to_string());
  allowed(authorization, action, &host_resource)
}

struct CacheWarmPolicyInput<'a> {
  host: &'a str,
  requested_policy: Option<&'a str>,
  scheme: &'a str,
  uri: &'a Uri,
  method: &'a Method,
  headers: &'a HeaderMap,
  peer_addr: SocketAddr,
}

fn effective_warm_policy(
  snapshot: &AppSnapshot,
  input: CacheWarmPolicyInput<'_>,
) -> Result<String, &'static str> {
  let CacheWarmPolicyInput {
    host,
    requested_policy,
    scheme,
    uri,
    method,
    headers,
    peer_addr,
  } = input;
  if scheme != "http" && scheme != "https" {
    return Err("scheme must be http or https");
  }
  let mut request_headers = headers.clone();
  request_headers.insert(
    ::http::header::HOST,
    HeaderValue::from_str(host).map_err(|_| "invalid warm host")?,
  );
  let client_addr = crate::identity::resolve_client_addr(
    &request_headers,
    peer_addr,
    &snapshot.config.proxy.real_ip,
  )
  .map_err(|_| "invalid real IP metadata")?;
  let tls = crate::waf::WafTlsMetadata {
    enabled: scheme == "https",
    sni: Some(host.to_string()),
    ..crate::waf::WafTlsMetadata::default()
  };
  Ok(
    snapshot
      .route_table
      .resolve_normalized_host_with_context(
        &normalize_host(host),
        RouteMatchContext {
          path: uri.path(),
          method: Some(method),
          headers: Some(&request_headers),
          query: uri.query(),
          source_ip: Some(client_addr.ip()),
          protocol: Some(RouteRequestProtocol::Http1),
          tls: Some(&tls),
        },
        &snapshot.upstreams,
      )
      .map(|resolved| resolved.route.cache.as_deref().unwrap_or("default"))
      .or(requested_policy)
      .unwrap_or("default")
      .to_string(),
  )
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

pub(in crate::server) fn signed_cache_purge_actor(
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

pub(in crate::server) async fn cache_key_explain_response(
  request: hyper::Request<Incoming>,
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
) -> Response<ProxyBody> {
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let body = match collect_admin_json::<AdminCacheKeyExplainRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  let policy = body.policy.as_deref().unwrap_or("default");
  if !authorize_cache_target(authorization, "cache:ExplainKey", policy, Some(&body.host)) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
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

pub(in crate::server) async fn cache_purge_json_response(
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

  let (purged, external_reports) = match body.purge_type.as_str() {
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
      if !authorize_cache_target(authorization, "cache:PurgeObject", policy, Some(host)) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = snapshot
        .cache
        .purge_exact_partition_async(policy, scheme, host, uri, partition)
        .await;
      let external_reports = snapshot
        .cache
        .purge_external_exact_partition(policy, scheme, host, uri, partition)
        .await;
      (purged, external_reports)
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
      if !authorize_cache_target(authorization, "cache:PurgePrefix", policy, Some(host)) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = snapshot
        .cache
        .purge_prefix_partition_async(policy, scheme, host, path_prefix, partition)
        .await;
      let external_reports = snapshot
        .cache
        .purge_external_prefix_partition(policy, scheme, host, path_prefix, partition)
        .await;
      (purged, external_reports)
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
      if !authorize_cache_target(
        authorization,
        "cache:PurgeTag",
        policy,
        body.host.as_deref(),
      ) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = snapshot
        .cache
        .purge_tag_partition_async(
          policy,
          tag,
          body.scheme.as_deref(),
          body.host.as_deref(),
          partition,
        )
        .await;
      let external_reports = snapshot
        .cache
        .purge_external_tag_partition(
          policy,
          tag,
          body.scheme.as_deref(),
          body.host.as_deref(),
          partition,
        )
        .await;
      (purged, external_reports)
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
  admin_audit(
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
    AdminAuditOutcome::Applied,
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
  let mut response = json!({ "purged": purged });
  if !external_reports.is_empty() {
    response["external_handlers"] = json!(external_reports);
  }
  json_response(StatusCode::OK, &response)
}

fn audit_rejected_cache_purge(
  peer_addr: SocketAddr,
  actor: &AdminActor,
  operation: &'static str,
  reason: &'static str,
) {
  admin_audit(
    peer_addr,
    actor,
    operation,
    None,
    None,
    AdminAuditOutcome::Rejected,
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

pub(in crate::server) async fn cache_purge_response(
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
  let partition = params.get("partition").map(String::as_str);
  let purge_scheme = params.get("scheme").map(String::as_str).unwrap_or(scheme);
  let host = params.get("host").map(String::as_str);
  let (purged, external_reports) = match path {
    "/cache/purge" => {
      let Some(host) = host else {
        admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge",
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("missing host"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing host");
      };
      let Some(uri) = params.get("uri").map(String::as_str) else {
        admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge",
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("missing uri"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing uri");
      };
      if !authorize_cache_target(authorization, action, policy, Some(host)) {
        admin_audit(
          peer_addr,
          authorization.actor,
          operation,
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("permission denied"),
        );
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = snapshot
        .cache
        .purge_exact_partition_async(policy, purge_scheme, host, uri, partition)
        .await;
      let external_reports = snapshot
        .cache
        .purge_external_exact_partition(policy, purge_scheme, host, uri, partition)
        .await;
      (purged, external_reports)
    }
    "/cache/purge-prefix" => {
      let Some(host) = host else {
        admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge_prefix",
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("missing host"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing host");
      };
      let Some(path_prefix) = params.get("path_prefix").map(String::as_str) else {
        admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge_prefix",
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("missing path_prefix"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing path_prefix");
      };
      if !authorize_cache_target(authorization, action, policy, Some(host)) {
        admin_audit(
          peer_addr,
          authorization.actor,
          operation,
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("permission denied"),
        );
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = snapshot
        .cache
        .purge_prefix_partition_async(policy, purge_scheme, host, path_prefix, partition)
        .await;
      let external_reports = snapshot
        .cache
        .purge_external_prefix_partition(policy, purge_scheme, host, path_prefix, partition)
        .await;
      (purged, external_reports)
    }
    "/cache/purge-tag" => {
      let Some(tag) = params.get("tag").map(String::as_str) else {
        admin_audit(
          peer_addr,
          authorization.actor,
          "cache_purge_tag",
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("missing tag"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing tag");
      };
      if !authorize_cache_target(authorization, action, policy, host) {
        admin_audit(
          peer_addr,
          authorization.actor,
          operation,
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("permission denied"),
        );
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = snapshot
        .cache
        .purge_tag_partition_async(
          policy,
          tag,
          params.get("scheme").map(String::as_str),
          host,
          partition,
        )
        .await;
      let external_reports = snapshot
        .cache
        .purge_external_tag_partition(
          policy,
          tag,
          params.get("scheme").map(String::as_str),
          host,
          partition,
        )
        .await;
      (purged, external_reports)
    }
    _ => unreachable!("admin cache purge path checked before dispatch"),
  };
  if path == "/cache/purge-tag" {
    snapshot.metrics.record_cache_tag_purge();
  } else {
    snapshot.metrics.record_cache_purge();
  }
  admin_audit(
    peer_addr,
    authorization.actor,
    operation,
    None,
    None,
    AdminAuditOutcome::Applied,
    None,
  );
  info!(peer = %peer_addr, actor = %authorization.actor.name, policy, purged, "admin cache purge completed");
  let mut body = format!("purged={purged}\n");
  for report in external_reports {
    body.push_str("external_handler=");
    body.push_str(&report.handler);
    body.push_str(" status=");
    body.push_str(report.status);
    if let Some(purged) = report.purged {
      body.push_str(" purged=");
      body.push_str(&purged.to_string());
    }
    body.push('\n');
  }
  text_response(StatusCode::OK, &body)
}
