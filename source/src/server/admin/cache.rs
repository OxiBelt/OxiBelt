use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use ::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri};
use anyhow::bail;
use base64::Engine as _;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::routes::{RouteMatchContext, RouteRequestProtocol, normalize_host};
use crate::state::AppSnapshot;

use super::super::{
  AdminActor, AdminAuditOutcome, AdminAuthorization, admin_audit, admin_resource,
};
use super::{collect_admin_json, json_response};

mod warm;
pub(in crate::server) use warm::{
  cache_warm_response, enqueue_cache_warm_operation, recover_cache_warm_command,
};

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

/// RFC 9875-capable policies make every purge operation capable of removing a
/// group-associated representation. Require the group-specific grant before
/// dispatching any mutation, including the legacy signed-query endpoints.
fn authorize_cache_purge_mutation(
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  action: &str,
  policy: &str,
  host: Option<&str>,
) -> bool {
  authorize_cache_target(authorization, action, policy, host)
    && (!snapshot.cache.groups_enabled(policy)
      || authorize_cache_target(authorization, "cache:PurgeGroup", policy, host))
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
  let tls = crate::proxy::http::cache_warm_tls_metadata(scheme, host);
  let client_addr = snapshot
    .resolve_client_addr(
      &request_headers,
      peer_addr,
      &normalize_host(host),
      tls.sni.as_deref().filter(|_| tls.enabled),
    )
    .map_err(|_| "invalid real IP metadata")?;
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
  #[serde(default)]
  query: Option<AdminCacheQueryExplain>,
}

/// A base64 field value keeps the diagnostic wire format lossless without
/// interpreting untrusted header bytes as UTF-8.  A vector, rather than a
/// map, preserves field order and repeated names.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(in crate::server) struct AdminBase64Header {
  pub(in crate::server) name: String,
  pub(in crate::server) value_base64: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AdminCacheQueryTarget {
  scheme: String,
  authority: String,
  uri: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AdminCacheQueryRepresentation {
  target: AdminCacheQueryTarget,
  headers: Vec<AdminBase64Header>,
  body_base64: String,
  #[serde(default)]
  trailers: Vec<AdminBase64Header>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AdminCacheQueryExplain {
  original: AdminCacheQueryRepresentation,
  effective: AdminCacheQueryRepresentation,
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
  origin: Option<String>,
  #[serde(default)]
  group: Option<String>,
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
  let mut headers = match header_map_from_strings(body.headers) {
    Ok(headers) => headers,
    Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
  };
  let response_headers = match header_map_from_strings(body.response_headers) {
    Ok(headers) => headers,
    Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
  };
  let query_identity = match prepare_key_explain_query(&method, body.query.as_ref()) {
    Ok(identity) => identity,
    Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
  };
  crate::proxy::http::client_certificate::strip_reserved(&mut headers, snapshot);
  let no_vary_search = body.query.as_ref().and_then(|query| {
    crate::cache::CacheNvsRequest::new(query.effective.target.uri.parse().ok()?, b"admin-explain")
  });
  // Key explanation only needs the stable origin portion of a group request
  // to derive its base key; it must not obtain or mutate a group epoch.
  let group_request = crate::cache::CacheGroupOrigin::new(&body.scheme, &body.host)
    .ok()
    .map(crate::cache::CacheGroupRequest::new);
  let mut explain = snapshot.cache.explain_key(
    crate::cache::CacheLookupContext {
      group_request: group_request.as_ref(),
      no_vary_search: no_vary_search.as_ref(),
      proxy_protocol_identity: None,
      certificate_identity: None,
      policy_name: body.policy.as_deref(),
      scheme: &body.scheme,
      host: &body.host,
      method: &method,
      uri: &uri,
      request_headers: &headers,
      query_identity: query_identity.as_ref().map(|value| &value.identity),
    },
    (!response_headers.is_empty()).then_some(&response_headers),
  );
  if !snapshot.client_certificate_forwarding_headers.is_empty() {
    explain.reasons.push("Certificate-forwarding routes add a trusted TLS discriminator unavailable to this diagnostic".to_string());
  }
  if let Some(query) = query_identity {
    let mut response = serde_json::to_value(explain).unwrap_or(serde_json::Value::Null);
    response["query"] = query.wire;
    json_response(StatusCode::OK, &response)
  } else {
    json_response(StatusCode::OK, &explain)
  }
}

struct PreparedKeyExplainQuery {
  identity: crate::cache::CacheQueryIdentity,
  wire: serde_json::Value,
}

fn prepare_key_explain_query(
  method: &Method,
  query: Option<&AdminCacheQueryExplain>,
) -> Result<Option<PreparedKeyExplainQuery>, &'static str> {
  if method.as_str() != "QUERY" {
    return if query.is_some() {
      Err("query identity is only valid for QUERY")
    } else {
      Ok(None)
    };
  }
  let query = query.ok_or("QUERY key-explain requires query.original and query.effective")?;
  let (original, _) = prepare_key_explain_query_representation(&query.original)?;
  let (effective, effective_headers) = prepare_key_explain_query_representation(&query.effective)?;
  let identity = crate::cache::CacheQueryIdentity::new(original, effective, effective_headers)
    .map_err(|_| "invalid QUERY cache identity")?;
  Ok(Some(PreparedKeyExplainQuery {
    identity,
    wire: serde_json::to_value(query).map_err(|_| "invalid QUERY cache identity")?,
  }))
}

fn prepare_key_explain_query_representation(
  representation: &AdminCacheQueryRepresentation,
) -> Result<(crate::cache::CacheQueryRepresentation, HeaderMap), &'static str> {
  let uri = representation
    .target
    .uri
    .parse::<Uri>()
    .map_err(|_| "invalid QUERY target URI")?;
  let headers = header_map_from_base64(&representation.headers)?;
  let trailers = header_map_from_base64(&representation.trailers)?;
  let query_method = Method::from_bytes(b"QUERY").map_err(|_| "invalid QUERY cache identity")?;
  crate::proxy::http::query::validate_content_type(&query_method, &headers)?;
  let body = decode_base64_bounded(&representation.body_base64)?;
  let identity = crate::cache::CacheQueryRepresentation::new(
    &representation.target.scheme,
    &representation.target.authority,
    &uri,
    body.len() as u64,
    crate::crypto::sha256(&body),
    &headers,
    &trailers,
  )
  .map_err(|_| "invalid QUERY cache identity")?;
  Ok((identity, headers))
}

const ADMIN_QUERY_BODY_MAX_BYTES: usize = 48 * 1024;

pub(in crate::server) fn decode_base64_bounded(value: &str) -> Result<Vec<u8>, &'static str> {
  // The request envelope has a 64 KiB limit. Keep the decoded request body
  // separately bounded so it cannot turn a compact encoded value into an
  // unbounded replay payload.
  if value.len() > (ADMIN_QUERY_BODY_MAX_BYTES * 4 / 3) + 8 {
    return Err("QUERY body exceeds its bound");
  }
  let body = base64::engine::general_purpose::STANDARD
    .decode(value)
    .map_err(|_| "invalid QUERY body base64")?;
  if body.len() > ADMIN_QUERY_BODY_MAX_BYTES {
    return Err("QUERY body exceeds its bound");
  }
  Ok(body)
}

pub(in crate::server) fn header_map_from_base64(
  headers: &[AdminBase64Header],
) -> Result<HeaderMap, &'static str> {
  let mut map = HeaderMap::new();
  for header in headers {
    let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| "invalid header name")?;
    let value = base64::engine::general_purpose::STANDARD
      .decode(&header.value_base64)
      .map_err(|_| "invalid header value base64")?;
    let value = HeaderValue::from_bytes(&value).map_err(|_| "invalid header value")?;
    map.append(name, value);
  }
  Ok(map)
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
      if !authorize_cache_purge_mutation(
        snapshot,
        authorization,
        "cache:PurgeObject",
        policy,
        Some(host),
      ) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = match snapshot
        .cache
        .purge_exact_partition_async(policy, scheme, host, uri, partition)
        .await
      {
        Ok(purged) => purged,
        Err(error) => {
          return cache_purge_unavailable_response(
            peer_addr,
            authorization.actor,
            "cache_purge_json",
            error,
          );
        }
      };
      let external_reports = if snapshot.cache.groups_enabled(policy) {
        Vec::new()
      } else {
        snapshot
          .cache
          .purge_external_exact_partition(policy, scheme, host, uri, partition)
          .await
      };
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
      if !authorize_cache_purge_mutation(
        snapshot,
        authorization,
        "cache:PurgePrefix",
        policy,
        Some(host),
      ) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = match snapshot
        .cache
        .purge_prefix_partition_async(policy, scheme, host, path_prefix, partition)
        .await
      {
        Ok(purged) => purged,
        Err(error) => {
          return cache_purge_unavailable_response(
            peer_addr,
            authorization.actor,
            "cache_purge_prefix_json",
            error,
          );
        }
      };
      let external_reports = if snapshot.cache.groups_enabled(policy) {
        Vec::new()
      } else {
        snapshot
          .cache
          .purge_external_prefix_partition(policy, scheme, host, path_prefix, partition)
          .await
      };
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
      if !authorize_cache_purge_mutation(
        snapshot,
        authorization,
        "cache:PurgeTag",
        policy,
        body.host.as_deref(),
      ) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = match snapshot
        .cache
        .purge_tag_partition_async(
          policy,
          tag,
          body.scheme.as_deref(),
          body.host.as_deref(),
          partition,
        )
        .await
      {
        Ok(purged) => purged,
        Err(error) => {
          return cache_purge_unavailable_response(
            peer_addr,
            authorization.actor,
            "cache_purge_tag_json",
            error,
          );
        }
      };
      let external_reports = if snapshot.cache.groups_enabled(policy) {
        Vec::new()
      } else {
        snapshot
          .cache
          .purge_external_tag_partition(
            policy,
            tag,
            body.scheme.as_deref(),
            body.host.as_deref(),
            partition,
          )
          .await
      };
      (purged, external_reports)
    }
    "group" => {
      let Some(origin) = body.origin.as_deref() else {
        audit_rejected_cache_purge(
          peer_addr,
          authorization.actor,
          "cache_purge_group_json",
          "missing origin",
        );
        return text_response(StatusCode::BAD_REQUEST, "missing origin");
      };
      let origin = match crate::cache::CacheGroupOrigin::parse_origin(origin) {
        Ok(origin) => origin,
        Err(_) => {
          audit_rejected_cache_purge(
            peer_addr,
            authorization.actor,
            "cache_purge_group_json",
            "invalid origin",
          );
          return text_response(StatusCode::BAD_REQUEST, "invalid origin");
        }
      };
      let Some(group) = body.group.as_deref() else {
        audit_rejected_cache_purge(
          peer_addr,
          authorization.actor,
          "cache_purge_group_json",
          "missing group",
        );
        return text_response(StatusCode::BAD_REQUEST, "missing group");
      };
      let group = match parse_admin_cache_group(group) {
        Ok(group) => group,
        Err(reason) => {
          audit_rejected_cache_purge(
            peer_addr,
            authorization.actor,
            "cache_purge_group_json",
            reason,
          );
          return text_response(StatusCode::BAD_REQUEST, reason);
        }
      };
      if !authorize_cache_target(
        authorization,
        "cache:PurgeGroup",
        policy,
        Some(&origin.authority()),
      ) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let purged = match snapshot
        .cache
        .purge_group_async(policy, &origin, &group, partition)
        .await
      {
        Ok(purged) => purged,
        Err(error) => {
          return cache_purge_unavailable_response(
            peer_addr,
            authorization.actor,
            "cache_purge_group_json",
            error,
          );
        }
      };
      (purged, Vec::new())
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
      "group" => "cache_purge_group_json",
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

fn parse_admin_cache_group(value: &str) -> Result<String, &'static str> {
  if value.len() > 256 {
    return Err("group exceeds 256 bytes");
  }
  if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
    return Err("invalid group");
  }
  Ok(value.to_string())
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

fn cache_purge_unavailable_response(
  peer_addr: SocketAddr,
  actor: &AdminActor,
  operation: &'static str,
  error: impl std::fmt::Display,
) -> Response<ProxyBody> {
  warn!(peer = %peer_addr, actor = %actor.name, operation, error = %error, "shared cache purge did not complete");
  admin_audit(
    peer_addr,
    actor,
    operation,
    None,
    None,
    AdminAuditOutcome::Rejected,
    Some("shared cache purge unavailable"),
  );
  text_response(
    StatusCode::SERVICE_UNAVAILABLE,
    "shared cache purge unavailable",
  )
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
      if !authorize_cache_purge_mutation(snapshot, authorization, action, policy, Some(host)) {
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
      let purged = match snapshot
        .cache
        .purge_exact_partition_async(policy, purge_scheme, host, uri, partition)
        .await
      {
        Ok(purged) => purged,
        Err(error) => {
          return cache_purge_unavailable_response(
            peer_addr,
            authorization.actor,
            operation,
            error,
          );
        }
      };
      let external_reports = if snapshot.cache.groups_enabled(policy) {
        Vec::new()
      } else {
        snapshot
          .cache
          .purge_external_exact_partition(policy, purge_scheme, host, uri, partition)
          .await
      };
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
      if !authorize_cache_purge_mutation(snapshot, authorization, action, policy, Some(host)) {
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
      let purged = match snapshot
        .cache
        .purge_prefix_partition_async(policy, purge_scheme, host, path_prefix, partition)
        .await
      {
        Ok(purged) => purged,
        Err(error) => {
          return cache_purge_unavailable_response(
            peer_addr,
            authorization.actor,
            operation,
            error,
          );
        }
      };
      let external_reports = if snapshot.cache.groups_enabled(policy) {
        Vec::new()
      } else {
        snapshot
          .cache
          .purge_external_prefix_partition(policy, purge_scheme, host, path_prefix, partition)
          .await
      };
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
      if !authorize_cache_purge_mutation(snapshot, authorization, action, policy, host) {
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
      let purged = match snapshot
        .cache
        .purge_tag_partition_async(
          policy,
          tag,
          params.get("scheme").map(String::as_str),
          host,
          partition,
        )
        .await
      {
        Ok(purged) => purged,
        Err(error) => {
          return cache_purge_unavailable_response(
            peer_addr,
            authorization.actor,
            operation,
            error,
          );
        }
      };
      let external_reports = if snapshot.cache.groups_enabled(policy) {
        Vec::new()
      } else {
        snapshot
          .cache
          .purge_external_tag_partition(
            policy,
            tag,
            params.get("scheme").map(String::as_str),
            host,
            partition,
          )
          .await
      };
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

#[cfg(test)]
mod tests {
  use super::*;

  fn query_representation(uri: &str) -> AdminCacheQueryRepresentation {
    AdminCacheQueryRepresentation {
      target: AdminCacheQueryTarget {
        scheme: "https".to_string(),
        authority: "example.com".to_string(),
        uri: uri.to_string(),
      },
      headers: vec![AdminBase64Header {
        name: "content-type".to_string(),
        value_base64: "YXBwbGljYXRpb24vanNvbg==".to_string(),
      }],
      body_base64: "e30=".to_string(),
      trailers: vec![AdminBase64Header {
        name: "x-query-trailer".to_string(),
        value_base64: "dmFsdWU=".to_string(),
      }],
    }
  }

  #[test]
  fn query_key_explain_requires_explicit_lossless_representations() {
    let method = Method::from_bytes(b"QUERY").expect("QUERY method");
    assert_eq!(
      prepare_key_explain_query(&method, None).err(),
      Some("QUERY key-explain requires query.original and query.effective")
    );
    let prepared = prepare_key_explain_query(
      &method,
      Some(&AdminCacheQueryExplain {
        original: query_representation("/received"),
        effective: query_representation("/forwarded"),
      }),
    )
    .expect("valid QUERY views")
    .expect("QUERY identity");
    assert_eq!(
      prepared.wire["original"]["target"]["uri"].as_str(),
      Some("/received")
    );
    assert_eq!(
      prepared.wire["effective"]["target"]["uri"].as_str(),
      Some("/forwarded")
    );
  }

  #[test]
  fn cache_group_purge_accepts_bounded_decoded_printable_strings() {
    assert_eq!(
      parse_admin_cache_group("release-1"),
      Ok("release-1".to_string())
    );
    assert_eq!(parse_admin_cache_group("a\\\"b"), Ok("a\\\"b".to_string()));
    assert_eq!(parse_admin_cache_group(""), Ok(String::new()));
    assert_eq!(parse_admin_cache_group("release\n1"), Err("invalid group"));
    assert_eq!(parse_admin_cache_group("snowman ☃"), Err("invalid group"));
    assert_eq!(
      parse_admin_cache_group(&"x".repeat(257)),
      Err("group exceeds 256 bytes")
    );
  }

  #[test]
  fn query_header_decoder_preserves_repeated_header_order() {
    let headers = header_map_from_base64(&[
      AdminBase64Header {
        name: "x-query".to_string(),
        value_base64: "b25l".to_string(),
      },
      AdminBase64Header {
        name: "x-query".to_string(),
        value_base64: "dHdv".to_string(),
      },
    ])
    .expect("base64 headers");
    let values = headers
      .get_all("x-query")
      .iter()
      .map(|value| value.as_bytes())
      .collect::<Vec<_>>();
    assert_eq!(values, vec![b"one".as_slice(), b"two".as_slice()]);
  }
}
