//! Upstream health snapshot projection for admin and diagnostics.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::convert::Infallible;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderName, HeaderValue, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Incoming;
use regex::Regex;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::config::{
  GrpcHealthServingStatus, HealthCheckMode, HealthCheckProtocol, HttpVersion, UpstreamPoolConfig,
  UpstreamPoolHealthCheckConfig,
};
use crate::state::{AppHandle, AppSnapshot, UpstreamBody};

pub(crate) async fn run_pool_health_checks(state: AppHandle, mut shutdown: watch::Receiver<bool>) {
  let mut next_checks = HashMap::new();

  loop {
    if *shutdown.borrow() {
      break;
    }

    let snapshot = state.snapshot();
    let now = Instant::now();
    let mut next_sleep = Duration::from_secs(5);

    for pool in &snapshot.config.upstream_pools {
      if pool.health_check.mode != HealthCheckMode::Active || !pool.health_check.enabled {
        continue;
      }

      for index in 0..pool.servers.len() {
        let server_id = crate::config::upstream_pool_server_id(index, &pool.servers[index]);
        let upstream_name = crate::pools::synthetic_upstream_name_for_id(&pool.name, &server_id);
        let due = next_checks.entry(upstream_name.clone()).or_insert(now);
        if *due > now {
          next_sleep = next_sleep.min(*due - now);
          continue;
        }

        *due = now + next_check_delay(&pool.health_check, &upstream_name);
        if check_pool_server(snapshot.clone(), pool, index, &upstream_name).await {
          snapshot
            .pools
            .report_active_success_async(&upstream_name)
            .await;
        } else {
          snapshot
            .pools
            .report_active_failure_async(&upstream_name)
            .await;
        }
      }
    }

    tokio::select! {
      _ = shutdown.changed() => {}
      _ = tokio::time::sleep(next_sleep) => {}
    }
  }
}

async fn check_pool_server(
  snapshot: Arc<AppSnapshot>,
  pool: &UpstreamPoolConfig,
  index: usize,
  upstream_name: &str,
) -> bool {
  let server = &pool.servers[index];
  if pool.health_check.protocol == HealthCheckProtocol::Grpc {
    return check_grpc_pool_server(snapshot, pool, index, upstream_name).await;
  }

  let url = match health_check_url(&server.origin, &pool.health_check, false) {
    Ok(url) => url,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "active health check URL is invalid");
      return false;
    }
  };
  let uri = match url.as_str().parse::<http::Uri>() {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "active health check URI is invalid");
      return false;
    }
  };

  let Some(client) = snapshot.health_check_clients.for_upstream_version(
    upstream_name,
    server.origin.scheme(),
    HttpVersion::H1,
  ) else {
    warn!(
      upstream = upstream_name,
      "active health check upstream client is not configured"
    );
    return false;
  };

  let request = match build_http_health_request(&pool.health_check, uri) {
    Ok(request) => request,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "failed to build active health check request");
      return false;
    }
  };

  let response = match tokio::time::timeout(
    Duration::from_millis(pool.health_check.timeout_ms),
    client.request(request),
  )
  .await
  {
    Ok(Ok(response)) => response,
    Ok(Err(error)) => {
      debug!(error = %error, upstream = upstream_name, "active health check request failed");
      return false;
    }
    Err(_) => {
      debug!(
        upstream = upstream_name,
        "active health check request timed out"
      );
      return false;
    }
  };

  let status = response.status();
  let status_matches = health_status_matches(&pool.health_check, status);
  let healthy = if status_matches {
    http_response_body_matches(response.into_body(), &pool.health_check, upstream_name).await
  } else {
    false
  };
  debug!(
    upstream = upstream_name,
    status = status.as_u16(),
    healthy,
    "active health check completed"
  );
  healthy
}

async fn check_grpc_pool_server(
  snapshot: Arc<AppSnapshot>,
  pool: &UpstreamPoolConfig,
  index: usize,
  upstream_name: &str,
) -> bool {
  let server = &pool.servers[index];
  let url = match health_check_url(&server.origin, &pool.health_check, true) {
    Ok(url) => url,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "gRPC active health check URL is invalid");
      return false;
    }
  };

  let uri = match url.as_str().parse::<http::Uri>() {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "gRPC active health check URI is invalid");
      return false;
    }
  };

  let Some(client) = snapshot.health_check_clients.for_upstream_version(
    upstream_name,
    server.origin.scheme(),
    HttpVersion::H2,
  ) else {
    warn!(
      upstream = upstream_name,
      "gRPC active health check upstream client is not configured"
    );
    return false;
  };

  let request = match build_grpc_health_request(&pool.health_check, uri) {
    Ok(request) => request,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "failed to build gRPC active health check request");
      return false;
    }
  };

  let response = match tokio::time::timeout(
    Duration::from_millis(pool.health_check.timeout_ms),
    client.request(request),
  )
  .await
  {
    Ok(Ok(response)) => response,
    Ok(Err(error)) => {
      debug!(error = %error, upstream = upstream_name, "gRPC active health check request failed");
      return false;
    }
    Err(_) => {
      debug!(
        upstream = upstream_name,
        "gRPC active health check request timed out"
      );
      return false;
    }
  };

  if response.status() != http::StatusCode::OK {
    debug!(
      upstream = upstream_name,
      status = response.status().as_u16(),
      "gRPC active health check returned non-OK HTTP status"
    );
    return false;
  }

  let (parts, body) = response.into_parts();
  let collected = match Limited::new(body, pool.health_check.body_match_max_bytes)
    .collect()
    .await
  {
    Ok(collected) => collected,
    Err(error) => {
      debug!(error = %error, upstream = upstream_name, "failed to read gRPC active health check response");
      return false;
    }
  };
  let trailers = collected.trailers();
  let grpc_status = trailers
    .and_then(|headers| headers.get("grpc-status"))
    .or_else(|| parts.headers.get("grpc-status"))
    .and_then(|value| value.to_str().ok())
    .unwrap_or("0");
  if grpc_status != "0" {
    debug!(
      upstream = upstream_name,
      grpc_status, "gRPC active health check returned non-zero grpc-status"
    );
    return false;
  }

  let status = match decode_grpc_health_response(&collected.to_bytes()) {
    Some(status) => status,
    None => {
      debug!(
        upstream = upstream_name,
        "failed to decode gRPC active health check response"
      );
      return false;
    }
  };
  let healthy = pool.health_check.grpc_expected_statuses.contains(&status);
  debug!(
    upstream = upstream_name,
    ?status,
    healthy,
    "gRPC active health check completed"
  );
  healthy
}

fn next_check_delay(health_check: &UpstreamPoolHealthCheckConfig, upstream_name: &str) -> Duration {
  Duration::from_millis(health_check.interval_ms)
    + jitter_duration(upstream_name, health_check.jitter_ms)
}

fn jitter_duration(upstream_name: &str, jitter_ms: u64) -> Duration {
  if jitter_ms == 0 {
    return Duration::ZERO;
  }
  let seed = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_nanos() as u64)
    .unwrap_or_default();
  let mut hasher = DefaultHasher::new();
  upstream_name.hash(&mut hasher);
  seed.hash(&mut hasher);
  Duration::from_millis(bounded_jitter_ms(hasher.finish(), jitter_ms))
}

fn bounded_jitter_ms(seed: u64, jitter_ms: u64) -> u64 {
  if jitter_ms == 0 {
    return 0;
  }
  seed % (jitter_ms + 1)
}

pub(crate) fn health_check_url(
  origin: &url::Url,
  health_check: &UpstreamPoolHealthCheckConfig,
  grpc: bool,
) -> anyhow::Result<url::Url> {
  let mut url = origin.clone();
  if let Some(port) = health_check.health_port {
    url
      .set_port(Some(port))
      .map_err(|()| anyhow::anyhow!("failed to apply health_check.health_port"))?;
  }
  url.set_path(if grpc {
    "/grpc.health.v1.Health/Check"
  } else {
    &health_check.path
  });
  url.set_query(None);
  url.set_fragment(None);
  Ok(url)
}

pub(crate) fn build_http_health_request(
  health_check: &UpstreamPoolHealthCheckConfig,
  uri: http::Uri,
) -> anyhow::Result<http::Request<UpstreamBody>> {
  let method = http::Method::from_bytes(health_check.method.as_bytes())?;
  let body = if health_check.body.is_empty() {
    empty_body()
  } else {
    full_body(Bytes::from(health_check.body.clone()))
  };
  let mut request = http::Request::builder()
    .method(method)
    .uri(uri)
    .body(body)?;
  apply_configured_health_headers(&mut request, health_check)?;
  Ok(request)
}

fn build_grpc_health_request(
  health_check: &UpstreamPoolHealthCheckConfig,
  uri: http::Uri,
) -> anyhow::Result<http::Request<UpstreamBody>> {
  let mut request = http::Request::builder()
    .method(http::Method::POST)
    .uri(uri)
    .header(http::header::CONTENT_TYPE, "application/grpc")
    .header(http::header::TE, "trailers")
    .body(full_body(encode_grpc_health_request(
      &health_check.grpc_service,
    )))?;
  apply_configured_health_headers(&mut request, health_check)?;
  Ok(request)
}

fn apply_configured_health_headers(
  request: &mut http::Request<UpstreamBody>,
  health_check: &UpstreamPoolHealthCheckConfig,
) -> anyhow::Result<()> {
  if let Some(host) = health_check.health_host.as_deref() {
    request
      .headers_mut()
      .insert(HOST, HeaderValue::from_str(host)?);
  }
  for header in &health_check.headers {
    request.headers_mut().append(
      HeaderName::from_bytes(header.name.as_bytes())?,
      HeaderValue::from_str(&header.value)?,
    );
  }
  Ok(())
}

pub(crate) fn health_status_matches(
  health_check: &UpstreamPoolHealthCheckConfig,
  status: StatusCode,
) -> bool {
  let status = status.as_u16();
  health_check.expected_status.contains(&status)
    || health_check
      .expected_status_ranges
      .iter()
      .any(|range| status >= range.start && status <= range.end)
}

async fn http_response_body_matches(
  body: Incoming,
  health_check: &UpstreamPoolHealthCheckConfig,
  upstream_name: &str,
) -> bool {
  let Some(pattern) = health_check.expected_body_regex.as_deref() else {
    return true;
  };
  let regex = match Regex::new(pattern) {
    Ok(regex) => regex,
    Err(error) => {
      debug!(
        error = %error,
        upstream = upstream_name,
        "active health check body regex is invalid"
      );
      return false;
    }
  };
  let collected = match Limited::new(body, health_check.body_match_max_bytes)
    .collect()
    .await
  {
    Ok(collected) => collected,
    Err(error) => {
      debug!(error = %error, upstream = upstream_name, "failed to read active health check response body");
      return false;
    }
  };
  let body_bytes = collected.to_bytes();
  let body = String::from_utf8_lossy(&body_bytes);
  regex.is_match(&body)
}

fn empty_body() -> UpstreamBody {
  Empty::<Bytes>::new()
    .map_err(|never: Infallible| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
    .boxed()
}

fn full_body(bytes: Bytes) -> UpstreamBody {
  http_body_util::Full::new(bytes)
    .map_err(|never: Infallible| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
    .boxed()
}

fn encode_grpc_health_request(service: &str) -> Bytes {
  let mut message = Vec::new();
  if !service.is_empty() {
    message.push(0x0a);
    encode_varint(service.len() as u64, &mut message);
    message.extend_from_slice(service.as_bytes());
  }
  let mut frame = Vec::with_capacity(5 + message.len());
  frame.push(0);
  frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
  frame.extend_from_slice(&message);
  Bytes::from(frame)
}

fn decode_grpc_health_response(frame: &[u8]) -> Option<GrpcHealthServingStatus> {
  if frame.len() < 5 || frame[0] != 0 {
    return None;
  }
  let len = u32::from_be_bytes(frame[1..5].try_into().ok()?) as usize;
  let message = frame.get(5..5 + len)?;
  let mut index = 0;
  while index < message.len() {
    let key = decode_varint(message, &mut index)?;
    let field = key >> 3;
    let wire = key & 0x07;
    if field == 1 && wire == 0 {
      return match decode_varint(message, &mut index)? {
        0 => Some(GrpcHealthServingStatus::Unknown),
        1 => Some(GrpcHealthServingStatus::Serving),
        2 => Some(GrpcHealthServingStatus::NotServing),
        3 => Some(GrpcHealthServingStatus::ServiceUnknown),
        _ => None,
      };
    }
    skip_protobuf_field(wire, message, &mut index)?;
  }
  None
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
  while value >= 0x80 {
    out.push((value as u8 & 0x7f) | 0x80);
    value >>= 7;
  }
  out.push(value as u8);
}

fn decode_varint(input: &[u8], index: &mut usize) -> Option<u64> {
  let mut value = 0u64;
  let mut shift = 0;
  loop {
    let byte = *input.get(*index)?;
    *index += 1;
    value |= ((byte & 0x7f) as u64) << shift;
    if byte & 0x80 == 0 {
      return Some(value);
    }
    shift += 7;
    if shift >= 64 {
      return None;
    }
  }
}

fn skip_protobuf_field(wire: u64, input: &[u8], index: &mut usize) -> Option<()> {
  match wire {
    0 => {
      decode_varint(input, index)?;
      Some(())
    }
    2 => {
      let len = decode_varint(input, index)? as usize;
      *index = (*index).checked_add(len)?;
      if *index <= input.len() {
        Some(())
      } else {
        None
      }
    }
    5 => {
      *index = (*index).checked_add(4)?;
      if *index <= input.len() {
        Some(())
      } else {
        None
      }
    }
    1 => {
      *index = (*index).checked_add(8)?;
      if *index <= input.len() {
        Some(())
      } else {
        None
      }
    }
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{
    UpstreamPoolHealthCheckHeaderConfig, UpstreamPoolHealthCheckStatusRangeConfig,
  };

  #[test]
  fn encodes_grpc_health_request() {
    let frame = encode_grpc_health_request("svc");
    assert_eq!(frame.as_ref(), &[0, 0, 0, 0, 5, 0x0a, 3, b's', b'v', b'c']);
  }

  #[test]
  fn decodes_grpc_health_response() {
    let frame = Bytes::from_static(&[0, 0, 0, 0, 2, 0x08, 1]);
    assert_eq!(
      decode_grpc_health_response(&frame),
      Some(GrpcHealthServingStatus::Serving)
    );
  }

  #[tokio::test]
  async fn builds_http_health_check_request_with_method_headers_body_and_host() {
    let mut health_check = UpstreamPoolHealthCheckConfig {
      method: "POST".to_string(),
      health_host: Some("health.internal.example".to_string()),
      body: "{\"probe\":\"ok\"}".to_string(),
      headers: vec![UpstreamPoolHealthCheckHeaderConfig {
        name: "X-OxiBelt-Health".to_string(),
        value: "active".to_string(),
      }],
      ..UpstreamPoolHealthCheckConfig::default()
    };
    health_check.expected_status = vec![204];

    let request = build_http_health_request(
      &health_check,
      "http://backend.internal:18081/health".parse().unwrap(),
    )
    .expect("health request should build");
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.headers()[HOST], "health.internal.example");
    assert_eq!(request.headers()["x-oxibelt-health"], "active");

    let body = request
      .into_body()
      .collect()
      .await
      .expect("body should collect")
      .to_bytes();
    assert_eq!(body.as_ref(), br#"{"probe":"ok"}"#);
  }

  #[test]
  fn matches_exact_status_or_status_range() {
    let health_check = UpstreamPoolHealthCheckConfig {
      expected_status: vec![204],
      expected_status_ranges: vec![UpstreamPoolHealthCheckStatusRangeConfig {
        start: 200,
        end: 202,
      }],
      ..UpstreamPoolHealthCheckConfig::default()
    };

    assert!(health_status_matches(&health_check, StatusCode::OK));
    assert!(health_status_matches(&health_check, StatusCode::NO_CONTENT));
    assert!(!health_status_matches(
      &health_check,
      StatusCode::INTERNAL_SERVER_ERROR
    ));
  }

  #[test]
  fn bounded_jitter_stays_within_limit() {
    assert_eq!(bounded_jitter_ms(42, 0), 0);
    for seed in [0, 1, 42, u64::MAX] {
      assert!(bounded_jitter_ms(seed, 250) <= 250);
    }
  }

  #[tokio::test]
  async fn grpc_health_request_preserves_protocol_shape_and_custom_headers() {
    let health_check = UpstreamPoolHealthCheckConfig {
      protocol: HealthCheckProtocol::Grpc,
      health_host: Some("grpc-health.internal.example".to_string()),
      headers: vec![UpstreamPoolHealthCheckHeaderConfig {
        name: "X-OxiBelt-Health".to_string(),
        value: "grpc".to_string(),
      }],
      grpc_service: "svc".to_string(),
      ..UpstreamPoolHealthCheckConfig::default()
    };

    let request = build_grpc_health_request(
      &health_check,
      "http://backend.internal/grpc.health.v1.Health/Check"
        .parse()
        .unwrap(),
    )
    .expect("gRPC health request should build");
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(
      request.headers()[http::header::CONTENT_TYPE],
      "application/grpc"
    );
    assert_eq!(request.headers()[HOST], "grpc-health.internal.example");
    assert_eq!(request.headers()["x-oxibelt-health"], "grpc");

    let body = request
      .into_body()
      .collect()
      .await
      .expect("body should collect")
      .to_bytes();
    assert_eq!(body.as_ref(), &[0, 0, 0, 0, 5, 0x0a, 3, b's', b'v', b'c']);
  }
}
