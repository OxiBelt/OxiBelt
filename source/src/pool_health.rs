use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::config::{
  GrpcHealthServingStatus, HealthCheckMode, HealthCheckProtocol, HttpVersion, UpstreamPoolConfig,
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

        *due = now + Duration::from_millis(pool.health_check.interval_ms);
        if check_pool_server(snapshot.clone(), pool, index, &upstream_name).await {
          snapshot.pools.report_active_success(&upstream_name);
        } else {
          snapshot.pools.report_active_failure(&upstream_name);
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

  let mut url = server.origin.clone();
  url.set_path(&pool.health_check.path);
  url.set_query(None);
  url.set_fragment(None);

  let uri = match url.as_str().parse::<http::Uri>() {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "active health check URI is invalid");
      return false;
    }
  };

  let Some(client) =
    snapshot
      .clients
      .for_upstream_version(upstream_name, server.origin.scheme(), HttpVersion::H1)
  else {
    warn!(
      upstream = upstream_name,
      "active health check upstream client is not configured"
    );
    return false;
  };

  let request = match http::Request::builder()
    .method(http::Method::GET)
    .uri(uri)
    .body(empty_body())
  {
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

  let healthy = pool
    .health_check
    .expected_status
    .iter()
    .any(|status| *status == response.status().as_u16());
  debug!(
    upstream = upstream_name,
    status = response.status().as_u16(),
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
  let mut url = server.origin.clone();
  url.set_path("/grpc.health.v1.Health/Check");
  url.set_query(None);
  url.set_fragment(None);

  let uri = match url.as_str().parse::<http::Uri>() {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "gRPC active health check URI is invalid");
      return false;
    }
  };

  let Some(client) =
    snapshot
      .clients
      .for_upstream_version(upstream_name, server.origin.scheme(), HttpVersion::H2)
  else {
    warn!(
      upstream = upstream_name,
      "gRPC active health check upstream client is not configured"
    );
    return false;
  };

  let request = match http::Request::builder()
    .method(http::Method::POST)
    .uri(uri)
    .header(http::header::CONTENT_TYPE, "application/grpc")
    .header(http::header::TE, "trailers")
    .body(full_body(encode_grpc_health_request(
      &pool.health_check.grpc_service,
    ))) {
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
  let collected = match body.collect().await {
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
}
