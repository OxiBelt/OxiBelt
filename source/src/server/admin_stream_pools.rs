//! Admin stream-pool status and server mutation endpoints.
//! Generic stream pools are L4-only and accept `tcp://` or `udp://` server origins.

use std::net::SocketAddr;

use ::http::{Response, StatusCode};
use anyhow::{Context, bail};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;

use crate::config::{StreamUpstreamPoolServerConfig, UpstreamPoolServerState};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::{AppHandle, AppSnapshot};
use crate::stream_control;

use super::admin::json_response;
use super::admin_auth::{AdminActor, AdminAuthorization};
use super::admin_body::collect_admin_json;
use super::{AdminAuditOutcome, admin_audit, admin_error, admin_resource};

pub(super) async fn admin_stream_pools_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path == "/admin/v1/stream-pools" {
    if !authorization.is_allowed("stream-pool:List", "*") {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::GET {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    return Some(json_response(
      StatusCode::OK,
      &snapshot.stream_pools.snapshots(),
    ));
  }

  if path == "/admin/v1/stream-pools/status" {
    if !authorization.is_allowed(
      "stream-pool:GetStatus",
      admin_resource::stream_pool_status(),
    ) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::GET {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    return Some(json_response(
      StatusCode::OK,
      &stream_control::stream_pool_status(snapshot),
    ));
  }

  let rest = path.strip_prefix("/admin/v1/stream-pools/")?;
  let segments = rest.split('/').collect::<Vec<_>>();
  if segments.len() == 1 {
    if !authorization.is_allowed("stream-pool:Get", segments[0]) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::GET {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    let Some(pool) = snapshot.stream_pools.snapshot(segments[0]) else {
      return Some(text_response(StatusCode::NOT_FOUND, "not found"));
    };
    return Some(json_response(StatusCode::OK, &pool));
  }

  if segments.len() == 2 && segments[1] == "servers" {
    if *method != ::http::Method::POST {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    let if_match = request_if_match(&request);
    let body = match collect_admin_json::<AdminAddStreamPoolServerRequest>(request).await {
      Ok(body) => body,
      Err(response) => {
        admin_audit(
          peer_addr,
          authorization.actor,
          "stream_server_add",
          Some(segments[0]),
          None,
          AdminAuditOutcome::Rejected,
          Some("invalid request body"),
        );
        return Some(response);
      }
    };
    let resource = admin_resource::stream_pool_server(segments[0], &body.id);
    if !authorization.is_allowed("stream-pool:AddServer", &resource) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    return Some(
      admin_add_stream_pool_server(
        body,
        &state,
        peer_addr,
        authorization.actor,
        segments[0].to_string(),
        if_match.as_deref(),
      )
      .await,
    );
  }

  if segments.len() == 3 && segments[1] == "servers" {
    let action = match *method {
      ::http::Method::PATCH => "stream-pool:UpdateServer",
      ::http::Method::DELETE => "stream-pool:RemoveServer",
      _ => {
        return Some(text_response(
          StatusCode::METHOD_NOT_ALLOWED,
          "method not allowed",
        ));
      }
    };
    let resource = admin_resource::stream_pool_server(segments[0], segments[2]);
    if !authorization.is_allowed(action, &resource) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    let if_match = request_if_match(&request);
    return Some(match *method {
      ::http::Method::PATCH => {
        admin_patch_stream_pool_server(
          request,
          &state,
          peer_addr,
          authorization.actor,
          segments[0].to_string(),
          segments[2].to_string(),
          if_match.as_deref(),
        )
        .await
      }
      ::http::Method::DELETE => {
        admin_delete_stream_pool_server(
          &state,
          peer_addr,
          authorization.actor,
          segments[0].to_string(),
          segments[2].to_string(),
          if_match.as_deref(),
        )
        .await
      }
      _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    });
  }

  Some(text_response(StatusCode::NOT_FOUND, "not found"))
}

#[derive(Debug, Deserialize)]
struct AdminAddStreamPoolServerRequest {
  id: String,
  origin: url::Url,
  #[serde(default = "default_admin_stream_pool_server_weight")]
  weight: u32,
  #[serde(default)]
  max_conns: usize,
  #[serde(default)]
  backup: bool,
  #[serde(default)]
  state: UpstreamPoolServerState,
}

fn default_admin_stream_pool_server_weight() -> u32 {
  1
}

#[derive(Debug, Deserialize)]
struct AdminPatchStreamPoolServerRequest {
  #[serde(default)]
  state: Option<UpstreamPoolServerState>,
  #[serde(default)]
  weight: Option<u32>,
  #[serde(default)]
  max_conns: Option<usize>,
  #[serde(default)]
  backup: Option<bool>,
}

async fn admin_add_stream_pool_server(
  body: AdminAddStreamPoolServerRequest,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
  if_match: Option<&str>,
) -> Response<ProxyBody> {
  let server_id = body.id.clone();
  let result =
    stream_control::apply_runtime_stream_pool_update_checked(state, if_match, |config| {
      let pool = stream_control::find_pool_mut(config, &pool_name)?;
      stream_control::ensure_unique_server_id(pool, &server_id)?;
      if body.weight == 0 {
        bail!("stream upstream pool server weight must be greater than 0");
      }
      pool.servers.push(StreamUpstreamPoolServerConfig {
        id: Some(server_id.clone()),
        origin: body.origin.clone(),
        weight: body.weight,
        max_conns: body.max_conns,
        backup: body.backup,
        state: body.state,
      });
      Ok(())
    })
    .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "stream_server_add",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Applied,
        None,
      );
      json_response(StatusCode::CREATED, &json!({ "ok": true }))
    }
    Err(error) => {
      let message = error.to_string();
      admin_audit(
        peer_addr,
        actor,
        "stream_server_add",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      stream_pool_error_response(error)
    }
  }
}

async fn admin_patch_stream_pool_server(
  request: hyper::Request<Incoming>,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
  server_id: String,
  if_match: Option<&str>,
) -> Response<ProxyBody> {
  let body = match collect_admin_json::<AdminPatchStreamPoolServerRequest>(request).await {
    Ok(body) => body,
    Err(response) => {
      admin_audit(
        peer_addr,
        actor,
        "stream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some("invalid request body"),
      );
      return response;
    }
  };
  let result =
    stream_control::apply_runtime_stream_pool_update_checked(state, if_match, |config| {
      let pool = stream_control::find_pool_mut(config, &pool_name)?;
      let (_, server) = stream_control::find_server_mut(pool, &server_id)?;
      if let Some(state) = body.state {
        server.state = state;
      }
      if let Some(weight) = body.weight {
        if weight == 0 {
          bail!("stream upstream pool server weight must be greater than 0");
        }
        server.weight = weight;
      }
      if let Some(max_conns) = body.max_conns {
        server.max_conns = max_conns;
      }
      if let Some(backup) = body.backup {
        server.backup = backup;
      }
      Ok(())
    })
    .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "stream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Applied,
        None,
      );
      json_response(StatusCode::OK, &json!({ "ok": true }))
    }
    Err(error) => {
      let message = error.to_string();
      admin_audit(
        peer_addr,
        actor,
        "stream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      stream_pool_error_response(error)
    }
  }
}

async fn admin_delete_stream_pool_server(
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
  server_id: String,
  if_match: Option<&str>,
) -> Response<ProxyBody> {
  let result =
    stream_control::apply_runtime_stream_pool_update_checked(state, if_match, |config| {
      let pool = stream_control::find_pool_mut(config, &pool_name)?;
      let index = pool
        .servers
        .iter()
        .enumerate()
        .find(|(index, server)| {
          crate::config::stream_upstream_pool_server_id(*index, server) == server_id.as_str()
        })
        .map(|(index, _)| index)
        .with_context(|| format!("unknown stream upstream pool server {server_id}"))?;
      pool.servers.remove(index);
      Ok(())
    })
    .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "stream_server_delete",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Applied,
        None,
      );
      json_response(StatusCode::OK, &json!({ "ok": true }))
    }
    Err(error) => {
      let message = error.to_string();
      admin_audit(
        peer_addr,
        actor,
        "stream_server_delete",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      stream_pool_error_response(error)
    }
  }
}

fn request_if_match(request: &hyper::Request<Incoming>) -> Option<String> {
  request
    .headers()
    .get(::http::header::IF_MATCH)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string)
}

fn stream_pool_error_response(error: anyhow::Error) -> Response<ProxyBody> {
  if let Some(precondition) = error.downcast_ref::<stream_control::StreamPoolPreconditionError>() {
    let status = match precondition.kind() {
      stream_control::StreamPoolPreconditionErrorKind::Missing => StatusCode::PRECONDITION_REQUIRED,
      stream_control::StreamPoolPreconditionErrorKind::Stale => StatusCode::PRECONDITION_FAILED,
    };
    return admin_error::error_response_with_details(
      status,
      &error.to_string(),
      Some(json!({ "header": "If-Match", "expected": precondition.expected() })),
    );
  }
  text_response(StatusCode::BAD_REQUEST, &error.to_string())
}
