use std::net::SocketAddr;

use ::http::{Response, StatusCode};
use anyhow::{Context, bail};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;

use crate::config::{UpstreamPoolServerConfig, UpstreamPoolServerSource, UpstreamPoolServerState};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::{AppHandle, AppSnapshot};
use crate::upstream_control;

use super::admin::json_response;
use super::admin_auth::{AdminActor, AdminAuthorization};
use super::admin_body::collect_admin_json;
use super::{AdminAuditOutcome, admin_audit, admin_resource};

pub(super) async fn admin_upstream_pools_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path == "/admin/v1/upstream-pools" {
    if !authorization.is_allowed("upstream-pool:List", "*") {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::GET {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    return Some(json_response(StatusCode::OK, &snapshot.pools.snapshots()));
  }

  let rest = path.strip_prefix("/admin/v1/upstream-pools/")?;
  let segments = rest.split('/').collect::<Vec<_>>();
  if segments.len() == 1 {
    if !authorization.is_allowed("upstream-pool:Get", segments[0]) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::GET {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    let Some(pool) = snapshot.pools.snapshot(segments[0]) else {
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
    let body = match collect_admin_json::<AdminAddPoolServerRequest>(request).await {
      Ok(body) => body,
      Err(response) => {
        admin_audit(
          peer_addr,
          authorization.actor,
          "upstream_server_add",
          Some(segments[0]),
          None,
          AdminAuditOutcome::Rejected,
          Some("invalid request body"),
        );
        return Some(response);
      }
    };
    let resource = admin_resource::upstream_pool_server(segments[0], &body.id);
    if !authorization.is_allowed("upstream-pool:AddServer", &resource) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    return Some(
      admin_add_pool_server(
        body,
        &state,
        peer_addr,
        authorization.actor,
        segments[0].to_string(),
      )
      .await,
    );
  }

  if segments.len() == 3 && segments[1] == "servers" {
    let action = match *method {
      ::http::Method::PATCH => "upstream-pool:UpdateServer",
      ::http::Method::DELETE => "upstream-pool:RemoveServer",
      _ => {
        return Some(text_response(
          StatusCode::METHOD_NOT_ALLOWED,
          "method not allowed",
        ));
      }
    };
    let resource = admin_resource::upstream_pool_server(segments[0], segments[2]);
    if !authorization.is_allowed(action, &resource) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    return Some(
      admin_mutate_pool_server(
        request,
        &state,
        peer_addr,
        authorization.actor,
        method,
        segments[0].to_string(),
        segments[2].to_string(),
      )
      .await,
    );
  }

  Some(text_response(StatusCode::NOT_FOUND, "not found"))
}

#[derive(Debug, Deserialize)]
struct AdminAddPoolServerRequest {
  id: String,
  origin: url::Url,
  #[serde(default = "default_admin_pool_server_weight")]
  weight: u32,
  #[serde(default)]
  max_conns: usize,
  #[serde(default)]
  backup: bool,
  #[serde(default)]
  state: UpstreamPoolServerState,
}

fn default_admin_pool_server_weight() -> u32 {
  1
}

#[derive(Debug, Deserialize)]
struct AdminPatchPoolServerRequest {
  #[serde(default)]
  state: Option<UpstreamPoolServerState>,
  #[serde(default)]
  weight: Option<u32>,
  #[serde(default)]
  max_conns: Option<usize>,
  #[serde(default)]
  backup: Option<bool>,
}

async fn admin_add_pool_server(
  body: AdminAddPoolServerRequest,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
) -> Response<ProxyBody> {
  let server_id = body.id.clone();
  let result = upstream_control::apply_runtime_pool_update(state, |config| {
    let pool = upstream_control::find_pool_mut(config, &pool_name)?;
    upstream_control::ensure_unique_server_id(pool, &server_id)?;
    let mut server = UpstreamPoolServerConfig {
      id: Some(server_id.clone()),
      origin: body.origin,
      weight: body.weight,
      max_conns: body.max_conns,
      backup: body.backup,
      state: body.state,
      source: UpstreamPoolServerSource::Admin,
    };
    if server.weight == 0 {
      bail!("upstream pool server weight must be greater than 0");
    }
    server.source = UpstreamPoolServerSource::Admin;
    pool.servers.push(server);
    Ok(())
  })
  .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_add",
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
        "upstream_server_add",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      text_response(StatusCode::BAD_REQUEST, &message)
    }
  }
}

async fn admin_mutate_pool_server(
  request: hyper::Request<Incoming>,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  method: &::http::Method,
  pool_name: String,
  server_id: String,
) -> Response<ProxyBody> {
  if *method == ::http::Method::PATCH {
    return admin_patch_pool_server(request, state, peer_addr, actor, pool_name, server_id).await;
  }
  if *method == ::http::Method::DELETE {
    return admin_delete_pool_server(state, peer_addr, actor, pool_name, server_id).await;
  }
  text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

async fn admin_patch_pool_server(
  request: hyper::Request<Incoming>,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
  server_id: String,
) -> Response<ProxyBody> {
  let body = match collect_admin_json::<AdminPatchPoolServerRequest>(request).await {
    Ok(body) => body,
    Err(response) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some("invalid request body"),
      );
      return response;
    }
  };
  let result = upstream_control::apply_runtime_pool_update(state, |config| {
    let pool = upstream_control::find_pool_mut(config, &pool_name)?;
    let (_, server) = upstream_control::find_server_mut(pool, &server_id)?;
    if let Some(state) = body.state {
      server.state = state;
    }
    if let Some(weight) = body.weight {
      if weight == 0 {
        bail!("upstream pool server weight must be greater than 0");
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
        "upstream_server_patch",
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
        "upstream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      text_response(StatusCode::BAD_REQUEST, &message)
    }
  }
}

async fn admin_delete_pool_server(
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
  server_id: String,
) -> Response<ProxyBody> {
  let result = upstream_control::apply_runtime_pool_update(state, |config| {
    let pool = upstream_control::find_pool_mut(config, &pool_name)?;
    let index = pool
      .servers
      .iter()
      .enumerate()
      .find(|(index, server)| crate::config::upstream_pool_server_id(*index, server) == server_id)
      .map(|(index, _)| index)
      .with_context(|| format!("unknown upstream pool server {server_id}"))?;
    if pool.servers[index].source != UpstreamPoolServerSource::Admin {
      bail!("only admin-managed upstream pool servers can be deleted");
    }
    pool.servers.remove(index);
    Ok(())
  })
  .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_delete",
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
        "upstream_server_delete",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      text_response(StatusCode::BAD_REQUEST, &message)
    }
  }
}
