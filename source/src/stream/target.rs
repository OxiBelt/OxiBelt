//! Stream target resolution for direct targets and stream upstream pools.

use std::net::SocketAddr;

use anyhow::Context;
use url::Url;

use crate::config::{StreamNetwork, parse_stream_target};
use crate::state::{AppHandle, AppSnapshot};
use crate::stream::pools::StreamPoolSelection;
use crate::stream::sni::StreamRouteTarget;

pub(crate) struct ResolvedStreamTarget {
  pub(crate) addr: SocketAddr,
  pub(crate) label: String,
  pub(crate) selection: Option<StreamPoolSelection>,
}

pub(crate) enum SelectedStreamTarget {
  Direct {
    host: String,
    port: u16,
    label: String,
  },
  Pool(StreamPoolSelection),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum StreamTargetIdentity {
  Direct,
  Pool {
    pool_name: String,
    server_id: String,
  },
}

impl SelectedStreamTarget {
  pub(crate) fn identity(&self) -> StreamTargetIdentity {
    match self {
      Self::Direct { .. } => StreamTargetIdentity::Direct,
      Self::Pool(selection) => StreamTargetIdentity::Pool {
        pool_name: selection.pool_name.clone(),
        server_id: selection.server_id.clone(),
      },
    }
  }

  pub(crate) async fn resolve(self) -> anyhow::Result<ResolvedStreamTarget> {
    match self {
      Self::Direct { host, port, label } => {
        let addr = super::resolve_target_addr(&host, port).await?;
        Ok(ResolvedStreamTarget {
          addr,
          label,
          selection: None,
        })
      }
      Self::Pool(selection) => {
        let addr = resolve_stream_origin(&selection.origin)
          .await
          .with_context(|| {
            format!(
              "failed to resolve stream upstream pool {} server {}",
              selection.pool_name, selection.server_id
            )
          })?;
        let label = format!("{}/{}", selection.pool_name, selection.server_id);
        Ok(ResolvedStreamTarget {
          addr,
          label,
          selection: Some(selection),
        })
      }
    }
  }
}

pub(crate) async fn resolve_stream_route_target(
  state: &AppHandle,
  network: StreamNetwork,
  target: StreamRouteTarget<'_>,
  peer_addr: SocketAddr,
) -> anyhow::Result<ResolvedStreamTarget> {
  let snapshot = state.snapshot();
  select_stream_route_target(&snapshot, network, target, peer_addr)?
    .resolve()
    .await
}

pub(crate) fn select_stream_route_target(
  snapshot: &AppSnapshot,
  network: StreamNetwork,
  target: StreamRouteTarget<'_>,
  peer_addr: SocketAddr,
) -> anyhow::Result<SelectedStreamTarget> {
  match target {
    StreamRouteTarget::Direct(target) => {
      let (host, port) = parse_stream_target(target)?;
      Ok(SelectedStreamTarget::Direct {
        host,
        port,
        label: target.to_string(),
      })
    }
    StreamRouteTarget::Pool(pool) => {
      let selection =
        snapshot
          .stream_pools
          .select(pool, network, peer_addr.ip(), &peer_addr.to_string())?;
      Ok(SelectedStreamTarget::Pool(selection))
    }
  }
}

pub(crate) fn select_restored_stream_route_target(
  snapshot: &AppSnapshot,
  network: StreamNetwork,
  target: StreamRouteTarget<'_>,
  identity: &StreamTargetIdentity,
) -> anyhow::Result<SelectedStreamTarget> {
  match (target, identity) {
    (StreamRouteTarget::Direct(target), StreamTargetIdentity::Direct) => {
      let (host, port) = parse_stream_target(target)?;
      Ok(SelectedStreamTarget::Direct {
        host,
        port,
        label: target.to_string(),
      })
    }
    (
      StreamRouteTarget::Pool(pool),
      StreamTargetIdentity::Pool {
        pool_name,
        server_id,
      },
    ) if pool == pool_name => {
      let selection = snapshot
        .stream_pools
        .select_exact(pool, server_id, network)?;
      Ok(SelectedStreamTarget::Pool(selection))
    }
    _ => anyhow::bail!("durable UDP flow target no longer matches the active route"),
  }
}

pub(crate) async fn resolve_stream_origin(origin: &Url) -> anyhow::Result<SocketAddr> {
  let host = origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("stream origin is missing host"))?;
  let port = origin
    .port()
    .ok_or_else(|| anyhow::anyhow!("stream origin is missing port"))?;
  super::resolve_target_addr(host, port).await
}
