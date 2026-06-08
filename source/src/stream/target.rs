//! Stream target resolution for direct targets and stream upstream pools.

use std::net::SocketAddr;

use anyhow::Context;
use url::Url;

use crate::config::{StreamNetwork, parse_stream_target};
use crate::state::AppHandle;
use crate::stream::pools::StreamPoolSelection;
use crate::stream::sni::StreamRouteTarget;

pub(crate) struct ResolvedStreamTarget {
  pub(crate) addr: SocketAddr,
  pub(crate) label: String,
  pub(crate) selection: Option<StreamPoolSelection>,
}

pub(crate) async fn resolve_stream_route_target(
  state: &AppHandle,
  network: StreamNetwork,
  target: StreamRouteTarget<'_>,
  peer_addr: SocketAddr,
) -> anyhow::Result<ResolvedStreamTarget> {
  match target {
    StreamRouteTarget::Direct(target) => {
      let (host, port) = parse_stream_target(target)?;
      let addr = super::resolve_target_addr(&host, port).await?;
      Ok(ResolvedStreamTarget {
        addr,
        label: target.to_string(),
        selection: None,
      })
    }
    StreamRouteTarget::Pool(pool) => {
      let snapshot = state.snapshot();
      let selection =
        snapshot
          .stream_pools
          .select(pool, network, peer_addr.ip(), &peer_addr.to_string())?;
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

pub(crate) async fn resolve_stream_origin(origin: &Url) -> anyhow::Result<SocketAddr> {
  let host = origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("stream origin is missing host"))?;
  let port = origin
    .port()
    .ok_or_else(|| anyhow::anyhow!("stream origin is missing port"))?;
  super::resolve_target_addr(host, port).await
}
