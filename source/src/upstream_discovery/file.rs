use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use crate::config::{
  UpstreamPoolDiscoveryConfig, UpstreamPoolServerConfig, UpstreamPoolServerSource,
  UpstreamPoolServerState,
};

#[derive(Debug, Deserialize)]
struct FileDiscoveryDocument {
  servers: Vec<FileDiscoveryServer>,
}

#[derive(Debug, Deserialize)]
struct FileDiscoveryServer {
  id: String,
  origin: url::Url,
  #[serde(default = "super::default_discovered_weight")]
  weight: u32,
  #[serde(default)]
  max_conns: usize,
  #[serde(default)]
  backup: bool,
  #[serde(default)]
  state: UpstreamPoolServerState,
}

pub(super) async fn discover_file_servers(
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  let path = discovery
    .file
    .as_ref()
    .ok_or_else(|| anyhow!("file discovery requires file"))?;
  let raw = tokio::fs::read_to_string(path)
    .await
    .with_context(|| format!("failed to read file discovery {}", path.display()))?;
  let document: FileDiscoveryDocument = serde_json::from_str(&raw)
    .with_context(|| format!("failed to parse file discovery {}", path.display()))?;
  let servers = document
    .servers
    .into_iter()
    .map(|server| {
      if server.weight == 0 {
        bail!(
          "file discovery server {} weight must be greater than 0",
          server.id
        );
      }
      Ok(UpstreamPoolServerConfig {
        id: Some(server.id),
        origin: server.origin,
        weight: server.weight,
        max_conns: server.max_conns,
        backup: server.backup,
        state: server.state,
        source: UpstreamPoolServerSource::File,
      })
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok((
    servers,
    Duration::from_millis(discovery.refresh_interval_ms),
  ))
}
