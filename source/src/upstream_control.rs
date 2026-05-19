use std::collections::HashMap;

use anyhow::{Context, bail};

use crate::config::{
  Config, UpstreamPoolConfig, UpstreamPoolServerConfig, UpstreamPoolServerSource,
  UpstreamPoolServerState, upstream_pool_server_id, validate_runtime_identifier,
};
use crate::state::{AppHandle, AppSnapshot};

pub(crate) async fn apply_runtime_pool_update<F>(state: &AppHandle, mutate: F) -> anyhow::Result<()>
where
  F: FnOnce(&mut Config) -> anyhow::Result<()>,
{
  let active = state.snapshot();
  let mut config = active.config.clone();
  mutate(&mut config)?;
  if config.upstream_pools == active.config.upstream_pools {
    return Ok(());
  }
  config.validate()?;
  let snapshot = AppSnapshot::new_with_updated_upstream_pools(config, active.as_ref()).await?;
  state.replace(snapshot);
  Ok(())
}

pub(crate) fn find_pool_mut<'a>(
  config: &'a mut Config,
  pool_name: &str,
) -> anyhow::Result<&'a mut UpstreamPoolConfig> {
  config
    .upstream_pools
    .iter_mut()
    .find(|pool| pool.name == pool_name)
    .with_context(|| format!("unknown upstream pool {pool_name}"))
}

pub(crate) fn find_server_mut<'a>(
  pool: &'a mut UpstreamPoolConfig,
  server_id: &str,
) -> anyhow::Result<(usize, &'a mut UpstreamPoolServerConfig)> {
  validate_runtime_identifier("upstream pool server id", server_id)?;
  pool
    .servers
    .iter_mut()
    .enumerate()
    .find(|(index, server)| upstream_pool_server_id(*index, server) == server_id)
    .with_context(|| format!("unknown upstream pool server {server_id}"))
}

pub(crate) fn ensure_unique_server_id(
  pool: &UpstreamPoolConfig,
  candidate_id: &str,
) -> anyhow::Result<()> {
  validate_runtime_identifier("upstream pool server id", candidate_id)?;
  let exists = pool
    .servers
    .iter()
    .enumerate()
    .any(|(index, server)| upstream_pool_server_id(index, server) == candidate_id);
  if exists {
    bail!(
      "upstream pool {} already has server id {candidate_id}",
      pool.name
    );
  }
  Ok(())
}

pub(crate) fn replace_discovered_servers(
  config: &mut Config,
  pool_name: &str,
  source: UpstreamPoolServerSource,
  mut servers: Vec<UpstreamPoolServerConfig>,
) -> anyhow::Result<()> {
  if !matches!(
    source,
    UpstreamPoolServerSource::Dns
      | UpstreamPoolServerSource::File
      | UpstreamPoolServerSource::Kubernetes
      | UpstreamPoolServerSource::Consul
      | UpstreamPoolServerSource::Etcd
  ) {
    bail!("discovery updates require a supported discovery source");
  }

  let pool = find_pool_mut(config, pool_name)?;
  let previous_states = pool
    .servers
    .iter()
    .enumerate()
    .filter(|(_, server)| server.source == source)
    .map(|(index, server)| (upstream_pool_server_id(index, server), server.state))
    .collect::<HashMap<_, _>>();

  for (index, server) in servers.iter_mut().enumerate() {
    let server_id = upstream_pool_server_id(index, server);
    validate_runtime_identifier("discovered upstream pool server id", &server_id)?;
    server.id = Some(server_id.clone());
    server.source = source;
    if let Some(state) = previous_states.get(&server_id) {
      server.state = *state;
    } else if server.state != UpstreamPoolServerState::Ready {
      server.state = UpstreamPoolServerState::Ready;
    }
  }

  pool.servers.retain(|server| server.source != source);
  pool.servers.extend(servers);
  Ok(())
}

pub(crate) fn stable_generated_server_id(parts: &[&str]) -> String {
  let mut output = String::new();
  for part in parts {
    if !output.is_empty() {
      output.push('-');
    }
    for byte in part.bytes() {
      if byte.is_ascii_alphanumeric() {
        output.push((byte as char).to_ascii_lowercase());
      } else if matches!(byte, b'-' | b'_' | b'.') {
        output.push(byte as char);
      } else {
        output.push('-');
      }
    }
  }
  while output.contains("--") {
    output = output.replace("--", "-");
  }
  let output = output.trim_matches('-').to_string();
  if output.is_empty() {
    "server".to_string()
  } else {
    output
  }
}
