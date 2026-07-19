//! Administrative controls for upstream pool state.
//! Operator overrides are explicit so health automation and manual actions do not conflict.

use std::collections::HashMap;
#[cfg(feature = "admin-runtime")]
use std::fmt;

use anyhow::{Context, bail};
#[cfg(feature = "admin-runtime")]
use serde::Serialize;

use crate::config::{
  Config, UpstreamPoolConfig, UpstreamPoolServerConfig, UpstreamPoolServerSource,
  UpstreamPoolServerState, upstream_pool_server_id, validate_runtime_identifier,
};
use crate::state::{AppHandle, AppSnapshot};

const MAX_RUNTIME_POOL_UPDATE_ATTEMPTS: usize = 8;

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpstreamPoolAdminStatus {
  pub generation: u64,
  pub etag: String,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum UpstreamPoolPreconditionErrorKind {
  Missing,
  Stale,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone)]
pub(crate) struct UpstreamPoolPreconditionError {
  kind: UpstreamPoolPreconditionErrorKind,
  expected: String,
}

#[cfg(feature = "admin-runtime")]
impl UpstreamPoolPreconditionError {
  pub(crate) fn kind(&self) -> UpstreamPoolPreconditionErrorKind {
    self.kind
  }

  pub(crate) fn expected(&self) -> &str {
    &self.expected
  }
}

#[cfg(feature = "admin-runtime")]
impl fmt::Display for UpstreamPoolPreconditionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.kind {
      UpstreamPoolPreconditionErrorKind::Missing => write!(formatter, "If-Match is required"),
      UpstreamPoolPreconditionErrorKind::Stale => {
        write!(
          formatter,
          "If-Match does not match the active upstream-pool generation"
        )
      }
    }
  }
}

#[cfg(feature = "admin-runtime")]
impl std::error::Error for UpstreamPoolPreconditionError {}

pub(crate) async fn apply_runtime_pool_update<F>(state: &AppHandle, mutate: F) -> anyhow::Result<()>
where
  F: Fn(&mut Config) -> anyhow::Result<()>,
{
  #[cfg(feature = "admin-runtime")]
  {
    apply_runtime_pool_update_inner(state, None, mutate).await
  }
  #[cfg(not(feature = "admin-runtime"))]
  {
    apply_runtime_pool_update_inner(state, mutate).await
  }
}

#[cfg(feature = "admin-runtime")]
pub(crate) async fn apply_runtime_pool_update_checked<F>(
  state: &AppHandle,
  if_match: Option<&str>,
  mutate: F,
) -> anyhow::Result<()>
where
  F: Fn(&mut Config) -> anyhow::Result<()>,
{
  apply_runtime_pool_update_inner(state, Some(if_match), mutate).await
}

async fn apply_runtime_pool_update_inner<F>(
  state: &AppHandle,
  #[cfg(feature = "admin-runtime")] if_match: Option<Option<&str>>,
  mutate: F,
) -> anyhow::Result<()>
where
  F: Fn(&mut Config) -> anyhow::Result<()>,
{
  for _ in 0..MAX_RUNTIME_POOL_UPDATE_ATTEMPTS {
    let active = state.snapshot();
    #[cfg(feature = "admin-runtime")]
    let expected_generation = if let Some(if_match) = if_match {
      Some(check_if_match(active.as_ref(), if_match)?)
    } else {
      None
    };
    let mut config = active.config.clone();
    mutate(&mut config)?;
    if config.upstream_pools == active.config.upstream_pools {
      return Ok(());
    }
    config.validate()?;
    let snapshot = AppSnapshot::new_with_updated_upstream_pools(config, active.as_ref()).await?;
    if state.replace_if_current(&active, snapshot) {
      return Ok(());
    }
    #[cfg(feature = "admin-runtime")]
    let latest = state.snapshot();
    #[cfg(feature = "admin-runtime")]
    if let Some(expected_generation) = expected_generation
      && latest.upstream_pool_generation != expected_generation
    {
      return Err(
        UpstreamPoolPreconditionError {
          kind: UpstreamPoolPreconditionErrorKind::Stale,
          expected: upstream_pool_etag(latest.upstream_pool_generation),
        }
        .into(),
      );
    }
  }
  bail!("upstream pool update conflicted with repeated runtime snapshot changes");
}

#[cfg(feature = "admin-runtime")]
pub(crate) fn upstream_pool_status(snapshot: &AppSnapshot) -> UpstreamPoolAdminStatus {
  UpstreamPoolAdminStatus {
    generation: snapshot.upstream_pool_generation,
    etag: upstream_pool_etag(snapshot.upstream_pool_generation),
  }
}

#[cfg(feature = "admin-runtime")]
pub(crate) fn upstream_pool_etag(generation: u64) -> String {
  format!("\"oxibelt-upstream-pools-{generation}\"")
}

#[cfg(feature = "admin-runtime")]
fn check_if_match(snapshot: &AppSnapshot, if_match: Option<&str>) -> anyhow::Result<u64> {
  let expected = upstream_pool_etag(snapshot.upstream_pool_generation);
  match if_match {
    Some(value) if value == expected => Ok(snapshot.upstream_pool_generation),
    Some(_) => Err(
      UpstreamPoolPreconditionError {
        kind: UpstreamPoolPreconditionErrorKind::Stale,
        expected,
      }
      .into(),
    ),
    None => Err(
      UpstreamPoolPreconditionError {
        kind: UpstreamPoolPreconditionErrorKind::Missing,
        expected,
      }
      .into(),
    ),
  }
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

#[cfg(feature = "admin-runtime")]
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

#[cfg(feature = "admin-runtime")]
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
      | UpstreamPoolServerSource::Nomad
  ) {
    bail!("discovery updates require a supported discovery source");
  }

  let pool = find_pool_mut(config, pool_name)?;
  let discovery_tls = pool
    .discovery
    .iter()
    .find(|discovery| discovery_source(discovery.provider) == source)
    .map(|discovery| discovery.tls.clone())
    .ok_or_else(|| anyhow::anyhow!("upstream pool {pool_name} has no matching discovery policy"))?;
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
    server.tls = discovery_tls.clone();
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

fn discovery_source(
  provider: crate::config::UpstreamDiscoveryProvider,
) -> UpstreamPoolServerSource {
  match provider {
    crate::config::UpstreamDiscoveryProvider::Dns => UpstreamPoolServerSource::Dns,
    crate::config::UpstreamDiscoveryProvider::File => UpstreamPoolServerSource::File,
    crate::config::UpstreamDiscoveryProvider::Kubernetes => UpstreamPoolServerSource::Kubernetes,
    crate::config::UpstreamDiscoveryProvider::Consul => UpstreamPoolServerSource::Consul,
    crate::config::UpstreamDiscoveryProvider::Etcd => UpstreamPoolServerSource::Etcd,
    crate::config::UpstreamDiscoveryProvider::Nomad => UpstreamPoolServerSource::Nomad,
  }
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
