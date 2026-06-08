//! Administrative controls for generic stream upstream pools.
//! Runtime mutations use ETags so concurrent operator changes do not silently overwrite each other.

use std::fmt;

use anyhow::{Context, bail};
use serde::Serialize;

use crate::config::{
  Config, StreamUpstreamPoolConfig, StreamUpstreamPoolServerConfig, stream_upstream_pool_server_id,
  validate_runtime_identifier,
};
use crate::state::{AppHandle, AppSnapshot};

const MAX_RUNTIME_STREAM_POOL_UPDATE_ATTEMPTS: usize = 8;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StreamPoolAdminStatus {
  pub generation: u64,
  pub etag: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum StreamPoolPreconditionErrorKind {
  Missing,
  Stale,
}

#[derive(Debug, Clone)]
pub(crate) struct StreamPoolPreconditionError {
  kind: StreamPoolPreconditionErrorKind,
  expected: String,
}

impl StreamPoolPreconditionError {
  pub(crate) fn kind(&self) -> StreamPoolPreconditionErrorKind {
    self.kind
  }

  pub(crate) fn expected(&self) -> &str {
    &self.expected
  }
}

impl fmt::Display for StreamPoolPreconditionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.kind {
      StreamPoolPreconditionErrorKind::Missing => write!(formatter, "If-Match is required"),
      StreamPoolPreconditionErrorKind::Stale => {
        write!(
          formatter,
          "If-Match does not match the active stream-pool generation"
        )
      }
    }
  }
}

impl std::error::Error for StreamPoolPreconditionError {}

pub(crate) async fn apply_runtime_stream_pool_update_checked<F>(
  state: &AppHandle,
  if_match: Option<&str>,
  mutate: F,
) -> anyhow::Result<()>
where
  F: Fn(&mut Config) -> anyhow::Result<()>,
{
  for _ in 0..MAX_RUNTIME_STREAM_POOL_UPDATE_ATTEMPTS {
    let active = state.snapshot();
    let expected_generation = check_if_match(active.as_ref(), if_match)?;
    let mut config = active.config.clone();
    mutate(&mut config)?;
    if config.stream_upstream_pools == active.config.stream_upstream_pools {
      return Ok(());
    }
    config.validate()?;
    let snapshot = AppSnapshot::new_with_updated_stream_pools(config, active.as_ref()).await?;
    if state.replace_if_current(&active, snapshot) {
      return Ok(());
    }
    let latest = state.snapshot();
    if latest.stream_pool_generation != expected_generation {
      return Err(
        StreamPoolPreconditionError {
          kind: StreamPoolPreconditionErrorKind::Stale,
          expected: stream_pool_etag(latest.stream_pool_generation),
        }
        .into(),
      );
    }
  }
  bail!("stream pool update conflicted with repeated runtime snapshot changes");
}

pub(crate) fn stream_pool_status(snapshot: &AppSnapshot) -> StreamPoolAdminStatus {
  StreamPoolAdminStatus {
    generation: snapshot.stream_pool_generation,
    etag: stream_pool_etag(snapshot.stream_pool_generation),
  }
}

pub(crate) fn stream_pool_etag(generation: u64) -> String {
  format!("\"oxibelt-stream-pools-{generation}\"")
}

fn check_if_match(snapshot: &AppSnapshot, if_match: Option<&str>) -> anyhow::Result<u64> {
  let expected = stream_pool_etag(snapshot.stream_pool_generation);
  match if_match {
    Some(value) if value == expected => Ok(snapshot.stream_pool_generation),
    Some(_) => Err(
      StreamPoolPreconditionError {
        kind: StreamPoolPreconditionErrorKind::Stale,
        expected,
      }
      .into(),
    ),
    None => Err(
      StreamPoolPreconditionError {
        kind: StreamPoolPreconditionErrorKind::Missing,
        expected,
      }
      .into(),
    ),
  }
}

pub(crate) fn find_pool_mut<'a>(
  config: &'a mut Config,
  pool_name: &str,
) -> anyhow::Result<&'a mut StreamUpstreamPoolConfig> {
  config
    .stream_upstream_pools
    .iter_mut()
    .find(|pool| pool.name == pool_name)
    .with_context(|| format!("unknown stream upstream pool {pool_name}"))
}

pub(crate) fn find_server_mut<'a>(
  pool: &'a mut StreamUpstreamPoolConfig,
  server_id: &str,
) -> anyhow::Result<(usize, &'a mut StreamUpstreamPoolServerConfig)> {
  validate_runtime_identifier("stream upstream pool server id", server_id)?;
  pool
    .servers
    .iter_mut()
    .enumerate()
    .find(|(index, server)| stream_upstream_pool_server_id(*index, server) == server_id)
    .with_context(|| format!("unknown stream upstream pool server {server_id}"))
}

pub(crate) fn ensure_unique_server_id(
  pool: &StreamUpstreamPoolConfig,
  candidate_id: &str,
) -> anyhow::Result<()> {
  validate_runtime_identifier("stream upstream pool server id", candidate_id)?;
  let exists = pool
    .servers
    .iter()
    .enumerate()
    .any(|(index, server)| stream_upstream_pool_server_id(index, server) == candidate_id);
  if exists {
    bail!(
      "stream upstream pool {} already has server id {candidate_id}",
      pool.name
    );
  }
  Ok(())
}
