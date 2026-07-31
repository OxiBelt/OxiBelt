//! Runtime-backend and upstream URI values computed while snapshots are built.

use std::collections::HashMap;

use anyhow::Context;

use crate::config::UpstreamConfig;
#[cfg(test)]
use crate::config::{Config, RuntimeDirectH1IoMode, RuntimeMainRuntimeMode};
use crate::proxy::http::uri::UpstreamUriParts;
#[cfg(test)]
use crate::runtime::backend::{RuntimeBackendSnapshot, TOKIO_HYPER_RUNTIME_NAME};

#[cfg(test)]
pub(super) fn effective_direct_h1_io_for_backend(
  config: &Config,
  runtime_backend: RuntimeBackendSnapshot,
) -> RuntimeDirectH1IoMode {
  if config.runtime.direct_h1_io != RuntimeDirectH1IoMode::Compio {
    return config.runtime.direct_h1_io;
  }
  if config.runtime.main_runtime == RuntimeMainRuntimeMode::TokioHyper
    || runtime_backend.active_runtime == TOKIO_HYPER_RUNTIME_NAME
  {
    tracing::warn!(
      configured_direct_h1_io = "compio",
      active_runtime = runtime_backend.active_runtime,
      "runtime.direct_h1_io = \"compio\" requires an active Compio main runtime; using Tokio/Hyper direct-H1 IO"
    );
    return RuntimeDirectH1IoMode::TokioHyper;
  }
  RuntimeDirectH1IoMode::Compio
}

pub(super) fn build_upstream_uri_parts(
  upstreams: &[UpstreamConfig],
) -> anyhow::Result<(HashMap<String, UpstreamUriParts>, Vec<UpstreamUriParts>)> {
  let mut by_name = HashMap::with_capacity(upstreams.len());
  let mut by_index = Vec::with_capacity(upstreams.len());
  for upstream in upstreams {
    let parts = UpstreamUriParts::from_url(&upstream.origin)
      .with_context(|| format!("failed to precompute URI parts for {}", upstream.name))?;
    by_name.insert(upstream.name.clone(), parts.clone());
    by_index.push(parts);
  }
  Ok((by_name, by_index))
}
