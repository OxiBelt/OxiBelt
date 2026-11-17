//! Upstream URI values computed while snapshots are built.

use std::collections::HashMap;

use anyhow::Context;

use crate::config::UpstreamConfig;
use crate::proxy::http::uri::UpstreamUriParts;
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
