//! Administrative controls for upstream pool state.
//! Operator overrides are explicit so health automation and manual actions do not conflict.

use std::collections::HashMap;
#[cfg(feature = "admin-runtime")]
use std::fmt;

use anyhow::{Context, bail};
#[cfg(feature = "admin-runtime")]
use serde::Serialize;
use sha2::{Digest, Sha256};

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
  discovery_instance_id: &str,
  mut servers: Vec<UpstreamPoolServerConfig>,
) -> anyhow::Result<()> {
  if !is_discovery_source(source) {
    bail!("discovery updates require a supported discovery source");
  }
  validate_runtime_identifier("upstream discovery id", discovery_instance_id)?;

  let pool = find_pool_mut(config, pool_name)?;
  let mut candidate = pool.clone();
  let discovery = candidate
    .discovery
    .iter()
    .find(|discovery| {
      discovery_source(discovery.provider) == source
        && discovery.effective_id() == discovery_instance_id
    })
    .ok_or_else(|| anyhow::anyhow!("upstream pool {pool_name} has no matching discovery policy"))?;
  let discovery_tls = discovery.tls.clone();
  let previous_states = candidate
    .servers
    .iter()
    .enumerate()
    .filter(|(_, server)| server_belongs_to_discovery(server, source, discovery_instance_id))
    .map(|(index, server)| (upstream_pool_server_id(index, server), server.state))
    .collect::<HashMap<_, _>>();

  for (index, server) in servers.iter_mut().enumerate() {
    let provider_server_id = upstream_pool_server_id(index, server);
    validate_runtime_identifier(
      "discovered upstream pool provider server id",
      &provider_server_id,
    )?;
    let server_id = scoped_discovered_server_id(source, discovery_instance_id, &provider_server_id);
    if server.weight == 0 {
      bail!("discovered upstream pool server weight must be greater than 0");
    }
    server.id = Some(server_id.clone());
    server.source = source;
    server.tls = discovery_tls.clone();
    server.discovery_instance_id = Some(discovery_instance_id.to_string());
    server.discovered_weight = Some(server.weight);
    if let Some(state) = previous_states.get(&server_id) {
      server.state = *state;
    } else if server.state != UpstreamPoolServerState::Ready {
      server.state = UpstreamPoolServerState::Ready;
    }
  }

  candidate
    .servers
    .retain(|server| !server_belongs_to_discovery(server, source, discovery_instance_id));
  candidate.servers.extend(servers);
  normalize_discovered_server_weights(&mut candidate)?;
  sort_discovered_servers(&mut candidate);
  *pool = candidate;
  Ok(())
}

pub(crate) fn scoped_discovered_server_id(
  source: UpstreamPoolServerSource,
  discovery_instance_id: &str,
  provider_server_id: &str,
) -> String {
  let mut digest = Sha256::new();
  digest.update(b"oxibelt-discovered-server-id-v1\0");
  for component in [source.as_str(), discovery_instance_id, provider_server_id] {
    digest.update(component.as_bytes());
    digest.update(b"\0");
  }
  let digest = digest.finalize();
  let encoded = digest
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
  format!("discovered-{encoded}")
}

pub(crate) fn remove_discovered_servers(
  config: &mut Config,
  pool_name: &str,
  source: UpstreamPoolServerSource,
  discovery_instance_id: &str,
) -> anyhow::Result<()> {
  if !is_discovery_source(source) {
    bail!("discovery updates require a supported discovery source");
  }
  validate_runtime_identifier("upstream discovery id", discovery_instance_id)?;
  let pool = find_pool_mut(config, pool_name)?;
  prune_removed_discovery_cohorts(pool, source, discovery_instance_id)
}

fn prune_removed_discovery_cohorts(
  pool: &mut UpstreamPoolConfig,
  source: UpstreamPoolServerSource,
  discovery_instance_id: &str,
) -> anyhow::Result<()> {
  let mut candidate = pool.clone();
  let discovery_policies = candidate.discovery.clone();
  candidate.servers.retain(|server| {
    !server_belongs_to_discovery(server, source, discovery_instance_id)
      && (!is_discovery_source(server.source)
        || discovery_policies.iter().any(|discovery| {
          discovery_source(discovery.provider) == server.source
            && discovery.effective_id()
              == server
                .discovery_instance_id
                .as_deref()
                .unwrap_or_else(|| server.source.as_str())
        }))
  });
  normalize_discovered_server_weights(&mut candidate)?;
  sort_discovered_servers(&mut candidate);
  *pool = candidate;
  Ok(())
}

fn is_discovery_source(source: UpstreamPoolServerSource) -> bool {
  matches!(
    source,
    UpstreamPoolServerSource::Dns
      | UpstreamPoolServerSource::File
      | UpstreamPoolServerSource::Kubernetes
      | UpstreamPoolServerSource::Consul
      | UpstreamPoolServerSource::Etcd
      | UpstreamPoolServerSource::Nomad
  )
}

fn server_belongs_to_discovery(
  server: &UpstreamPoolServerConfig,
  source: UpstreamPoolServerSource,
  discovery_instance_id: &str,
) -> bool {
  server.source == source
    && server
      .discovery_instance_id
      .as_deref()
      .unwrap_or_else(|| source.as_str())
      == discovery_instance_id
}

fn normalize_discovered_server_weights(pool: &mut UpstreamPoolConfig) -> anyhow::Result<()> {
  let mut cohorts = std::collections::BTreeMap::<String, DiscoveryWeightCohort>::new();
  for (index, server) in pool.servers.iter_mut().enumerate() {
    if !is_discovery_source(server.source) {
      continue;
    }
    let discovery_instance_id = server
      .discovery_instance_id
      .clone()
      .unwrap_or_else(|| server.source.as_str().to_string());
    let discovery = pool
      .discovery
      .iter()
      .find(|discovery| {
        discovery_source(discovery.provider) == server.source
          && discovery.effective_id() == discovery_instance_id
      })
      .ok_or_else(|| {
        anyhow::anyhow!(
          "upstream pool {} has no matching discovery policy for {}",
          pool.name,
          discovery_instance_id
        )
      })?;
    let discovered_weight = server.discovered_weight.unwrap_or(server.weight);
    if discovered_weight == 0 {
      bail!("discovered upstream pool server weight must be greater than 0");
    }
    server.discovery_instance_id = Some(discovery_instance_id);
    server.discovered_weight = Some(discovered_weight);
    let cohort = cohorts
      .entry(discovery.effective_id().to_string())
      .or_insert_with(|| DiscoveryWeightCohort {
        multiplier: discovery.weight_multiplier,
        endpoint_weight_sum: 0,
        endpoints: Vec::new(),
      });
    cohort.endpoint_weight_sum = cohort
      .endpoint_weight_sum
      .checked_add(u64::from(discovered_weight))
      .ok_or_else(|| {
        anyhow::anyhow!(
          "upstream pool {} discovery endpoint weight sum cannot be represented safely",
          pool.name
        )
      })?;
    cohort.endpoints.push((index, discovered_weight));
  }
  if cohorts.is_empty() {
    return Ok(());
  }

  let fractions = cohorts
    .values()
    .flat_map(|cohort| {
      cohort
        .endpoints
        .iter()
        .map(move |(index, endpoint_weight)| (*index, *endpoint_weight, cohort))
    })
    .map(|(index, endpoint_weight, cohort)| {
      let numerator = u64::from(cohort.multiplier)
        .checked_mul(u64::from(endpoint_weight))
        .ok_or_else(|| {
          anyhow::anyhow!(
            "upstream pool {} discovery weight cannot be represented safely",
            pool.name
          )
        })?;
      Ok(DiscoveredWeightFraction {
        index,
        numerator,
        denominator: cohort.endpoint_weight_sum,
      })
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  let normalized =
    exact_discovered_weights(&fractions).unwrap_or_else(|| scaled_discovered_weights(&fractions));
  let normalized = normalized?;

  let distinct_fractions = fractions
    .iter()
    .map(|fraction| {
      let divisor = greatest_common_divisor(
        u128::from(fraction.numerator),
        u128::from(fraction.denominator),
      );
      (
        u128::from(fraction.numerator) / divisor,
        u128::from(fraction.denominator) / divisor,
      )
    })
    .collect::<std::collections::HashSet<_>>();
  let distinct_weights = normalized
    .iter()
    .map(|(_, weight)| *weight)
    .collect::<std::collections::HashSet<_>>();
  if distinct_fractions.len() > 1 && distinct_weights.len() == 1 {
    bail!(
      "upstream pool {} discovery weight normalization would collapse distinct backend shares",
      pool.name
    );
  }

  for (index, weight) in normalized {
    pool.servers[index].weight = weight;
  }
  Ok(())
}

struct DiscoveryWeightCohort {
  multiplier: u32,
  endpoint_weight_sum: u64,
  endpoints: Vec<(usize, u32)>,
}

#[derive(Clone, Copy)]
struct DiscoveredWeightFraction {
  index: usize,
  numerator: u64,
  denominator: u64,
}

fn exact_discovered_weights(
  fractions: &[DiscoveredWeightFraction],
) -> Option<anyhow::Result<Vec<(usize, u32)>>> {
  let common_denominator = fractions.iter().try_fold(1_u128, |common, fraction| {
    checked_least_common_multiple(common, u128::from(fraction.denominator))
  })?;
  let weighted = fractions
    .iter()
    .map(|fraction| {
      u128::from(fraction.numerator)
        .checked_mul(common_denominator / u128::from(fraction.denominator))
        .map(|weight| (fraction.index, weight))
    })
    .collect::<Option<Vec<_>>>()?;
  let max_weight = weighted
    .iter()
    .map(|(_, weight)| *weight)
    .max()
    .unwrap_or(1);
  let divisor = if max_weight > u128::from(u32::MAX) {
    weighted
      .iter()
      .map(|(_, weight)| *weight)
      .reduce(greatest_common_divisor)
      .unwrap_or(1)
  } else {
    1
  };
  let reduced = weighted
    .into_iter()
    .map(|(index, weight)| (index, weight / divisor))
    .collect::<Vec<_>>();
  if reduced
    .iter()
    .any(|(_, weight)| *weight > u128::from(u32::MAX))
  {
    return None;
  }
  Some(
    reduced
      .into_iter()
      .map(|(index, weight)| {
        u32::try_from(weight)
          .map(|weight| (index, weight))
          .map_err(anyhow::Error::from)
      })
      .collect(),
  )
}

fn scaled_discovered_weights(
  fractions: &[DiscoveredWeightFraction],
) -> anyhow::Result<Vec<(usize, u32)>> {
  let Some(maximum) = fractions
    .iter()
    .copied()
    .max_by(compare_discovered_fractions)
  else {
    return Ok(Vec::new());
  };
  fractions
    .iter()
    .map(|fraction| {
      let weight = scaled_fraction_weight(*fraction, maximum);
      if weight == 0 {
        bail!("discovery weight normalization would lose a positive backend share");
      }
      Ok((fraction.index, weight))
    })
    .collect()
}

fn compare_discovered_fractions(
  left: &DiscoveredWeightFraction,
  right: &DiscoveredWeightFraction,
) -> std::cmp::Ordering {
  (u128::from(left.numerator) * u128::from(right.denominator))
    .cmp(&(u128::from(right.numerator) * u128::from(left.denominator)))
    .then_with(|| right.index.cmp(&left.index))
}

fn scaled_fraction_weight(
  fraction: DiscoveredWeightFraction,
  maximum: DiscoveredWeightFraction,
) -> u32 {
  let numerator_factors = (fraction.numerator, maximum.denominator, u64::from(u32::MAX));
  let denominator_factors = (fraction.denominator, maximum.numerator);
  let mut low = 0_u32;
  let mut high = u32::MAX;
  while low < high {
    let midpoint = low + ((high - low) / 2) + 1;
    let left = wide_product(
      numerator_factors.0,
      numerator_factors.1,
      numerator_factors.2,
    );
    let right = wide_product(
      denominator_factors.0,
      denominator_factors.1,
      u64::from(midpoint),
    );
    if compare_wide_product(left, right).is_ge() {
      low = midpoint;
    } else {
      high = midpoint - 1;
    }
  }
  if low == u32::MAX {
    return low;
  }
  let doubled_left = wide_product(
    fraction.numerator,
    maximum.denominator,
    u64::from(u32::MAX) * 2,
  );
  let rounding_threshold = wide_product(
    fraction.denominator,
    maximum.numerator,
    u64::from(low) * 2 + 1,
  );
  if compare_wide_product(doubled_left, rounding_threshold).is_ge() {
    low + 1
  } else {
    low
  }
}

fn wide_product(left: u64, middle: u64, right: u64) -> [u64; 3] {
  let first = u128::from(left) * u128::from(middle);
  let low = first as u64;
  let high = (first >> 64) as u64;
  let low_product = u128::from(low) * u128::from(right);
  let high_product = u128::from(high) * u128::from(right);
  let middle_sum = (low_product >> 64) + u128::from(high_product as u64);
  [
    low_product as u64,
    middle_sum as u64,
    ((high_product >> 64) + (middle_sum >> 64)) as u64,
  ]
}

fn compare_wide_product(left: [u64; 3], right: [u64; 3]) -> std::cmp::Ordering {
  (left[2], left[1], left[0]).cmp(&(right[2], right[1], right[0]))
}

fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
  while right != 0 {
    let remainder = left % right;
    left = right;
    right = remainder;
  }
  left.max(1)
}

fn checked_least_common_multiple(left: u128, right: u128) -> Option<u128> {
  left
    .checked_div(greatest_common_divisor(left, right))?
    .checked_mul(right)
}

fn sort_discovered_servers(pool: &mut UpstreamPoolConfig) {
  let mut discovered = Vec::new();
  pool.servers.retain(|server| {
    if is_discovery_source(server.source) {
      discovered.push(server.clone());
      false
    } else {
      true
    }
  });
  discovered.sort_by(|left, right| {
    (
      left.source.as_str(),
      left.discovery_instance_id.as_deref().unwrap_or_default(),
      left.id.as_deref().unwrap_or_default(),
      left.origin.as_str(),
    )
      .cmp(&(
        right.source.as_str(),
        right.discovery_instance_id.as_deref().unwrap_or_default(),
        right.id.as_deref().unwrap_or_default(),
        right.origin.as_str(),
      ))
  });
  pool.servers.extend(discovered);
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rational_weight_scaling_survives_common_denominator_overflow() {
    let fractions = [
      DiscoveredWeightFraction {
        index: 0,
        numerator: u64::MAX,
        denominator: u64::MAX,
      },
      DiscoveredWeightFraction {
        index: 1,
        numerator: u64::MAX - 1,
        denominator: u64::MAX - 1,
      },
      DiscoveredWeightFraction {
        index: 2,
        numerator: u64::MAX - 2,
        denominator: u64::MAX - 2,
      },
    ];
    assert!(
      exact_discovered_weights(&fractions).is_none(),
      "the fixture must exercise the bounded rational fallback"
    );
    assert_eq!(
      scaled_discovered_weights(&fractions).expect("equal ratios should remain representable"),
      [(0, u32::MAX), (1, u32::MAX), (2, u32::MAX)]
    );
  }

  #[test]
  fn rational_weight_scaling_rounds_half_up_deterministically() {
    let fraction = DiscoveredWeightFraction {
      index: 0,
      numerator: 1,
      denominator: 3,
    };
    let maximum = DiscoveredWeightFraction {
      index: 1,
      numerator: 2,
      denominator: 3,
    };
    assert_eq!(scaled_fraction_weight(fraction, maximum), 2_147_483_648);
    assert_eq!(scaled_fraction_weight(maximum, maximum), u32::MAX);
  }

  #[test]
  fn exact_weights_preserve_legacy_single_instance_values() {
    let fractions = [
      DiscoveredWeightFraction {
        index: 0,
        numerator: 2,
        denominator: 6,
      },
      DiscoveredWeightFraction {
        index: 1,
        numerator: 4,
        denominator: 6,
      },
    ];
    assert_eq!(
      exact_discovered_weights(&fractions)
        .expect("legacy weights should use the exact representation")
        .expect("legacy weights should fit u32"),
      [(0, 2), (1, 4)]
    );
  }

  #[test]
  fn stale_cleanup_prunes_all_removed_discovery_cohorts_transactionally() {
    let mut pool: UpstreamPoolConfig = toml::from_str(
      r#"
name = "stale-discovery"

[[servers]]
id = "alpha-a"
origin = "http://127.0.0.1:8080"
weight = 20

[[servers]]
id = "beta-a"
origin = "http://127.0.0.1:8081"
weight = 80

[[servers]]
id = "static-a"
origin = "http://127.0.0.1:8082"
weight = 1
"#,
    )
    .expect("pool should parse");
    for (server, instance) in pool.servers[..2].iter_mut().zip(["alpha", "beta"]) {
      server.source = UpstreamPoolServerSource::File;
      server.discovery_instance_id = Some(instance.to_string());
      server.discovered_weight = Some(server.weight);
    }

    prune_removed_discovery_cohorts(&mut pool, UpstreamPoolServerSource::File, "alpha")
      .expect("one stale-worker cleanup must prune every no-longer-configured cohort");

    assert_eq!(pool.servers.len(), 1);
    assert_eq!(pool.servers[0].id.as_deref(), Some("static-a"));
    assert_eq!(pool.servers[0].source, UpstreamPoolServerSource::Static);
  }
}
