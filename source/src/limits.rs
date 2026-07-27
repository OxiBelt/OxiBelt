//! Connection and rate-limit enforcement shared across transports.
//! Limit decisions are fail-closed where accepting more traffic would hide enforcement errors.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, bail};
use http::header::{AUTHORIZATION, HeaderName};
use http::{HeaderMap, StatusCode};

use crate::config::{
  AccessTokenRateLimitSource, ConnectionLimitConfig, LimitMode, LimitsConfig, RateLimitConfig,
  RateLimitIdentityPart, RateLimitKey,
};
use crate::runtime_health::{
  PROCESS_GENERATION, RuntimeHealth, RuntimeSubsystem, RuntimeSubsystemError, RuntimeSubsystemState,
};
use crate::shared_state::{SharedCounterLease, SharedState, UdpFlowConnectionMarker};
use crate::waf::PersonProofTokenBinding;

#[path = "limits/context.rs"]
mod context;
#[path = "limits/rate.rs"]
mod rate;
#[path = "limits/shared_failure.rs"]
mod shared_failure;
#[path = "limits/sybil_identity.rs"]
pub(crate) mod sybil_identity;
#[path = "limits/webtransport.rs"]
mod webtransport;
pub use context::ConnectionLimitContext;
use rate::*;
pub use rate::{ParsedRate, parse_rate};
use sybil_identity::{SybilIdentityContext, SybilIdentitySpec};

pub const DEFAULT_RATE_LIMIT_MAX_BUCKETS: usize = 16_384;

pub fn default_rate_limit_max_buckets() -> usize {
  DEFAULT_RATE_LIMIT_MAX_BUCKETS
}

pub fn default_rate_limit_ipv4_prefix_bits() -> u8 {
  24
}

pub fn default_rate_limit_ipv6_prefix_bits() -> u8 {
  56
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitContext<'a> {
  pub ip: IpAddr,
  pub route_name: Option<&'a str>,
  pub path: Option<&'a str>,
  pub headers: Option<&'a HeaderMap>,
  pub tls_fingerprint: Option<&'a str>,
  pub client_asn: Option<u32>,
  pub tcp_max_hop: Option<u8>,
  pub person_proof_clearance_hash: Option<&'a str>,
}

impl<'a> RateLimitContext<'a> {
  pub fn pre_route(ip: IpAddr) -> Self {
    Self {
      ip,
      route_name: None,
      path: None,
      headers: None,
      tls_fingerprint: None,
      client_asn: None,
      tcp_max_hop: None,
      person_proof_clearance_hash: None,
    }
  }

  pub fn route(ip: IpAddr, route_name: &'a str, path: &'a str, headers: &'a HeaderMap) -> Self {
    Self {
      ip,
      route_name: Some(route_name),
      path: Some(path),
      headers: Some(headers),
      tls_fingerprint: None,
      client_asn: None,
      tcp_max_hop: None,
      person_proof_clearance_hash: None,
    }
  }

  pub fn with_tls_fingerprint(mut self, value: Option<&'a str>) -> Self {
    self.tls_fingerprint = value;
    self
  }

  pub fn with_client_asn(mut self, value: Option<u32>) -> Self {
    self.client_asn = value;
    self
  }

  pub fn with_tcp_max_hop(mut self, value: Option<u8>) -> Self {
    self.tcp_max_hop = value;
    self
  }

  pub fn with_person_proof_clearance_hash(mut self, value: Option<&'a str>) -> Self {
    self.person_proof_clearance_hash = value;
    self
  }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitCheck<'a> {
  pub name: &'a str,
  pub key: RateLimitKey,
  pub token_header: Option<&'a str>,
  pub access_token_source: Option<AccessTokenRateLimitSource>,
  pub ipv4_prefix_bits: u8,
  pub ipv6_prefix_bits: u8,
  pub identity_parts: &'a [RateLimitIdentityPart],
  pub token_bindings: &'a [PersonProofTokenBinding],
  pub rate: &'a str,
  pub burst: u32,
  pub max_buckets: usize,
  pub mode: LimitMode,
  pub status: u16,
}

struct RateLimitBucketSpec<'a> {
  name: &'a str,
  key: &'a str,
  rate: ParsedRate,
  burst: u32,
  max_buckets: usize,
  mode: LimitMode,
  status: u16,
}

impl<'a> From<&'a RateLimitConfig> for RateLimitCheck<'a> {
  fn from(limit: &'a RateLimitConfig) -> Self {
    Self {
      name: &limit.name,
      key: limit.key,
      token_header: limit.token_header.as_deref(),
      access_token_source: limit.access_token_source,
      ipv4_prefix_bits: limit.ipv4_prefix_bits,
      ipv6_prefix_bits: limit.ipv6_prefix_bits,
      identity_parts: &limit.identity_parts,
      token_bindings: &limit.token_bindings,
      rate: &limit.rate,
      burst: limit.burst,
      max_buckets: limit.max_buckets,
      mode: limit.mode,
      status: limit.status,
    }
  }
}

#[derive(Debug)]
pub struct LimitState {
  connections: Mutex<ConnectionCounts>,
  rates: Mutex<HashMap<(String, String), TokenBucket>>,
  shared_state: Option<Arc<SharedState>>,
  runtime_health: Arc<RuntimeHealth>,
}

#[derive(Debug, Default)]
struct ConnectionCounts {
  total: usize,
  per_ip: HashMap<IpAddr, usize>,
  named: HashMap<(String, IpAddr), usize>,
  scoped: HashMap<String, usize>,
}

#[derive(Debug)]
struct ConnectionAcquireSpec {
  key: String,
  kind: ConnectionAcquireKind,
  limit: usize,
  status: StatusCode,
}

#[derive(Debug)]
enum ConnectionAcquireKind {
  Total,
  Ip(IpAddr),
  Named { name: String, ip: IpAddr },
  Scoped(String),
}

#[derive(Debug, Default)]
struct LocalConnectionRelease {
  total: bool,
  ip: Option<IpAddr>,
  names: Vec<String>,
  scopes: Vec<String>,
}

#[derive(Debug)]
struct TokenBucket {
  tokens: f64,
  last: Instant,
}

impl LimitState {
  pub fn new(shared_state: Option<Arc<SharedState>>) -> Arc<Self> {
    Self::new_with_health(shared_state, Arc::new(RuntimeHealth::default()))
  }

  pub(crate) fn new_with_health(
    shared_state: Option<Arc<SharedState>>,
    runtime_health: Arc<RuntimeHealth>,
  ) -> Arc<Self> {
    Arc::new(Self {
      connections: Mutex::new(ConnectionCounts::default()),
      rates: Mutex::new(HashMap::new()),
      shared_state,
      runtime_health,
    })
  }

  fn mark_unavailable(&self) {
    let error = RuntimeSubsystemError::CriticalStateUnavailable(RuntimeSubsystem::Limits);
    tracing::error!(error = %error, "failing request closed");
    self.runtime_health.set_subsystem_state(
      PROCESS_GENERATION,
      RuntimeSubsystem::Limits,
      RuntimeSubsystemState::Failed,
      true,
    );
  }
  pub async fn acquire_global_connection_async(
    self: &Arc<Self>,
    limits: &LimitsConfig,
  ) -> Result<ConnectionPermit, StatusCode> {
    self
      .acquire_scopes_async(Self::global_connection_specs(limits))
      .await
  }

  pub async fn acquire_ip_connection_async(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
    self
      .acquire_scopes_async(Self::ip_connection_specs(ip, limits, connection_limits))
      .await
  }

  pub async fn acquire_connection_async(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
    self
      .acquire_scopes_async(Self::connection_specs(ip, limits, connection_limits))
      .await
  }

  pub(crate) async fn acquire_connection_with_udp_marker_async(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
    marker: &UdpFlowConnectionMarker,
  ) -> Result<ConnectionPermit, StatusCode> {
    self
      .acquire_scopes_async_with_marker(
        Self::connection_specs(ip, limits, connection_limits),
        Some(marker),
      )
      .await
  }

  fn acquire_scopes_local(
    self: &Arc<Self>,
    specs: Vec<ConnectionAcquireSpec>,
  ) -> Result<ConnectionPermit, StatusCode> {
    let mut counts = match self.connections.lock() {
      Ok(counts) => counts,
      Err(_) => {
        self.mark_unavailable();
        return Err(StatusCode::SERVICE_UNAVAILABLE);
      }
    };
    for spec in &specs {
      match &spec.kind {
        ConnectionAcquireKind::Total => {
          if counts.total >= spec.limit {
            return Err(spec.status);
          }
        }
        ConnectionAcquireKind::Ip(ip) => {
          if counts.per_ip.get(ip).copied().unwrap_or(0) >= spec.limit {
            return Err(spec.status);
          }
        }
        ConnectionAcquireKind::Named { name, ip } => {
          if counts.named.get(&(name.clone(), *ip)).copied().unwrap_or(0) >= spec.limit {
            return Err(spec.status);
          }
        }
        ConnectionAcquireKind::Scoped(scope) => {
          if counts.scoped.get(scope).copied().unwrap_or(0) >= spec.limit {
            return Err(spec.status);
          }
        }
      }
    }
    let mut local_release = LocalConnectionRelease::default();
    for spec in specs {
      match spec.kind {
        ConnectionAcquireKind::Total => {
          counts.total += 1;
          local_release.total = true;
        }
        ConnectionAcquireKind::Ip(ip) => {
          *counts.per_ip.entry(ip).or_insert(0) += 1;
          local_release.ip = Some(ip);
        }
        ConnectionAcquireKind::Named { name, ip } => {
          *counts.named.entry((name.clone(), ip)).or_insert(0) += 1;
          local_release.ip = Some(ip);
          local_release.names.push(name);
        }
        ConnectionAcquireKind::Scoped(scope) => {
          *counts.scoped.entry(scope.clone()).or_insert(0) += 1;
          local_release.scopes.push(scope);
        }
      }
    }
    Ok(ConnectionPermit {
      state: self.clone(),
      local_release,
      shared_lease: None,
    })
  }

  pub fn acquire_global_connection(
    self: &Arc<Self>,
    limits: &LimitsConfig,
  ) -> Result<ConnectionPermit, StatusCode> {
    self.acquire_scopes_local_or_fail_closed(Self::global_connection_specs(limits))
  }

  pub fn acquire_ip_connection(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
    self.acquire_scopes_local_or_fail_closed(Self::ip_connection_specs(
      ip,
      limits,
      connection_limits,
    ))
  }

  pub fn acquire_connection(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
    self.acquire_scopes_local_or_fail_closed(Self::connection_specs(ip, limits, connection_limits))
  }

  fn acquire_scopes_local_or_fail_closed(
    self: &Arc<Self>,
    specs: Vec<ConnectionAcquireSpec>,
  ) -> Result<ConnectionPermit, StatusCode> {
    if self
      .shared_state
      .as_ref()
      .is_some_and(|shared| shared.has_connection_limits())
    {
      return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    self.acquire_scopes_local(specs)
  }

  fn global_connection_specs(limits: &LimitsConfig) -> Vec<ConnectionAcquireSpec> {
    vec![ConnectionAcquireSpec {
      key: "total".to_string(),
      kind: ConnectionAcquireKind::Total,
      limit: limits.max_connections,
      status: StatusCode::SERVICE_UNAVAILABLE,
    }]
  }

  fn ip_connection_specs(
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Vec<ConnectionAcquireSpec> {
    let mut specs = vec![ConnectionAcquireSpec {
      key: format!("ip:{ip}"),
      kind: ConnectionAcquireKind::Ip(ip),
      limit: limits.max_connections_per_ip,
      status: StatusCode::TOO_MANY_REQUESTS,
    }];
    specs.extend(connection_limits.iter().map(|limit| ConnectionAcquireSpec {
      key: format!("named:{}:{ip}", limit.name),
      kind: ConnectionAcquireKind::Named {
        name: limit.name.clone(),
        ip,
      },
      limit: limit.limit,
      status: StatusCode::from_u16(limit.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
    }));
    specs
  }

  fn connection_specs(
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Vec<ConnectionAcquireSpec> {
    let mut specs = Self::global_connection_specs(limits);
    specs.extend(Self::ip_connection_specs(ip, limits, connection_limits));
    specs
  }

  pub async fn check_rate_limits_async(
    &self,
    ip: IpAddr,
    rate_limits: &[RateLimitConfig],
  ) -> Option<StatusCode> {
    self
      .check_pre_route_rate_limits_async(ip, rate_limits)
      .await
  }

  pub async fn check_pre_route_rate_limits_async(
    &self,
    ip: IpAddr,
    rate_limits: &[RateLimitConfig],
  ) -> Option<StatusCode> {
    let context = RateLimitContext::pre_route(ip);
    for limit in rate_limits
      .iter()
      .filter(|limit| rate_limit_applies_before_route(limit))
    {
      if let Some(status) = self
        .check_rate_limit_async(context, RateLimitCheck::from(limit))
        .await
      {
        return Some(status);
      }
    }
    None
  }

  pub async fn check_route_rate_limits_async(
    &self,
    context: RateLimitContext<'_>,
    rate_limits: &[RateLimitConfig],
  ) -> Option<StatusCode> {
    for limit in rate_limits
      .iter()
      .filter(|limit| rate_limit_applies_after_route(limit, context.route_name.unwrap_or_default()))
    {
      if let Some(status) = self
        .check_rate_limit_async(context, RateLimitCheck::from(limit))
        .await
      {
        return Some(status);
      }
    }
    None
  }

  pub async fn check_rate_limit_async(
    &self,
    context: RateLimitContext<'_>,
    limit: RateLimitCheck<'_>,
  ) -> Option<StatusCode> {
    let Ok(rate) = parse_rate(limit.rate) else {
      return Some(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let key = rate_limit_key(context, &limit);
    self
      .check_rate_limit_bucket(RateLimitBucketSpec {
        name: limit.name,
        key: &key,
        rate,
        burst: limit.burst,
        max_buckets: limit.max_buckets,
        mode: limit.mode,
        status: limit.status,
      })
      .await
  }

  pub async fn check_direct_rate_limit_async(
    &self,
    bucket: &str,
    rate: &str,
    burst: u32,
    status: u16,
  ) -> Option<StatusCode> {
    let Ok(rate) = parse_rate(rate) else {
      return Some(StatusCode::INTERNAL_SERVER_ERROR);
    };
    self
      .check_rate_limit_bucket(RateLimitBucketSpec {
        name: bucket,
        key: "",
        rate,
        burst,
        max_buckets: 1,
        mode: LimitMode::Enforcing,
        status,
      })
      .await
  }

  pub fn check_rate_limits(
    &self,
    ip: IpAddr,
    rate_limits: &[RateLimitConfig],
  ) -> Option<StatusCode> {
    self.check_pre_route_rate_limits(ip, rate_limits)
  }

  pub fn check_pre_route_rate_limits(
    &self,
    ip: IpAddr,
    rate_limits: &[RateLimitConfig],
  ) -> Option<StatusCode> {
    let context = RateLimitContext::pre_route(ip);
    for limit in rate_limits
      .iter()
      .filter(|limit| rate_limit_applies_before_route(limit))
    {
      if let Some(status) = self.check_rate_limit(context, RateLimitCheck::from(limit)) {
        return Some(status);
      }
    }
    None
  }

  pub fn check_route_rate_limits(
    &self,
    context: RateLimitContext<'_>,
    rate_limits: &[RateLimitConfig],
  ) -> Option<StatusCode> {
    for limit in rate_limits
      .iter()
      .filter(|limit| rate_limit_applies_after_route(limit, context.route_name.unwrap_or_default()))
    {
      if let Some(status) = self.check_rate_limit(context, RateLimitCheck::from(limit)) {
        return Some(status);
      }
    }
    None
  }

  pub fn check_rate_limit(
    &self,
    context: RateLimitContext<'_>,
    limit: RateLimitCheck<'_>,
  ) -> Option<StatusCode> {
    self.check_rate_limit_local(context, limit)
  }

  pub fn check_direct_rate_limit(
    &self,
    bucket: &str,
    rate: &str,
    burst: u32,
    status: u16,
  ) -> Option<StatusCode> {
    self.check_direct_rate_limit_local(bucket, rate, burst, status)
  }

  pub(crate) fn check_direct_rate_limit_local(
    &self,
    bucket: &str,
    rate: &str,
    burst: u32,
    status: u16,
  ) -> Option<StatusCode> {
    let Ok(rate) = parse_rate(rate) else {
      return Some(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if self
      .shared_state
      .as_ref()
      .is_some_and(|shared| shared.has_rate_limits())
    {
      return Some(StatusCode::SERVICE_UNAVAILABLE);
    }
    self.check_rate_limit_bucket_local(RateLimitBucketSpec {
      name: bucket,
      key: "",
      rate,
      burst,
      max_buckets: 1,
      mode: LimitMode::Enforcing,
      status,
    })
  }

  pub(crate) fn check_rate_limit_local(
    &self,
    context: RateLimitContext<'_>,
    limit: RateLimitCheck<'_>,
  ) -> Option<StatusCode> {
    let Ok(rate) = parse_rate(limit.rate) else {
      return Some(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if self
      .shared_state
      .as_ref()
      .is_some_and(|shared| shared.has_rate_limits())
    {
      return Some(StatusCode::SERVICE_UNAVAILABLE);
    }
    let key = rate_limit_key(context, &limit);
    self.check_rate_limit_bucket_local(RateLimitBucketSpec {
      name: limit.name,
      key: &key,
      rate,
      burst: limit.burst,
      max_buckets: limit.max_buckets,
      mode: limit.mode,
      status: limit.status,
    })
  }

  fn check_rate_limit_bucket_local(&self, spec: RateLimitBucketSpec<'_>) -> Option<StatusCode> {
    let burst = f64::from(spec.burst.max(1));
    let now = Instant::now();
    let mut buckets = match self.rates.lock() {
      Ok(buckets) => buckets,
      Err(_) => {
        self.mark_unavailable();
        return Some(StatusCode::SERVICE_UNAVAILABLE);
      }
    };
    let bucket_key = (spec.name.to_string(), spec.key.to_string());
    if let Some(bucket) = buckets.get_mut(&bucket_key) {
      return take_local_rate_token(bucket, now, spec.rate, burst, spec.mode, spec.status);
    }

    prune_refilled_rate_buckets(&mut buckets, spec.name, now, spec.rate.per_second(), burst);
    if rate_limit_bucket_count(&buckets, spec.name) >= spec.max_buckets.max(1) {
      if spec.mode == LimitMode::Enforcing {
        return Some(rate_limit_status(spec.status));
      }
      return None;
    }

    let bucket = buckets.entry(bucket_key).or_insert(TokenBucket {
      tokens: burst,
      last: now,
    });
    take_local_rate_token(bucket, now, spec.rate, burst, spec.mode, spec.status)
  }

  fn release_connection(&self, release: &LocalConnectionRelease) {
    let Ok(mut counts) = self.connections.lock() else {
      self.mark_unavailable();
      return;
    };
    if release.total {
      counts.total = counts.total.saturating_sub(1);
    }
    if let Some(ip) = release.ip {
      decrement_or_remove(&mut counts.per_ip, &ip);
      for name in &release.names {
        decrement_or_remove(&mut counts.named, &(name.clone(), ip));
      }
    }
    for scope in &release.scopes {
      decrement_or_remove(&mut counts.scoped, scope);
    }
  }

  async fn release_shared_connection(&self, lease: SharedCounterLease) {
    if let Some(shared) = &self.shared_state {
      shared.release_connections(lease).await;
    }
  }

  fn defer_shared_connection_release(&self, lease: SharedCounterLease) {
    if let Some(shared) = &self.shared_state {
      shared.defer_connection_release(lease);
    }
  }
}

pub struct ConnectionPermit {
  state: Arc<LimitState>,
  local_release: LocalConnectionRelease,
  shared_lease: Option<SharedCounterLease>,
}

impl ConnectionPermit {
  pub async fn release(&mut self) {
    if let Some(lease) = self.shared_lease.take() {
      self.state.release_shared_connection(lease).await;
    } else {
      self.state.release_connection(&self.local_release);
    }
    self.local_release = LocalConnectionRelease::default();
  }
}

impl Drop for ConnectionPermit {
  fn drop(&mut self) {
    if let Some(lease) = self.shared_lease.take() {
      self.state.defer_shared_connection_release(lease);
    } else {
      self.state.release_connection(&self.local_release);
    }
  }
}

fn decrement_or_remove<K>(map: &mut HashMap<K, usize>, key: &K)
where
  K: Eq + std::hash::Hash,
{
  if let Some(value) = map.get_mut(key) {
    *value = value.saturating_sub(1);
    if *value == 0 {
      map.remove(key);
    }
  }
}

#[cfg(test)]
#[path = "limits/poison_tests.rs"]
mod poison_tests;
#[cfg(test)]
#[path = "limits/sybil_tests.rs"]
mod sybil_tests;
#[cfg(test)]
#[path = "limits/tests.rs"]
mod tests;
