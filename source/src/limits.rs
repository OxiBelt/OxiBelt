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
use crate::shared_state::{ConnectionScope, SharedRateLimitOutcome, SharedState};
use crate::waf::PersonProofTokenBinding;

#[path = "limits/context.rs"]
mod context;
#[path = "limits/sybil_identity.rs"]
pub(crate) mod sybil_identity;
#[path = "limits/webtransport.rs"]
mod webtransport;
pub use context::ConnectionLimitContext;
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
pub struct ParsedRate {
  per_second: f64,
}

pub fn parse_rate(raw: &str) -> anyhow::Result<ParsedRate> {
  let Some((amount, unit)) = raw.split_once("r/") else {
    bail!("rate must use format like 10r/s or 600r/m");
  };
  let amount: f64 = amount
    .parse()
    .with_context(|| format!("invalid rate amount {raw}"))?;
  if amount <= 0.0 {
    bail!("rate amount must be greater than 0");
  }
  let divisor = match unit {
    "s" => 1.0,
    "m" => 60.0,
    "h" => 3600.0,
    _ => bail!("rate unit must be s, m, or h"),
  };
  Ok(ParsedRate {
    per_second: amount / divisor,
  })
}

impl ParsedRate {
  pub fn per_second(self) -> f64 {
    self.per_second
  }
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
    Arc::new(Self {
      connections: Mutex::new(ConnectionCounts::default()),
      rates: Mutex::new(HashMap::new()),
      shared_state,
    })
  }

  pub fn acquire_global_connection(
    self: &Arc<Self>,
    limits: &LimitsConfig,
  ) -> Result<ConnectionPermit, StatusCode> {
    self.acquire_scopes(vec![ConnectionAcquireSpec {
      key: "total".to_string(),
      kind: ConnectionAcquireKind::Total,
      limit: limits.max_connections,
      status: StatusCode::SERVICE_UNAVAILABLE,
    }])
  }

  pub fn acquire_ip_connection(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
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
    self.acquire_scopes(specs)
  }

  pub fn acquire_connection(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
    let mut specs = vec![
      ConnectionAcquireSpec {
        key: "total".to_string(),
        kind: ConnectionAcquireKind::Total,
        limit: limits.max_connections,
        status: StatusCode::SERVICE_UNAVAILABLE,
      },
      ConnectionAcquireSpec {
        key: format!("ip:{ip}"),
        kind: ConnectionAcquireKind::Ip(ip),
        limit: limits.max_connections_per_ip,
        status: StatusCode::TOO_MANY_REQUESTS,
      },
    ];
    specs.extend(connection_limits.iter().map(|limit| ConnectionAcquireSpec {
      key: format!("named:{}:{ip}", limit.name),
      kind: ConnectionAcquireKind::Named {
        name: limit.name.clone(),
        ip,
      },
      limit: limit.limit,
      status: StatusCode::from_u16(limit.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
    }));
    self.acquire_scopes(specs)
  }

  fn acquire_scopes(
    self: &Arc<Self>,
    specs: Vec<ConnectionAcquireSpec>,
  ) -> Result<ConnectionPermit, StatusCode> {
    if let Some(shared) = &self.shared_state
      && shared.has_connection_limits()
    {
      let owned_scopes = specs
        .iter()
        .map(|spec| spec.key.clone())
        .collect::<Vec<_>>();
      let scopes = specs
        .iter()
        .enumerate()
        .map(|(index, spec)| ConnectionScope {
          key: owned_scopes[index].as_str(),
          limit: spec.limit,
          status: spec.status,
        })
        .collect::<Vec<_>>();
      let acquired = shared.acquire_connections(&scopes);
      drop(scopes);
      return match acquired {
        Ok(None) => Ok(ConnectionPermit {
          state: self.clone(),
          local_release: LocalConnectionRelease::default(),
          shared_scopes: owned_scopes,
        }),
        Ok(Some(status)) => Err(status),
        Err(error) => {
          tracing::warn!(error = %error, "shared connection limit backend failed closed");
          Err(StatusCode::SERVICE_UNAVAILABLE)
        }
      };
    }
    let mut counts = self
      .connections
      .lock()
      .expect("connection limit lock poisoned");
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
      shared_scopes: Vec::new(),
    })
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
    let Ok(rate) = parse_rate(limit.rate) else {
      return Some(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let key = rate_limit_key(context, &limit);
    self.check_rate_limit_bucket(RateLimitBucketSpec {
      name: limit.name,
      key: &key,
      rate,
      burst: limit.burst,
      max_buckets: limit.max_buckets,
      mode: limit.mode,
      status: limit.status,
    })
  }

  pub fn check_direct_rate_limit(
    &self,
    bucket: &str,
    rate: &str,
    burst: u32,
    status: u16,
  ) -> Option<StatusCode> {
    let Ok(rate) = parse_rate(rate) else {
      return Some(StatusCode::INTERNAL_SERVER_ERROR);
    };
    self.check_rate_limit_bucket(RateLimitBucketSpec {
      name: bucket,
      key: "",
      rate,
      burst,
      max_buckets: 1,
      mode: LimitMode::Enforcing,
      status,
    })
  }

  fn check_rate_limit_bucket(&self, spec: RateLimitBucketSpec<'_>) -> Option<StatusCode> {
    if let Some(shared) = &self.shared_state
      && shared.has_rate_limits()
    {
      let result = if spec.key.is_empty() {
        shared.take_rate_token_bucket(spec.name, spec.rate, spec.burst)
      } else {
        shared.take_rate_token(spec.name, spec.key, spec.rate, spec.burst, spec.max_buckets)
      };
      match result {
        Ok(SharedRateLimitOutcome::Allowed) => {}
        Ok(SharedRateLimitOutcome::RateLimited | SharedRateLimitOutcome::BucketCapExceeded) => {
          if spec.mode == LimitMode::Enforcing {
            return Some(
              StatusCode::from_u16(spec.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
            );
          }
        }
        Err(error) => {
          tracing::warn!(error = %error, "shared rate limit backend failed closed");
          return Some(StatusCode::SERVICE_UNAVAILABLE);
        }
      }
      return None;
    }
    let burst = f64::from(spec.burst.max(1));
    let now = Instant::now();
    let mut buckets = self.rates.lock().expect("rate limit lock poisoned");
    let bucket_key = (spec.name.to_string(), spec.key.to_string());
    if let Some(bucket) = buckets.get_mut(&bucket_key) {
      return take_local_rate_token(bucket, now, spec.rate, burst, spec.mode, spec.status);
    }

    prune_refilled_rate_buckets(&mut buckets, spec.name, now, spec.rate.per_second, burst);
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
    let mut counts = self
      .connections
      .lock()
      .expect("connection limit lock poisoned");
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

  fn release_shared_connection(&self, scopes: &[String]) {
    if let Some(shared) = &self.shared_state {
      shared.release_connections(scopes);
    }
  }
}

pub struct ConnectionPermit {
  state: Arc<LimitState>,
  local_release: LocalConnectionRelease,
  shared_scopes: Vec<String>,
}

impl Drop for ConnectionPermit {
  fn drop(&mut self) {
    if self.shared_scopes.is_empty() {
      self.state.release_connection(&self.local_release);
    } else {
      self.state.release_shared_connection(&self.shared_scopes);
    }
  }
}

fn rate_limit_applies_before_route(limit: &RateLimitConfig) -> bool {
  matches!(limit.key, RateLimitKey::ClientIp | RateLimitKey::Global) && limit.routes.is_empty()
}

fn rate_limit_applies_after_route(limit: &RateLimitConfig, route_name: &str) -> bool {
  if rate_limit_applies_before_route(limit) {
    return false;
  }
  limit.routes.is_empty() || limit.routes.iter().any(|route| route == route_name)
}

fn take_local_rate_token(
  bucket: &mut TokenBucket,
  now: Instant,
  rate: ParsedRate,
  burst: f64,
  mode: LimitMode,
  status: u16,
) -> Option<StatusCode> {
  let elapsed = now.duration_since(bucket.last).as_secs_f64();
  bucket.tokens = (bucket.tokens + elapsed * rate.per_second).min(burst);
  bucket.last = now;
  if bucket.tokens < 1.0 && mode == LimitMode::Enforcing {
    return Some(rate_limit_status(status));
  }
  bucket.tokens -= 1.0;
  None
}

fn prune_refilled_rate_buckets(
  buckets: &mut HashMap<(String, String), TokenBucket>,
  limit_name: &str,
  now: Instant,
  rate_per_second: f64,
  burst: f64,
) {
  buckets.retain(|(bucket_limit_name, _), bucket| {
    bucket_limit_name != limit_name || !bucket_refills_to_burst(bucket, now, rate_per_second, burst)
  });
}

fn bucket_refills_to_burst(
  bucket: &TokenBucket,
  now: Instant,
  rate_per_second: f64,
  burst: f64,
) -> bool {
  if bucket.tokens >= burst {
    return true;
  }
  let elapsed = now.duration_since(bucket.last).as_secs_f64();
  bucket.tokens + elapsed * rate_per_second >= burst
}

fn rate_limit_bucket_count(
  buckets: &HashMap<(String, String), TokenBucket>,
  limit_name: &str,
) -> usize {
  buckets
    .keys()
    .filter(|(bucket_limit_name, _)| bucket_limit_name == limit_name)
    .count()
}

fn rate_limit_status(status: u16) -> StatusCode {
  StatusCode::from_u16(status).unwrap_or(StatusCode::TOO_MANY_REQUESTS)
}

fn rate_limit_key(context: RateLimitContext<'_>, check: &RateLimitCheck<'_>) -> String {
  let route = context.route_name.unwrap_or_default();
  let path = context.path.unwrap_or_default();
  let identity_context = SybilIdentityContext::from(context);
  let identity_spec = SybilIdentitySpec::from(check);
  match check.key {
    RateLimitKey::Global => String::new(),
    RateLimitKey::Route => format!("route:{route}"),
    RateLimitKey::ClientIp => format!("client_ip:{}", context.ip),
    RateLimitKey::ClientIpRoute => format!("client_ip_route:{}:{route}", context.ip),
    RateLimitKey::ClientIpPath => format!("client_ip_path:{}:{path}", context.ip),
    RateLimitKey::AccessToken => {
      format!(
        "access_token:{}",
        access_token_bucket_identity(context, check.access_token_source, check.token_header)
      )
    }
    RateLimitKey::AccessTokenRoute => format!(
      "access_token_route:{}:{route}",
      access_token_bucket_identity(context, check.access_token_source, check.token_header)
    ),
    RateLimitKey::AccessTokenPath => format!(
      "access_token_path:{}:{path}",
      access_token_bucket_identity(context, check.access_token_source, check.token_header)
    ),
    RateLimitKey::ClientIpPrefix => format!(
      "client_ip_prefix:{}",
      sybil_identity::client_ip_prefix_identity(identity_context, identity_spec)
    ),
    RateLimitKey::ClientIpPrefixRoute => format!(
      "client_ip_prefix_route:{}:{route}",
      sybil_identity::client_ip_prefix_identity(identity_context, identity_spec)
    ),
    RateLimitKey::ClientIpPrefixPath => format!(
      "client_ip_prefix_path:{}:{path}",
      sybil_identity::client_ip_prefix_identity(identity_context, identity_spec)
    ),
    RateLimitKey::TlsFingerprint => format!(
      "tls_fingerprint:{}",
      sybil_identity::tls_fingerprint_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::TlsFingerprintRoute => format!(
      "tls_fingerprint_route:{}:{route}",
      sybil_identity::tls_fingerprint_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::TokenBindingHash => format!(
      "token_binding_hash:{}",
      sybil_identity::token_binding_hash_identity(identity_context, identity_spec)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::TokenBindingHashRoute => format!(
      "token_binding_hash_route:{}:{route}",
      sybil_identity::token_binding_hash_identity(identity_context, identity_spec)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::PersonProofClearance => format!(
      "person_proof_clearance:{}",
      sybil_identity::person_proof_clearance_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::PersonProofClearanceRoute => format!(
      "person_proof_clearance_route:{}:{route}",
      sybil_identity::person_proof_clearance_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::CompositeClient => format!(
      "composite_client:{}",
      sybil_identity::composite_client_rate_limit_identity(identity_context, identity_spec)
    ),
    RateLimitKey::CompositeClientRoute => format!(
      "composite_client_route:{}:{route}",
      sybil_identity::composite_client_rate_limit_identity(identity_context, identity_spec)
    ),
    RateLimitKey::Asn => format!(
      "asn:{}",
      sybil_identity::asn_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::AsnRoute => format!(
      "asn_route:{}:{route}",
      sybil_identity::asn_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
  }
}

fn access_token_bucket_identity(
  context: RateLimitContext<'_>,
  access_token_source: Option<AccessTokenRateLimitSource>,
  token_header: Option<&str>,
) -> String {
  context
    .headers
    .and_then(|headers| access_token(headers, access_token_source, token_header))
    .map(|token| format!("token:{}", sybil_identity::sha256_hex(token.as_bytes())))
    .unwrap_or_else(|| format!("fallback_ip:{}", context.ip))
}

fn access_token(
  headers: &HeaderMap,
  access_token_source: Option<AccessTokenRateLimitSource>,
  token_header: Option<&str>,
) -> Option<String> {
  match access_token_source {
    Some(AccessTokenRateLimitSource::TrustedAuthorizationBearer) => bearer_token(headers),
    Some(AccessTokenRateLimitSource::TrustedHeader) => {
      token_header.and_then(|name| named_header_token(headers, name))
    }
    None => None,
  }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
  let raw = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
  let mut parts = raw.splitn(2, char::is_whitespace);
  let scheme = parts.next()?;
  let token = parts.next()?.trim();
  if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
    return None;
  }
  Some(token.to_string())
}

fn named_header_token(headers: &HeaderMap, name: &str) -> Option<String> {
  let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
  let value = headers.get(name)?.to_str().ok()?.trim();
  if value.is_empty() {
    return None;
  }
  Some(value.to_string())
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
#[path = "limits/sybil_tests.rs"]
mod sybil_tests;
#[cfg(test)]
#[path = "limits/tests.rs"]
mod tests;

impl<'a> From<RateLimitContext<'a>> for SybilIdentityContext<'a> {
  fn from(context: RateLimitContext<'a>) -> Self {
    Self {
      ip: context.ip,
      route_name: context.route_name,
      headers: context.headers,
      tls_fingerprint: context.tls_fingerprint,
      client_asn: context.client_asn,
      tcp_max_hop: context.tcp_max_hop,
      person_proof_clearance_hash: context.person_proof_clearance_hash,
    }
  }
}

impl<'a> From<&'a RateLimitCheck<'a>> for SybilIdentitySpec<'a> {
  fn from(check: &'a RateLimitCheck<'a>) -> Self {
    Self {
      ipv4_prefix_bits: check.ipv4_prefix_bits,
      ipv6_prefix_bits: check.ipv6_prefix_bits,
      identity_parts: check.identity_parts,
      token_bindings: check.token_bindings,
    }
  }
}
