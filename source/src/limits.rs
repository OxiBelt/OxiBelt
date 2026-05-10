use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, bail};
use http::header::{AUTHORIZATION, HeaderName};
use http::{HeaderMap, StatusCode};
use ring::digest;

use crate::config::{
  ConnectionLimitConfig, LimitMode, LimitsConfig, RateLimitConfig, RateLimitKey,
};
use crate::shared_state::{ConnectionScope, SharedState};

pub const DEFAULT_RATE_LIMIT_MAX_BUCKETS: usize = 16_384;

pub fn default_rate_limit_max_buckets() -> usize {
  DEFAULT_RATE_LIMIT_MAX_BUCKETS
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
}

impl<'a> RateLimitContext<'a> {
  pub fn pre_route(ip: IpAddr) -> Self {
    Self {
      ip,
      route_name: None,
      path: None,
      headers: None,
    }
  }

  pub fn route(ip: IpAddr, route_name: &'a str, path: &'a str, headers: &'a HeaderMap) -> Self {
    Self {
      ip,
      route_name: Some(route_name),
      path: Some(path),
      headers: Some(headers),
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitCheck<'a> {
  pub name: &'a str,
  pub key: RateLimitKey,
  pub token_header: Option<&'a str>,
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
}

#[derive(Debug, Default)]
struct LocalConnectionRelease {
  total: bool,
  ip: Option<IpAddr>,
  names: Vec<String>,
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
    let key = rate_limit_key(context, limit.key, limit.token_header);
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
        shared.take_rate_token(spec.name, spec.key, spec.rate, spec.burst)
      };
      match result {
        Ok(true) => {}
        Ok(false) => {
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

#[derive(Clone, Default)]
pub struct ConnectionLimitContext {
  first_request: Arc<Mutex<Option<ConnectionPermit>>>,
}

impl ConnectionLimitContext {
  pub fn bind_first_request<F>(&self, acquire: F) -> Result<(), StatusCode>
  where
    F: FnOnce() -> Result<ConnectionPermit, StatusCode>,
  {
    let mut first_request = self
      .first_request
      .lock()
      .expect("first request connection limit lock poisoned");
    if first_request.is_some() {
      return Ok(());
    }
    *first_request = Some(acquire()?);
    Ok(())
  }
}

fn rate_limit_applies_before_route(limit: &RateLimitConfig) -> bool {
  limit.key == RateLimitKey::ClientIp && limit.routes.is_empty()
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

fn rate_limit_key(
  context: RateLimitContext<'_>,
  key: RateLimitKey,
  token_header: Option<&str>,
) -> String {
  let route = context.route_name.unwrap_or_default();
  let path = context.path.unwrap_or_default();
  match key {
    RateLimitKey::ClientIp => format!("client_ip:{}", context.ip),
    RateLimitKey::ClientIpRoute => format!("client_ip_route:{}:{route}", context.ip),
    RateLimitKey::ClientIpPath => format!("client_ip_path:{}:{path}", context.ip),
    RateLimitKey::AccessToken => {
      format!(
        "access_token:{}",
        access_token_bucket_identity(context, token_header)
      )
    }
    RateLimitKey::AccessTokenRoute => format!(
      "access_token_route:{}:{route}",
      access_token_bucket_identity(context, token_header)
    ),
    RateLimitKey::AccessTokenPath => format!(
      "access_token_path:{}:{path}",
      access_token_bucket_identity(context, token_header)
    ),
  }
}

fn access_token_bucket_identity(
  context: RateLimitContext<'_>,
  token_header: Option<&str>,
) -> String {
  context
    .headers
    .and_then(|headers| access_token(headers, token_header))
    .map(|token| format!("token:{}", sha256_hex(token.as_bytes())))
    .unwrap_or_else(|| format!("fallback_ip:{}", context.ip))
}

fn access_token(headers: &HeaderMap, token_header: Option<&str>) -> Option<String> {
  bearer_token(headers).or_else(|| token_header.and_then(|name| named_header_token(headers, name)))
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

fn sha256_hex(bytes: &[u8]) -> String {
  let digest = digest::digest(&digest::SHA256, bytes);
  let mut output = String::with_capacity(digest.as_ref().len() * 2);
  for byte in digest.as_ref() {
    use std::fmt::Write as _;
    let _ = write!(&mut output, "{byte:02x}");
  }
  output
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
mod tests {
  use super::*;
  use crate::config::LimitKey;
  use std::time::Duration;

  #[test]
  fn parses_rates() {
    assert!((parse_rate("10r/s").unwrap().per_second - 10.0).abs() < f64::EPSILON);
    assert!((parse_rate("60r/m").unwrap().per_second - 1.0).abs() < f64::EPSILON);
    assert!(parse_rate("10/s").is_err());
  }

  #[test]
  fn split_connection_permits_release_independent_scopes() {
    let state = LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let other_ip = "203.0.113.11".parse().unwrap();
    let limits = LimitsConfig {
      max_connections: 1,
      max_connections_per_ip: 1,
      ..LimitsConfig::default()
    };

    let total = state.acquire_global_connection(&limits).unwrap();
    assert_eq!(
      state.acquire_global_connection(&limits).err(),
      Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    let ip_permit = state.acquire_ip_connection(ip, &limits, &[]).unwrap();
    assert_eq!(
      state.acquire_ip_connection(ip, &limits, &[]).err(),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    let _other_ip_permit = state.acquire_ip_connection(other_ip, &limits, &[]).unwrap();
    drop(ip_permit);
    drop(total);
    assert!(state.acquire_global_connection(&limits).is_ok());
  }

  #[test]
  fn split_connection_permits_enforce_named_limits_per_ip() {
    let state = LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let limits = LimitsConfig {
      max_connections: 10,
      max_connections_per_ip: 10,
      ..LimitsConfig::default()
    };
    let named = [ConnectionLimitConfig {
      name: "per-client".to_string(),
      key: LimitKey::ClientIp,
      limit: 1,
      status: 409,
    }];

    let permit = state.acquire_ip_connection(ip, &limits, &named).unwrap();
    assert_eq!(
      state.acquire_ip_connection(ip, &limits, &named).err(),
      Some(StatusCode::CONFLICT)
    );
    drop(permit);
    assert!(state.acquire_ip_connection(ip, &limits, &named).is_ok());
  }

  #[test]
  fn shared_state_enforces_rate_and_connection_limits_across_instances() {
    let shared = SharedState::test_memory("limit-test");
    let first = LimitState::new(Some(shared.clone()));
    let second = LimitState::new(Some(shared));
    let ip = "203.0.113.10".parse().unwrap();
    let rate_limits = [RateLimitConfig {
      name: "per-ip".to_string(),
      key: RateLimitKey::ClientIp,
      routes: Vec::new(),
      token_header: None,
      rate: "1r/h".to_string(),
      burst: 1,
      max_buckets: default_rate_limit_max_buckets(),
      mode: LimitMode::Enforcing,
      status: 429,
    }];

    assert_eq!(first.check_rate_limits(ip, &rate_limits), None);
    assert_eq!(
      second.check_rate_limits(ip, &rate_limits),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );

    let limits = LimitsConfig {
      max_connections: 1,
      max_connections_per_ip: 1,
      ..LimitsConfig::default()
    };
    let total = first.acquire_global_connection(&limits).unwrap();
    assert_eq!(
      second.acquire_global_connection(&limits).err(),
      Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert!(second.acquire_ip_connection(ip, &limits, &[]).is_ok());
    drop(total);
    let ip_permit = first.acquire_ip_connection(ip, &limits, &[]).unwrap();
    assert_eq!(
      second.acquire_ip_connection(ip, &limits, &[]).err(),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    drop(ip_permit);
    assert!(second.acquire_global_connection(&limits).is_ok());
  }

  #[test]
  fn route_and_path_rate_limit_keys_are_isolated() {
    let state = LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let headers = HeaderMap::new();
    let route_limit = [RateLimitConfig {
      name: "per-route".to_string(),
      key: RateLimitKey::ClientIpRoute,
      routes: Vec::new(),
      token_header: None,
      rate: "1r/h".to_string(),
      burst: 1,
      max_buckets: default_rate_limit_max_buckets(),
      mode: LimitMode::Enforcing,
      status: 429,
    }];
    let app = RateLimitContext::route(ip, "app", "/same", &headers);
    let admin = RateLimitContext::route(ip, "admin", "/same", &headers);

    assert_eq!(state.check_route_rate_limits(app, &route_limit), None);
    assert_eq!(
      state.check_route_rate_limits(app, &route_limit),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    assert_eq!(state.check_route_rate_limits(admin, &route_limit), None);

    let path_limit = [RateLimitConfig {
      name: "per-path".to_string(),
      key: RateLimitKey::ClientIpPath,
      routes: Vec::new(),
      token_header: None,
      rate: "1r/h".to_string(),
      burst: 1,
      max_buckets: default_rate_limit_max_buckets(),
      mode: LimitMode::Enforcing,
      status: 429,
    }];
    let first_path = RateLimitContext::route(ip, "app", "/first", &headers);
    let second_path = RateLimitContext::route(ip, "app", "/second", &headers);

    assert_eq!(state.check_route_rate_limits(first_path, &path_limit), None);
    assert_eq!(
      state.check_route_rate_limits(first_path, &path_limit),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    assert_eq!(
      state.check_route_rate_limits(second_path, &path_limit),
      None
    );
  }

  #[test]
  fn access_token_keys_hash_tokens_and_fallback_to_ip() {
    let ip = "203.0.113.10".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer bearer-secret".parse().unwrap());
    headers.insert("x-api-token", "header-secret".parse().unwrap());
    let context = RateLimitContext::route(ip, "app", "/tokens", &headers);

    let bearer_key = rate_limit_key(context, RateLimitKey::AccessToken, Some("X-Api-Token"));
    assert!(bearer_key.starts_with("access_token:token:"));
    assert!(!bearer_key.contains("bearer-secret"));
    assert!(!bearer_key.contains("header-secret"));

    let mut header_only = HeaderMap::new();
    header_only.insert("x-api-token", "header-secret".parse().unwrap());
    let header_context = RateLimitContext::route(ip, "app", "/tokens", &header_only);
    let header_key = rate_limit_key(
      header_context,
      RateLimitKey::AccessTokenRoute,
      Some("X-Api-Token"),
    );
    assert!(header_key.starts_with("access_token_route:token:"));
    assert!(header_key.ends_with(":app"));
    assert!(!header_key.contains("header-secret"));
    assert_ne!(bearer_key, header_key);

    let empty_headers = HeaderMap::new();
    let fallback_context = RateLimitContext::route(ip, "app", "/tokens", &empty_headers);
    assert_eq!(
      rate_limit_key(
        fallback_context,
        RateLimitKey::AccessTokenPath,
        Some("X-Api-Token"),
      ),
      "access_token_path:fallback_ip:203.0.113.10:/tokens"
    );
  }

  #[test]
  fn access_token_rate_limits_are_isolated_by_token_and_fallback_ip() {
    let state = LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let limit = [RateLimitConfig {
      name: "per-token".to_string(),
      key: RateLimitKey::AccessToken,
      routes: Vec::new(),
      token_header: None,
      rate: "1r/h".to_string(),
      burst: 1,
      max_buckets: default_rate_limit_max_buckets(),
      mode: LimitMode::Enforcing,
      status: 429,
    }];
    let mut token_a = HeaderMap::new();
    token_a.insert(AUTHORIZATION, "Bearer token-a".parse().unwrap());
    let mut token_b = HeaderMap::new();
    token_b.insert(AUTHORIZATION, "Bearer token-b".parse().unwrap());
    let token_a_context = RateLimitContext::route(ip, "app", "/tokens", &token_a);
    let token_b_context = RateLimitContext::route(ip, "app", "/tokens", &token_b);

    assert_eq!(state.check_route_rate_limits(token_a_context, &limit), None);
    assert_eq!(
      state.check_route_rate_limits(token_a_context, &limit),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    assert_eq!(state.check_route_rate_limits(token_b_context, &limit), None);

    let fallback_state = LimitState::new(None);
    let empty_headers = HeaderMap::new();
    let fallback_context = RateLimitContext::route(ip, "app", "/tokens", &empty_headers);
    assert_eq!(
      fallback_state.check_route_rate_limits(fallback_context, &limit),
      None
    );
    assert_eq!(
      fallback_state.check_route_rate_limits(fallback_context, &limit),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
  }

  #[test]
  fn local_rate_limit_rejects_new_bucket_when_max_buckets_exhausted() {
    let state = LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let limit = [RateLimitConfig {
      name: "per-token".to_string(),
      key: RateLimitKey::AccessToken,
      routes: Vec::new(),
      token_header: None,
      rate: "1r/h".to_string(),
      burst: 1,
      max_buckets: 1,
      mode: LimitMode::Enforcing,
      status: 429,
    }];
    let mut token_a = HeaderMap::new();
    token_a.insert(AUTHORIZATION, "Bearer token-a".parse().unwrap());
    let mut token_b = HeaderMap::new();
    token_b.insert(AUTHORIZATION, "Bearer token-b".parse().unwrap());

    assert_eq!(
      state.check_route_rate_limits(
        RateLimitContext::route(ip, "app", "/tokens", &token_a),
        &limit
      ),
      None
    );
    assert_eq!(state.rates.lock().unwrap().len(), 1);
    assert_eq!(
      state.check_route_rate_limits(
        RateLimitContext::route(ip, "app", "/tokens", &token_b),
        &limit
      ),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    assert_eq!(state.rates.lock().unwrap().len(), 1);
  }

  #[test]
  fn local_rate_limit_monitor_mode_does_not_grow_after_bucket_cap() {
    let state = LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let limit = [RateLimitConfig {
      name: "per-token-monitor".to_string(),
      key: RateLimitKey::AccessToken,
      routes: Vec::new(),
      token_header: None,
      rate: "1r/h".to_string(),
      burst: 1,
      max_buckets: 1,
      mode: LimitMode::Monitor,
      status: 429,
    }];
    let mut token_a = HeaderMap::new();
    token_a.insert(AUTHORIZATION, "Bearer token-a".parse().unwrap());
    let mut token_b = HeaderMap::new();
    token_b.insert(AUTHORIZATION, "Bearer token-b".parse().unwrap());

    assert_eq!(
      state.check_route_rate_limits(
        RateLimitContext::route(ip, "app", "/tokens", &token_a),
        &limit
      ),
      None
    );
    assert_eq!(
      state.check_route_rate_limits(
        RateLimitContext::route(ip, "app", "/tokens", &token_b),
        &limit
      ),
      None
    );
    assert_eq!(state.rates.lock().unwrap().len(), 1);
  }

  #[test]
  fn local_rate_limit_prunes_refilled_buckets_before_enforcing_cap() {
    let state = LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let headers = HeaderMap::new();
    let limit = [RateLimitConfig {
      name: "per-path".to_string(),
      key: RateLimitKey::ClientIpPath,
      routes: Vec::new(),
      token_header: None,
      rate: "1r/s".to_string(),
      burst: 1,
      max_buckets: 1,
      mode: LimitMode::Enforcing,
      status: 429,
    }];

    assert_eq!(
      state.check_route_rate_limits(
        RateLimitContext::route(ip, "app", "/first", &headers),
        &limit
      ),
      None
    );
    {
      let mut buckets = state.rates.lock().unwrap();
      for bucket in buckets.values_mut() {
        bucket.last = bucket.last.checked_sub(Duration::from_secs(2)).unwrap();
      }
    }

    assert_eq!(
      state.check_route_rate_limits(
        RateLimitContext::route(ip, "app", "/second", &headers),
        &limit
      ),
      None
    );
    let buckets = state.rates.lock().unwrap();
    assert_eq!(buckets.len(), 1);
    assert!(buckets.keys().any(|(_, key)| key.ends_with(":/second")));
  }
}
