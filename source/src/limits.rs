use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, bail};
use http::StatusCode;

use crate::config::{ConnectionLimitConfig, LimitKey, LimitMode, LimitsConfig, RateLimitConfig};
use crate::shared_state::{ConnectionScope, SharedState};

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
    if let Some(shared) = &self.shared_state
      && shared.has_rate_limits()
    {
      for limit in rate_limits {
        let Ok(rate) = parse_rate(&limit.rate) else {
          return Some(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let key = match limit.key {
          LimitKey::ClientIp => ip.to_string(),
        };
        match shared.take_rate_token(&limit.name, &key, rate, limit.burst) {
          Ok(true) => {}
          Ok(false) => {
            if limit.mode == LimitMode::Enforcing {
              return Some(
                StatusCode::from_u16(limit.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
              );
            }
          }
          Err(error) => {
            tracing::warn!(error = %error, "shared rate limit backend failed closed");
            return Some(StatusCode::SERVICE_UNAVAILABLE);
          }
        }
      }
      return None;
    }
    let now = Instant::now();
    let mut buckets = self.rates.lock().expect("rate limit lock poisoned");
    for limit in rate_limits {
      let Ok(rate) = parse_rate(&limit.rate) else {
        return Some(StatusCode::INTERNAL_SERVER_ERROR);
      };
      let burst = f64::from(limit.burst.max(1));
      let key = (limit.name.clone(), ip.to_string());
      let bucket = buckets.entry(key).or_insert(TokenBucket {
        tokens: burst,
        last: now,
      });
      let elapsed = now.duration_since(bucket.last).as_secs_f64();
      bucket.tokens = (bucket.tokens + elapsed * rate.per_second).min(burst);
      bucket.last = now;
      if bucket.tokens < 1.0 && limit.mode == LimitMode::Enforcing {
        return Some(StatusCode::from_u16(limit.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS));
      }
      bucket.tokens -= 1.0;
    }
    None
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
      key: LimitKey::ClientIp,
      rate: "1r/h".to_string(),
      burst: 1,
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
}
