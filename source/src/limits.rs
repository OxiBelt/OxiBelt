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

  pub fn acquire_connection(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
    if let Some(shared) = &self.shared_state
      && shared.has_connection_limits()
    {
      let mut owned_scopes = vec!["total".to_string(), format!("ip:{ip}")];
      for limit in connection_limits {
        owned_scopes.push(format!("named:{}:{ip}", limit.name));
      }
      let mut scopes = vec![
        ConnectionScope {
          key: owned_scopes[0].as_str(),
          limit: limits.max_connections,
          status: StatusCode::SERVICE_UNAVAILABLE,
        },
        ConnectionScope {
          key: owned_scopes[1].as_str(),
          limit: limits.max_connections_per_ip,
          status: StatusCode::TOO_MANY_REQUESTS,
        },
      ];
      for (index, limit) in connection_limits.iter().enumerate() {
        scopes.push(ConnectionScope {
          key: owned_scopes[index + 2].as_str(),
          limit: limit.limit,
          status: StatusCode::from_u16(limit.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
        });
      }
      let acquired = shared.acquire_connections(&scopes);
      drop(scopes);
      return match acquired {
        Ok(None) => Ok(ConnectionPermit {
          state: self.clone(),
          ip,
          names: connection_limits
            .iter()
            .map(|limit| limit.name.clone())
            .collect(),
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
    if counts.total >= limits.max_connections {
      return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    if counts.per_ip.get(&ip).copied().unwrap_or(0) >= limits.max_connections_per_ip {
      return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    for limit in connection_limits {
      let key = (limit.name.clone(), ip);
      if counts.named.get(&key).copied().unwrap_or(0) >= limit.limit {
        return Err(StatusCode::from_u16(limit.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS));
      }
    }
    counts.total += 1;
    *counts.per_ip.entry(ip).or_insert(0) += 1;
    for limit in connection_limits {
      *counts.named.entry((limit.name.clone(), ip)).or_insert(0) += 1;
    }
    Ok(ConnectionPermit {
      state: self.clone(),
      ip,
      names: connection_limits
        .iter()
        .map(|limit| limit.name.clone())
        .collect(),
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

  fn release_connection(&self, ip: IpAddr, names: &[String]) {
    let mut counts = self
      .connections
      .lock()
      .expect("connection limit lock poisoned");
    counts.total = counts.total.saturating_sub(1);
    decrement_or_remove(&mut counts.per_ip, &ip);
    for name in names {
      decrement_or_remove(&mut counts.named, &(name.clone(), ip));
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
  ip: IpAddr,
  names: Vec<String>,
  shared_scopes: Vec<String>,
}

impl Drop for ConnectionPermit {
  fn drop(&mut self) {
    if self.shared_scopes.is_empty() {
      self.state.release_connection(self.ip, &self.names);
    } else {
      self.state.release_shared_connection(&self.shared_scopes);
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
mod tests {
  use super::*;

  #[test]
  fn parses_rates() {
    assert!((parse_rate("10r/s").unwrap().per_second - 10.0).abs() < f64::EPSILON);
    assert!((parse_rate("60r/m").unwrap().per_second - 1.0).abs() < f64::EPSILON);
    assert!(parse_rate("10/s").is_err());
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
    let permit = first.acquire_connection(ip, &limits, &[]).unwrap();
    assert_eq!(
      second.acquire_connection(ip, &limits, &[]).err(),
      Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    drop(permit);
    assert!(second.acquire_connection(ip, &limits, &[]).is_ok());
  }
}
