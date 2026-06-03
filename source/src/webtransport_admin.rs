//! Registry for admin-visible WebTransport sessions.
//! Session metadata is scoped to diagnostics and drain operations rather than request policy.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::bail;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

const SESSION_ID_PREFIX: &str = "wts_";

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WebTransportSessionScope {
  #[serde(default)]
  pub session_ids: Vec<String>,
  #[serde(default)]
  pub route: Option<String>,
  #[serde(default)]
  pub upstream: Option<String>,
  #[serde(default)]
  pub client_ip: Option<IpAddr>,
}

impl WebTransportSessionScope {
  pub fn is_empty(&self) -> bool {
    self.session_ids.is_empty()
      && self.route.is_none()
      && self.upstream.is_none()
      && self.client_ip.is_none()
  }
}

#[derive(Debug, Clone)]
pub struct WebTransportSessionRegistration {
  pub route: String,
  pub upstream: String,
  pub peer_ip: IpAddr,
  pub client_ip: IpAddr,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebTransportSessionSnapshot {
  pub id: String,
  pub route: String,
  pub upstream: String,
  pub peer_ip: IpAddr,
  pub client_ip: IpAddr,
  pub started_at_unix_ms: u64,
  pub last_activity_unix_ms: u64,
  pub draining: bool,
}

#[derive(Debug, Clone)]
pub struct WebTransportSessionCommand {
  pub close_code: u32,
  pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebTransportDrainInstallResult {
  pub drain_id: String,
  pub matched_sessions: usize,
}

#[derive(Debug, Default)]
pub struct WebTransportAdminRegistry {
  inner: Arc<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
  state: Mutex<RegistryState>,
}

#[derive(Debug, Default)]
struct RegistryState {
  sessions: HashMap<String, SessionRecord>,
  drain_rules: HashMap<String, DrainRule>,
}

#[derive(Debug)]
struct SessionRecord {
  metadata: WebTransportSessionRegistration,
  started_at_unix_ms: u64,
  last_activity_unix_ms: u64,
  commands: mpsc::UnboundedSender<WebTransportSessionCommand>,
}

#[derive(Debug, Clone)]
struct DrainRule {
  scope: WebTransportSessionScope,
  close_code: u32,
  reason: String,
}

pub struct WebTransportSessionGuard {
  id: String,
  registry: Weak<RegistryInner>,
}

impl WebTransportAdminRegistry {
  pub fn new() -> Arc<Self> {
    Arc::new(Self::default())
  }

  pub fn register(
    &self,
    metadata: WebTransportSessionRegistration,
    commands: mpsc::UnboundedSender<WebTransportSessionCommand>,
  ) -> anyhow::Result<WebTransportSessionGuard> {
    let id = new_session_id()?;
    let now = now_unix_ms();
    let record = SessionRecord {
      metadata,
      started_at_unix_ms: now,
      last_activity_unix_ms: now,
      commands,
    };
    self
      .inner
      .state
      .lock()
      .expect("webtransport registry lock poisoned")
      .sessions
      .insert(id.clone(), record);
    Ok(WebTransportSessionGuard {
      id,
      registry: Arc::downgrade(&self.inner),
    })
  }

  pub fn is_draining(&self, metadata: &WebTransportSessionRegistration) -> bool {
    let state = self
      .inner
      .state
      .lock()
      .expect("webtransport registry lock poisoned");
    state
      .drain_rules
      .values()
      .any(|rule| rule.matches_metadata(metadata))
  }

  pub fn record_activity(&self, id: &str) {
    let mut state = self
      .inner
      .state
      .lock()
      .expect("webtransport registry lock poisoned");
    if let Some(record) = state.sessions.get_mut(id) {
      record.last_activity_unix_ms = now_unix_ms();
    }
  }

  pub fn list(&self, scope: Option<&WebTransportSessionScope>) -> Vec<WebTransportSessionSnapshot> {
    let state = self
      .inner
      .state
      .lock()
      .expect("webtransport registry lock poisoned");
    state
      .sessions
      .iter()
      .filter(|(id, record)| scope.is_none_or(|scope| scope.matches_record(id, record)))
      .map(|(id, record)| snapshot_locked(id, record, &state.drain_rules))
      .collect()
  }

  pub fn install_drain_rule(
    &self,
    drain_id: String,
    scope: WebTransportSessionScope,
    close_code: u32,
    reason: String,
  ) -> WebTransportDrainInstallResult {
    let mut state = self
      .inner
      .state
      .lock()
      .expect("webtransport registry lock poisoned");
    let matched_sessions = state
      .sessions
      .iter()
      .filter(|(id, record)| scope.matches_record(id, record))
      .count();
    state.drain_rules.insert(
      drain_id.clone(),
      DrainRule {
        scope,
        close_code,
        reason,
      },
    );
    WebTransportDrainInstallResult {
      drain_id,
      matched_sessions,
    }
  }

  pub fn close_matching_drain_rule(&self, drain_id: &str) -> anyhow::Result<usize> {
    let state = self
      .inner
      .state
      .lock()
      .expect("webtransport registry lock poisoned");
    let Some(rule) = state.drain_rules.get(drain_id) else {
      bail!("webtransport drain rule not found");
    };
    let mut sent = 0usize;
    for (id, record) in &state.sessions {
      if !rule.scope.matches_record(id, record) {
        continue;
      }
      if record
        .commands
        .send(WebTransportSessionCommand {
          close_code: rule.close_code,
          reason: rule.reason.clone(),
        })
        .is_ok()
      {
        sent = sent.saturating_add(1);
      }
    }
    Ok(sent)
  }

  pub fn remove_drain_rule(&self, drain_id: &str) -> bool {
    self
      .inner
      .state
      .lock()
      .expect("webtransport registry lock poisoned")
      .drain_rules
      .remove(drain_id)
      .is_some()
  }
}

impl WebTransportSessionGuard {
  pub fn id(&self) -> &str {
    &self.id
  }
}

impl Drop for WebTransportSessionGuard {
  fn drop(&mut self) {
    let Some(registry) = self.registry.upgrade() else {
      return;
    };
    registry
      .state
      .lock()
      .expect("webtransport registry lock poisoned")
      .sessions
      .remove(&self.id);
  }
}

impl DrainRule {
  fn matches_metadata(&self, metadata: &WebTransportSessionRegistration) -> bool {
    if !self.scope.session_ids.is_empty() {
      return false;
    }
    self
      .scope
      .route
      .as_ref()
      .is_none_or(|route| route == &metadata.route)
      && self
        .scope
        .upstream
        .as_ref()
        .is_none_or(|upstream| upstream == &metadata.upstream)
      && self
        .scope
        .client_ip
        .is_none_or(|client_ip| client_ip == metadata.client_ip)
  }
}

impl WebTransportSessionScope {
  fn matches_record(&self, id: &str, record: &SessionRecord) -> bool {
    (self.session_ids.is_empty() || self.session_ids.iter().any(|session_id| session_id == id))
      && self
        .route
        .as_ref()
        .is_none_or(|route| route == &record.metadata.route)
      && self
        .upstream
        .as_ref()
        .is_none_or(|upstream| upstream == &record.metadata.upstream)
      && self
        .client_ip
        .is_none_or(|client_ip| client_ip == record.metadata.client_ip)
  }
}

fn snapshot_locked(
  id: &str,
  record: &SessionRecord,
  drain_rules: &HashMap<String, DrainRule>,
) -> WebTransportSessionSnapshot {
  WebTransportSessionSnapshot {
    id: id.to_string(),
    route: record.metadata.route.clone(),
    upstream: record.metadata.upstream.clone(),
    peer_ip: record.metadata.peer_ip,
    client_ip: record.metadata.client_ip,
    started_at_unix_ms: record.started_at_unix_ms,
    last_activity_unix_ms: record.last_activity_unix_ms,
    draining: drain_rules
      .values()
      .any(|rule| rule.scope.matches_record(id, record)),
  }
}

fn new_session_id() -> anyhow::Result<String> {
  let mut bytes = [0_u8; 16];
  SystemRandom::new()
    .fill(&mut bytes)
    .map_err(|_| anyhow::anyhow!("failed to generate WebTransport session ID"))?;
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  Ok(format!(
    "{SESSION_ID_PREFIX}{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
    bytes[0],
    bytes[1],
    bytes[2],
    bytes[3],
    bytes[4],
    bytes[5],
    bytes[6],
    bytes[7],
    bytes[8],
    bytes[9],
    bytes[10],
    bytes[11],
    bytes[12],
    bytes[13],
    bytes[14],
    bytes[15]
  ))
}

fn now_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn metadata(route: &str, upstream: &str, client_ip: &str) -> WebTransportSessionRegistration {
    WebTransportSessionRegistration {
      route: route.to_string(),
      upstream: upstream.to_string(),
      peer_ip: "203.0.113.9".parse().expect("peer IP should parse"),
      client_ip: client_ip.parse().expect("client IP should parse"),
    }
  }

  #[test]
  fn register_list_and_unregister_session() {
    let registry = WebTransportAdminRegistry::new();
    let (tx, _rx) = mpsc::unbounded_channel();
    let guard = registry
      .register(metadata("app", "origin", "198.51.100.10"), tx)
      .expect("session should register");

    let sessions = registry.list(None);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, guard.id());
    assert_eq!(sessions[0].route, "app");
    assert!(!sessions[0].draining);

    drop(guard);
    assert!(registry.list(None).is_empty());
  }

  #[test]
  fn drain_rule_matches_active_and_future_sessions() {
    let registry = WebTransportAdminRegistry::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let _guard = registry
      .register(metadata("app", "origin", "198.51.100.10"), tx)
      .expect("session should register");
    let scope = WebTransportSessionScope {
      route: Some("app".to_string()),
      ..WebTransportSessionScope::default()
    };

    let installed =
      registry.install_drain_rule("op_1".to_string(), scope.clone(), 7, "drain".to_string());
    assert_eq!(installed.matched_sessions, 1);
    assert!(registry.is_draining(&metadata("app", "origin", "198.51.100.10")));
    assert!(!registry.is_draining(&metadata("other", "origin", "198.51.100.10")));
    assert!(registry.list(Some(&scope))[0].draining);

    assert_eq!(
      registry
        .close_matching_drain_rule("op_1")
        .expect("rule should close"),
      1
    );
    let command = rx.try_recv().expect("session should receive close command");
    assert_eq!(command.close_code, 7);
    assert_eq!(command.reason, "drain");
    assert!(registry.remove_drain_rule("op_1"));
  }
}
