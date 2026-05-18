use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use rustls::client::{Resumption, Tls12Resumption};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ServerConfig};

use crate::config::{
  TlsClientAuthConfig, TlsServerResumptionConfig, TlsServerResumptionMode, UpstreamEchConfig,
  UpstreamTls12ResumptionMode, UpstreamTlsResumptionConfig, UpstreamTlsResumptionMode,
};

#[derive(Clone, Default)]
pub struct TlsResumptionState {
  server: Arc<Mutex<HashMap<TlsServerResumptionKey, TlsServerResumptionRuntime>>>,
  upstream_clients: Arc<Mutex<HashMap<TlsClientConfigKey, ClientConfig>>>,
}

#[derive(Clone, Debug)]
enum TlsServerResumptionRuntime {
  Stateful(Arc<dyn rustls::server::StoresServerSessions>),
  Stateless(Arc<dyn rustls::server::ProducesTickets>),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct TlsServerResumptionKey {
  pub(super) scope: &'static str,
  pub(super) mode: TlsServerResumptionMode,
  pub(super) server_identity: String,
  pub(super) client_auth_identity: String,
  pub(super) alpn_family: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct TlsClientConfigKey {
  scope: &'static str,
  upstream_name: String,
  roots_identity: String,
  ech_identity: String,
  mode: UpstreamTlsResumptionMode,
  session_cache_size: usize,
  tls12: UpstreamTls12ResumptionMode,
}

#[derive(Debug)]
struct TtlServerSessionCache {
  capacity: usize,
  ttl: Duration,
  inner: Mutex<TtlServerSessionCacheInner>,
}

#[derive(Debug, Default)]
struct TtlServerSessionCacheInner {
  entries: HashMap<Vec<u8>, StoredServerSession>,
  order: VecDeque<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct StoredServerSession {
  value: Vec<u8>,
  inserted_at: Instant,
}

impl TtlServerSessionCache {
  fn new(capacity: usize, ttl: Duration) -> Self {
    Self {
      capacity,
      ttl,
      inner: Mutex::new(TtlServerSessionCacheInner::default()),
    }
  }

  fn remove_expired_at(&self, inner: &mut TtlServerSessionCacheInner, now: Instant) {
    while let Some(key) = inner.order.front() {
      let Some(stored) = inner.entries.get(key) else {
        inner.order.pop_front();
        continue;
      };
      if now.duration_since(stored.inserted_at) <= self.ttl {
        break;
      }
      let key = inner.order.pop_front().expect("front key should exist");
      inner.entries.remove(&key);
    }
  }

  fn remove_over_capacity(&self, inner: &mut TtlServerSessionCacheInner) {
    while inner.entries.len() > self.capacity {
      let Some(key) = inner.order.pop_front() else {
        break;
      };
      inner.entries.remove(&key);
    }
  }
}

impl rustls::server::StoresServerSessions for TtlServerSessionCache {
  fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
    if self.capacity == 0 {
      return false;
    }
    let now = Instant::now();
    let mut inner = self.inner.lock().expect("TLS session cache lock poisoned");
    self.remove_expired_at(&mut inner, now);
    if inner.entries.contains_key(&key) {
      inner.order.retain(|queued| queued != &key);
    }
    inner.order.push_back(key.clone());
    inner.entries.insert(
      key,
      StoredServerSession {
        value,
        inserted_at: now,
      },
    );
    self.remove_over_capacity(&mut inner);
    true
  }

  fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
    let now = Instant::now();
    let mut inner = self.inner.lock().expect("TLS session cache lock poisoned");
    self.remove_expired_at(&mut inner, now);
    inner.entries.get(key).map(|stored| stored.value.clone())
  }

  fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
    let now = Instant::now();
    let mut inner = self.inner.lock().expect("TLS session cache lock poisoned");
    self.remove_expired_at(&mut inner, now);
    let value = inner.entries.remove(key).map(|stored| stored.value);
    if value.is_some() {
      inner.order.retain(|queued| queued.as_slice() != key);
    }
    value
  }

  fn can_cache(&self) -> bool {
    self.capacity > 0
  }
}

pub(super) fn configure_server_resumption(
  server_config: &mut ServerConfig,
  resumption: &TlsServerResumptionConfig,
  key: TlsServerResumptionKey,
  state: Option<&TlsResumptionState>,
) -> anyhow::Result<()> {
  match resumption.mode {
    TlsServerResumptionMode::Off => {
      server_config.send_tls13_tickets = 0;
      server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    }
    TlsServerResumptionMode::Stateful => {
      server_config.send_tls13_tickets = resumption.tls13_ticket_count;
      let runtime = match state {
        Some(state) => state.server_resumption_runtime(key, resumption)?,
        None => TlsServerResumptionRuntime::Stateful(Arc::new(TtlServerSessionCache::new(
          resumption.session_cache_size,
          Duration::from_secs(resumption.rotation_seconds),
        ))),
      };
      let TlsServerResumptionRuntime::Stateful(storage) = runtime else {
        bail!("TLS resumption cache kind changed unexpectedly");
      };
      server_config.session_storage = storage;
    }
    TlsServerResumptionMode::Stateless => {
      server_config.send_tls13_tickets = resumption.tls13_ticket_count;
      server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
      let runtime = match state {
        Some(state) => state.server_resumption_runtime(key, resumption)?,
        None => TlsServerResumptionRuntime::Stateless(
          rustls::crypto::aws_lc_rs::Ticketer::new()
            .context("failed to create TLS session ticket producer")?,
        ),
      };
      let TlsServerResumptionRuntime::Stateless(ticketer) = runtime else {
        bail!("TLS resumption ticketer kind changed unexpectedly");
      };
      server_config.ticketer = ticketer;
    }
  }
  Ok(())
}

impl TlsResumptionState {
  fn server_resumption_runtime(
    &self,
    key: TlsServerResumptionKey,
    resumption: &TlsServerResumptionConfig,
  ) -> anyhow::Result<TlsServerResumptionRuntime> {
    let mut server = self
      .server
      .lock()
      .expect("TLS resumption state lock poisoned");
    if let Some(runtime) = server.get(&key) {
      return Ok(runtime.clone());
    }
    let runtime = match resumption.mode {
      TlsServerResumptionMode::Off => {
        bail!("server resumption runtime is not used when resumption is off")
      }
      TlsServerResumptionMode::Stateful => {
        TlsServerResumptionRuntime::Stateful(Arc::new(TtlServerSessionCache::new(
          resumption.session_cache_size,
          Duration::from_secs(resumption.rotation_seconds),
        )))
      }
      TlsServerResumptionMode::Stateless => TlsServerResumptionRuntime::Stateless(
        rustls::crypto::aws_lc_rs::Ticketer::new()
          .context("failed to create TLS session ticket producer")?,
      ),
    };
    server.insert(key, runtime.clone());
    Ok(runtime)
  }

  pub(super) fn upstream_client_config(
    &self,
    key: TlsClientConfigKey,
    build: impl FnOnce() -> anyhow::Result<ClientConfig>,
  ) -> anyhow::Result<ClientConfig> {
    let mut clients = self
      .upstream_clients
      .lock()
      .expect("TLS upstream client config cache lock poisoned");
    if let Some(config) = clients.get(&key) {
      return Ok(config.clone());
    }
    let config = build()?;
    clients.insert(key, config.clone());
    Ok(config)
  }
}

pub(super) fn upstream_client_resumption(config: &UpstreamTlsResumptionConfig) -> Resumption {
  if config.mode == UpstreamTlsResumptionMode::Disabled {
    return Resumption::disabled();
  }
  let tls12 = match config.tls12 {
    UpstreamTls12ResumptionMode::Disabled => Tls12Resumption::Disabled,
    UpstreamTls12ResumptionMode::SessionIdOnly => Tls12Resumption::SessionIdOnly,
    UpstreamTls12ResumptionMode::SessionIdOrTickets => Tls12Resumption::SessionIdOrTickets,
  };
  Resumption::in_memory_sessions(config.session_cache_size).tls12_resumption(tls12)
}

pub(super) fn upstream_client_config_key(
  scope: &'static str,
  upstream_name: &str,
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
) -> anyhow::Result<TlsClientConfigKey> {
  Ok(TlsClientConfigKey {
    scope,
    upstream_name: upstream_name.to_string(),
    roots_identity: upstream_roots_identity(extra_root_certificates)?,
    ech_identity: upstream_ech_identity(ech)?,
    mode: resumption.mode,
    session_cache_size: resumption.session_cache_size,
    tls12: resumption.tls12,
  })
}

pub(super) fn certificate_identity(certs: &[CertificateDer<'static>]) -> String {
  let mut context = ring::digest::Context::new(&ring::digest::SHA256);
  context.update(b"certs");
  for cert in certs {
    context.update(&(cert.as_ref().len() as u64).to_be_bytes());
    context.update(cert.as_ref());
  }
  hex_encode(context.finish().as_ref())
}

pub(super) fn client_auth_identity(client_auth: &TlsClientAuthConfig) -> anyhow::Result<String> {
  let mut context = ring::digest::Context::new(&ring::digest::SHA256);
  context.update(format!("mode:{:?}", client_auth.mode).as_bytes());
  for path in &client_auth.ca_certs {
    for cert in super::load_certs(path)? {
      context.update(&(cert.as_ref().len() as u64).to_be_bytes());
      context.update(cert.as_ref());
    }
  }
  Ok(hex_encode(context.finish().as_ref()))
}

fn upstream_roots_identity(paths: &[std::path::PathBuf]) -> anyhow::Result<String> {
  let mut context = ring::digest::Context::new(&ring::digest::SHA256);
  context.update(b"webpki-roots");
  for path in paths {
    for cert in super::load_certs(path)? {
      context.update(path.to_string_lossy().as_bytes());
      context.update(&(cert.as_ref().len() as u64).to_be_bytes());
      context.update(cert.as_ref());
    }
  }
  Ok(hex_encode(context.finish().as_ref()))
}

fn upstream_ech_identity(ech: &UpstreamEchConfig) -> anyhow::Result<String> {
  let mut context = ring::digest::Context::new(&ring::digest::SHA256);
  context.update(format!("mode:{:?}", ech.mode).as_bytes());
  if let Some(path) = &ech.config_list_file {
    context.update(&super::read_existing_file(
      "upstream ECH config list file",
      path,
    )?);
  }
  Ok(hex_encode(context.finish().as_ref()))
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

#[cfg(test)]
mod tests {
  use super::TtlServerSessionCache;
  use rustls::server::StoresServerSessions;
  use std::time::Duration;

  #[test]
  fn stateful_cache_take_removes_consumed_keys_from_order() {
    let cache = TtlServerSessionCache::new(2, Duration::from_secs(60));

    for index in 0..16u8 {
      let key = vec![index];
      assert!(cache.put(key.clone(), vec![1, 2, 3]));
      assert_eq!(cache.take(&key), Some(vec![1, 2, 3]));
    }

    assert_cache_lengths(&cache, 0, 0);
  }

  #[test]
  fn stateful_cache_expiry_removes_stale_order_entries() {
    let cache = TtlServerSessionCache::new(4, Duration::from_millis(1));
    assert!(cache.put(b"expired".to_vec(), b"old".to_vec()));
    std::thread::sleep(Duration::from_millis(5));

    assert_eq!(cache.get(b"expired"), None);
    assert_cache_lengths(&cache, 0, 0);
  }

  #[test]
  fn stateful_cache_capacity_bounds_entries_and_order() {
    let cache = TtlServerSessionCache::new(2, Duration::from_secs(60));

    assert!(cache.put(b"first".to_vec(), b"1".to_vec()));
    assert!(cache.put(b"second".to_vec(), b"2".to_vec()));
    assert_cache_order(&cache, &[b"first".as_slice(), b"second".as_slice()]);
    assert!(cache.put(b"third".to_vec(), b"3".to_vec()));

    assert_eq!(cache.get(b"first"), None);
    assert_eq!(cache.get(b"second"), Some(b"2".to_vec()));
    assert_eq!(cache.get(b"third"), Some(b"3".to_vec()));
    assert_cache_order(&cache, &[b"second".as_slice(), b"third".as_slice()]);
    assert_cache_lengths(&cache, 2, 2);
  }

  #[test]
  fn stateful_cache_reinsert_moves_key_to_newest_capacity_slot() {
    let cache = TtlServerSessionCache::new(2, Duration::from_secs(60));

    assert!(cache.put(b"first".to_vec(), b"1".to_vec()));
    assert!(cache.put(b"second".to_vec(), b"2".to_vec()));
    assert!(cache.put(b"first".to_vec(), b"new".to_vec()));
    assert_cache_order(&cache, &[b"second".as_slice(), b"first".as_slice()]);
    assert!(cache.put(b"third".to_vec(), b"3".to_vec()));

    assert_eq!(cache.get(b"first"), Some(b"new".to_vec()));
    assert_eq!(cache.get(b"second"), None);
    assert_eq!(cache.get(b"third"), Some(b"3".to_vec()));
    assert_cache_order(&cache, &[b"first".as_slice(), b"third".as_slice()]);
    assert_cache_lengths(&cache, 2, 2);
  }

  #[test]
  fn stateful_cache_capacity_skips_consumed_order_entries() {
    let cache = TtlServerSessionCache::new(2, Duration::from_secs(60));

    assert!(cache.put(b"consumed".to_vec(), b"gone".to_vec()));
    assert_eq!(cache.take(b"consumed"), Some(b"gone".to_vec()));
    assert!(cache.put(b"first".to_vec(), b"1".to_vec()));
    assert!(cache.put(b"second".to_vec(), b"2".to_vec()));
    assert!(cache.put(b"third".to_vec(), b"3".to_vec()));

    assert_eq!(cache.get(b"first"), None);
    assert_eq!(cache.get(b"second"), Some(b"2".to_vec()));
    assert_eq!(cache.get(b"third"), Some(b"3".to_vec()));
    assert_cache_lengths(&cache, 2, 2);
  }

  fn assert_cache_lengths(cache: &TtlServerSessionCache, entries: usize, order: usize) {
    let inner = cache.inner.lock().expect("TLS session cache lock poisoned");
    assert_eq!(inner.entries.len(), entries);
    assert_eq!(inner.order.len(), order);
    assert_eq!(
      inner.order.len(),
      inner.entries.len(),
      "order must track every live entry"
    );
    assert!(
      inner.order.len() <= cache.capacity,
      "order length must stay bounded by capacity"
    );
    for key in &inner.order {
      assert!(
        inner.entries.contains_key(key),
        "order must only contain live entry keys"
      );
    }
  }

  fn assert_cache_order(cache: &TtlServerSessionCache, expected: &[&[u8]]) {
    let inner = cache.inner.lock().expect("TLS session cache lock poisoned");
    let actual = inner
      .order
      .iter()
      .map(|key| key.as_slice())
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }
}
