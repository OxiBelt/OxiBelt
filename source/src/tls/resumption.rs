use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
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

const SERVER_SESSION_CACHE_SHARDS: usize = 16;

#[derive(Clone, Default)]
pub struct TlsResumptionState {
  server: Arc<Mutex<HashMap<TlsServerResumptionKey, TlsServerResumptionRuntime>>>,
  upstream_clients: Arc<Mutex<HashMap<TlsClientConfigKey, ClientConfig>>>,
}

#[derive(Clone, Debug)]
enum TlsServerResumptionRuntime {
  Stateful(Arc<TtlServerSessionCache>),
  Stateless(Arc<dyn rustls::server::ProducesTickets>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TlsServerSessionStorageStats {
  pub put_count: u64,
  pub get_count: u64,
  pub take_count: u64,
  pub lock_wait_ns: u64,
  pub put_duration_ns: u64,
}

impl TlsServerSessionStorageStats {
  fn add(&mut self, other: Self) {
    self.put_count = self.put_count.saturating_add(other.put_count);
    self.get_count = self.get_count.saturating_add(other.get_count);
    self.take_count = self.take_count.saturating_add(other.take_count);
    self.lock_wait_ns = self.lock_wait_ns.saturating_add(other.lock_wait_ns);
    self.put_duration_ns = self.put_duration_ns.saturating_add(other.put_duration_ns);
  }
}

#[derive(Debug, Default)]
struct TtlServerSessionCacheStats {
  put_count: AtomicU64,
  get_count: AtomicU64,
  take_count: AtomicU64,
  lock_wait_ns: AtomicU64,
  put_duration_ns: AtomicU64,
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
  shard_capacity: usize,
  ttl: Duration,
  shards: Vec<TtlServerSessionCacheShard>,
  stats: TtlServerSessionCacheStats,
}

#[derive(Debug)]
struct TtlServerSessionCacheShard {
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
    let shard_count = if capacity >= SERVER_SESSION_CACHE_SHARDS {
      SERVER_SESSION_CACHE_SHARDS
    } else {
      1
    };
    let shard_capacity = (capacity / shard_count).max(1);
    Self {
      capacity,
      shard_capacity,
      ttl,
      shards: (0..shard_count)
        .map(|_| TtlServerSessionCacheShard {
          inner: Mutex::new(TtlServerSessionCacheInner::default()),
        })
        .collect(),
      stats: TtlServerSessionCacheStats::default(),
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
    while inner.entries.len() > self.shard_capacity {
      let Some(key) = inner.order.pop_front() else {
        break;
      };
      inner.entries.remove(&key);
    }
  }

  fn shard(&self, key: &[u8]) -> &TtlServerSessionCacheShard {
    let index = if self.shards.len() == 1 {
      0
    } else {
      let mut hasher = std::collections::hash_map::DefaultHasher::new();
      key.hash(&mut hasher);
      (hasher.finish() as usize) % self.shards.len()
    };
    &self.shards[index]
  }

  fn record_lock_wait(&self, elapsed: Duration) {
    self
      .stats
      .lock_wait_ns
      .fetch_add(duration_ns(elapsed), Ordering::Relaxed);
  }

  fn record_put_duration(&self, elapsed: Duration) {
    self
      .stats
      .put_duration_ns
      .fetch_add(duration_ns(elapsed), Ordering::Relaxed);
  }

  fn snapshot(&self) -> TlsServerSessionStorageStats {
    TlsServerSessionStorageStats {
      put_count: self.stats.put_count.load(Ordering::Relaxed),
      get_count: self.stats.get_count.load(Ordering::Relaxed),
      take_count: self.stats.take_count.load(Ordering::Relaxed),
      lock_wait_ns: self.stats.lock_wait_ns.load(Ordering::Relaxed),
      put_duration_ns: self.stats.put_duration_ns.load(Ordering::Relaxed),
    }
  }
}

impl rustls::server::StoresServerSessions for TtlServerSessionCache {
  fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
    let started = Instant::now();
    self.stats.put_count.fetch_add(1, Ordering::Relaxed);
    if self.capacity == 0 {
      self.record_put_duration(started.elapsed());
      return false;
    }
    let now = Instant::now();
    let lock_started = Instant::now();
    let mut inner = self
      .shard(&key)
      .inner
      .lock()
      .expect("TLS session cache lock poisoned");
    self.record_lock_wait(lock_started.elapsed());
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
    self.record_put_duration(started.elapsed());
    true
  }

  fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
    self.stats.get_count.fetch_add(1, Ordering::Relaxed);
    let now = Instant::now();
    let lock_started = Instant::now();
    let mut inner = self
      .shard(key)
      .inner
      .lock()
      .expect("TLS session cache lock poisoned");
    self.record_lock_wait(lock_started.elapsed());
    self.remove_expired_at(&mut inner, now);
    inner.entries.get(key).map(|stored| stored.value.clone())
  }

  fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
    self.stats.take_count.fetch_add(1, Ordering::Relaxed);
    let now = Instant::now();
    let lock_started = Instant::now();
    let mut inner = self
      .shard(key)
      .inner
      .lock()
      .expect("TLS session cache lock poisoned");
    self.record_lock_wait(lock_started.elapsed());
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

fn duration_ns(duration: Duration) -> u64 {
  duration.as_nanos().min(u128::from(u64::MAX)) as u64
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

  pub(crate) fn server_session_storage_stats(&self) -> TlsServerSessionStorageStats {
    let server = self
      .server
      .lock()
      .expect("TLS resumption state lock poisoned");
    let mut stats = TlsServerSessionStorageStats::default();
    for runtime in server.values() {
      if let TlsServerResumptionRuntime::Stateful(cache) = runtime {
        stats.add(cache.snapshot());
      }
    }
    stats
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
  context.update(format!("verify_depth:{}", client_auth.verify_depth).as_bytes());
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
  use super::{TlsClientAuthConfig, TtlServerSessionCache, client_auth_identity};
  use crate::config::TlsClientAuthMode;
  use rustls::server::StoresServerSessions;
  use std::sync::Arc;
  use std::time::Duration;

  #[test]
  fn client_auth_identity_includes_verify_depth() {
    let shallow = TlsClientAuthConfig {
      mode: TlsClientAuthMode::Require,
      ca_certs: Vec::new(),
      verify_depth: 1,
    };
    let deep = TlsClientAuthConfig {
      verify_depth: 2,
      ..shallow.clone()
    };

    assert_ne!(
      client_auth_identity(&shallow).expect("identity should hash"),
      client_auth_identity(&deep).expect("identity should hash")
    );
  }

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

  #[test]
  fn stateful_cache_uses_shards_for_larger_capacities() {
    let cache = TtlServerSessionCache::new(64, Duration::from_secs(60));
    assert!(
      cache.shards.len() > 1,
      "larger TLS session caches should shard lock contention"
    );

    for index in 0..128_u8 {
      assert!(cache.put(vec![index], vec![index]));
    }

    let live_entries = cache
      .shards
      .iter()
      .map(|shard| {
        shard
          .inner
          .lock()
          .expect("TLS session cache lock poisoned")
          .entries
          .len()
      })
      .sum::<usize>();
    assert!(
      live_entries <= cache.capacity,
      "sharded cache should stay bounded by configured capacity"
    );
  }

  #[test]
  fn stateful_cache_diagnostic_counters_track_operations() {
    let cache = TtlServerSessionCache::new(2, Duration::from_secs(60));

    assert!(cache.put(b"first".to_vec(), b"1".to_vec()));
    assert_eq!(cache.get(b"first"), Some(b"1".to_vec()));
    assert_eq!(cache.take(b"first"), Some(b"1".to_vec()));

    let stats = cache.snapshot();
    assert_eq!(stats.put_count, 1);
    assert_eq!(stats.get_count, 1);
    assert_eq!(stats.take_count, 1);
    assert!(
      stats.put_duration_ns > 0,
      "put duration should accumulate elapsed time"
    );
  }

  #[test]
  fn stateful_cache_diagnostic_counters_track_lock_wait() {
    let cache = Arc::new(TtlServerSessionCache::new(2, Duration::from_secs(60)));
    let guard = cache
      .shard(b"missing")
      .inner
      .lock()
      .expect("TLS session cache lock poisoned");
    let waiting_cache = cache.clone();
    let handle = std::thread::spawn(move || {
      assert_eq!(waiting_cache.get(b"missing"), None);
    });

    std::thread::sleep(Duration::from_millis(5));
    drop(guard);
    handle.join().expect("worker should not panic");

    let stats = cache.snapshot();
    assert_eq!(stats.get_count, 1);
    assert!(
      stats.lock_wait_ns > 0,
      "lock wait should accumulate elapsed time"
    );
  }

  fn assert_cache_lengths(cache: &TtlServerSessionCache, entries: usize, order: usize) {
    let mut actual_entries = 0;
    let mut actual_order = 0;
    for shard in &cache.shards {
      let inner = shard.inner.lock().expect("TLS session cache lock poisoned");
      assert_eq!(
        inner.order.len(),
        inner.entries.len(),
        "order must track every live entry"
      );
      assert!(
        inner.order.len() <= cache.shard_capacity,
        "shard order length must stay bounded by shard capacity"
      );
      for key in &inner.order {
        assert!(
          inner.entries.contains_key(key),
          "order must only contain live entry keys"
        );
      }
      actual_entries += inner.entries.len();
      actual_order += inner.order.len();
    }
    assert_eq!(actual_entries, entries);
    assert_eq!(actual_order, order);
    assert!(
      actual_order <= cache.capacity,
      "order length must stay bounded by capacity"
    );
  }

  fn assert_cache_order(cache: &TtlServerSessionCache, expected: &[&[u8]]) {
    assert_eq!(
      cache.shards.len(),
      1,
      "ordered assertions only apply to single-shard test caches"
    );
    let inner = cache.shards[0]
      .inner
      .lock()
      .expect("TLS session cache lock poisoned");
    let actual = inner
      .order
      .iter()
      .map(|key| key.as_slice())
      .collect::<Vec<_>>();
    assert_eq!(actual, expected);
  }
}
