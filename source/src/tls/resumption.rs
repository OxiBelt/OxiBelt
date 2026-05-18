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

  fn remove_expired(&self, inner: &mut TtlServerSessionCacheInner) {
    let now = Instant::now();
    inner
      .entries
      .retain(|_, stored| now.duration_since(stored.inserted_at) <= self.ttl);
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
    let mut inner = self.inner.lock().expect("TLS session cache lock poisoned");
    self.remove_expired(&mut inner);
    if !inner.entries.contains_key(&key) {
      inner.order.push_back(key.clone());
    }
    inner.entries.insert(
      key,
      StoredServerSession {
        value,
        inserted_at: Instant::now(),
      },
    );
    self.remove_expired(&mut inner);
    true
  }

  fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
    let mut inner = self.inner.lock().expect("TLS session cache lock poisoned");
    self.remove_expired(&mut inner);
    inner.entries.get(key).map(|stored| stored.value.clone())
  }

  fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
    let mut inner = self.inner.lock().expect("TLS session cache lock poisoned");
    self.remove_expired(&mut inner);
    inner.entries.remove(key).map(|stored| stored.value)
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
