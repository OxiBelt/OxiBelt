//! Upstream HTTP/3 pooling and connection establishment.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ::http::{Request, Response};
use anyhow::Context;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::{
  H3_POOL_SELECTION_RETRIES, H3SendRequest, connect_h3_upstream, resolve_upstream_addr,
  send_h3_request,
};
use crate::config::{Config, HttpVersion, UpstreamConfig};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::ProxyBody;
use crate::tls;

#[derive(Clone, Default)]
pub(crate) struct UpstreamH3Pools {
  by_upstream: HashMap<String, Arc<UpstreamH3Pool>>,
}

impl UpstreamH3Pools {
  pub(crate) fn new(
    upstreams: &[UpstreamConfig],
    config: &Config,
    tls_resumption: &tls::TlsResumptionState,
    outbound_revocation: &tls::OutboundRevocationRuntime,
  ) -> anyhow::Result<Self> {
    if !config.quic.upstream_pool.enabled {
      return Ok(Self::default());
    }

    let mut by_upstream = HashMap::new();
    for upstream in upstreams {
      if upstream.max_http_version != HttpVersion::H3 {
        continue;
      }
      let quic_config =
        tls::build_upstream_quic_client_config_with_crypto_resumption_and_revocation(
          &config.crypto,
          &config.proxy.trusted_ca_certs,
          &upstream.tls.ech,
          &config.quic,
          &upstream.tls.resumption,
          Some(tls_resumption),
          &upstream.name,
          Some((
            outbound_revocation,
            outbound_revocation.policy_for_upstream(upstream),
          )),
        )
        .with_context(|| format!("failed to build upstream HTTP/3 pool for {}", upstream.name))?;
      by_upstream.insert(
        upstream.name.clone(),
        Arc::new(UpstreamH3Pool {
          client_config: quic_config,
          quic_config: config.quic.clone(),
          quic_host_key_base_dir: config.source_paths.cert_dir.clone(),
          entries: Mutex::new(HashMap::new()),
        }),
      );
    }

    Ok(Self { by_upstream })
  }

  pub(super) fn for_upstream(&self, upstream_name: &str) -> Option<Arc<UpstreamH3Pool>> {
    self.by_upstream.get(upstream_name).cloned()
  }
}

pub(super) struct UpstreamH3Pool {
  client_config: h3_quinn::quinn::ClientConfig,
  quic_config: crate::config::QuicConfig,
  quic_host_key_base_dir: Option<PathBuf>,
  entries: Mutex<HashMap<H3PoolKey, Arc<H3PoolSlot>>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct H3PoolKey {
  remote_addr: SocketAddr,
  server_name: String,
}

struct PooledH3Connection {
  _endpoint: h3_quinn::quinn::Endpoint,
  connection: h3_quinn::quinn::Connection,
  send_request: H3SendRequest,
  created_at: Instant,
  last_used: std::sync::Mutex<Instant>,
  streams: H3PoolStreamTracker,
  driver_task: JoinHandle<()>,
}

struct H3PoolSlot {
  connection: Mutex<Option<Arc<PooledH3Connection>>>,
  retired: AtomicBool,
}

impl H3PoolSlot {
  fn new() -> Self {
    Self {
      connection: Mutex::new(None),
      retired: AtomicBool::new(false),
    }
  }
}

enum H3PoolSlotSelection {
  Exact(Arc<H3PoolSlot>),
  ReuseOnly(Arc<H3PoolSlot>),
}

#[derive(Default)]
struct H3PoolStreamTracker {
  active_streams: AtomicUsize,
}

impl H3PoolStreamTracker {
  fn acquire(&self) {
    self.active_streams.fetch_add(1, Ordering::AcqRel);
  }

  fn release(&self) {
    let previous = self.active_streams.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(
      previous > 0,
      "H3 pool stream lease released without a reservation"
    );
  }

  fn is_active(&self) -> bool {
    self.active_streams.load(Ordering::Acquire) > 0
  }

  fn evictable(&self) -> bool {
    !self.is_active()
  }
}

struct PooledH3Lease {
  connection: Arc<PooledH3Connection>,
}

impl PooledH3Connection {
  fn usable(&self, upstream: &UpstreamConfig, quic_config: &crate::config::QuicConfig) -> bool {
    if self.connection.close_reason().is_some() {
      return false;
    }
    if self.streams.is_active() {
      return true;
    }
    self.created_at.elapsed() < Duration::from_millis(quic_config.upstream_pool.max_lifetime_ms)
      && self
        .last_used
        .lock()
        .expect("pooled H3 connection last_used lock poisoned")
        .elapsed()
        < Duration::from_millis(upstream.idle_timeout_ms)
  }

  fn mark_used(&self) {
    *self
      .last_used
      .lock()
      .expect("pooled H3 connection last_used lock poisoned") = Instant::now();
  }

  fn reserve(connection: &Arc<Self>) -> PooledH3Lease {
    connection.streams.acquire();
    connection.mark_used();
    PooledH3Lease {
      connection: Arc::clone(connection),
    }
  }

  fn evictable(&self) -> bool {
    self.streams.evictable()
  }

  fn last_used(&self) -> Instant {
    *self
      .last_used
      .lock()
      .expect("pooled H3 connection last_used lock poisoned")
  }
}

impl Drop for PooledH3Lease {
  fn drop(&mut self) {
    self.connection.mark_used();
    self.connection.streams.release();
  }
}

impl Drop for PooledH3Connection {
  fn drop(&mut self) {
    self.connection.close(0u32.into(), b"pool entry dropped");
    self.driver_task.abort();
  }
}

impl UpstreamH3Pool {
  pub(super) async fn forward_request(
    self: Arc<Self>,
    request: Request<ProxyBody>,
    upstream: &UpstreamConfig,
    timeouts: EffectiveTimeouts,
    metrics: &Arc<crate::metrics::Metrics>,
  ) -> anyhow::Result<Response<ProxyBody>> {
    let uri = request.uri().clone();
    metrics.record_http_upstream_client_request("h3", "https", "primary");
    let (server_name, remote_addr) = resolve_upstream_addr(&upstream.origin).await?;
    let key = H3PoolKey {
      remote_addr,
      server_name,
    };
    let lease = self
      .send_request_for(key.clone(), upstream, timeouts, metrics)
      .await?;
    let entry = Arc::clone(&lease.connection);
    match send_h3_request(entry.send_request.clone(), request, &uri, timeouts).await {
      Ok(response) => {
        let (parts, body) = response.into_parts();
        let body = crate::proxy::http::body::with_drop_guard(body, lease);
        Ok(Response::from_parts(parts, body))
      }
      Err(error) => {
        let connection_closed = entry.connection.close_reason().is_some();
        drop(lease);
        if connection_closed {
          self.remove_entry(&key, &entry).await;
        }
        Err(error)
      }
    }
  }

  async fn send_request_for(
    &self,
    key: H3PoolKey,
    upstream: &UpstreamConfig,
    timeouts: EffectiveTimeouts,
    metrics: &Arc<crate::metrics::Metrics>,
  ) -> anyhow::Result<PooledH3Lease> {
    for _ in 0..H3_POOL_SELECTION_RETRIES {
      match self.slot_for_key(key.clone()).await? {
        H3PoolSlotSelection::Exact(slot) => {
          let mut connection = slot.connection.lock().await;
          if slot.retired.load(Ordering::Acquire) {
            continue;
          }
          if let Some(entry) = connection.as_ref()
            && entry.usable(upstream, &self.quic_config)
          {
            return Ok(PooledH3Connection::reserve(entry));
          }

          *connection = None;
          let entry = self.connect_entry(key.clone(), timeouts, metrics).await?;
          let lease = PooledH3Connection::reserve(&entry);
          *connection = Some(entry);
          return Ok(lease);
        }
        H3PoolSlotSelection::ReuseOnly(slot) => {
          let connection = slot.connection.lock().await;
          if slot.retired.load(Ordering::Acquire) {
            continue;
          }
          if let Some(entry) = connection.as_ref()
            && entry.usable(upstream, &self.quic_config)
          {
            return Ok(PooledH3Connection::reserve(entry));
          }
        }
      }
    }

    anyhow::bail!(
      "upstream HTTP/3 pool reached its configured connection capacity without a reusable connection"
    )
  }

  async fn connect_entry(
    &self,
    key: H3PoolKey,
    timeouts: EffectiveTimeouts,
    metrics: &Arc<crate::metrics::Metrics>,
  ) -> anyhow::Result<Arc<PooledH3Connection>> {
    metrics.record_http_upstream_client_pool_miss("h3", "https", "primary");
    let connected = connect_h3_upstream(
      key.server_name.clone(),
      key.remote_addr,
      self.client_config.clone(),
      &self.quic_config,
      self.quic_host_key_base_dir.as_deref(),
      timeouts.upstream_connect,
    )
    .await?;
    metrics.record_http_upstream_client_connection_created("h3", "https", "primary");
    let entry = Arc::new(PooledH3Connection {
      _endpoint: connected.endpoint,
      connection: connected.connection,
      send_request: connected.send_request,
      created_at: Instant::now(),
      last_used: std::sync::Mutex::new(Instant::now()),
      streams: H3PoolStreamTracker::default(),
      driver_task: connected.driver_task,
    });
    Ok(entry)
  }

  async fn slot_for_key(&self, key: H3PoolKey) -> anyhow::Result<H3PoolSlotSelection> {
    select_h3_pool_slot(
      &self.entries,
      self.quic_config.upstream_pool.max_connections_per_upstream,
      key,
    )
    .await
  }

  async fn remove_entry(&self, key: &H3PoolKey, target: &Arc<PooledH3Connection>) {
    let slot = self.entries.lock().await.get(key).cloned();
    if let Some(slot) = slot {
      let mut connection = slot.connection.lock().await;
      if connection
        .as_ref()
        .is_some_and(|candidate| Arc::ptr_eq(candidate, target))
      {
        *connection = None;
      }
    }
  }
}

async fn select_h3_pool_slot(
  entries: &Mutex<HashMap<H3PoolKey, Arc<H3PoolSlot>>>,
  max_connections: usize,
  key: H3PoolKey,
) -> anyhow::Result<H3PoolSlotSelection> {
  let mut entries = entries.lock().await;
  if let Some(slot) = entries.get(&key) {
    return Ok(H3PoolSlotSelection::Exact(slot.clone()));
  }

  if entries.len() < max_connections {
    let slot = Arc::new(H3PoolSlot::new());
    entries.insert(key, slot.clone());
    return Ok(H3PoolSlotSelection::Exact(slot));
  }

  let mut eviction_candidates = entries
    .iter()
    .filter_map(|(candidate_key, slot)| {
      if slot.retired.load(Ordering::Acquire) {
        return None;
      }
      let connection = slot.connection.try_lock().ok()?;
      match connection.as_ref() {
        None => Some((candidate_key.clone(), slot.clone(), Instant::now())),
        Some(entry) if entry.evictable() => {
          Some((candidate_key.clone(), slot.clone(), entry.last_used()))
        }
        Some(_) => None,
      }
    })
    .collect::<Vec<_>>();
  eviction_candidates.sort_by_key(|(_, _, last_used)| *last_used);
  for (candidate_key, slot, _) in eviction_candidates {
    let mut connection = slot.connection.lock().await;
    if slot.retired.load(Ordering::Acquire)
      || connection.as_ref().is_some_and(|entry| !entry.evictable())
    {
      continue;
    }
    slot.retired.store(true, Ordering::Release);
    *connection = None;
    entries.remove(&candidate_key);
    let slot = Arc::new(H3PoolSlot::new());
    entries.insert(key, slot.clone());
    return Ok(H3PoolSlotSelection::Exact(slot));
  }

  let slot = entries
    .iter()
    .find_map(|(candidate_key, slot)| {
      (same_h3_pool_authority(candidate_key, &key) && !slot.retired.load(Ordering::Acquire))
        .then(|| slot.clone())
    })
    .context("upstream HTTP/3 pool reached capacity without a same-authority connection")?;
  Ok(H3PoolSlotSelection::ReuseOnly(slot))
}

fn same_h3_pool_authority(existing: &H3PoolKey, requested: &H3PoolKey) -> bool {
  existing.server_name == requested.server_name
}
#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::sync::Arc;
  use std::sync::atomic::Ordering;

  use super::*;

  #[test]
  fn stream_reservation_blocks_eviction_until_release() {
    let streams = H3PoolStreamTracker::default();
    assert!(streams.evictable());

    streams.acquire();
    assert!(streams.is_active());
    assert!(!streams.evictable());

    streams.release();
    assert!(!streams.is_active());
    assert!(streams.evictable());
  }

  #[test]
  fn same_authority_reuse_keeps_origins_separate() {
    let first = H3PoolKey {
      remote_addr: "127.0.0.1:443".parse().unwrap(),
      server_name: "api.example.test".to_owned(),
    };
    let same_authority_different_address = H3PoolKey {
      remote_addr: "127.0.0.2:443".parse().unwrap(),
      server_name: "api.example.test".to_owned(),
    };
    let different_authority = H3PoolKey {
      remote_addr: "127.0.0.1:443".parse().unwrap(),
      server_name: "other.example.test".to_owned(),
    };

    assert!(same_h3_pool_authority(
      &first,
      &same_authority_different_address
    ));
    assert!(!same_h3_pool_authority(&first, &different_authority));
  }

  #[tokio::test]
  async fn slot_selection_retires_an_evictable_slot_before_replacement() {
    let entries = Mutex::new(HashMap::new());
    let old_key = H3PoolKey {
      remote_addr: "127.0.0.1:443".parse().unwrap(),
      server_name: "api.example.test".to_owned(),
    };
    let new_key = H3PoolKey {
      remote_addr: "127.0.0.2:443".parse().unwrap(),
      server_name: "api.example.test".to_owned(),
    };
    let old_slot = Arc::new(H3PoolSlot::new());
    entries
      .lock()
      .await
      .insert(old_key.clone(), old_slot.clone());

    let selection = select_h3_pool_slot(&entries, 1, new_key.clone())
      .await
      .expect("an empty slot should be safely replaceable");
    let H3PoolSlotSelection::Exact(new_slot) = selection else {
      panic!("replacement should produce an exact pool slot");
    };

    assert!(
      old_slot.retired.load(Ordering::Acquire),
      "a request that selected the old slot before eviction must observe retirement and retry"
    );
    assert!(!new_slot.retired.load(Ordering::Acquire));
    let entries = entries.lock().await;
    assert!(!entries.contains_key(&old_key));
    assert!(
      entries
        .get(&new_key)
        .is_some_and(|slot| Arc::ptr_eq(slot, &new_slot))
    );
  }
}
