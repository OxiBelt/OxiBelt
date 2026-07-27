//! Atomic durable UDP-flow records.
//!
//! This module deliberately owns storage mechanics only. Stream routing decides
//! when a flow may be created, which canonical route/server material is
//! authorized, and how backend failures affect packet forwarding.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};

use crate::config::{MAX_SHARED_UDP_IDLE_TIMEOUT_MS, SHARED_UDP_RENEW_BATCH_SIZE};

#[cfg(test)]
use super::MemoryBackend;
use super::{
  Backend, BackendFailureRegistry, PostgresBackend, RedisBackend, SharedState, SharedStateFeature,
  hex_encode,
};

#[cfg(test)]
mod memory;
#[cfg(test)]
pub(super) use memory::MemoryUdpFlowScope;
mod postgres;
pub(super) use postgres::init_postgres_udp_flows;
mod redis;
#[cfg(test)]
mod tests;

const UDP_FLOW_RECORD_VERSION: u8 = 1;
const MAX_UDP_FLOW_SCOPE_CAPACITY: usize = 1_048_576;
const _: () =
  assert!(SHARED_UDP_RENEW_BATCH_SIZE > 0 && SHARED_UDP_RENEW_BATCH_SIZE <= usize::MAX as u64);
const MAX_UDP_FLOW_BATCH: usize = SHARED_UDP_RENEW_BATCH_SIZE as usize;
const MAX_UDP_FLOW_GC_PER_OPERATION: usize = 64;
const MAX_UDP_FLOW_DERIVATION_MATERIAL: usize = 1024 * 1024;
const MAX_UDP_FLOW_TOKEN_BURST: u32 = 1_048_576;
const TOKEN_MICROS: u64 = 1_000_000;
const MAX_EXACT_BACKEND_INTEGER: u64 = (1_u64 << 53) - 1;
const MAX_TOKEN_RATE_MICROS_PER_SECOND: u64 =
  crate::config::MAX_SHARED_UDP_RATE_PER_SECOND * TOKEN_MICROS;

const IDENTITY_SCOPE_DOMAIN: &[u8] = b"oxibelt-udp-flow-scope-v1";
const IDENTITY_FLOW_DOMAIN: &[u8] = b"oxibelt-udp-flow-identity-v1";
const GENERATION_DOMAIN: &[u8] = b"oxibelt-udp-flow-generation-v1";
const OWNER_ID_DOMAIN: &[u8] = b"oxibelt-udp-flow-owner-v1";
const OWNER_GENERATION_DOMAIN: &[u8] = b"oxibelt-udp-flow-owner-generation-v1";
const ROUTE_ID_DOMAIN: &[u8] = b"oxibelt-udp-flow-route-v1";
const TARGET_ID_DOMAIN: &[u8] = b"oxibelt-udp-flow-target-v1";
const KEY_FINGERPRINT_DOMAIN: &[u8] = b"oxibelt-udp-flow-key-fingerprint-v1";
const CONNECTION_MARKER_DOMAIN: &[u8] = b"oxibelt-udp-flow-connection-marker-v1";
const CONNECTION_HOLDER_DOMAIN: &[u8] = b"oxibelt-udp-flow-connection-holder-v1";

#[derive(Clone)]
pub(crate) struct UdpFlowStore {
  namespace: Arc<str>,
  backend: Arc<Backend>,
  identity_secret: Arc<zeroize::Zeroizing<[u8; 32]>>,
  boot_generation: Arc<[u8; 32]>,
  failure_registry: Arc<BackendFailureRegistry>,
}

impl fmt::Debug for UdpFlowStore {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("UdpFlowStore")
      .field("namespace", &self.namespace)
      .field("key_fingerprint", &hex_encode(&self.key_fingerprint()))
      .finish_non_exhaustive()
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct UdpFlowIdentity {
  scope: Digest,
  flow: Digest,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct UdpFlowGeneration(Digest);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct UdpFlowOwner {
  id: Digest,
  generation: Digest,
}

/// Opaque configured route and target identifiers.
///
/// The backend never receives route names, pool/server names, origins, or
/// resolved socket addresses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct UdpFlowTarget {
  route: Digest,
  target: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpFlowRecord {
  identity: UdpFlowIdentity,
  generation: UdpFlowGeneration,
  target: UdpFlowTarget,
  owner: UdpFlowOwner,
  fence: u64,
  server_now_ms: i64,
  owner_expires_at_ms: i64,
  idle_expires_at_ms: i64,
}

impl UdpFlowRecord {
  pub(crate) fn identity(&self) -> &UdpFlowIdentity {
    &self.identity
  }

  pub(crate) fn generation(&self) -> UdpFlowGeneration {
    self.generation
  }

  pub(crate) fn target(&self) -> &UdpFlowTarget {
    &self.target
  }

  pub(crate) fn owner(&self) -> &UdpFlowOwner {
    &self.owner
  }

  pub(crate) fn fence(&self) -> u64 {
    self.fence
  }

  pub(crate) fn server_now_ms(&self) -> i64 {
    self.server_now_ms
  }

  pub(crate) fn owner_expires_at_ms(&self) -> i64 {
    self.owner_expires_at_ms
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpFlowLease(UdpFlowRecord);

impl UdpFlowLease {
  pub(crate) fn record(&self) -> &UdpFlowRecord {
    &self.0
  }

  pub(crate) fn identity(&self) -> &UdpFlowIdentity {
    self.0.identity()
  }

  pub(crate) fn generation(&self) -> UdpFlowGeneration {
    self.0.generation()
  }

  pub(crate) fn target(&self) -> &UdpFlowTarget {
    self.0.target()
  }

  pub(crate) fn owner(&self) -> &UdpFlowOwner {
    self.0.owner()
  }

  pub(crate) fn fence(&self) -> u64 {
    self.0.fence()
  }
}

#[derive(Clone, Debug)]
pub(crate) struct UdpFlowClaimRequest {
  pub(crate) identity: UdpFlowIdentity,
  pub(crate) generation: UdpFlowGeneration,
  pub(crate) owner: UdpFlowOwner,
  pub(crate) proposed_target: UdpFlowTarget,
  pub(crate) max_flows: usize,
  pub(crate) owner_ttl: Duration,
  pub(crate) idle_ttl: Duration,
  /// Initial whole tokens made available to a newly created record.
  pub(crate) initial_tokens: u32,
  /// Optional cluster-wide admission bucket for new mappings in this scope.
  ///
  /// Existing mappings do not consume this bucket when they are owned,
  /// recovered, or reported busy.
  pub(crate) new_flow_rate: Option<UdpFlowRateLimit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UdpFlowRateLimit {
  /// Fixed-point tokens per second, where one token is `1_000_000`.
  pub(crate) refill_micros_per_second: u64,
  pub(crate) burst: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpFlowConnectionMarker {
  marker: Digest,
  holder: Digest,
}

impl UdpFlowConnectionMarker {
  pub(super) fn marker_hex(&self) -> String {
    self.marker.hex()
  }

  pub(super) fn holder_hex(&self) -> String {
    self.holder.hex()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UdpFlowLookupOutcome {
  Missing { server_now_ms: i64 },
  Found(UdpFlowRecord),
  GenerationMismatch { server_now_ms: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UdpFlowClaimOutcome {
  Created(UdpFlowLease),
  Recovered(UdpFlowLease),
  Owned(UdpFlowLease),
  Busy {
    record: UdpFlowRecord,
    retry_after_ms: u64,
  },
  CapacityReached {
    server_now_ms: i64,
  },
  RateLimited {
    retry_after_ms: u64,
    server_now_ms: i64,
  },
  GenerationMismatch {
    server_now_ms: i64,
  },
}

#[derive(Clone, Debug)]
pub(crate) struct UdpFlowTouchRequest {
  pub(crate) lease: UdpFlowLease,
  pub(crate) owner_ttl: Duration,
  pub(crate) idle_ttl: Duration,
  pub(crate) touch_idle: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UdpFlowTouchOutcome {
  Renewed(UdpFlowLease),
  Lost { server_now_ms: i64 },
  GenerationMismatch { server_now_ms: i64 },
}

#[derive(Clone, Debug)]
pub(crate) struct UdpFlowTokenRequest {
  pub(crate) lease: UdpFlowLease,
  pub(crate) requested_tokens: u32,
  /// Fixed-point tokens per second, where one token is `1_000_000`.
  pub(crate) refill_micros_per_second: u64,
  pub(crate) burst: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UdpFlowTokenOutcome {
  Granted {
    tokens: u32,
    server_now_ms: i64,
  },
  RateLimited {
    retry_after_ms: u64,
    server_now_ms: i64,
  },
  Lost {
    server_now_ms: i64,
  },
  GenerationMismatch {
    server_now_ms: i64,
  },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UdpFlowReleaseOutcome {
  Released { server_now_ms: i64 },
  Missing { server_now_ms: i64 },
  Lost { server_now_ms: i64 },
  GenerationMismatch { server_now_ms: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UdpFlowAbortOutcome {
  Aborted { server_now_ms: i64 },
  Missing { server_now_ms: i64 },
  Lost { server_now_ms: i64 },
  GenerationMismatch { server_now_ms: i64 },
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Digest([u8; 32]);

impl Digest {
  fn hex(self) -> String {
    hex_encode(&self.0)
  }

  fn from_hex(value: &str) -> anyhow::Result<Self> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
      bail!("durable UDP flow digest must be exactly 64 hexadecimal characters");
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
      let offset = index * 2;
      *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
        .context("durable UDP flow digest contains invalid hexadecimal")?;
    }
    Ok(Self(digest))
  }
}

#[derive(Clone, Debug)]
struct StoredUdpFlow {
  identity: UdpFlowIdentity,
  generation: UdpFlowGeneration,
  target: UdpFlowTarget,
  owner: UdpFlowOwner,
  fence: u64,
  owner_expires_at_ms: i64,
  idle_expires_at_ms: i64,
  token_balance_micros: u64,
  token_refill_at_ms: i64,
}

impl StoredUdpFlow {
  fn validate(&self, server_now_ms: i64) -> anyhow::Result<()> {
    if self.fence == 0 || self.fence > MAX_EXACT_BACKEND_INTEGER {
      bail!("durable UDP flow fence is outside the supported range");
    }
    if server_now_ms < 0
      || self.owner_expires_at_ms < 0
      || self.idle_expires_at_ms < 0
      || self.token_refill_at_ms < 0
      || self.owner_expires_at_ms > self.idle_expires_at_ms
    {
      bail!("durable UDP flow contains invalid server-time bounds");
    }
    let maximum_deadline = server_now_ms.saturating_add(
      i64::try_from(MAX_SHARED_UDP_IDLE_TIMEOUT_MS)
        .context("shared UDP idle timeout bound does not fit backend milliseconds")?,
    );
    if self.owner_expires_at_ms > maximum_deadline
      || self.idle_expires_at_ms > maximum_deadline
      || self.token_refill_at_ms > server_now_ms
    {
      bail!("durable UDP flow contains an excessive or future timestamp");
    }
    if self.token_balance_micros > u64::from(MAX_UDP_FLOW_TOKEN_BURST).saturating_mul(TOKEN_MICROS)
    {
      bail!("durable UDP flow token balance exceeds the supported maximum");
    }
    Ok(())
  }

  fn record(&self, server_now_ms: i64) -> UdpFlowRecord {
    UdpFlowRecord {
      identity: self.identity.clone(),
      generation: self.generation,
      target: self.target.clone(),
      owner: self.owner.clone(),
      fence: self.fence,
      server_now_ms,
      owner_expires_at_ms: self.owner_expires_at_ms,
      idle_expires_at_ms: self.idle_expires_at_ms,
    }
  }

  fn lease(&self, server_now_ms: i64) -> UdpFlowLease {
    UdpFlowLease(self.record(server_now_ms))
  }
}

impl UdpFlowStore {
  pub(super) fn new(
    namespace: Arc<str>,
    backend: Arc<Backend>,
    identity_secret: [u8; 32],
    boot_generation: Arc<[u8; 32]>,
    failure_registry: Arc<BackendFailureRegistry>,
  ) -> Self {
    Self {
      namespace,
      backend,
      identity_secret: Arc::new(zeroize::Zeroizing::new(identity_secret)),
      boot_generation,
      failure_registry,
    }
  }

  pub(crate) fn key_fingerprint(&self) -> [u8; 32] {
    crate::crypto::hmac_sha256(&**self.identity_secret, KEY_FINGERPRINT_DOMAIN)
  }

  pub(crate) fn derive_identity(
    &self,
    scope_material: &[u8],
    flow_material: &[u8],
  ) -> anyhow::Result<UdpFlowIdentity> {
    validate_derivation_material(scope_material, "UDP flow scope")?;
    validate_derivation_material(flow_material, "UDP flow identity")?;
    let scope = Digest(keyed_digest(
      &**self.identity_secret,
      IDENTITY_SCOPE_DOMAIN,
      &[scope_material],
    ));
    let flow = Digest(keyed_digest(
      &**self.identity_secret,
      IDENTITY_FLOW_DOMAIN,
      &[&scope.0, flow_material],
    ));
    Ok(UdpFlowIdentity { scope, flow })
  }

  pub(crate) fn generation_for(
    &self,
    configuration_material: &[u8],
  ) -> anyhow::Result<UdpFlowGeneration> {
    validate_derivation_material(configuration_material, "UDP flow configuration")?;
    Ok(UdpFlowGeneration(Digest(keyed_digest(
      &**self.identity_secret,
      GENERATION_DOMAIN,
      &[configuration_material],
    ))))
  }

  pub(crate) fn owner_for(&self, instance_material: &[u8]) -> anyhow::Result<UdpFlowOwner> {
    validate_derivation_material(instance_material, "UDP flow owner")?;
    Ok(UdpFlowOwner {
      id: Digest(keyed_digest(
        &**self.identity_secret,
        OWNER_ID_DOMAIN,
        &[instance_material],
      )),
      generation: Digest(keyed_digest(
        &**self.identity_secret,
        OWNER_GENERATION_DOMAIN,
        &[self.boot_generation.as_ref()],
      )),
    })
  }

  pub(crate) fn target_for(
    &self,
    route_material: &[u8],
    target_material: &[u8],
  ) -> anyhow::Result<UdpFlowTarget> {
    validate_derivation_material(route_material, "UDP flow route")?;
    validate_derivation_material(target_material, "UDP flow target")?;
    let route = Digest(keyed_digest(
      &**self.identity_secret,
      ROUTE_ID_DOMAIN,
      &[route_material],
    ));
    Ok(UdpFlowTarget {
      route,
      target: Digest(keyed_digest(
        &**self.identity_secret,
        TARGET_ID_DOMAIN,
        &[&route.0, target_material],
      )),
    })
  }

  pub(crate) fn connection_lease_marker(&self, lease: &UdpFlowLease) -> UdpFlowConnectionMarker {
    let identity = lease.identity();
    let fence = lease.fence().to_be_bytes();
    UdpFlowConnectionMarker {
      marker: Digest(keyed_digest(
        &**self.identity_secret,
        CONNECTION_MARKER_DOMAIN,
        &[&identity.scope.0, &identity.flow.0],
      )),
      holder: Digest(keyed_digest(
        &**self.identity_secret,
        CONNECTION_HOLDER_DOMAIN,
        &[
          &lease.generation().0.0,
          &lease.owner().id.0,
          &lease.owner().generation.0,
          &fence,
        ],
      )),
    }
  }

  pub(crate) async fn lookup(
    &self,
    identity: &UdpFlowIdentity,
    generation: UdpFlowGeneration,
  ) -> anyhow::Result<UdpFlowLookupOutcome> {
    let result = self.backend_lookup(identity, generation).await;
    self.observe_backend_result(&result);
    result
  }

  pub(crate) async fn claim_or_create(
    &self,
    request: UdpFlowClaimRequest,
  ) -> anyhow::Result<UdpFlowClaimOutcome> {
    validate_claim(&request)?;
    let result = self.backend_claim(request).await;
    self.observe_backend_result(&result);
    result
  }

  /// Renews a bounded set of records in one backend batch.
  ///
  /// Redis pipelines one atomic script per record. PostgreSQL uses one
  /// transaction and one set-based statement. Per-record fencing remains
  /// atomic and outcomes retain input order; the complete batch is
  /// intentionally not an all-or-nothing contract across backends.
  pub(crate) async fn renew_and_touch_batch(
    &self,
    requests: &[UdpFlowTouchRequest],
  ) -> anyhow::Result<Vec<UdpFlowTouchOutcome>> {
    if requests.len() > MAX_UDP_FLOW_BATCH {
      bail!("durable UDP flow touch batch exceeds {MAX_UDP_FLOW_BATCH} records");
    }
    let mut identities = HashSet::with_capacity(requests.len());
    for request in requests {
      validate_ttls(request.owner_ttl, request.idle_ttl)?;
      let identity = (
        request.lease.identity().scope,
        request.lease.identity().flow,
      );
      if !identities.insert(identity) {
        bail!("durable UDP flow touch batch contains a duplicate identity");
      }
    }
    if requests.is_empty() {
      return Ok(Vec::new());
    }
    let result = self.backend_touch_batch(requests).await;
    self.observe_backend_result(&result);
    result
  }

  pub(crate) async fn lease_tokens(
    &self,
    request: UdpFlowTokenRequest,
  ) -> anyhow::Result<UdpFlowTokenOutcome> {
    validate_token_request(&request)?;
    let result = self.backend_tokens(&request).await;
    self.observe_backend_result(&result);
    result
  }

  pub(crate) async fn release_if_generation(
    &self,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowReleaseOutcome> {
    let result = self.backend_release(lease).await;
    self.observe_backend_result(&result);
    result
  }

  /// Removes a mapping whose `Created` lease failed before local activation.
  ///
  /// The delete is fenced by generation, owner generation, and fence. A stale
  /// setup task therefore cannot remove a recovered successor.
  pub(crate) async fn abort_created(
    &self,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowAbortOutcome> {
    let result = self.backend_abort_created(lease).await;
    self.observe_backend_result(&result);
    result
  }

  fn observe_backend_result<T>(&self, result: &anyhow::Result<T>) {
    if result.is_ok() {
      self
        .failure_registry
        .record_success(SharedStateFeature::UdpFlows);
    } else {
      self
        .failure_registry
        .record_failure(SharedStateFeature::UdpFlows);
    }
  }

  fn redis_keys(&self, identity: &UdpFlowIdentity) -> RedisUdpFlowKeys {
    let scope = identity.scope.hex();
    let flow = identity.flow.hex();
    let prefix = format!("{}:udp-flow:{{{scope}}}", self.namespace);
    RedisUdpFlowKeys {
      scope: format!("{prefix}:scope"),
      index: format!("{prefix}:index"),
      flow: format!("{prefix}:flow:{flow}"),
      flow_prefix: format!("{prefix}:flow:"),
      member: flow,
    }
  }

  async fn backend_lookup(
    &self,
    identity: &UdpFlowIdentity,
    generation: UdpFlowGeneration,
  ) -> anyhow::Result<UdpFlowLookupOutcome> {
    match self.backend.as_ref() {
      Backend::Redis(redis) => {
        let keys = self.redis_keys(identity);
        redis
          .runtime
          .execute("udp_flow_lookup", || {
            redis.udp_flow_lookup(&keys, identity, generation)
          })
          .await
      }
      Backend::Postgres(postgres) => {
        postgres
          .runtime
          .execute("udp_flow_lookup", || {
            postgres.udp_flow_lookup(&self.namespace, identity, generation)
          })
          .await
      }
      #[cfg(test)]
      Backend::Memory(memory) => memory.udp_flow_lookup(&self.namespace, identity, generation),
    }
  }

  async fn backend_claim(
    &self,
    request: UdpFlowClaimRequest,
  ) -> anyhow::Result<UdpFlowClaimOutcome> {
    match self.backend.as_ref() {
      Backend::Redis(redis) => {
        let keys = self.redis_keys(&request.identity);
        redis
          .runtime
          .execute("udp_flow_claim", || redis.udp_flow_claim(&keys, &request))
          .await
      }
      Backend::Postgres(postgres) => {
        postgres
          .runtime
          .execute("udp_flow_claim", || {
            postgres.udp_flow_claim(&self.namespace, &request)
          })
          .await
      }
      #[cfg(test)]
      Backend::Memory(memory) => memory.udp_flow_claim(&self.namespace, &request),
    }
  }

  async fn backend_touch_batch(
    &self,
    requests: &[UdpFlowTouchRequest],
  ) -> anyhow::Result<Vec<UdpFlowTouchOutcome>> {
    match self.backend.as_ref() {
      Backend::Redis(redis) => {
        let keys = requests
          .iter()
          .map(|request| self.redis_keys(request.lease.identity()))
          .collect::<Vec<_>>();
        redis
          .runtime
          .execute("udp_flow_touch_batch", || {
            redis.udp_flow_touch_batch(&keys, requests)
          })
          .await
      }
      Backend::Postgres(postgres) => {
        postgres
          .runtime
          .execute("udp_flow_touch_batch", || {
            postgres.udp_flow_touch_batch(&self.namespace, requests)
          })
          .await
      }
      #[cfg(test)]
      Backend::Memory(memory) => memory.udp_flow_touch_batch(&self.namespace, requests),
    }
  }

  async fn backend_tokens(
    &self,
    request: &UdpFlowTokenRequest,
  ) -> anyhow::Result<UdpFlowTokenOutcome> {
    match self.backend.as_ref() {
      Backend::Redis(redis) => {
        let keys = self.redis_keys(request.lease.identity());
        redis
          .runtime
          .execute("udp_flow_tokens", || redis.udp_flow_tokens(&keys, request))
          .await
      }
      Backend::Postgres(postgres) => {
        postgres
          .runtime
          .execute("udp_flow_tokens", || {
            postgres.udp_flow_tokens(&self.namespace, request)
          })
          .await
      }
      #[cfg(test)]
      Backend::Memory(memory) => memory.udp_flow_tokens(&self.namespace, request),
    }
  }

  async fn backend_release(&self, lease: &UdpFlowLease) -> anyhow::Result<UdpFlowReleaseOutcome> {
    match self.backend.as_ref() {
      Backend::Redis(redis) => {
        let keys = self.redis_keys(lease.identity());
        redis
          .runtime
          .execute("udp_flow_release", || redis.udp_flow_release(&keys, lease))
          .await
      }
      Backend::Postgres(postgres) => {
        postgres
          .runtime
          .execute("udp_flow_release", || {
            postgres.udp_flow_release(&self.namespace, lease)
          })
          .await
      }
      #[cfg(test)]
      Backend::Memory(memory) => memory.udp_flow_release(&self.namespace, lease),
    }
  }

  async fn backend_abort_created(
    &self,
    lease: &UdpFlowLease,
  ) -> anyhow::Result<UdpFlowAbortOutcome> {
    match self.backend.as_ref() {
      Backend::Redis(redis) => {
        let keys = self.redis_keys(lease.identity());
        redis
          .runtime
          .execute("udp_flow_abort_created", || {
            redis.udp_flow_abort_created(&keys, lease)
          })
          .await
      }
      Backend::Postgres(postgres) => {
        postgres
          .runtime
          .execute("udp_flow_abort_created", || {
            postgres.udp_flow_abort_created(&self.namespace, lease)
          })
          .await
      }
      #[cfg(test)]
      Backend::Memory(memory) => memory.udp_flow_abort_created(&self.namespace, lease),
    }
  }
}

impl SharedState {
  pub(crate) fn udp_flow_store(&self) -> Option<UdpFlowStore> {
    self.udp_flows.clone()
  }
}

#[derive(Debug)]
struct RedisUdpFlowKeys {
  scope: String,
  index: String,
  flow: String,
  flow_prefix: String,
  member: String,
}

fn validate_derivation_material(material: &[u8], label: &str) -> anyhow::Result<()> {
  if material.is_empty() || material.len() > MAX_UDP_FLOW_DERIVATION_MATERIAL {
    bail!("{label} material must contain 1-{MAX_UDP_FLOW_DERIVATION_MATERIAL} bytes");
  }
  Ok(())
}

fn keyed_digest(secret: &[u8; 32], domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
  let capacity = domain.len()
    + 1
    + parts
      .iter()
      .map(|part| 8usize.saturating_add(part.len()))
      .sum::<usize>();
  let mut material = Vec::with_capacity(capacity);
  material.extend_from_slice(domain);
  material.push(0);
  for part in parts {
    material.extend_from_slice(&(part.len() as u64).to_be_bytes());
    material.extend_from_slice(part);
  }
  crate::crypto::hmac_sha256(secret, &material)
}

fn validate_claim(request: &UdpFlowClaimRequest) -> anyhow::Result<()> {
  if request.max_flows == 0 || request.max_flows > MAX_UDP_FLOW_SCOPE_CAPACITY {
    bail!("durable UDP flow max_flows must be between 1 and {MAX_UDP_FLOW_SCOPE_CAPACITY}");
  }
  validate_ttls(request.owner_ttl, request.idle_ttl)?;
  if request.initial_tokens > MAX_UDP_FLOW_TOKEN_BURST {
    bail!("durable UDP flow initial token count exceeds {MAX_UDP_FLOW_TOKEN_BURST}");
  }
  if let Some(rate) = request.new_flow_rate {
    validate_rate_limit(rate, "durable UDP new-flow")?;
  }
  Ok(())
}

fn validate_ttls(owner_ttl: Duration, idle_ttl: Duration) -> anyhow::Result<()> {
  if owner_ttl.is_zero() || idle_ttl.is_zero() {
    bail!("durable UDP flow owner and idle TTLs must be greater than zero");
  }
  if owner_ttl > idle_ttl {
    bail!("durable UDP flow owner TTL must not exceed idle TTL");
  }
  if idle_ttl.as_millis() > u128::from(MAX_SHARED_UDP_IDLE_TIMEOUT_MS) {
    bail!(
      "durable UDP flow idle TTL must not exceed {MAX_SHARED_UDP_IDLE_TIMEOUT_MS} milliseconds"
    );
  }
  Ok(())
}

fn validate_token_request(request: &UdpFlowTokenRequest) -> anyhow::Result<()> {
  if request.requested_tokens == 0
    || request.requested_tokens > request.burst
    || request.burst == 0
    || request.burst > MAX_UDP_FLOW_TOKEN_BURST
  {
    bail!("durable UDP token request and burst are outside supported bounds");
  }
  validate_rate_limit(
    UdpFlowRateLimit {
      refill_micros_per_second: request.refill_micros_per_second,
      burst: request.burst,
    },
    "durable UDP token",
  )
}

fn validate_rate_limit(rate: UdpFlowRateLimit, label: &str) -> anyhow::Result<()> {
  if rate.burst == 0 || rate.burst > MAX_UDP_FLOW_TOKEN_BURST {
    bail!("{label} burst is outside supported bounds");
  }
  if rate.refill_micros_per_second == 0
    || rate.refill_micros_per_second > MAX_TOKEN_RATE_MICROS_PER_SECOND
  {
    bail!("{label} refill rate is outside supported bounds");
  }
  Ok(())
}

fn duration_ms(duration: Duration) -> anyhow::Result<i64> {
  i64::try_from(duration.as_millis())
    .map_err(|_| anyhow!("duration does not fit backend milliseconds"))
}

fn initial_token_micros(tokens: u32) -> u64 {
  u64::from(tokens).saturating_mul(TOKEN_MICROS)
}

fn take_available_tokens(balance_micros: &mut u64, requested_tokens: u32) -> u32 {
  let available_tokens = *balance_micros / TOKEN_MICROS;
  let granted_tokens = u64::from(requested_tokens).min(available_tokens);
  *balance_micros = balance_micros.saturating_sub(granted_tokens.saturating_mul(TOKEN_MICROS));
  u32::try_from(granted_tokens).expect("granted durable UDP tokens are bounded by the u32 request")
}

fn retry_after_ms(deficit_micros: u64, refill_micros_per_second: u64) -> u64 {
  deficit_micros
    .saturating_mul(1_000)
    .saturating_add(refill_micros_per_second.saturating_sub(1))
    / refill_micros_per_second
}

fn refill_balance(
  balance_micros: u64,
  refill_at_ms: i64,
  server_now_ms: i64,
  rate: UdpFlowRateLimit,
) -> u64 {
  let burst_micros = u64::from(rate.burst).saturating_mul(TOKEN_MICROS);
  let elapsed_ms = u64::try_from(server_now_ms.saturating_sub(refill_at_ms)).unwrap_or(0);
  let refill = elapsed_ms
    .saturating_mul(rate.refill_micros_per_second)
    .saturating_div(1_000)
    .min(burst_micros);
  balance_micros.saturating_add(refill).min(burst_micros)
}
