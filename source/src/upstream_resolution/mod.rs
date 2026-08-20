//! Bounded, TTL-aware upstream endpoint resolution.
//!
//! Resolver instances are scoped to one logical discovery origin.  Cache and
//! refresh state are shared by cheap clones, while DNS I/O always happens
//! outside the short state mutex.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::config::{
  HappyEyeballsMode, HappyEyeballsPolicyMode, UpstreamConfig, UpstreamResolutionConfig,
};

mod dns;
mod happy_eyeballs;
mod pref64;
mod rfc6724;
mod tcp;

pub(crate) use dns::{
  DnsAnswer, DnsLookup, DnsQueryType, DnsResolverBackend, HttpsAlpn, HttpsRecord, HttpsTarget,
  lookup_dns, lookup_dns_absolute_until,
};
pub(crate) use happy_eyeballs::{
  CandidateAttemptError, CandidateRaceError, CandidateSchedulerConfig, CandidateSchedulerMode,
  HappyEyeballsCandidate, race_happy_eyeballs_candidates,
};
pub(crate) use pref64::synthesize_pref64_ipv4_candidates;
pub(crate) use tcp::{
  ConnectionAdmissionContext, ConnectionAdmitted, HttpTransportProtocol,
  connect_http_ready_happy_eyeballs_admitted, connect_tcp_happy_eyeballs_admitted,
  resolve_http_candidate_updates, resolve_http_candidate_updates_with_resolver,
};

const DEFAULT_MAX_ENDPOINT_COUNT: usize = 16;
const HARD_MAX_ENDPOINT_COUNT: usize = 64;
const DEFAULT_MIN_TTL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_TTL: Duration = Duration::from_secs(30);
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(1);
const DEFAULT_RESOLUTION_DELAY: Duration = Duration::from_millis(50);

pub(crate) fn http_upstream_policies(
  config: &UpstreamResolutionConfig,
  upstream: &UpstreamConfig,
) -> anyhow::Result<(ResolutionPolicy, CandidateSchedulerConfig)> {
  let resolution = ResolutionPolicy::new_with_resolution_delay(
    config.max_endpoint_count,
    Duration::from_millis(config.min_ttl_ms),
    Duration::from_millis(config.max_ttl_ms),
    Duration::from_millis(config.negative_ttl_ms),
    Duration::from_millis(config.happy_eyeballs.resolution_delay_ms),
  )?
  .with_pref64_enabled(matches!(
    config.happy_eyeballs.pref64,
    crate::config::UpstreamResolutionDnsMode::Auto
  ));
  let mode = match upstream.happy_eyeballs_mode {
    HappyEyeballsMode::V3 => CandidateSchedulerMode::Enabled,
    HappyEyeballsMode::Legacy => CandidateSchedulerMode::LegacySequential,
    HappyEyeballsMode::Inherit => match config.happy_eyeballs.mode {
      HappyEyeballsPolicyMode::V3 => CandidateSchedulerMode::Enabled,
      HappyEyeballsPolicyMode::Legacy => CandidateSchedulerMode::LegacySequential,
    },
  };
  let happy = &config.happy_eyeballs;
  let scheduler = CandidateSchedulerConfig::new(
    mode,
    Duration::from_millis(happy.connection_attempt_delay_ms),
    Duration::from_millis(happy.minimum_connection_attempt_delay_ms),
    happy.max_connect_attempts.min(config.max_endpoint_count),
    happy.max_concurrent_attempts,
    happy.preferred_address_family_count,
  )?;
  Ok((resolution, scheduler))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionErrorClass {
  Deadline,
  NxDomain,
  NoData,
  ServerFailure,
  Refused,
  Truncated,
  Malformed,
  Io,
  NoNameservers,
  Cancelled,
  InvalidInput,
  Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolutionError {
  class: ResolutionErrorClass,
  detail: Arc<str>,
  dns_metadata_owner: Option<Arc<str>>,
}

impl ResolutionError {
  pub(crate) fn new(class: ResolutionErrorClass, detail: impl Into<Arc<str>>) -> Self {
    Self {
      class,
      detail: detail.into(),
      dns_metadata_owner: None,
    }
  }

  pub(crate) fn class(&self) -> ResolutionErrorClass {
    self.class
  }

  pub(crate) fn dns_metadata_owner(&self) -> Option<&str> {
    self.dns_metadata_owner.as_deref()
  }

  fn with_dns_metadata_owner(mut self, owner: Arc<str>) -> Self {
    self.dns_metadata_owner = Some(owner);
    self
  }

  fn negative_cacheable(&self) -> bool {
    matches!(
      self.class,
      ResolutionErrorClass::NxDomain | ResolutionErrorClass::NoData
    )
  }

  fn deadline() -> Self {
    Self::new(
      ResolutionErrorClass::Deadline,
      "upstream endpoint resolution deadline elapsed",
    )
  }

  fn cancelled() -> Self {
    Self::new(
      ResolutionErrorClass::Cancelled,
      "upstream endpoint resolution refresh was cancelled",
    )
  }
}

impl fmt::Display for ResolutionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.detail)
  }
}

impl Error for ResolutionError {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ResolutionOrigin {
  host: Arc<str>,
  port: u16,
  discovery_id: Arc<str>,
}

impl ResolutionOrigin {
  pub(crate) fn new(
    host: &str,
    port: u16,
    discovery_id: impl Into<Arc<str>>,
  ) -> Result<Self, ResolutionError> {
    if port == 0 {
      return Err(ResolutionError::new(
        ResolutionErrorClass::InvalidInput,
        "upstream resolution port must be greater than zero",
      ));
    }
    let host = normalize_origin_host(host)?;
    let discovery_id = discovery_id.into();
    if discovery_id.trim().is_empty() {
      return Err(ResolutionError::new(
        ResolutionErrorClass::InvalidInput,
        "upstream resolution discovery identity must not be empty",
      ));
    }
    Ok(Self {
      host: host.into(),
      port,
      discovery_id,
    })
  }

  pub(crate) fn host(&self) -> &str {
    &self.host
  }
}

fn normalize_origin_host(host: &str) -> Result<String, ResolutionError> {
  let trimmed = host.trim();
  if trimmed.is_empty() || trimmed != host {
    return Err(ResolutionError::new(
      ResolutionErrorClass::InvalidInput,
      "upstream resolution host must be a non-empty exact value",
    ));
  }
  let unbracketed = trimmed
    .strip_prefix('[')
    .and_then(|value| value.strip_suffix(']'))
    .unwrap_or(trimmed);
  if unbracketed.parse::<IpAddr>().is_ok() {
    return Ok(unbracketed.to_ascii_lowercase());
  }
  let absolute = unbracketed.ends_with('.');
  let canonical = dns::canonical_dns_name(unbracketed).map_err(|detail| {
    ResolutionError::new(ResolutionErrorClass::InvalidInput, Arc::<str>::from(detail))
  })?;
  Ok(if absolute {
    format!("{canonical}.")
  } else {
    canonical
  })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointAddressFamily {
  Ipv4,
  Ipv6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedEndpoint {
  socket_addr: SocketAddr,
  family: EndpointAddressFamily,
}

impl ResolvedEndpoint {
  fn ip(socket_addr: SocketAddr) -> Self {
    let family = if socket_addr.is_ipv4() {
      EndpointAddressFamily::Ipv4
    } else {
      EndpointAddressFamily::Ipv6
    };
    Self {
      socket_addr,
      family,
    }
  }

  pub(crate) fn socket_addr(&self) -> SocketAddr {
    self.socket_addr
  }

  pub(crate) fn family(&self) -> EndpointAddressFamily {
    self.family
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionSource {
  Literal,
  Hosts,
  Dns,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedEndpointSet {
  endpoints: Arc<[ResolvedEndpoint]>,
  valid_until: Instant,
  source: ResolutionSource,
  dns_metadata_owner: Option<Arc<str>>,
}

impl ResolvedEndpointSet {
  pub(crate) fn endpoints(&self) -> &[ResolvedEndpoint] {
    &self.endpoints
  }

  pub(crate) fn valid_until(&self) -> Instant {
    self.valid_until
  }

  pub(crate) fn source(&self) -> ResolutionSource {
    self.source
  }

  pub(crate) fn dns_metadata_owner(&self) -> Option<&str> {
    self.dns_metadata_owner.as_deref()
  }
}

/// Resolves one configured socket origin through OxiBelt's bounded hosts/DNS
/// backend rather than libc NSS.  This keeps post-confinement filesystem
/// dependencies limited to the manifest-declared resolver inputs.
pub(crate) async fn resolve_socket_addrs(
  host: &str,
  port: u16,
  deadline: Instant,
) -> Result<Vec<SocketAddr>, ResolutionError> {
  let origin = ResolutionOrigin::new(host, port, "socket-origin")?;
  let resolver = EndpointResolver::system(origin, ResolutionPolicy::default());
  let resolved = resolver.resolve(deadline).await?;
  Ok(
    resolved
      .endpoints()
      .iter()
      .map(ResolvedEndpoint::socket_addr)
      .collect(),
  )
}

pub(crate) fn resolve_socket_addrs_blocking(
  host: &str,
  port: u16,
  timeout: Duration,
) -> anyhow::Result<Vec<SocketAddr>> {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_io()
    .enable_time()
    .build()
    .map_err(|error| anyhow::anyhow!("failed to build bounded DNS runtime: {error}"))?;
  let deadline = Instant::now()
    .checked_add(timeout)
    .ok_or_else(|| anyhow::anyhow!("DNS deadline overflowed"))?;
  runtime
    .block_on(resolve_socket_addrs(host, port, deadline))
    .map_err(anyhow::Error::new)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolutionPolicy {
  max_endpoint_count: usize,
  min_ttl: Duration,
  max_ttl: Duration,
  negative_ttl: Duration,
  resolution_delay: Duration,
  pref64_enabled: bool,
}

impl Default for ResolutionPolicy {
  fn default() -> Self {
    Self {
      max_endpoint_count: DEFAULT_MAX_ENDPOINT_COUNT,
      min_ttl: DEFAULT_MIN_TTL,
      max_ttl: DEFAULT_MAX_TTL,
      negative_ttl: DEFAULT_NEGATIVE_TTL,
      resolution_delay: DEFAULT_RESOLUTION_DELAY,
      pref64_enabled: false,
    }
  }
}

impl ResolutionPolicy {
  pub(crate) fn max_endpoint_count(self) -> usize {
    self.max_endpoint_count
  }

  pub(crate) fn resolution_delay(self) -> Duration {
    self.resolution_delay
  }

  pub(crate) fn pref64_enabled(self) -> bool {
    self.pref64_enabled
  }

  fn with_pref64_enabled(mut self, enabled: bool) -> Self {
    self.pref64_enabled = enabled;
    self
  }

  #[cfg(test)]
  pub(crate) fn new(
    max_endpoint_count: usize,
    min_ttl: Duration,
    max_ttl: Duration,
    negative_ttl: Duration,
  ) -> Result<Self, ResolutionError> {
    Self::new_with_resolution_delay(
      max_endpoint_count,
      min_ttl,
      max_ttl,
      negative_ttl,
      DEFAULT_RESOLUTION_DELAY,
    )
  }

  pub(crate) fn new_with_resolution_delay(
    max_endpoint_count: usize,
    min_ttl: Duration,
    max_ttl: Duration,
    negative_ttl: Duration,
    resolution_delay: Duration,
  ) -> Result<Self, ResolutionError> {
    if !(1..=HARD_MAX_ENDPOINT_COUNT).contains(&max_endpoint_count) {
      return Err(ResolutionError::new(
        ResolutionErrorClass::InvalidInput,
        format!(
          "upstream resolver max endpoint count must be between 1 and {HARD_MAX_ENDPOINT_COUNT}"
        ),
      ));
    }
    if min_ttl.is_zero() || max_ttl < min_ttl {
      return Err(ResolutionError::new(
        ResolutionErrorClass::InvalidInput,
        "upstream resolver TTL bounds require 0 < min_ttl <= max_ttl",
      ));
    }
    if negative_ttl.is_zero() || negative_ttl > max_ttl {
      return Err(ResolutionError::new(
        ResolutionErrorClass::InvalidInput,
        "upstream resolver negative TTL must be nonzero and no greater than max_ttl",
      ));
    }
    if resolution_delay.is_zero() {
      return Err(ResolutionError::new(
        ResolutionErrorClass::InvalidInput,
        "upstream resolver resolution delay must be nonzero",
      ));
    }
    Ok(Self {
      max_endpoint_count,
      min_ttl,
      max_ttl,
      negative_ttl,
      resolution_delay,
      pref64_enabled: false,
    })
  }
}

pub(crate) trait ResolverBackend: Send + Sync + 'static {
  fn lookup(
    &self,
    name: &str,
    query_type: DnsQueryType,
    deadline: Instant,
  ) -> impl Future<Output = Result<DnsLookup, ResolutionError>> + Send;
}

pub(crate) type SharedEndpointResolver = EndpointResolver<DnsResolverBackend>;

pub(crate) struct EndpointResolver<B = DnsResolverBackend> {
  inner: Arc<ResolverInner<B>>,
}

impl<B> Clone for EndpointResolver<B> {
  fn clone(&self) -> Self {
    Self {
      inner: Arc::clone(&self.inner),
    }
  }
}

struct ResolverInner<B> {
  origin: ResolutionOrigin,
  backend: B,
  policy: ResolutionPolicy,
  state: Mutex<ResolverState>,
}

#[derive(Default)]
struct ResolverState {
  generation: u64,
  cache: Option<CachedResolution>,
  refresh: Option<InFlightRefresh>,
}

enum CachedResolution {
  Positive(Arc<ResolvedEndpointSet>),
  Negative {
    error: ResolutionError,
    valid_until: Instant,
  },
}

#[derive(Clone)]
struct InFlightRefresh {
  generation: u64,
  signal: Arc<RefreshSignal>,
}

type SharedResolutionResult = Result<Arc<ResolvedEndpointSet>, ResolutionError>;

struct RefreshSignal {
  sender: watch::Sender<Option<SharedResolutionResult>>,
}

impl RefreshSignal {
  fn new() -> Self {
    let (sender, _) = watch::channel(None);
    Self { sender }
  }

  fn subscribe(&self) -> watch::Receiver<Option<SharedResolutionResult>> {
    self.sender.subscribe()
  }

  fn complete(&self, result: SharedResolutionResult) {
    self.sender.send_replace(Some(result));
  }
}

impl EndpointResolver<DnsResolverBackend> {
  pub(crate) fn system(origin: ResolutionOrigin, policy: ResolutionPolicy) -> Self {
    Self::new_with_backend(origin, DnsResolverBackend, policy)
  }
}

impl<B: ResolverBackend> EndpointResolver<B> {
  pub(crate) fn new_with_backend(
    origin: ResolutionOrigin,
    backend: B,
    policy: ResolutionPolicy,
  ) -> Self {
    Self {
      inner: Arc::new(ResolverInner {
        origin,
        backend,
        policy,
        state: Mutex::new(ResolverState::default()),
      }),
    }
  }

  pub(crate) async fn resolve(&self, deadline: Instant) -> SharedResolutionResult {
    loop {
      if deadline <= Instant::now() {
        return Err(ResolutionError::deadline());
      }
      match self.begin_resolution(Instant::now()) {
        ResolutionStart::Cached(result) => return result,
        ResolutionStart::Wait(mut receiver) => {
          let result = wait_for_refresh(&mut receiver, deadline).await;
          if result
            .as_ref()
            .is_err_and(|error| error.class() == ResolutionErrorClass::Cancelled)
          {
            continue;
          }
          return result;
        }
        ResolutionStart::Lead { generation, signal } => {
          let mut guard =
            RefreshGuard::new(Arc::clone(&self.inner), generation, Arc::clone(&signal));
          let result =
            match tokio::time::timeout_at(deadline, self.resolve_fresh(generation, deadline)).await
            {
              Ok(result) => result,
              Err(_) => Err(ResolutionError::deadline()),
            };
          self.finish_resolution(generation, &signal, &result);
          guard.complete(result.clone());
          return result;
        }
      }
    }
  }

  pub(crate) async fn lookup_https_metadata(
    &self,
    owner: &str,
    deadline: Instant,
  ) -> Result<DnsLookup, ResolutionError> {
    if deadline <= Instant::now() {
      return Err(ResolutionError::deadline());
    }
    self
      .inner
      .backend
      .lookup(owner, DnsQueryType::Https, deadline)
      .await
  }

  fn begin_resolution(&self, now: Instant) -> ResolutionStart {
    let mut state = lock_unpoisoned(&self.inner.state);
    if let Some(cache) = &state.cache {
      match cache {
        CachedResolution::Positive(endpoint_set) if endpoint_set.valid_until > now => {
          return ResolutionStart::Cached(Ok(Arc::clone(endpoint_set)));
        }
        CachedResolution::Negative { error, valid_until } if *valid_until > now => {
          return ResolutionStart::Cached(Err(error.clone()));
        }
        _ => state.cache = None,
      }
    }
    if let Some(refresh) = &state.refresh {
      return ResolutionStart::Wait(refresh.signal.subscribe());
    }
    let Some(next_generation) = state.generation.checked_add(1) else {
      return ResolutionStart::Cached(Err(ResolutionError::new(
        ResolutionErrorClass::Internal,
        "upstream resolver exhausted its generation space",
      )));
    };
    state.generation = next_generation;
    let generation = state.generation;
    let signal = Arc::new(RefreshSignal::new());
    state.refresh = Some(InFlightRefresh {
      generation,
      signal: Arc::clone(&signal),
    });
    ResolutionStart::Lead { generation, signal }
  }

  async fn resolve_fresh(&self, generation: u64, deadline: Instant) -> SharedResolutionResult {
    if let Ok(ip) = self.inner.origin.host.parse::<IpAddr>() {
      return self.endpoint_set(
        vec![ResolvedEndpoint::ip(SocketAddr::new(
          ip,
          self.inner.origin.port,
        ))],
        self.inner.policy.max_ttl,
        ResolutionSource::Literal,
        None,
        generation,
      );
    }

    let a = self
      .inner
      .backend
      .lookup(self.inner.origin.host(), DnsQueryType::A, deadline);
    let aaaa = self
      .inner
      .backend
      .lookup(self.inner.origin.host(), DnsQueryType::Aaaa, deadline);
    tokio::pin!(a);
    tokio::pin!(aaaa);
    let (a, aaaa) = tokio::select! {
      a_result = &mut a => {
        let a_has_addresses = dns_result_has_addresses(&a_result);
        let aaaa_result = if a_has_addresses {
          match tokio::time::timeout(self.inner.policy.resolution_delay, &mut aaaa).await {
            Ok(result) => result,
            Err(_) => Err(ResolutionError::new(
              ResolutionErrorClass::Deadline,
              "upstream AAAA lookup did not complete within the resolution delay",
            )),
          }
        } else {
          aaaa.await
        };
        (a_result, aaaa_result)
      }
      aaaa_result = &mut aaaa => {
        let aaaa_has_addresses = dns_result_has_addresses(&aaaa_result);
        let a_result = if aaaa_has_addresses {
          match tokio::time::timeout(self.inner.policy.resolution_delay, &mut a).await {
            Ok(result) => result,
            Err(_) => Err(ResolutionError::new(
              ResolutionErrorClass::Deadline,
              "upstream A lookup did not complete within the resolution delay",
            )),
          }
        } else {
          a.await
        };
        (a_result, aaaa_result)
      }
    };
    self.combine_dns_results(a, aaaa, generation).await
  }

  async fn combine_dns_results(
    &self,
    a: Result<DnsLookup, ResolutionError>,
    aaaa: Result<DnsLookup, ResolutionError>,
    generation: u64,
  ) -> SharedResolutionResult {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut ttl_ms = None;
    let mut source = None;
    let mut dns_metadata_complete = true;
    let mut successful_lookups = 0usize;
    let mut positive_owner: Option<Arc<str>> = None;
    let mut positive_owner_conflict = false;
    let mut empty_owner: Option<Arc<str>> = None;
    let mut empty_owner_conflict = false;
    let mut errors = Vec::new();
    for result in [a, aaaa] {
      match result {
        Ok(lookup) => {
          successful_lookups = successful_lookups.saturating_add(1);
          dns_metadata_complete &= lookup.source == ResolutionSource::Dns;
          let query_owner = lookup.query_name().map(Arc::<str>::from);
          dns_metadata_complete &= query_owner.is_some();
          source = Some(match (source, lookup.source) {
            (Some(ResolutionSource::Hosts), _) | (_, ResolutionSource::Hosts) => {
              ResolutionSource::Hosts
            }
            (_, value) => value,
          });
          let mut accepted = false;
          for answer in lookup.answers {
            if let DnsAnswer::Ip(ip) = answer {
              accepted = true;
              let endpoint = ResolvedEndpoint::ip(SocketAddr::new(ip, self.inner.origin.port));
              match endpoint.family {
                EndpointAddressFamily::Ipv4 => {
                  push_bounded_unique(&mut ipv4, endpoint, self.inner.policy.max_endpoint_count)
                }
                EndpointAddressFamily::Ipv6 => {
                  push_bounded_unique(&mut ipv6, endpoint, self.inner.policy.max_endpoint_count)
                }
              }
            }
          }
          if accepted {
            merge_dns_metadata_owner(
              &mut positive_owner,
              &mut positive_owner_conflict,
              query_owner,
            );
            ttl_ms = Some(ttl_ms.map_or(lookup.ttl_ms, |ttl: u64| ttl.min(lookup.ttl_ms)));
          } else {
            merge_dns_metadata_owner(&mut empty_owner, &mut empty_owner_conflict, query_owner);
            errors.push(ResolutionError::new(
              ResolutionErrorClass::NoData,
              "upstream DNS response contained no eligible address records",
            ));
          }
        }
        Err(error) => {
          dns_metadata_complete = false;
          errors.push(error);
        }
      }
    }
    dns_metadata_complete &= successful_lookups == 2;
    let dns_metadata_owner = if !dns_metadata_complete || positive_owner_conflict {
      None
    } else if let Some(owner) = positive_owner {
      Some(owner)
    } else if !empty_owner_conflict {
      empty_owner
    } else {
      None
    };

    if ipv4.is_empty() && ipv6.is_empty() {
      let error = select_combined_error(errors);
      return Err(match (dns_metadata_owner, error.class()) {
        (Some(owner), ResolutionErrorClass::NoData) => error.with_dns_metadata_owner(owner),
        _ => error,
      });
    }
    sort_and_deduplicate(&mut ipv4);
    sort_and_deduplicate(&mut ipv6);
    let mut ordered = ipv6;
    ordered.extend(ipv4);
    rfc6724::sort_destinations(&mut ordered).await;
    let first_family = ordered
      .first()
      .map(ResolvedEndpoint::family)
      .unwrap_or(EndpointAddressFamily::Ipv6);
    let (first, second): (Vec<_>, Vec<_>) = ordered
      .into_iter()
      .partition(|endpoint| endpoint.family() == first_family);
    let endpoints = interleave_bounded(first, second, self.inner.policy.max_endpoint_count);
    let observed_ttl = Duration::from_millis(ttl_ms.unwrap_or_default());
    self.endpoint_set(
      endpoints,
      observed_ttl.clamp(self.inner.policy.min_ttl, self.inner.policy.max_ttl),
      source.unwrap_or(ResolutionSource::Dns),
      dns_metadata_owner,
      generation,
    )
  }

  fn endpoint_set(
    &self,
    endpoints: Vec<ResolvedEndpoint>,
    ttl: Duration,
    source: ResolutionSource,
    dns_metadata_owner: Option<Arc<str>>,
    _generation: u64,
  ) -> SharedResolutionResult {
    let valid_until = Instant::now().checked_add(ttl).ok_or_else(|| {
      ResolutionError::new(
        ResolutionErrorClass::InvalidInput,
        "upstream endpoint TTL exceeded the supported clock range",
      )
    })?;
    Ok(Arc::new(ResolvedEndpointSet {
      endpoints: endpoints.into(),
      valid_until,
      source,
      dns_metadata_owner,
    }))
  }

  fn finish_resolution(
    &self,
    generation: u64,
    signal: &Arc<RefreshSignal>,
    result: &SharedResolutionResult,
  ) {
    let mut state = lock_unpoisoned(&self.inner.state);
    if !state.refresh.as_ref().is_some_and(|refresh| {
      refresh.generation == generation && Arc::ptr_eq(&refresh.signal, signal)
    }) {
      return;
    }
    state.cache = match result {
      Ok(endpoint_set) => Some(CachedResolution::Positive(Arc::clone(endpoint_set))),
      Err(error) if error.negative_cacheable() => Instant::now()
        .checked_add(self.inner.policy.negative_ttl)
        .map(|valid_until| CachedResolution::Negative {
          error: error.clone(),
          valid_until,
        }),
      Err(_) => None,
    };
    state.refresh = None;
  }
}

fn push_bounded_unique(
  endpoints: &mut Vec<ResolvedEndpoint>,
  endpoint: ResolvedEndpoint,
  limit: usize,
) {
  if endpoints.len() < limit && !endpoints.contains(&endpoint) {
    endpoints.push(endpoint);
  }
}

fn merge_dns_metadata_owner(
  current: &mut Option<Arc<str>>,
  conflict: &mut bool,
  candidate: Option<Arc<str>>,
) {
  let Some(candidate) = candidate else {
    return;
  };
  match current {
    Some(existing) if existing.as_ref() != candidate.as_ref() => *conflict = true,
    Some(_) => {}
    None => *current = Some(candidate),
  }
}

fn dns_result_has_addresses(result: &Result<DnsLookup, ResolutionError>) -> bool {
  result.as_ref().is_ok_and(|lookup| {
    lookup
      .answers
      .iter()
      .any(|answer| matches!(answer, DnsAnswer::Ip(_)))
  })
}

enum ResolutionStart {
  Cached(SharedResolutionResult),
  Wait(watch::Receiver<Option<SharedResolutionResult>>),
  Lead {
    generation: u64,
    signal: Arc<RefreshSignal>,
  },
}

struct RefreshGuard<B> {
  inner: Arc<ResolverInner<B>>,
  generation: u64,
  signal: Arc<RefreshSignal>,
  completed: bool,
}

impl<B> RefreshGuard<B> {
  fn new(inner: Arc<ResolverInner<B>>, generation: u64, signal: Arc<RefreshSignal>) -> Self {
    Self {
      inner,
      generation,
      signal,
      completed: false,
    }
  }

  fn complete(&mut self, result: SharedResolutionResult) {
    self.signal.complete(result);
    self.completed = true;
  }
}

impl<B> Drop for RefreshGuard<B> {
  fn drop(&mut self) {
    if self.completed {
      return;
    }
    let mut state = lock_unpoisoned(&self.inner.state);
    if state.refresh.as_ref().is_some_and(|refresh| {
      refresh.generation == self.generation && Arc::ptr_eq(&refresh.signal, &self.signal)
    }) {
      state.refresh = None;
    }
    drop(state);
    self.signal.complete(Err(ResolutionError::cancelled()));
  }
}

async fn wait_for_refresh(
  receiver: &mut watch::Receiver<Option<SharedResolutionResult>>,
  deadline: Instant,
) -> SharedResolutionResult {
  loop {
    if let Some(result) = receiver.borrow().clone() {
      return result;
    }
    match tokio::time::timeout_at(deadline, receiver.changed()).await {
      Ok(Ok(())) => {}
      Ok(Err(_)) => return Err(ResolutionError::cancelled()),
      Err(_) => return Err(ResolutionError::deadline()),
    }
  }
}

fn select_combined_error(mut errors: Vec<ResolutionError>) -> ResolutionError {
  if errors.len() == 2 && errors.iter().all(ResolutionError::negative_cacheable) {
    if let Some(error) = errors
      .iter()
      .find(|error| error.class == ResolutionErrorClass::NxDomain)
    {
      return error.clone();
    }
    return errors.remove(0);
  }
  errors
    .into_iter()
    .find(|error| !error.negative_cacheable())
    .unwrap_or_else(|| {
      ResolutionError::new(
        ResolutionErrorClass::NoData,
        "upstream DNS returned no eligible addresses",
      )
    })
}

fn sort_and_deduplicate(endpoints: &mut Vec<ResolvedEndpoint>) {
  endpoints.sort_by_key(ResolvedEndpoint::socket_addr);
  endpoints.dedup_by_key(|endpoint| endpoint.socket_addr);
}

fn interleave_bounded(
  first: Vec<ResolvedEndpoint>,
  second: Vec<ResolvedEndpoint>,
  limit: usize,
) -> Vec<ResolvedEndpoint> {
  let mut first = first.into_iter();
  let mut second = second.into_iter();
  let mut endpoints = Vec::with_capacity(limit);
  while endpoints.len() < limit {
    let before = endpoints.len();
    if let Some(endpoint) = first.next() {
      endpoints.push(endpoint);
    }
    if endpoints.len() < limit
      && let Some(endpoint) = second.next()
    {
      endpoints.push(endpoint);
    }
    if endpoints.len() == before {
      break;
    }
  }
  endpoints
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_dns_response(data: &[u8]) {
  dns::fuzz_parse_dns_response(data);
}

#[cfg(test)]
mod tests;
