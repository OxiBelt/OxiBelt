//! Bounded TCP connection establishment over the shared endpoint resolver.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;

use super::{
  CandidateAttemptError, CandidateRaceError, CandidateSchedulerConfig, DnsAnswer, DnsQueryType,
  EndpointResolver, HappyEyeballsCandidate, HttpsAlpn, HttpsRecord, HttpsTarget,
  ResolutionErrorClass, ResolutionOrigin, ResolutionPolicy, ResolutionSource,
  lookup_dns_absolute_until, race_happy_eyeballs_candidates, synthesize_pref64_ipv4_candidates,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpTransportProtocol {
  H1,
  H2,
  #[allow(
    dead_code,
    reason = "HTTP/3 integration consumes this in the next migration stage"
  )]
  H3,
}

impl HttpTransportProtocol {
  fn accepted_by(self, record: &HttpsRecord) -> bool {
    !record.alpn_present
      || record.alpn.iter().any(|alpn| {
        matches!(
          (self, alpn),
          (Self::H1, HttpsAlpn::H1) | (Self::H2, HttpsAlpn::H2) | (Self::H3, HttpsAlpn::H3)
        )
      })
  }
}

pub(crate) async fn connect_tcp_happy_eyeballs(
  host: &str,
  port: u16,
  discovery_id: &str,
  resolution_policy: ResolutionPolicy,
  scheduler_config: CandidateSchedulerConfig,
  deadline: Instant,
) -> anyhow::Result<(TcpStream, SocketAddr)> {
  let candidates =
    resolve_tcp_candidates(host, port, discovery_id, resolution_policy, deadline).await?;
  let (sender, mut updates) = watch::channel(candidates);
  drop(sender);

  race_happy_eyeballs_candidates(
    &mut updates,
    scheduler_config,
    deadline,
    |candidate, attempt_deadline| async move {
      let address = candidate.into_value();
      match tokio::time::timeout_at(attempt_deadline, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => Ok((stream, address)),
        Ok(Err(error)) => Err(CandidateAttemptError::Endpoint(
          anyhow::Error::new(error).context(format!(
            "failed to connect upstream TCP candidate {address}"
          )),
        )),
        Err(_) => Err(CandidateAttemptError::Endpoint(anyhow::anyhow!(
          "upstream TCP candidate {address} timed out"
        ))),
      }
    },
  )
  .await
  .map_err(candidate_race_error)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_http_tcp_happy_eyeballs(
  host: &str,
  port: u16,
  discovery_id: &str,
  resolution_policy: ResolutionPolicy,
  scheduler_config: CandidateSchedulerConfig,
  protocol: HttpTransportProtocol,
  tls_enabled: bool,
  svcb_enabled: bool,
  allowed_svcb_ports: &[u16],
  deadline: Instant,
) -> anyhow::Result<(TcpStream, SocketAddr)> {
  let mut updates = resolve_http_candidate_updates(
    host,
    port,
    discovery_id,
    resolution_policy,
    protocol,
    tls_enabled,
    svcb_enabled,
    allowed_svcb_ports,
    deadline,
  )?;
  race_happy_eyeballs_candidates(
    &mut updates,
    scheduler_config,
    deadline,
    |candidate, attempt_deadline| async move {
      let address = candidate.into_value();
      match tokio::time::timeout_at(attempt_deadline, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => Ok((stream, address)),
        Ok(Err(error)) => Err(CandidateAttemptError::Endpoint(anyhow::Error::new(error))),
        Err(_) => Err(CandidateAttemptError::Endpoint(anyhow::anyhow!(
          "upstream TCP candidate {address} timed out"
        ))),
      }
    },
  )
  .await
  .map_err(candidate_race_error)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_http_ready_happy_eyeballs<T, Connect, ConnectFuture>(
  host: &str,
  port: u16,
  discovery_id: &str,
  resolution_policy: ResolutionPolicy,
  scheduler_config: CandidateSchedulerConfig,
  protocol: HttpTransportProtocol,
  tls_enabled: bool,
  svcb_enabled: bool,
  allowed_svcb_ports: &[u16],
  deadline: Instant,
  connect: Connect,
) -> anyhow::Result<T>
where
  Connect: Fn(SocketAddr, Instant) -> ConnectFuture,
  ConnectFuture: Future<Output = anyhow::Result<T>>,
{
  let mut updates = resolve_http_candidate_updates(
    host,
    port,
    discovery_id,
    resolution_policy,
    protocol,
    tls_enabled,
    svcb_enabled,
    allowed_svcb_ports,
    deadline,
  )?;
  race_happy_eyeballs_candidates(
    &mut updates,
    scheduler_config,
    deadline,
    |candidate, attempt_deadline| {
      let address = candidate.into_value();
      let future = connect(address, attempt_deadline);
      async move { future.await.map_err(CandidateAttemptError::Endpoint) }
    },
  )
  .await
  .map_err(candidate_race_error)
}

enum HttpCandidateUpdate {
  Base(Vec<SocketAddr>),
  Svcb(Vec<SocketAddr>),
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_http_candidate_updates(
  host: &str,
  configured_port: u16,
  discovery_id: &str,
  resolution_policy: ResolutionPolicy,
  protocol: HttpTransportProtocol,
  tls_enabled: bool,
  svcb_enabled: bool,
  allowed_svcb_ports: &[u16],
  deadline: Instant,
) -> anyhow::Result<watch::Receiver<Arc<[HappyEyeballsCandidate<SocketAddr>]>>> {
  let origin = ResolutionOrigin::new(
    host,
    configured_port,
    Arc::<str>::from(discovery_id.to_string()),
  )?;
  Ok(resolve_http_candidate_updates_with_resolver(
    EndpointResolver::system(origin, resolution_policy),
    host,
    configured_port,
    resolution_policy,
    protocol,
    tls_enabled,
    svcb_enabled,
    allowed_svcb_ports,
    deadline,
  ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_http_candidate_updates_with_resolver<B: super::ResolverBackend>(
  resolver: EndpointResolver<B>,
  host: &str,
  configured_port: u16,
  resolution_policy: ResolutionPolicy,
  protocol: HttpTransportProtocol,
  tls_enabled: bool,
  svcb_enabled: bool,
  allowed_svcb_ports: &[u16],
  deadline: Instant,
) -> watch::Receiver<Arc<[HappyEyeballsCandidate<SocketAddr>]>> {
  let (updates_tx, updates_rx) =
    watch::channel(Arc::from(Vec::<HappyEyeballsCandidate<SocketAddr>>::new()));
  let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(4);
  let host = host.to_string();
  let allowed_svcb_ports = Arc::<[u16]>::from(allowed_svcb_ports.to_vec());

  let base_events = events_tx.clone();
  let base_cancellation = updates_tx.clone();
  let base_host = host.clone();
  let metadata_resolver = resolver.clone();
  tokio::spawn(async move {
    let resolved = tokio::select! {
      _ = base_cancellation.closed() => return,
      resolved = resolver.resolve(deadline) => resolved,
    };
    let (resolved, dns_metadata_eligible) = match resolved {
      Ok(resolved) => {
        if resolved.valid_until() <= Instant::now() {
          return;
        }
        let eligible =
          resolved.source() == ResolutionSource::Dns && resolved.dns_metadata_eligible();
        (Some(resolved), eligible)
      }
      Err(error)
        if error.class() == ResolutionErrorClass::NoData && error.dns_metadata_eligible() =>
      {
        (None, true)
      }
      Err(_) => return,
    };
    if svcb_enabled && dns_metadata_eligible && base_host.parse::<IpAddr>().is_err() {
      spawn_http_svcb_candidate_producer(
        metadata_resolver,
        base_events.clone(),
        base_cancellation.clone(),
        configured_port,
        resolution_policy,
        protocol,
        tls_enabled,
        Arc::clone(&allowed_svcb_ports),
        deadline,
      );
    }

    let Some(resolved) = resolved else {
      return;
    };
    let base: Arc<[HappyEyeballsCandidate<SocketAddr>]> = Arc::from(
      resolved
        .endpoints()
        .iter()
        .enumerate()
        .map(|(index, endpoint)| {
          HappyEyeballsCandidate::new(index as u64, endpoint.family(), endpoint.socket_addr())
        })
        .collect::<Vec<_>>(),
    );
    let raw = base
      .iter()
      .map(|candidate| *candidate.value_ref())
      .collect::<Vec<_>>();
    tokio::select! {
      _ = base_cancellation.closed() => return,
      sent = base_events.send(HttpCandidateUpdate::Base(raw)) => {
        if sent.is_err() {
          return;
        }
      }
    }
    if resolution_policy.pref64_enabled()
      && let Ok(augmented) = tokio::select! {
        _ = base_cancellation.closed() => return,
        augmented = augment_http_candidates(
          &base_host,
          configured_port,
          base,
          resolution_policy,
          protocol,
          tls_enabled,
          false,
          &[],
          deadline,
        ) => augmented,
      }
    {
      let addresses = augmented
        .iter()
        .map(|candidate| *candidate.value_ref())
        .collect::<Vec<_>>();
      tokio::select! {
        _ = base_cancellation.closed() => {}
        _ = base_events.send(HttpCandidateUpdate::Base(addresses)) => {}
      }
    }
  });
  drop(events_tx);

  tokio::spawn(async move {
    let mut base = Vec::new();
    let mut svcb = Vec::new();
    let mut ids = HashMap::new();
    let mut next_id = 0u64;
    loop {
      let update = tokio::select! {
        _ = updates_tx.closed() => return,
        update = events_rx.recv() => update,
      };
      let Some(update) = update else {
        return;
      };
      match update {
        HttpCandidateUpdate::Base(addresses) => base = addresses,
        HttpCandidateUpdate::Svcb(addresses) => svcb = addresses,
      }
      let mut seen = HashSet::new();
      let candidates = svcb
        .iter()
        .chain(&base)
        .copied()
        .filter(|address| seen.insert(*address))
        .take(resolution_policy.max_endpoint_count())
        .map(|address| {
          let id = *ids.entry(address).or_insert_with(|| {
            let id = next_id;
            next_id = next_id.saturating_add(1);
            id
          });
          HappyEyeballsCandidate::new(
            id,
            if address.is_ipv4() {
              super::EndpointAddressFamily::Ipv4
            } else {
              super::EndpointAddressFamily::Ipv6
            },
            address,
          )
        })
        .collect::<Vec<_>>();
      if updates_tx.send(Arc::from(candidates)).is_err() {
        return;
      }
    }
  });
  updates_rx
}

#[allow(clippy::too_many_arguments)]
fn spawn_http_svcb_candidate_producer<B: super::ResolverBackend>(
  resolver: EndpointResolver<B>,
  events: tokio::sync::mpsc::Sender<HttpCandidateUpdate>,
  cancellation: watch::Sender<Arc<[HappyEyeballsCandidate<SocketAddr>]>>,
  configured_port: u16,
  resolution_policy: ResolutionPolicy,
  protocol: HttpTransportProtocol,
  tls_enabled: bool,
  allowed_ports: Arc<[u16]>,
  deadline: Instant,
) {
  tokio::spawn(async move {
    let metadata_deadline = Instant::now()
      .checked_add(resolution_policy.resolution_delay())
      .unwrap_or(deadline)
      .min(deadline);
    let lookup = tokio::select! {
      _ = cancellation.closed() => return,
      lookup = tokio::time::timeout_at(
        metadata_deadline,
        resolver.lookup_https_metadata(deadline),
      ) => lookup,
    };
    let https = match lookup {
      Ok(Ok(lookup)) => Some(lookup),
      Ok(Err(_)) | Err(_) => None,
    };
    let candidates = tokio::select! {
      _ = cancellation.closed() => return,
      candidates = apply_http_candidate_metadata(
        configured_port,
        Arc::from(Vec::<HappyEyeballsCandidate<SocketAddr>>::new()),
        resolution_policy,
        protocol,
        tls_enabled,
        &allowed_ports,
        deadline,
        https,
      ) => candidates,
    };
    let Ok(candidates) = candidates else {
      return;
    };
    let addresses = candidates
      .iter()
      .map(|candidate| *candidate.value_ref())
      .collect::<Vec<_>>();
    if !addresses.is_empty() {
      tokio::select! {
        _ = cancellation.closed() => {}
        _ = events.send(HttpCandidateUpdate::Svcb(addresses)) => {}
      }
    }
  });
}

pub(crate) async fn resolve_tcp_candidates(
  host: &str,
  port: u16,
  discovery_id: &str,
  resolution_policy: ResolutionPolicy,
  deadline: Instant,
) -> anyhow::Result<Arc<[HappyEyeballsCandidate<SocketAddr>]>> {
  let origin = ResolutionOrigin::new(host, port, Arc::<str>::from(discovery_id.to_string()))?;
  let resolver = EndpointResolver::system(origin, resolution_policy);
  let resolved = resolver.resolve(deadline).await?;
  if resolved.valid_until() <= Instant::now() {
    anyhow::bail!("upstream endpoint set expired before TCP connection selection");
  }
  let candidates = resolved
    .endpoints()
    .iter()
    .enumerate()
    .map(|(index, endpoint)| {
      HappyEyeballsCandidate::new(index as u64, endpoint.family(), endpoint.socket_addr())
    })
    .collect::<Vec<_>>();
  Ok(Arc::from(candidates))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn augment_http_candidates(
  host: &str,
  configured_port: u16,
  base: Arc<[HappyEyeballsCandidate<SocketAddr>]>,
  resolution_policy: ResolutionPolicy,
  protocol: HttpTransportProtocol,
  tls_enabled: bool,
  svcb_enabled: bool,
  allowed_svcb_ports: &[u16],
  deadline: Instant,
) -> anyhow::Result<Arc<[HappyEyeballsCandidate<SocketAddr>]>> {
  if host.parse::<IpAddr>().is_ok() {
    return Ok(base);
  }
  let https = if svcb_enabled {
    let metadata_deadline = Instant::now()
      .checked_add(resolution_policy.resolution_delay())
      .unwrap_or(deadline)
      .min(deadline);
    match tokio::time::timeout_at(
      metadata_deadline,
      lookup_dns_absolute_until(host, DnsQueryType::Https, deadline),
    )
    .await
    {
      Ok(Ok(lookup)) => Some(lookup),
      Ok(Err(_)) | Err(_) => None,
    }
  } else {
    None
  };
  apply_http_candidate_metadata(
    configured_port,
    base,
    resolution_policy,
    protocol,
    tls_enabled,
    allowed_svcb_ports,
    deadline,
    https,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn apply_http_candidate_metadata(
  configured_port: u16,
  base: Arc<[HappyEyeballsCandidate<SocketAddr>]>,
  resolution_policy: ResolutionPolicy,
  protocol: HttpTransportProtocol,
  tls_enabled: bool,
  allowed_svcb_ports: &[u16],
  deadline: Instant,
  https: Option<super::DnsLookup>,
) -> anyhow::Result<Arc<[HappyEyeballsCandidate<SocketAddr>]>> {
  let mut records = https
    .into_iter()
    .flat_map(|lookup| lookup.answers)
    .filter_map(|answer| match answer {
      DnsAnswer::Https(record) if record.priority > 0 && protocol.accepted_by(&record) => {
        Some(record)
      }
      _ => None,
    })
    .collect::<Vec<_>>();
  records.sort_by_key(|record| record.priority);

  let mut addresses = Vec::new();
  for record in records {
    if addresses.len() >= resolution_policy.max_endpoint_count() {
      break;
    }
    let selected_port = selected_svcb_port(
      configured_port,
      record.port.map(std::num::NonZeroU16::get),
      tls_enabled,
      allowed_svcb_ports,
    );
    for ip in record
      .ipv6_hints
      .iter()
      .copied()
      .map(IpAddr::V6)
      .chain(record.ipv4_hints.iter().copied().map(IpAddr::V4))
    {
      addresses.push(SocketAddr::new(ip, selected_port));
      if addresses.len() >= resolution_policy.max_endpoint_count() {
        break;
      }
    }
    if record.ipv4_hints.is_empty()
      && record.ipv6_hints.is_empty()
      && let HttpsTarget::Absolute(target) = record.target
    {
      let remaining = resolution_policy
        .max_endpoint_count()
        .saturating_sub(addresses.len());
      if remaining > 0 {
        let delegated = resolve_absolute_target(&target, selected_port, remaining, deadline).await;
        if let Ok(delegated) = delegated {
          addresses.extend(delegated);
        }
      }
    }
  }
  addresses.extend(base.iter().map(|candidate| *candidate.value_ref()));
  if resolution_policy.pref64_enabled() && !addresses.iter().any(SocketAddr::is_ipv6) {
    let native_ipv4 = base
      .iter()
      .map(|candidate| *candidate.value_ref())
      .collect::<Vec<_>>();
    let remaining = resolution_policy
      .max_endpoint_count()
      .saturating_sub(addresses.len());
    addresses.extend(
      synthesize_pref64_ipv4_candidates(&native_ipv4, configured_port, remaining, deadline).await,
    );
  }
  let mut seen = HashSet::new();
  addresses.retain(|address| seen.insert(*address));
  addresses.truncate(resolution_policy.max_endpoint_count());
  Ok(Arc::from(
    addresses
      .into_iter()
      .enumerate()
      .map(|(index, address)| {
        HappyEyeballsCandidate::new(
          index as u64,
          if address.is_ipv4() {
            super::EndpointAddressFamily::Ipv4
          } else {
            super::EndpointAddressFamily::Ipv6
          },
          address,
        )
      })
      .collect::<Vec<_>>(),
  ))
}

fn selected_svcb_port(
  configured_port: u16,
  advertised_port: Option<u16>,
  tls_enabled: bool,
  allowed_svcb_ports: &[u16],
) -> u16 {
  advertised_port
    .filter(|port| *port == configured_port || (tls_enabled && allowed_svcb_ports.contains(port)))
    .unwrap_or(configured_port)
}

async fn resolve_absolute_target(
  target: &str,
  port: u16,
  max_count: usize,
  deadline: Instant,
) -> anyhow::Result<Vec<SocketAddr>> {
  let (a, aaaa) = tokio::join!(
    lookup_dns_absolute_until(target, DnsQueryType::A, deadline),
    lookup_dns_absolute_until(target, DnsQueryType::Aaaa, deadline),
  );
  let mut addresses = Vec::new();
  let mut seen = HashSet::new();
  for lookup in [a, aaaa].into_iter().flatten() {
    for address in lookup
      .answers
      .into_iter()
      .filter_map(|answer| match answer {
        DnsAnswer::Ip(ip) => Some(SocketAddr::new(ip, port)),
        _ => None,
      })
    {
      if seen.insert(address) {
        addresses.push(address);
      }
      if addresses.len() >= max_count {
        return Ok(addresses);
      }
    }
  }
  if addresses.is_empty() {
    anyhow::bail!("DNS HTTPS target returned no address records");
  }
  Ok(addresses)
}

fn candidate_race_error(error: CandidateRaceError<anyhow::Error>) -> anyhow::Error {
  match error {
    CandidateRaceError::Deadline => anyhow::anyhow!("upstream TCP connection deadline elapsed"),
    CandidateRaceError::NoCandidates => {
      anyhow::anyhow!("upstream resolver returned no TCP candidates")
    }
    CandidateRaceError::Exhausted {
      admission_error: Some(error),
      ..
    }
    | CandidateRaceError::Exhausted {
      last_endpoint_error: Some(error),
      admission_error: None,
    } => error,
    CandidateRaceError::Exhausted {
      last_endpoint_error: None,
      admission_error: None,
    } => anyhow::anyhow!("upstream TCP candidates were exhausted"),
  }
}

#[cfg(test)]
#[path = "tcp/provenance_tests.rs"]
mod provenance_tests;

#[cfg(test)]
mod tests {
  use super::super::ResolutionError;
  use super::provenance_tests::{
    PendingMetadataBackend, candidate_backend, ip_lookup, wait_for_candidate,
  };
  use super::*;
  use std::sync::atomic::{AtomicUsize, Ordering};

  #[derive(Clone)]
  struct PendingBackend {
    started: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
  }

  struct PendingLookupGuard(Arc<AtomicUsize>);

  impl Drop for PendingLookupGuard {
    fn drop(&mut self) {
      self.0.fetch_add(1, Ordering::AcqRel);
    }
  }

  impl super::super::ResolverBackend for PendingBackend {
    #[allow(
      clippy::manual_async_fn,
      reason = "the production resolver trait intentionally requires a Send future"
    )]
    fn lookup(
      &self,
      _name: &str,
      _query_type: DnsQueryType,
      _deadline: Instant,
    ) -> impl Future<Output = Result<super::super::DnsLookup, super::super::ResolutionError>> + Send
    {
      async move {
        self.started.fetch_add(1, Ordering::AcqRel);
        let _guard = PendingLookupGuard(Arc::clone(&self.dropped));
        std::future::pending().await
      }
    }
  }

  fn service_record(alpn_present: bool, alpn: Vec<HttpsAlpn>) -> HttpsRecord {
    HttpsRecord {
      priority: 1,
      target: HttpsTarget::Owner,
      alpn_present,
      alpn: alpn.into_boxed_slice(),
      port: None,
      ipv4_hints: Box::default(),
      ipv6_hints: Box::default(),
    }
  }

  #[test]
  fn present_alpn_parameter_requires_the_selected_protocol() {
    let unknown_only = service_record(true, Vec::new());
    assert!(!HttpTransportProtocol::H1.accepted_by(&unknown_only));
    assert!(!HttpTransportProtocol::H2.accepted_by(&unknown_only));
    assert!(!HttpTransportProtocol::H3.accepted_by(&unknown_only));

    let mixed = service_record(true, vec![HttpsAlpn::H2]);
    assert!(!HttpTransportProtocol::H1.accepted_by(&mixed));
    assert!(HttpTransportProtocol::H2.accepted_by(&mixed));
    assert!(!HttpTransportProtocol::H3.accepted_by(&mixed));

    let absent = service_record(false, Vec::new());
    assert!(HttpTransportProtocol::H1.accepted_by(&absent));
    assert!(HttpTransportProtocol::H2.accepted_by(&absent));
    assert!(HttpTransportProtocol::H3.accepted_by(&absent));
  }

  #[test]
  fn dns_port_never_expands_plaintext_origin_authority() {
    assert_eq!(selected_svcb_port(80, Some(8080), false, &[8080]), 80);
  }

  #[test]
  fn dns_port_requires_an_explicit_tls_allowlist_entry() {
    assert_eq!(selected_svcb_port(443, Some(8443), true, &[]), 443);
    assert_eq!(selected_svcb_port(443, Some(8443), true, &[8443]), 8443);
  }

  #[test]
  fn dns_port_equal_to_the_configured_origin_is_always_safe() {
    assert_eq!(selected_svcb_port(443, Some(443), true, &[]), 443);
    assert_eq!(selected_svcb_port(80, Some(80), false, &[]), 80);
  }

  #[tokio::test]
  async fn svcb_hints_supply_candidates_when_the_owner_has_no_addresses() {
    let record = HttpsRecord {
      priority: 1,
      target: HttpsTarget::Owner,
      alpn_present: true,
      alpn: vec![HttpsAlpn::H3].into_boxed_slice(),
      port: None,
      ipv4_hints: vec!["192.0.2.10".parse().unwrap()].into_boxed_slice(),
      ipv6_hints: Box::default(),
    };
    let policy = ResolutionPolicy::new(
      4,
      std::time::Duration::from_secs(1),
      std::time::Duration::from_secs(30),
      std::time::Duration::from_secs(1),
    )
    .unwrap();
    let candidates = apply_http_candidate_metadata(
      443,
      Arc::from(Vec::<HappyEyeballsCandidate<SocketAddr>>::new()),
      policy,
      HttpTransportProtocol::H3,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(1),
      Some(super::super::DnsLookup::new(
        vec![DnsAnswer::Https(record)],
        1_000,
      )),
    )
    .await
    .unwrap();

    assert_eq!(
      candidates
        .iter()
        .map(|candidate| *candidate.value_ref())
        .collect::<Vec<_>>(),
      ["192.0.2.10:443".parse().unwrap()]
    );
  }

  #[tokio::test]
  async fn hosts_pinned_base_never_queries_or_admits_svcb_metadata() {
    let base_ip = "192.0.2.30".parse().unwrap();
    let svcb_ip = "203.0.113.30".parse().unwrap();
    let (backend, https_calls) = candidate_backend(
      Ok(ip_lookup(ResolutionSource::Hosts, vec![base_ip])),
      Ok(ip_lookup(ResolutionSource::Hosts, Vec::new())),
      svcb_ip,
    );
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("pinned.example", 443, "hosts-pinned-test").unwrap(),
      backend,
      ResolutionPolicy::default(),
    );
    let mut updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "pinned.example",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(1),
    );

    let addresses = wait_for_candidate(&mut updates, SocketAddr::new(base_ip, 443)).await;
    assert_eq!(addresses, vec![SocketAddr::new(base_ip, 443)]);
    assert_eq!(https_calls.load(Ordering::Acquire), 0);
    assert!(!addresses.contains(&SocketAddr::new(svcb_ip, 443)));
  }

  #[tokio::test]
  async fn literal_base_never_queries_svcb_metadata() {
    let literal_ip = "192.0.2.35".parse().unwrap();
    let error = ResolutionError::new(
      ResolutionErrorClass::Internal,
      "literal resolution must bypass the backend",
    );
    let (backend, https_calls) = candidate_backend(
      Err(error.clone()),
      Err(error),
      "203.0.113.35".parse().unwrap(),
    );
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("192.0.2.35", 443, "literal-source-test").unwrap(),
      backend,
      ResolutionPolicy::default(),
    );
    let mut updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "192.0.2.35",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(1),
    );

    let addresses = wait_for_candidate(&mut updates, SocketAddr::new(literal_ip, 443)).await;
    assert_eq!(addresses, vec![SocketAddr::new(literal_ip, 443)]);
    assert_eq!(https_calls.load(Ordering::Acquire), 0);
  }

  #[tokio::test]
  async fn mixed_base_provenance_never_queries_svcb_metadata() {
    let hosts_ip = "192.0.2.31".parse().unwrap();
    let dns_ip = "2001:db8::31".parse().unwrap();
    let svcb_ip = "203.0.113.31".parse().unwrap();
    let (backend, https_calls) = candidate_backend(
      Ok(ip_lookup(ResolutionSource::Hosts, vec![hosts_ip])),
      Ok(ip_lookup(ResolutionSource::Dns, vec![dns_ip])),
      svcb_ip,
    );
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("mixed.example", 443, "mixed-source-test").unwrap(),
      backend,
      ResolutionPolicy::default(),
    );
    let mut updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "mixed.example",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(1),
    );

    let addresses = wait_for_candidate(&mut updates, SocketAddr::new(hosts_ip, 443)).await;
    assert!(addresses.contains(&SocketAddr::new(dns_ip, 443)));
    assert_eq!(https_calls.load(Ordering::Acquire), 0);
    assert!(!addresses.contains(&SocketAddr::new(svcb_ip, 443)));
  }

  #[tokio::test]
  async fn incomplete_dns_base_never_queries_svcb_metadata() {
    let base_ip = "192.0.2.36".parse().unwrap();
    let svcb_ip = "203.0.113.36".parse().unwrap();
    let (backend, https_calls) = candidate_backend(
      Ok(ip_lookup(ResolutionSource::Dns, vec![base_ip])),
      Err(ResolutionError::new(
        ResolutionErrorClass::Deadline,
        "the second address-family lookup timed out",
      )),
      svcb_ip,
    );
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("partial-dns.example", 443, "partial-dns-test").unwrap(),
      backend,
      ResolutionPolicy::default(),
    );
    let mut updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "partial-dns.example",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(1),
    );

    let addresses = wait_for_candidate(&mut updates, SocketAddr::new(base_ip, 443)).await;
    assert_eq!(addresses, vec![SocketAddr::new(base_ip, 443)]);
    assert_eq!(https_calls.load(Ordering::Acquire), 0);
    assert!(!addresses.contains(&SocketAddr::new(svcb_ip, 443)));
  }

  #[tokio::test]
  async fn dns_base_retains_svcb_candidates_ahead_of_base_candidates() {
    let base_ip = "192.0.2.32".parse().unwrap();
    let svcb_ip = "203.0.113.32".parse().unwrap();
    let (backend, https_calls) = candidate_backend(
      Ok(ip_lookup(ResolutionSource::Dns, vec![base_ip])),
      Ok(ip_lookup(ResolutionSource::Dns, Vec::new())),
      svcb_ip,
    );
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("dns.example", 443, "dns-source-test").unwrap(),
      backend,
      ResolutionPolicy::default(),
    );
    let mut updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "dns.example",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(1),
    );

    let addresses = wait_for_candidate(&mut updates, SocketAddr::new(svcb_ip, 443)).await;
    assert_eq!(https_calls.load(Ordering::Acquire), 1);
    assert_eq!(
      addresses,
      vec![SocketAddr::new(svcb_ip, 443), SocketAddr::new(base_ip, 443)]
    );
  }

  #[tokio::test]
  async fn dns_nodata_retains_svcb_only_candidates() {
    let svcb_ip = "203.0.113.33".parse().unwrap();
    let (backend, https_calls) = candidate_backend(
      Ok(ip_lookup(ResolutionSource::Dns, Vec::new())),
      Ok(ip_lookup(ResolutionSource::Dns, Vec::new())),
      svcb_ip,
    );
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("svcb-only.example", 443, "svcb-only-test").unwrap(),
      backend,
      ResolutionPolicy::default(),
    );
    let mut updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "svcb-only.example",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(1),
    );

    let addresses = wait_for_candidate(&mut updates, SocketAddr::new(svcb_ip, 443)).await;
    assert_eq!(https_calls.load(Ordering::Acquire), 1);
    assert_eq!(addresses, vec![SocketAddr::new(svcb_ip, 443)]);
  }

  #[tokio::test]
  async fn bare_nodata_and_resolution_failures_do_not_enable_svcb() {
    for class in [
      ResolutionErrorClass::NoData,
      ResolutionErrorClass::NxDomain,
      ResolutionErrorClass::ServerFailure,
      ResolutionErrorClass::Malformed,
      ResolutionErrorClass::Io,
      ResolutionErrorClass::Deadline,
    ] {
      let error = ResolutionError::new(class, "candidate base resolution failed");
      let (backend, https_calls) = candidate_backend(
        Err(error.clone()),
        Err(error),
        "203.0.113.34".parse().unwrap(),
      );
      let resolver = EndpointResolver::new_with_backend(
        ResolutionOrigin::new("failed.example", 443, "failed-source-test").unwrap(),
        backend,
        ResolutionPolicy::default(),
      );
      let mut updates = resolve_http_candidate_updates_with_resolver(
        resolver,
        "failed.example",
        443,
        ResolutionPolicy::default(),
        HttpTransportProtocol::H2,
        true,
        true,
        &[],
        Instant::now() + std::time::Duration::from_secs(1),
      );

      assert!(updates.changed().await.is_err(), "{class:?}");
      assert_eq!(https_calls.load(Ordering::Acquire), 0, "{class:?}");
    }
  }

  #[tokio::test]
  async fn dropping_candidate_updates_cancels_pending_svcb_metadata() {
    let started = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("cancel-metadata.example", 443, "cancel-metadata-test").unwrap(),
      PendingMetadataBackend {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
      },
      ResolutionPolicy::default(),
    );
    let updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "cancel-metadata.example",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      true,
      &[],
      Instant::now() + std::time::Duration::from_secs(30),
    );
    for _ in 0..16 {
      if started.load(Ordering::Acquire) == 1 {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(started.load(Ordering::Acquire), 1);

    drop(updates);
    for _ in 0..16 {
      if dropped.load(Ordering::Acquire) == 1 {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(dropped.load(Ordering::Acquire), 1);
  }

  #[tokio::test]
  async fn dropping_candidate_updates_cancels_pending_dns_producers() {
    let started = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let resolver = EndpointResolver::new_with_backend(
      ResolutionOrigin::new("cancel.example", 443, "cancel-test").unwrap(),
      PendingBackend {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
      },
      ResolutionPolicy::default(),
    );
    let updates = resolve_http_candidate_updates_with_resolver(
      resolver,
      "cancel.example",
      443,
      ResolutionPolicy::default(),
      HttpTransportProtocol::H2,
      true,
      false,
      &[],
      Instant::now() + std::time::Duration::from_secs(30),
    );
    for _ in 0..8 {
      if started.load(Ordering::Acquire) == 2 {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(started.load(Ordering::Acquire), 2);

    drop(updates);
    for _ in 0..8 {
      if dropped.load(Ordering::Acquire) == 2 {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(dropped.load(Ordering::Acquire), 2);
  }
}
