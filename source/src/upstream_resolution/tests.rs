use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;

use super::*;

#[derive(Clone)]
struct FakeBackend {
  calls: Arc<AtomicUsize>,
  a: Result<DnsLookup, ResolutionError>,
  aaaa: Result<DnsLookup, ResolutionError>,
  gate: Option<Arc<Semaphore>>,
}

impl FakeBackend {
  fn positive(a: Vec<IpAddr>, a_ttl_ms: u64, aaaa: Vec<IpAddr>, aaaa_ttl_ms: u64) -> Self {
    Self {
      calls: Arc::new(AtomicUsize::new(0)),
      a: Ok(ip_lookup(a, a_ttl_ms)),
      aaaa: Ok(ip_lookup(aaaa, aaaa_ttl_ms)),
      gate: None,
    }
  }

  fn errors(class: ResolutionErrorClass) -> Self {
    let error = ResolutionError::new(class, "fake resolver error");
    Self {
      calls: Arc::new(AtomicUsize::new(0)),
      a: Err(error.clone()),
      aaaa: Err(error),
      gate: None,
    }
  }

  fn calls(&self) -> usize {
    self.calls.load(Ordering::Acquire)
  }
}

impl ResolverBackend for FakeBackend {
  #[allow(
    clippy::manual_async_fn,
    reason = "the production resolver trait intentionally requires a Send future"
  )]
  fn lookup(
    &self,
    _name: &str,
    query_type: DnsQueryType,
    _deadline: Instant,
  ) -> impl std::future::Future<Output = Result<DnsLookup, ResolutionError>> + Send {
    async move {
      self.calls.fetch_add(1, Ordering::AcqRel);
      if let Some(gate) = &self.gate {
        let permit = gate
          .acquire()
          .await
          .map_err(|_| ResolutionError::cancelled())?;
        permit.forget();
      }
      match query_type {
        DnsQueryType::A => self.a.clone(),
        DnsQueryType::Aaaa => self.aaaa.clone(),
        DnsQueryType::Srv | DnsQueryType::Https => {
          unreachable!("endpoint resolver only queries A and AAAA")
        }
      }
    }
  }
}

fn ip_lookup(addresses: Vec<IpAddr>, ttl_ms: u64) -> DnsLookup {
  DnsLookup::new(addresses.into_iter().map(DnsAnswer::Ip).collect(), ttl_ms)
}

fn origin(host: &str) -> ResolutionOrigin {
  ResolutionOrigin::new(host, 443, "test-upstream").expect("valid origin")
}

fn deadline() -> Instant {
  Instant::now()
    .checked_add(Duration::from_secs(30))
    .expect("test deadline")
}

#[tokio::test(start_paused = true)]
async fn literal_resolution_is_static_and_does_not_call_the_backend() {
  let backend = FakeBackend::errors(ResolutionErrorClass::ServerFailure);
  let resolver = EndpointResolver::new_with_backend(
    origin("192.0.2.1"),
    backend.clone(),
    ResolutionPolicy::default(),
  );
  let result = resolver.resolve(deadline()).await.expect("literal result");
  assert_eq!(backend.calls(), 0);
  assert_eq!(result.source(), ResolutionSource::Literal);
  assert_eq!(result.endpoints().len(), 1);
  assert_eq!(
    result.endpoints()[0].socket_addr(),
    SocketAddr::from(([192, 0, 2, 1], 443))
  );
}

#[tokio::test(start_paused = true)]
async fn mixed_family_results_are_deduplicated_interleaved_and_bounded() {
  let ipv4_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
  let ipv4_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
  let ipv6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
  let ipv6_b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
  let backend = FakeBackend::positive(
    vec![ipv4_b, ipv4_a, ipv4_a],
    9_000,
    vec![ipv6_b, ipv6_a, ipv6_a],
    5_000,
  );
  let policy = ResolutionPolicy::new(
    3,
    Duration::from_secs(1),
    Duration::from_secs(30),
    Duration::from_secs(1),
  )
  .expect("valid policy");
  let started = Instant::now();
  let resolver = EndpointResolver::new_with_backend(origin("app.example"), backend, policy);
  let result = resolver.resolve(deadline()).await.expect("mixed result");
  assert_eq!(result.endpoints().len(), 3);
  assert_ne!(
    result.endpoints()[0].family(),
    result.endpoints()[1].family()
  );
  assert_eq!(
    result.endpoints()[0].family(),
    result.endpoints()[2].family()
  );
  assert_eq!(result.valid_until(), started + Duration::from_secs(5));
}

#[test]
fn untrusted_family_answers_are_deduplicated_and_bounded_before_sorting() {
  let mut endpoints = Vec::new();
  for address in [
    SocketAddr::from(([192, 0, 2, 1], 443)),
    SocketAddr::from(([192, 0, 2, 1], 443)),
    SocketAddr::from(([192, 0, 2, 2], 443)),
  ] {
    push_bounded_unique(&mut endpoints, ResolvedEndpoint::ip(address), 1);
  }
  assert_eq!(endpoints.len(), 1);
  assert_eq!(
    endpoints[0].socket_addr(),
    SocketAddr::from(([192, 0, 2, 1], 443))
  );
}

#[tokio::test(start_paused = true)]
async fn positive_cache_applies_min_and_max_ttl_clamps() {
  for (observed_ms, effective) in [(0, 1), (120_000, 30)] {
    let backend = FakeBackend::positive(
      vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
      observed_ms,
      Vec::new(),
      observed_ms,
    );
    let resolver = EndpointResolver::new_with_backend(
      origin(&format!("ttl-{observed_ms}.example")),
      backend.clone(),
      ResolutionPolicy::default(),
    );
    resolver.resolve(deadline()).await.expect("initial result");
    resolver.resolve(deadline()).await.expect("cached result");
    assert_eq!(backend.calls(), 2);
    tokio::time::advance(Duration::from_secs(effective)).await;
    resolver
      .resolve(deadline())
      .await
      .expect("refreshed result");
    assert_eq!(backend.calls(), 4);
  }
}

#[tokio::test(start_paused = true)]
async fn selected_negative_results_are_cached_but_transient_errors_are_not() {
  let negative = FakeBackend::errors(ResolutionErrorClass::NxDomain);
  let negative_resolver = EndpointResolver::new_with_backend(
    origin("negative.example"),
    negative.clone(),
    ResolutionPolicy::default(),
  );
  assert_eq!(
    negative_resolver
      .resolve(deadline())
      .await
      .expect_err("negative result")
      .class(),
    ResolutionErrorClass::NxDomain
  );
  assert!(negative_resolver.resolve(deadline()).await.is_err());
  assert_eq!(negative.calls(), 2);
  tokio::time::advance(Duration::from_secs(1)).await;
  assert!(negative_resolver.resolve(deadline()).await.is_err());
  assert_eq!(negative.calls(), 4);

  let transient = FakeBackend::errors(ResolutionErrorClass::ServerFailure);
  let transient_resolver = EndpointResolver::new_with_backend(
    origin("transient.example"),
    transient.clone(),
    ResolutionPolicy::default(),
  );
  assert!(transient_resolver.resolve(deadline()).await.is_err());
  assert!(transient_resolver.resolve(deadline()).await.is_err());
  assert_eq!(transient.calls(), 4);
}

#[tokio::test]
async fn concurrent_cold_requests_share_one_a_and_aaaa_refresh() {
  let gate = Arc::new(Semaphore::new(0));
  let mut backend = FakeBackend::positive(
    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    30_000,
    Vec::new(),
    30_000,
  );
  backend.gate = Some(Arc::clone(&gate));
  let resolver = EndpointResolver::new_with_backend(
    origin("coalesced.example"),
    backend.clone(),
    ResolutionPolicy::default(),
  );
  let mut tasks = Vec::new();
  for _ in 0..16 {
    let resolver = resolver.clone();
    tasks.push(tokio::spawn(
      async move { resolver.resolve(deadline()).await },
    ));
  }
  while backend.calls() < 2 {
    tokio::task::yield_now().await;
  }
  assert_eq!(backend.calls(), 2);
  gate.add_permits(2);
  for task in tasks {
    assert!(task.await.expect("resolver task").is_ok());
  }
  assert_eq!(backend.calls(), 2);
}

#[tokio::test]
async fn follower_retries_when_the_refresh_leader_is_cancelled() {
  let gate = Arc::new(Semaphore::new(0));
  let mut backend = FakeBackend::positive(
    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    30_000,
    Vec::new(),
    30_000,
  );
  backend.gate = Some(Arc::clone(&gate));
  let resolver = EndpointResolver::new_with_backend(
    origin("leader-cancelled.example"),
    backend.clone(),
    ResolutionPolicy::default(),
  );
  let leader = {
    let resolver = resolver.clone();
    tokio::spawn(async move { resolver.resolve(deadline()).await })
  };
  while backend.calls() < 2 {
    tokio::task::yield_now().await;
  }
  let follower = {
    let resolver = resolver.clone();
    tokio::spawn(async move { resolver.resolve(deadline()).await })
  };
  leader.abort();
  while backend.calls() < 4 {
    tokio::task::yield_now().await;
  }
  gate.add_permits(2);
  assert!(follower.await.expect("follower task").is_ok());
  assert_eq!(backend.calls(), 4);
}

#[tokio::test(start_paused = true)]
async fn one_family_success_survives_other_family_failure() {
  let backend = FakeBackend {
    calls: Arc::new(AtomicUsize::new(0)),
    a: Ok(ip_lookup(
      vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))],
      4_000,
    )),
    aaaa: Err(ResolutionError::new(
      ResolutionErrorClass::ServerFailure,
      "AAAA failed",
    )),
    gate: None,
  };
  let resolver = EndpointResolver::new_with_backend(
    origin("partial.example"),
    backend,
    ResolutionPolicy::default(),
  );
  let result = resolver.resolve(deadline()).await.expect("partial success");
  assert_eq!(result.endpoints().len(), 1);
  assert_eq!(result.endpoints()[0].family(), EndpointAddressFamily::Ipv4);
}
