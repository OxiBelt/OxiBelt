use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::*;
use crate::upstream_resolution::{
  CandidateSchedulerMode, DnsLookup, ResolutionError, ResolverBackend,
};

#[derive(Clone)]
struct Backend {
  calls: Arc<AtomicUsize>,
  gate: Option<Arc<Semaphore>>,
  address: Arc<Mutex<IpAddr>>,
}

impl Backend {
  fn new(gate: Option<Arc<Semaphore>>) -> Self {
    Self {
      calls: Arc::new(AtomicUsize::new(0)),
      gate,
      address: Arc::new(Mutex::new(IpAddr::V4(Ipv4Addr::LOCALHOST))),
    }
  }
}

impl ResolverBackend for Backend {
  #[allow(
    clippy::manual_async_fn,
    reason = "the resolver trait requires an explicitly Send future"
  )]
  fn lookup(
    &self,
    _name: &str,
    query_type: DnsQueryType,
    _deadline: Instant,
  ) -> impl Future<Output = Result<DnsLookup, ResolutionError>> + Send {
    async move {
      self.calls.fetch_add(1, Ordering::AcqRel);
      if let Some(gate) = &self.gate {
        gate
          .acquire()
          .await
          .expect("test gate remains open")
          .forget();
      }
      let answers = match query_type {
        DnsQueryType::A => vec![DnsAnswer::Ip(*self.address.lock().unwrap())],
        DnsQueryType::Aaaa => Vec::new(),
        _ => panic!("plain TCP resolution must query only A/AAAA"),
      };
      Ok(DnsLookup::new(answers, 1_000))
    }
  }
}

fn resolver(backend: Backend, port: u16) -> EndpointResolver<Backend> {
  EndpointResolver::new_with_backend(
    ResolutionOrigin::new("shared.example", port, "shared-tcp-test").unwrap(),
    backend,
    ResolutionPolicy::default(),
  )
}

fn scheduler() -> CandidateSchedulerConfig {
  CandidateSchedulerConfig::new(
    CandidateSchedulerMode::Enabled,
    Duration::from_millis(250),
    Duration::from_millis(10),
    8,
    2,
    1,
  )
  .unwrap()
}

async fn wait_for_calls(backend: &Backend, count: usize) {
  while backend.calls.load(Ordering::Acquire) < count {
    tokio::task::yield_now().await;
  }
}

#[tokio::test]
async fn concurrent_connections_share_dns_and_keep_independent_transports() {
  tokio::time::timeout(Duration::from_secs(5), async {
    const CONNECTIONS: usize = 16;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let backend = Backend::new(Some(gate.clone()));
    let resolver = resolver(backend.clone(), listener.local_addr().unwrap().port());
    let mut tasks = JoinSet::new();
    for _ in 0..CONNECTIONS {
      let resolver = resolver.clone();
      tasks.spawn(async move {
        let (mut stream, _) = connect_tcp_happy_eyeballs_with_resolver_admitted(
          &resolver,
          scheduler(),
          Instant::now() + Duration::from_secs(3),
          None,
        )
        .await
        .expect("each connection should resolve and connect");
        stream.write_all(b"x").await.unwrap();
        stream
      });
    }
    wait_for_calls(&backend, 2).await;
    assert_eq!(backend.calls.load(Ordering::Acquire), 2);
    gate.add_permits(2);
    let mut streams = Vec::new();
    while let Some(result) = tasks.join_next().await {
      streams.push(result.unwrap());
    }
    for _ in 0..CONNECTIONS {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut byte = [0];
      stream.read_exact(&mut byte).await.unwrap();
      assert_eq!(byte, *b"x");
    }
    assert_eq!(streams.len(), CONNECTIONS);
    assert_eq!(backend.calls.load(Ordering::Acquire), 2);
  })
  .await
  .expect("bounded connection burst should complete");
}

#[tokio::test(start_paused = true)]
async fn cached_tcp_candidates_refresh_after_ttl_instead_of_reusing_stale_address() {
  let backend = Backend::new(None);
  let resolver = resolver(backend.clone(), 8080);
  let initial = resolve_tcp_candidates(&resolver, Instant::now() + Duration::from_secs(5))
    .await
    .unwrap();
  *backend.address.lock().unwrap() = "127.0.0.2".parse().unwrap();
  let cached = resolve_tcp_candidates(&resolver, Instant::now() + Duration::from_secs(5))
    .await
    .unwrap();
  assert_eq!(initial[0].value_ref(), cached[0].value_ref());
  assert_eq!(backend.calls.load(Ordering::Acquire), 2);
  tokio::time::advance(Duration::from_secs(1)).await;
  let refreshed = resolve_tcp_candidates(&resolver, Instant::now() + Duration::from_secs(5))
    .await
    .unwrap();
  assert_eq!(*refreshed[0].value_ref(), "127.0.0.2:8080".parse().unwrap());
  assert_eq!(backend.calls.load(Ordering::Acquire), 4);
}

#[tokio::test]
async fn short_connection_follower_deadline_does_not_cancel_shared_refresh() {
  tokio::time::timeout(Duration::from_secs(5), async {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let backend = Backend::new(Some(gate.clone()));
    let resolver = resolver(backend.clone(), listener.local_addr().unwrap().port());
    let mut tasks = JoinSet::new();
    let leader_resolver = resolver.clone();
    tasks.spawn(async move {
      connect_tcp_happy_eyeballs_with_resolver_admitted(
        &leader_resolver,
        scheduler(),
        Instant::now() + Duration::from_secs(3),
        None,
      )
      .await
    });
    wait_for_calls(&backend, 2).await;
    let follower = connect_tcp_happy_eyeballs_with_resolver_admitted(
      &resolver,
      scheduler(),
      Instant::now() + Duration::from_millis(20),
      None,
    )
    .await;
    let error = follower.err().expect("short follower should time out");
    assert_eq!(
      error.downcast_ref::<ResolutionError>().unwrap().class(),
      ResolutionErrorClass::Deadline
    );
    assert_eq!(backend.calls.load(Ordering::Acquire), 2);
    gate.add_permits(2);
    let (stream, _) = tasks.join_next().await.unwrap().unwrap().unwrap();
    let (_accepted, _) = listener.accept().await.unwrap();
    drop(stream);
    assert_eq!(backend.calls.load(Ordering::Acquire), 2);
  })
  .await
  .expect("follower timeout must leave leader able to finish");
}

#[tokio::test]
async fn cancelled_connection_leader_does_not_strand_followers() {
  tokio::time::timeout(Duration::from_secs(5), async {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let backend = Backend::new(Some(gate.clone()));
    let resolver = resolver(backend.clone(), listener.local_addr().unwrap().port());
    let mut tasks = JoinSet::new();
    let leader_resolver = resolver.clone();
    let leader = tasks.spawn(async move {
      connect_tcp_happy_eyeballs_with_resolver_admitted(
        &leader_resolver,
        scheduler(),
        Instant::now() + Duration::from_secs(3),
        None,
      )
      .await
    });
    wait_for_calls(&backend, 2).await;
    tasks.spawn(async move {
      connect_tcp_happy_eyeballs_with_resolver_admitted(
        &resolver,
        scheduler(),
        Instant::now() + Duration::from_secs(3),
        None,
      )
      .await
    });
    tokio::task::yield_now().await;
    leader.abort();
    wait_for_calls(&backend, 4).await;
    gate.add_permits(2);
    let mut successes = 0;
    while let Some(result) = tasks.join_next().await {
      match result {
        Ok(Ok((_stream, _))) => successes += 1,
        Err(error) if error.is_cancelled() => {}
        _ => panic!("only the explicitly cancelled connection should fail"),
      }
    }
    assert_eq!(successes, 1);
    let (_accepted, _) = listener.accept().await.unwrap();
    assert_eq!(backend.calls.load(Ordering::Acquire), 4);
  })
  .await
  .expect("cancelled leader must release the refresh for a follower");
}
