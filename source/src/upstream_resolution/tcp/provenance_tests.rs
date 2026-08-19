use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::watch;
use tokio::time::Instant;

use super::super::{DnsLookup, ResolutionError};
use super::*;

#[derive(Clone)]
pub(super) struct CandidateBackend {
  a: Result<DnsLookup, ResolutionError>,
  aaaa: Result<DnsLookup, ResolutionError>,
  https: Result<DnsLookup, ResolutionError>,
  https_calls: Arc<AtomicUsize>,
}

impl super::super::ResolverBackend for CandidateBackend {
  #[allow(
    clippy::manual_async_fn,
    reason = "the production resolver trait intentionally requires a Send future"
  )]
  fn lookup(
    &self,
    _name: &str,
    query_type: DnsQueryType,
    _deadline: Instant,
  ) -> impl Future<Output = Result<DnsLookup, ResolutionError>> + Send {
    let result = match query_type {
      DnsQueryType::A => self.a.clone(),
      DnsQueryType::Aaaa => self.aaaa.clone(),
      DnsQueryType::Https => {
        self.https_calls.fetch_add(1, Ordering::AcqRel);
        self.https.clone()
      }
      DnsQueryType::Srv => unreachable!("HTTP candidate resolution does not query SRV"),
    };
    async move { result }
  }
}

#[derive(Clone)]
pub(super) struct PendingMetadataBackend {
  pub(super) started: Arc<AtomicUsize>,
  pub(super) dropped: Arc<AtomicUsize>,
}

struct PendingMetadataGuard(Arc<AtomicUsize>);

impl Drop for PendingMetadataGuard {
  fn drop(&mut self) {
    self.0.fetch_add(1, Ordering::AcqRel);
  }
}

impl super::super::ResolverBackend for PendingMetadataBackend {
  #[allow(
    clippy::manual_async_fn,
    reason = "the production resolver trait intentionally requires a Send future"
  )]
  fn lookup(
    &self,
    _name: &str,
    query_type: DnsQueryType,
    _deadline: Instant,
  ) -> impl Future<Output = Result<DnsLookup, ResolutionError>> + Send {
    async move {
      match query_type {
        DnsQueryType::A => Ok(ip_lookup(
          ResolutionSource::Dns,
          vec!["192.0.2.20".parse().unwrap()],
        )),
        DnsQueryType::Aaaa => Ok(ip_lookup(ResolutionSource::Dns, Vec::new())),
        DnsQueryType::Https => {
          self.started.fetch_add(1, Ordering::AcqRel);
          let _guard = PendingMetadataGuard(Arc::clone(&self.dropped));
          std::future::pending().await
        }
        DnsQueryType::Srv => unreachable!("HTTP candidate resolution does not query SRV"),
      }
    }
  }
}

pub(super) fn ip_lookup(source: ResolutionSource, addresses: Vec<IpAddr>) -> DnsLookup {
  let mut lookup = DnsLookup::new(addresses.into_iter().map(DnsAnswer::Ip).collect(), 1_000);
  lookup.source = source;
  lookup
}

fn https_hint_lookup(address: IpAddr) -> DnsLookup {
  DnsLookup::new(
    vec![DnsAnswer::Https(HttpsRecord {
      priority: 1,
      target: HttpsTarget::Owner,
      alpn_present: true,
      alpn: vec![HttpsAlpn::H2].into_boxed_slice(),
      port: None,
      ipv4_hints: match address {
        IpAddr::V4(address) => vec![address].into_boxed_slice(),
        IpAddr::V6(_) => Box::default(),
      },
      ipv6_hints: match address {
        IpAddr::V4(_) => Box::default(),
        IpAddr::V6(address) => vec![address].into_boxed_slice(),
      },
    })],
    1_000,
  )
}

pub(super) fn candidate_backend(
  a: Result<DnsLookup, ResolutionError>,
  aaaa: Result<DnsLookup, ResolutionError>,
  https_address: IpAddr,
) -> (CandidateBackend, Arc<AtomicUsize>) {
  let https_calls = Arc::new(AtomicUsize::new(0));
  (
    CandidateBackend {
      a,
      aaaa,
      https: Ok(https_hint_lookup(https_address)),
      https_calls: Arc::clone(&https_calls),
    },
    https_calls,
  )
}

pub(super) async fn wait_for_candidate(
  updates: &mut watch::Receiver<Arc<[HappyEyeballsCandidate<SocketAddr>]>>,
  address: SocketAddr,
) -> Vec<SocketAddr> {
  loop {
    let snapshot = updates.borrow_and_update().clone();
    let addresses = snapshot
      .iter()
      .map(|candidate| *candidate.value_ref())
      .collect::<Vec<_>>();
    if addresses.contains(&address) {
      return addresses;
    }
    updates.changed().await.expect("candidate producer closed");
  }
}
