use std::sync::Arc;

use http::HeaderValue;
use url::{Position, Url};

#[derive(Clone)]
pub(super) struct DirectH1Origin {
  pub(super) host: Arc<str>,
  pub(super) port: u16,
  pub(super) authority_header: HeaderValue,
  identity: DirectH1OriginIdentity,
}

impl DirectH1Origin {
  pub(super) fn worker_shard(&self, worker_count: usize) -> usize {
    debug_assert!(worker_count > 0);
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in self
      .host
      .as_bytes()
      .iter()
      .copied()
      .chain(self.port.to_be_bytes())
    {
      hash ^= u64::from(byte);
      hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash as usize) % worker_count
  }

  pub(super) fn identity(&self) -> DirectH1OriginIdentity {
    self.identity.clone()
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct DirectH1OriginIdentity {
  pub(super) host: Arc<str>,
  pub(super) port: u16,
}

impl DirectH1Origin {
  pub(super) fn from_url(origin: &Url) -> Option<Self> {
    if origin.scheme() != "http" {
      return None;
    }
    let host: Arc<str> = Arc::from(origin.host_str()?);
    let port = origin.port_or_known_default()?;
    let authority = match origin.port() {
      Some(_) => origin[Position::BeforeHost..Position::AfterPort].to_owned(),
      None => host.to_string(),
    };
    let authority_header = HeaderValue::from_str(&authority).ok()?;
    let identity = DirectH1OriginIdentity {
      host: Arc::clone(&host),
      port,
    };
    Some(Self {
      host,
      port,
      authority_header,
      identity,
    })
  }
}
