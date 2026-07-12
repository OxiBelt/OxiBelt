//! Precomputed Alt-Svc values selected by listener bind.

use std::collections::HashMap;
use std::net::SocketAddr;

use http::HeaderValue;

#[derive(Clone, Default)]
pub(crate) struct AltSvcHeaderValues {
  pub(super) default: Option<HeaderValue>,
  pub(super) by_listener_bind: HashMap<SocketAddr, HeaderValue>,
}

impl AltSvcHeaderValues {
  pub(crate) fn is_some(&self) -> bool {
    self.default.is_some()
  }

  pub(crate) fn for_listener_bind(&self, listener_bind: Option<SocketAddr>) -> Option<HeaderValue> {
    listener_bind
      .and_then(|bind| self.by_listener_bind.get(&bind))
      .or(self.default.as_ref())
      .cloned()
  }

  #[cfg(test)]
  pub(crate) fn default_value(&self) -> Option<&HeaderValue> {
    self.default.as_ref()
  }
}
