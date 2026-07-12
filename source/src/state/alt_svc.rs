//! Precomputed Alt-Svc values selected by listener bind.

use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::Context;
use http::HeaderValue;

use crate::config::Config;

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

pub(crate) fn build_alt_svc_header_values(config: &Config) -> anyhow::Result<AltSvcHeaderValues> {
  if !config.listeners.http3 || !config.quic.alt_svc.enabled {
    return Ok(AltSvcHeaderValues::default());
  }

  let port_overrides = config
    .quic
    .alt_svc
    .port_overrides
    .iter()
    .map(|port_override| (port_override.bind, port_override.advertised_port))
    .collect::<HashMap<_, _>>();
  let mut values = AltSvcHeaderValues::default();
  for bind in &config.listeners.https_binds {
    let advertised_port = port_overrides
      .get(bind)
      .copied()
      .unwrap_or_else(|| bind.port());
    let value = build_alt_svc_header_value(
      advertised_port,
      config.quic.alt_svc.max_age_seconds,
      config.quic.alt_svc.persist,
    )?;
    if *bind == config.listeners.https_bind {
      values.default = Some(value.clone());
    }
    values.by_listener_bind.insert(*bind, value);
  }
  Ok(values)
}

fn build_alt_svc_header_value(
  advertised_port: u16,
  max_age_seconds: u64,
  persist: bool,
) -> anyhow::Result<HeaderValue> {
  let mut value = format!("h3=\":{}\"; ma={}", advertised_port, max_age_seconds);
  if persist {
    value.push_str("; persist=1");
  }
  HeaderValue::from_str(&value).context("invalid Alt-Svc header value")
}
