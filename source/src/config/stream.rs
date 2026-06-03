//! Raw stream listener configuration validation.
//! Stream routes are checked before they can bypass HTTP-specific safeguards.

use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use super::{
  Config, ProxyProtocolEgressMode, default_client_idle_timeout_ms, default_connect_timeout_ms,
};

impl Config {
  pub(super) fn validate_stream_listeners(&self) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    let mut binds = HashSet::new();
    for listener in &self.stream_listeners {
      if listener.name.trim().is_empty() {
        bail!("stream listener name must not be empty");
      }
      if !names.insert(listener.name.clone()) {
        bail!("duplicate stream listener name: {}", listener.name);
      }
      if !binds.insert(listener.bind) {
        bail!(
          "duplicate stream listener bind {} on listener {}",
          listener.bind,
          listener.name
        );
      }
      if listener.connect_timeout_ms == 0 || listener.idle_timeout_ms == 0 {
        bail!(
          "stream listener {} timeout values must be greater than 0",
          listener.name
        );
      }
      validate_stream_target(&listener.name, &listener.target)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StreamListenerConfig {
  pub name: String,
  pub bind: SocketAddr,
  pub target: String,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default)]
  pub proxy_protocol_egress: ProxyProtocolEgressMode,
}

fn validate_stream_target(listener_name: &str, target: &str) -> anyhow::Result<()> {
  let (host, port) = parse_stream_target(target)
    .with_context(|| format!("stream listener {listener_name} target must be in host:port form"))?;
  if host.trim().is_empty() {
    bail!("stream listener {listener_name} target host must not be empty");
  }
  if port == 0 {
    bail!("stream listener {listener_name} target port must be greater than 0");
  }
  Ok(())
}

pub fn parse_stream_target(target: &str) -> anyhow::Result<(String, u16)> {
  if let Some(stripped) = target.strip_prefix('[') {
    let Some(end) = stripped.find(']') else {
      bail!("missing closing ']' in IPv6 stream target");
    };
    let host = stripped[..end].to_string();
    let port = stripped
      .get(end + 1..)
      .and_then(|rest| rest.strip_prefix(':'))
      .ok_or_else(|| anyhow!("missing port in stream target"))?
      .parse::<u16>()
      .context("invalid stream target port")?;
    return Ok((host, port));
  }

  let (host, port) = target
    .rsplit_once(':')
    .ok_or_else(|| anyhow!("missing port in stream target"))?;
  if host.contains(':') {
    bail!("IPv6 stream targets must use [addr]:port form");
  }
  Ok((
    host.to_string(),
    port.parse::<u16>().context("invalid stream target port")?,
  ))
}
