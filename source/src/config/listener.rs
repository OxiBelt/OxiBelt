//! Downstream HTTP listener configuration and bind-list compatibility.

use std::net::{IpAddr, SocketAddr};

use anyhow::bail;
use serde::Deserialize;

use super::default_true;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct RawListenerConfig {
  #[serde(default)]
  https_bind: Option<SocketAddr>,
  #[serde(default)]
  https_binds: Vec<SocketAddr>,
  #[serde(default)]
  http_bind: Option<SocketAddr>,
  #[serde(default)]
  http_binds: Vec<SocketAddr>,
  #[serde(default)]
  http_mode: HttpListenerMode,
  #[serde(default = "default_true")]
  http1: bool,
  #[serde(default = "default_true")]
  http2: bool,
  #[serde(default)]
  http3: bool,
  #[serde(default)]
  proxy_protocol: ProxyProtocolConfig,
}

impl RawListenerConfig {
  pub(super) fn resolve(self) -> anyhow::Result<ListenerConfig> {
    let https_binds = resolve_listener_bind_list(
      "listeners.https_bind",
      self.https_bind,
      "listeners.https_binds",
      self.https_binds,
      true,
    )?;
    let http_binds = resolve_listener_bind_list(
      "listeners.http_bind",
      self.http_bind,
      "listeners.http_binds",
      self.http_binds,
      false,
    )?;
    Ok(ListenerConfig {
      https_bind: https_binds[0],
      https_binds,
      http_bind: http_binds.first().copied(),
      http_binds,
      http_mode: self.http_mode,
      http1: self.http1,
      http2: self.http2,
      http3: self.http3,
      proxy_protocol: self.proxy_protocol,
    })
  }
}

fn resolve_listener_bind_list(
  scalar_name: &str,
  scalar: Option<SocketAddr>,
  list_name: &str,
  list: Vec<SocketAddr>,
  required: bool,
) -> anyhow::Result<Vec<SocketAddr>> {
  match (scalar, list.is_empty()) {
    (Some(_), false) => bail!("{scalar_name} must not be mixed with {list_name}"),
    (Some(bind), true) => Ok(vec![bind]),
    (None, false) => Ok(list),
    (None, true) if required => bail!("{scalar_name} or {list_name} is required"),
    (None, true) => Ok(Vec::new()),
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListenerConfig {
  pub https_bind: SocketAddr,
  pub https_binds: Vec<SocketAddr>,
  pub http_bind: Option<SocketAddr>,
  pub http_binds: Vec<SocketAddr>,
  pub http_mode: HttpListenerMode,
  pub http1: bool,
  pub http2: bool,
  pub http3: bool,
  pub proxy_protocol: ProxyProtocolConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HttpListenerMode {
  #[default]
  Off,
  RedirectToHttps,
  Proxy,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyProtocolConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub version: ProxyProtocolVersion,
  #[serde(default)]
  pub trusted_sources: Vec<String>,
}

impl Default for ProxyProtocolConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      version: ProxyProtocolVersion::Any,
      trusted_sources: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolVersion {
  V1,
  V2,
  #[default]
  Any,
}

pub(super) fn validate_bind_list(field_name: &str, binds: &[SocketAddr]) -> anyhow::Result<()> {
  if binds.is_empty() {
    bail!("{field_name} must include at least one bind address");
  }
  for (index, bind) in binds.iter().enumerate() {
    for other in binds.iter().skip(index + 1) {
      if binds_overlap(*bind, *other) {
        bail!("{field_name} entries {bind} and {other} overlap");
      }
    }
  }
  Ok(())
}

pub(super) fn validate_bind_lists_do_not_overlap(
  left_name: &str,
  left: &[SocketAddr],
  right_name: &str,
  right: &[SocketAddr],
) -> anyhow::Result<()> {
  for left_bind in left {
    for right_bind in right {
      if binds_overlap(*left_bind, *right_bind) {
        bail!("{left_name} entry {left_bind} overlaps {right_name} entry {right_bind}");
      }
    }
  }
  Ok(())
}

fn binds_overlap(left: SocketAddr, right: SocketAddr) -> bool {
  left.port() == right.port()
    && same_ip_family(left.ip(), right.ip())
    && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn same_ip_family(left: IpAddr, right: IpAddr) -> bool {
  matches!(
    (left, right),
    (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
  )
}
