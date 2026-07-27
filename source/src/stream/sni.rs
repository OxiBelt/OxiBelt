//! Per-listener SNI routing helpers for generic stream listeners.
//! Matching is deterministic and mirrors the existing SNI forwarding wildcard behavior.

use std::time::Duration;

use crate::config::{
  ProxyProtocolEgressMode, StreamListenerConfig, StreamSniRuleConfig, normalize_sni_pattern,
};

#[derive(Debug, Clone, Copy)]
pub(crate) enum StreamRouteTarget<'a> {
  Direct(&'a str),
  Pool(&'a str),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamRoute<'a> {
  pub(crate) name: &'a str,
  pub(crate) identity: StreamRouteIdentity<'a>,
  pub(crate) target: StreamRouteTarget<'a>,
  pub(crate) connect_timeout: Duration,
  pub(crate) idle_timeout: Duration,
  pub(crate) proxy_protocol_egress: ProxyProtocolEgressMode,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum StreamRouteIdentity<'a> {
  Default,
  Rule(&'a str),
}

pub(crate) fn select_stream_route<'a>(
  listener: &'a StreamListenerConfig,
  sni: Option<&str>,
) -> Option<StreamRoute<'a>> {
  if let Some(sni) = sni.map(normalize_sni_pattern)
    && let Some(rule) = matching_rule(&listener.sni_rules, &sni)
  {
    return route_from_rule(rule);
  }
  default_route(listener)
}

/// Resolves a durable route identifier only through the active listener.
///
/// UDP recovery calls this before inspecting the next datagram, which may no
/// longer contain a QUIC Initial.  The name is therefore a lookup key, never
/// a serialized target.
pub(crate) fn select_default_stream_route(
  listener: &StreamListenerConfig,
) -> Option<StreamRoute<'_>> {
  default_route(listener)
}

pub(crate) fn select_stream_rule_by_name<'a>(
  listener: &'a StreamListenerConfig,
  route_name: &str,
) -> Option<StreamRoute<'a>> {
  listener
    .sni_rules
    .iter()
    .find(|rule| rule.name == route_name)
    .and_then(route_from_rule)
}

fn matching_rule<'a>(
  rules: &'a [StreamSniRuleConfig],
  sni: &str,
) -> Option<&'a StreamSniRuleConfig> {
  rules
    .iter()
    .filter_map(|rule| {
      rule
        .server_names
        .iter()
        .filter_map(|pattern| match_pattern(pattern, sni))
        .max()
        .map(|score| (score, rule))
    })
    .max_by_key(|(score, _)| *score)
    .map(|(_, rule)| rule)
}

fn match_pattern(pattern: &str, sni: &str) -> Option<usize> {
  let normalized = normalize_sni_pattern(pattern);
  if normalized == sni {
    return Some(usize::MAX);
  }
  let suffix = normalized.strip_prefix("*.")?;
  if sni.len() > suffix.len()
    && sni.ends_with(suffix)
    && sni
      .as_bytes()
      .get(sni.len() - suffix.len() - 1)
      .is_some_and(|byte| *byte == b'.')
  {
    return Some(suffix.len());
  }
  None
}

fn route_from_rule(rule: &StreamSniRuleConfig) -> Option<StreamRoute<'_>> {
  let target = match (rule.target.as_deref(), rule.upstream_pool.as_deref()) {
    (Some(target), None) => StreamRouteTarget::Direct(target),
    (None, Some(pool)) => StreamRouteTarget::Pool(pool),
    _ => return None,
  };
  Some(StreamRoute {
    name: &rule.name,
    identity: StreamRouteIdentity::Rule(&rule.name),
    target,
    connect_timeout: Duration::from_millis(rule.connect_timeout_ms),
    idle_timeout: Duration::from_millis(rule.idle_timeout_ms),
    proxy_protocol_egress: rule.proxy_protocol_egress,
  })
}

fn default_route(listener: &StreamListenerConfig) -> Option<StreamRoute<'_>> {
  let target = match (
    listener.target.as_deref(),
    listener.upstream_pool.as_deref(),
  ) {
    (Some(target), None) => StreamRouteTarget::Direct(target),
    (None, Some(pool)) => StreamRouteTarget::Pool(pool),
    _ => return None,
  };
  Some(StreamRoute {
    name: "default",
    identity: StreamRouteIdentity::Default,
    target,
    connect_timeout: Duration::from_millis(listener.connect_timeout_ms),
    idle_timeout: Duration::from_millis(listener.idle_timeout_ms),
    proxy_protocol_egress: listener.proxy_protocol_egress,
  })
}
