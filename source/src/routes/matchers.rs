//! Extended route matchers compiled from validated route configuration.
//! Missing runtime metadata fails closed for matchers that depend on it.

use std::net::IpAddr;

use anyhow::Context;
use http::header::HeaderName;
use http::{HeaderMap, Method, Version};
use regex::Regex;

use crate::config::{
  RouteClientCertMatchConfig, RouteConfig, RouteNamedValueMatchConfig, RouteValueMatchConfig,
};
use crate::identity::Cidr;
use crate::waf::{WafProtocol, WafTlsMetadata};

#[derive(Debug, Clone)]
pub(super) struct CompiledRouteMatcher {
  valid: bool,
  methods: Vec<Method>,
  headers: Vec<CompiledNamedValueMatcher>,
  queries: Vec<CompiledNamedValueMatcher>,
  path_exact: Option<String>,
  path_regex: Option<Regex>,
  source_cidrs: Vec<Cidr>,
  protocols: Vec<CompiledRouteProtocol>,
  client_cert: CompiledClientCertMatcher,
  specificity: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RouteRequestProtocol {
  Http1,
  Http2,
  Http3,
  Websocket,
  Webtransport,
}

impl RouteRequestProtocol {
  pub fn from_http(version: Version, protocol: WafProtocol) -> Self {
    match protocol {
      WafProtocol::Websocket => Self::Websocket,
      WafProtocol::Webtransport => Self::Webtransport,
      WafProtocol::Http | WafProtocol::Webrtc => match version {
        Version::HTTP_3 => Self::Http3,
        Version::HTTP_2 => Self::Http2,
        _ => Self::Http1,
      },
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CompiledRouteProtocol {
  Http,
  Http1,
  Http2,
  Http3,
  Websocket,
  Webtransport,
}

#[derive(Debug, Clone)]
struct CompiledNamedValueMatcher {
  name: String,
  header_name: Option<HeaderName>,
  value: CompiledValueMatcher,
}

#[derive(Debug, Clone)]
enum CompiledValueMatcher {
  Present(bool),
  Exact(String),
  Prefix(String),
  Suffix(String),
  Contains(String),
  Regex(Regex),
}

#[derive(Debug, Clone, Default)]
struct CompiledClientCertMatcher {
  present: Option<bool>,
  fingerprint_sha256: Option<CompiledValueMatcher>,
  subject_cn: Option<CompiledValueMatcher>,
  san_dns: Option<CompiledValueMatcher>,
  san_ip: Option<CompiledValueMatcher>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RouteMatchContext<'a> {
  pub path: &'a str,
  pub method: Option<&'a Method>,
  pub headers: Option<&'a HeaderMap>,
  pub query: Option<&'a str>,
  pub source_ip: Option<IpAddr>,
  pub protocol: Option<RouteRequestProtocol>,
  pub tls: Option<&'a WafTlsMetadata>,
}

impl<'a> RouteMatchContext<'a> {
  pub fn path_only(path: &'a str) -> Self {
    Self {
      path,
      ..Self::default()
    }
  }
}

impl CompiledRouteMatcher {
  pub(super) fn from_route(route: &RouteConfig) -> anyhow::Result<Self> {
    let config = &route.r#match;
    let methods = config
      .methods
      .iter()
      .map(|method| {
        Method::from_bytes(method.as_bytes())
          .with_context(|| format!("route {} match.methods contains invalid method", route.name))
      })
      .collect::<anyhow::Result<Vec<_>>>()?;
    let headers = config
      .headers
      .iter()
      .map(|matcher| compile_named_value_matcher(&route.name, "match.headers", matcher, true))
      .collect::<anyhow::Result<Vec<_>>>()?;
    let queries = config
      .queries
      .iter()
      .map(|matcher| compile_named_value_matcher(&route.name, "match.queries", matcher, false))
      .collect::<anyhow::Result<Vec<_>>>()?;
    let path_regex = config
      .path
      .regex
      .as_ref()
      .map(|regex| Regex::new(regex))
      .transpose()
      .with_context(|| {
        format!(
          "route {} match.path.regex contains invalid regex",
          route.name
        )
      })?;
    let source_cidrs = config
      .source_cidrs
      .iter()
      .map(|cidr| Cidr::parse(cidr))
      .collect::<anyhow::Result<Vec<_>>>()?;
    let protocols = config
      .protocols
      .iter()
      .map(|protocol| compile_protocol(&route.name, protocol))
      .collect::<anyhow::Result<Vec<_>>>()?;
    let client_cert = compile_client_cert_matcher(&route.name, &config.tls.client_cert)?;
    let specificity = methods.len()
      + headers.len() * 2
      + queries.len() * 2
      + usize::from(config.path.exact.is_some()) * 4
      + usize::from(config.path.regex.is_some()) * 3
      + source_cidrs.len()
      + protocols.len()
      + client_cert.specificity();

    Ok(Self {
      valid: true,
      methods,
      headers,
      queries,
      path_exact: config.path.exact.clone(),
      path_regex,
      source_cidrs,
      protocols,
      client_cert,
      specificity,
    })
  }

  pub(super) fn never() -> Self {
    Self {
      valid: false,
      methods: Vec::new(),
      headers: Vec::new(),
      queries: Vec::new(),
      path_exact: None,
      path_regex: None,
      source_cidrs: Vec::new(),
      protocols: Vec::new(),
      client_cert: CompiledClientCertMatcher::default(),
      specificity: 0,
    }
  }

  pub(super) fn matches(&self, context: RouteMatchContext<'_>) -> bool {
    if !self.valid {
      return false;
    }
    if !self.methods.is_empty()
      && !context
        .method
        .is_some_and(|method| self.methods.iter().any(|candidate| candidate == method))
    {
      return false;
    }
    if !self.headers.is_empty() {
      let Some(headers) = context.headers else {
        return false;
      };
      if !self
        .headers
        .iter()
        .all(|matcher| matcher.matches_header(headers))
      {
        return false;
      }
    }
    if !self.queries.is_empty() {
      let Some(query) = context.query else {
        return false;
      };
      if !self
        .queries
        .iter()
        .all(|matcher| matcher.matches_query(query))
      {
        return false;
      }
    }
    if let Some(exact) = &self.path_exact
      && context.path != exact
    {
      return false;
    }
    if let Some(regex) = &self.path_regex
      && !regex.is_match(context.path)
    {
      return false;
    }
    if !self.source_cidrs.is_empty()
      && !context
        .source_ip
        .is_some_and(|ip| self.source_cidrs.iter().any(|cidr| cidr.contains(ip)))
    {
      return false;
    }
    if !self.protocols.is_empty()
      && !context.protocol.is_some_and(|protocol| {
        self
          .protocols
          .iter()
          .any(|matcher| matcher.matches(protocol))
      })
    {
      return false;
    }
    self.client_cert.matches(context.tls)
  }

  pub(super) fn specificity(&self) -> usize {
    self.specificity
  }
}

impl CompiledRouteProtocol {
  fn matches(self, protocol: RouteRequestProtocol) -> bool {
    match self {
      Self::Http => matches!(
        protocol,
        RouteRequestProtocol::Http1 | RouteRequestProtocol::Http2 | RouteRequestProtocol::Http3
      ),
      Self::Http1 => protocol == RouteRequestProtocol::Http1,
      Self::Http2 => protocol == RouteRequestProtocol::Http2,
      Self::Http3 => protocol == RouteRequestProtocol::Http3,
      Self::Websocket => protocol == RouteRequestProtocol::Websocket,
      Self::Webtransport => protocol == RouteRequestProtocol::Webtransport,
    }
  }
}

impl CompiledNamedValueMatcher {
  fn matches_header(&self, headers: &HeaderMap) -> bool {
    let Some(name) = &self.header_name else {
      return false;
    };
    self.value.matches(
      headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok()),
    )
  }

  fn matches_query(&self, query: &str) -> bool {
    let values = url::form_urlencoded::parse(query.as_bytes())
      .filter_map(|(name, value)| (name == self.name).then_some(value.into_owned()))
      .collect::<Vec<_>>();
    self.value.matches(values.iter().map(String::as_str))
  }
}

impl CompiledValueMatcher {
  fn from_config(
    route_name: &str,
    field_name: &str,
    config: &RouteValueMatchConfig,
  ) -> anyhow::Result<Option<Self>> {
    if let Some(present) = config.present {
      return Ok(Some(Self::Present(present)));
    }
    if let Some(exact) = &config.exact {
      return Ok(Some(Self::Exact(exact.clone())));
    }
    if let Some(prefix) = &config.prefix {
      return Ok(Some(Self::Prefix(prefix.clone())));
    }
    if let Some(suffix) = &config.suffix {
      return Ok(Some(Self::Suffix(suffix.clone())));
    }
    if let Some(contains) = &config.contains {
      return Ok(Some(Self::Contains(contains.clone())));
    }
    if let Some(regex) = &config.regex {
      return Ok(Some(Self::Regex(Regex::new(regex).with_context(|| {
        format!("route {route_name} {field_name} contains invalid regex")
      })?)));
    }
    Ok(None)
  }

  fn matches<'a>(&self, values: impl IntoIterator<Item = &'a str>) -> bool {
    let mut saw_value = false;
    let mut matched = false;
    for value in values {
      saw_value = true;
      matched |= match self {
        Self::Present(_) => false,
        Self::Exact(expected) => value == expected,
        Self::Prefix(prefix) => value.starts_with(prefix),
        Self::Suffix(suffix) => value.ends_with(suffix),
        Self::Contains(needle) => value.contains(needle),
        Self::Regex(regex) => regex.is_match(value),
      };
    }
    match self {
      Self::Present(true) => saw_value,
      Self::Present(false) => !saw_value,
      _ => saw_value && matched,
    }
  }
}

impl CompiledClientCertMatcher {
  fn specificity(&self) -> usize {
    usize::from(self.present.is_some())
      + usize::from(self.fingerprint_sha256.is_some()) * 3
      + usize::from(self.subject_cn.is_some()) * 2
      + usize::from(self.san_dns.is_some()) * 2
      + usize::from(self.san_ip.is_some()) * 2
  }

  fn matches(&self, tls: Option<&WafTlsMetadata>) -> bool {
    if self.specificity() == 0 {
      return true;
    }
    let cert = tls.and_then(|tls| tls.client_certificate.as_ref());
    if let Some(present) = self.present
      && (cert.is_some()) != present
    {
      return false;
    }
    let Some(cert) = cert else {
      return self.present == Some(false) && self.specificity() == 1;
    };
    if let Some(matcher) = &self.fingerprint_sha256
      && !matcher.matches([cert.fingerprint_sha256.as_str()])
    {
      return false;
    }
    if let Some(matcher) = &self.subject_cn
      && !matcher.matches(cert.subject_common_names.iter().map(String::as_str))
    {
      return false;
    }
    if let Some(matcher) = &self.san_dns
      && !matcher.matches(cert.san_dns_names.iter().map(String::as_str))
    {
      return false;
    }
    if let Some(matcher) = &self.san_ip
      && !matcher.matches(cert.san_ip_addresses.iter().map(String::as_str))
    {
      return false;
    }
    true
  }
}

fn compile_named_value_matcher(
  route_name: &str,
  field_name: &str,
  matcher: &RouteNamedValueMatchConfig,
  header_name: bool,
) -> anyhow::Result<CompiledNamedValueMatcher> {
  let header_name = header_name
    .then(|| HeaderName::from_bytes(matcher.name.as_bytes()))
    .transpose()
    .with_context(|| format!("route {route_name} {field_name} contains invalid header name"))?;
  let value = CompiledValueMatcher::from_config(route_name, field_name, &matcher.value)?
    .with_context(|| format!("route {route_name} {field_name} has no value matcher"))?;
  Ok(CompiledNamedValueMatcher {
    name: matcher.name.clone(),
    header_name,
    value,
  })
}

fn compile_client_cert_matcher(
  route_name: &str,
  config: &RouteClientCertMatchConfig,
) -> anyhow::Result<CompiledClientCertMatcher> {
  Ok(CompiledClientCertMatcher {
    present: config.present,
    fingerprint_sha256: CompiledValueMatcher::from_config(
      route_name,
      "match.tls.client_cert.fingerprint_sha256",
      &config.fingerprint_sha256,
    )?,
    subject_cn: CompiledValueMatcher::from_config(
      route_name,
      "match.tls.client_cert.subject_cn",
      &config.subject_cn,
    )?,
    san_dns: CompiledValueMatcher::from_config(
      route_name,
      "match.tls.client_cert.san_dns",
      &config.san_dns,
    )?,
    san_ip: CompiledValueMatcher::from_config(
      route_name,
      "match.tls.client_cert.san_ip",
      &config.san_ip,
    )?,
  })
}

fn compile_protocol(route_name: &str, protocol: &str) -> anyhow::Result<CompiledRouteProtocol> {
  match protocol {
    "http" => Ok(CompiledRouteProtocol::Http),
    "http1" => Ok(CompiledRouteProtocol::Http1),
    "http2" => Ok(CompiledRouteProtocol::Http2),
    "http3" => Ok(CompiledRouteProtocol::Http3),
    "websocket" => Ok(CompiledRouteProtocol::Websocket),
    "webtransport" => Ok(CompiledRouteProtocol::Webtransport),
    _ => anyhow::bail!("route {route_name} match.protocols contains unsupported protocol"),
  }
}
