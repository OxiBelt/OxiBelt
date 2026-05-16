use std::collections::HashMap;

use crate::config::{BufferingMode, Config, ErrorResponseMode, RouteConfig, UpstreamConfig};

#[derive(Debug, Clone)]
pub struct RouteTable {
  routes: Vec<RouteEntry>,
  exact_hosts: HashMap<String, Vec<usize>>,
  wildcard_hosts: Vec<WildcardHostEntry>,
  catch_all_hosts: Vec<usize>,
}

#[derive(Debug, Clone)]
struct RouteEntry {
  route: RouteConfig,
  execution_plan: RouteExecutionPlan,
  upstream_index: Option<usize>,
}

#[derive(Debug, Clone)]
struct WildcardHostEntry {
  suffix: String,
  route_index: usize,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RouteExecutionPlan {
  pub can_plain_proxy_fast_path: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedRoute<'a> {
  pub route: &'a RouteConfig,
  pub upstream: Option<&'a UpstreamConfig>,
  pub execution_plan: &'a RouteExecutionPlan,
}

impl RouteTable {
  pub fn new(config: &Config) -> Self {
    let upstream_indices: HashMap<&str, usize> = config
      .upstreams
      .iter()
      .enumerate()
      .map(|(index, upstream)| (upstream.name.as_str(), index))
      .collect();
    let mut table = Self::empty();
    for route in &config.routes {
      let execution_plan = RouteExecutionPlan {
        can_plain_proxy_fast_path: can_plain_proxy_fast_path(config, route),
      };
      let upstream_index = route
        .upstream
        .as_deref()
        .and_then(|name| upstream_indices.get(name).copied());
      table.push_route(route.clone(), execution_plan, upstream_index);
    }
    table
  }

  #[cfg(test)]
  fn from_routes_for_tests(routes: Vec<RouteConfig>) -> Self {
    let mut table = Self::empty();
    for route in routes {
      table.push_route(route, RouteExecutionPlan::default(), None);
    }
    table
  }

  fn empty() -> Self {
    Self {
      routes: Vec::new(),
      exact_hosts: HashMap::new(),
      wildcard_hosts: Vec::new(),
      catch_all_hosts: Vec::new(),
    }
  }

  fn push_route(
    &mut self,
    route: RouteConfig,
    execution_plan: RouteExecutionPlan,
    upstream_index: Option<usize>,
  ) {
    let route_index = self.routes.len();
    for pattern in &route.hosts {
      let pattern = normalize_host(pattern);
      if pattern == "*" {
        self.catch_all_hosts.push(route_index);
      } else if let Some(suffix) = pattern.strip_prefix("*.") {
        self.wildcard_hosts.push(WildcardHostEntry {
          suffix: suffix.to_string(),
          route_index,
        });
      } else {
        self
          .exact_hosts
          .entry(pattern)
          .or_default()
          .push(route_index);
      }
    }
    self.routes.push(RouteEntry {
      route,
      execution_plan,
      upstream_index,
    });
  }

  pub fn resolve<'a>(
    &'a self,
    host: &str,
    path: &str,
    upstreams: &'a [UpstreamConfig],
  ) -> Option<ResolvedRoute<'a>> {
    let normalized_host = normalize_host(host);
    let mut best = None;

    if let Some(route_indices) = self.exact_hosts.get(&normalized_host) {
      let host_score = 10_000 + normalized_host.len();
      for &route_index in route_indices {
        self.consider_route(&mut best, route_index, host_score, path);
      }
    }

    for wildcard in &self.wildcard_hosts {
      if wildcard_matches(&wildcard.suffix, &normalized_host) {
        self.consider_route(
          &mut best,
          wildcard.route_index,
          1_000 + wildcard.suffix.len(),
          path,
        );
      }
    }

    for &route_index in &self.catch_all_hosts {
      self.consider_route(&mut best, route_index, 1, path);
    }

    let entry = &self.routes[best?.route_index];
    let route = &entry.route;
    let upstream = match (entry.upstream_index, route.upstream.as_deref()) {
      (Some(index), Some(name)) => upstreams
        .get(index)
        .filter(|upstream| upstream.name == name)
        .or_else(|| upstreams.iter().find(|item| item.name == name)),
      (Some(index), None) => upstreams.get(index),
      (None, Some(name)) => upstreams.iter().find(|item| item.name == name),
      (None, None) => None,
    };
    Some(ResolvedRoute {
      route,
      upstream,
      execution_plan: &entry.execution_plan,
    })
  }

  fn consider_route(
    &self,
    best: &mut Option<RouteMatch>,
    route_index: usize,
    host_score: usize,
    path: &str,
  ) {
    let Some(entry) = self.routes.get(route_index) else {
      return;
    };
    if !path_prefix_matches(&entry.route.path_prefix, path) {
      return;
    }

    let candidate = RouteMatch {
      route_index,
      host_score,
      path_len: entry.route.path_prefix.len(),
    };
    if best
      .as_ref()
      .is_none_or(|current| candidate.is_better_than(current))
    {
      *best = Some(candidate);
    }
  }
}

#[derive(Debug, Clone, Copy)]
struct RouteMatch {
  route_index: usize,
  host_score: usize,
  path_len: usize,
}

impl RouteMatch {
  fn is_better_than(self, current: &Self) -> bool {
    self.host_score > current.host_score
      || (self.host_score == current.host_score && self.path_len > current.path_len)
      || (self.host_score == current.host_score
        && self.path_len == current.path_len
        && self.route_index < current.route_index)
  }
}

fn can_plain_proxy_fast_path(config: &Config, route: &RouteConfig) -> bool {
  !config.waf.enabled
    && config.rate_limits.is_empty()
    && !config.dynamic_policy.enabled
    && (!config.compression.enabled || route.compression.as_deref() == Some("off"))
    && route.static_root.is_none()
    && route.upstream_pool.is_none()
    && !route.grpc_web
    && !route.generic_http_upgrade
    && !route.connect_tunneling
    && route.buffering.request.is_none()
    && route.buffering.response.is_none()
    && config.proxy.buffering.request == BufferingMode::Streaming
    && config.proxy.buffering.response == BufferingMode::Streaming
    && config.proxy.http.errors.mode != ErrorResponseMode::Json
}

pub fn normalize_host(raw: &str) -> String {
  let trimmed = raw.trim().trim_end_matches('.');
  if trimmed.starts_with('[')
    && let Some(end) = trimmed.find(']')
  {
    return trimmed[1..end].to_ascii_lowercase();
  }

  if let Some((host, port)) = trimmed.rsplit_once(':')
    && !host.contains(':')
    && !port.is_empty()
    && port.chars().all(|ch| ch.is_ascii_digit())
  {
    return host.to_ascii_lowercase();
  }

  trimmed.to_ascii_lowercase()
}

fn wildcard_matches(suffix: &str, host: &str) -> bool {
  host
    .strip_suffix(suffix)
    .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
}

pub fn path_prefix_matches(prefix: &str, path: &str) -> bool {
  if prefix == "/" {
    return true;
  }
  if path == prefix {
    return true;
  }
  if let Some(rest) = path.strip_prefix(prefix) {
    return rest.starts_with('/');
  }
  false
}

#[cfg(test)]
mod tests {
  use pretty_assertions::assert_eq;
  use url::Url;

  use super::*;
  use crate::config::{HttpVersion, ProxyProtocolEgressMode, RouteConfig, UpstreamConfig};

  fn upstream(name: &str) -> UpstreamConfig {
    UpstreamConfig {
      name: name.to_string(),
      origin: Url::parse("https://upstream.internal").unwrap(),
      max_http_version: HttpVersion::H2,
      connect_timeout_ms: 1_000,
      request_timeout_ms: 10_000,
      first_byte_timeout_ms: 10_000,
      read_timeout_ms: 10_000,
      send_timeout_ms: 10_000,
      idle_timeout_ms: 75_000,
      preserve_host: false,
      websocket: true,
      webrtc: true,
      webtransport: true,
      proxy_protocol_egress: ProxyProtocolEgressMode::Off,
      tls: Default::default(),
    }
  }

  fn route(name: &str, hosts: &[&str], path_prefix: &str, upstream: &str) -> RouteConfig {
    RouteConfig {
      name: name.into(),
      hosts: hosts.iter().map(|host| (*host).into()).collect(),
      path_prefix: path_prefix.into(),
      replace_prefix_with: None,
      upstream: Some(upstream.into()),
      upstream_pool: None,
      static_root: None,
      upstream_http_version: None,
      generic_http_upgrade: false,
      connect_tunneling: false,
      grpc_web: false,
      cache: None,
      compression: None,
      buffering: Default::default(),
      timeouts: Default::default(),
      waf: Default::default(),
    }
  }

  #[test]
  fn exact_host_beats_wildcard() {
    let routes = vec![
      RouteConfig {
        name: "wild".into(),
        hosts: vec!["*.example.com".into()],
        path_prefix: "/".into(),
        replace_prefix_with: None,
        upstream: Some("wild".into()),
        upstream_pool: None,
        static_root: None,
        upstream_http_version: None,
        generic_http_upgrade: false,
        connect_tunneling: false,
        grpc_web: false,
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        waf: Default::default(),
      },
      RouteConfig {
        name: "exact".into(),
        hosts: vec!["api.example.com".into()],
        path_prefix: "/".into(),
        replace_prefix_with: None,
        upstream: Some("exact".into()),
        upstream_pool: None,
        static_root: None,
        upstream_http_version: None,
        generic_http_upgrade: false,
        connect_tunneling: false,
        grpc_web: false,
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        waf: Default::default(),
      },
    ];
    let upstreams = vec![upstream("wild"), upstream("exact")];
    let table = RouteTable::from_routes_for_tests(routes);

    let resolved = table.resolve("api.example.com", "/v1", &upstreams).unwrap();
    assert_eq!(resolved.route.name, "exact");
  }

  #[test]
  fn longer_path_prefix_wins() {
    let routes = vec![
      RouteConfig {
        name: "root".into(),
        hosts: vec!["example.com".into()],
        path_prefix: "/".into(),
        replace_prefix_with: None,
        upstream: Some("root".into()),
        upstream_pool: None,
        static_root: None,
        upstream_http_version: None,
        generic_http_upgrade: false,
        connect_tunneling: false,
        grpc_web: false,
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        waf: Default::default(),
      },
      RouteConfig {
        name: "api".into(),
        hosts: vec!["example.com".into()],
        path_prefix: "/api".into(),
        replace_prefix_with: None,
        upstream: Some("api".into()),
        upstream_pool: None,
        static_root: None,
        upstream_http_version: None,
        generic_http_upgrade: false,
        connect_tunneling: false,
        grpc_web: false,
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        waf: Default::default(),
      },
    ];
    let upstreams = vec![upstream("root"), upstream("api")];
    let table = RouteTable::from_routes_for_tests(routes);

    let resolved = table
      .resolve("example.com", "/api/users", &upstreams)
      .unwrap();
    assert_eq!(resolved.route.name, "api");
  }

  #[test]
  fn normalize_host_removes_port() {
    assert_eq!(normalize_host("Example.com:8443"), "example.com");
    assert_eq!(normalize_host("[2001:db8::1]:8443"), "2001:db8::1");
  }

  #[test]
  fn longer_wildcard_suffix_wins() {
    let routes = vec![
      route("broad", &["*.example.com"], "/", "broad"),
      route("narrow", &["*.api.example.com"], "/", "narrow"),
    ];
    let upstreams = vec![upstream("broad"), upstream("narrow")];
    let table = RouteTable::from_routes_for_tests(routes);

    let resolved = table
      .resolve("v1.api.example.com", "/", &upstreams)
      .unwrap();

    assert_eq!(resolved.route.name, "narrow");
    assert_eq!(resolved.upstream.unwrap().name, "narrow");
  }

  #[test]
  fn catch_all_host_is_fallback() {
    let routes = vec![
      route("fallback", &["*"], "/", "fallback"),
      route("exact", &["api.example.com"], "/", "exact"),
    ];
    let upstreams = vec![upstream("fallback"), upstream("exact")];
    let table = RouteTable::from_routes_for_tests(routes);

    assert_eq!(
      table
        .resolve("api.example.com", "/", &upstreams)
        .unwrap()
        .route
        .name,
      "exact"
    );
    assert_eq!(
      table
        .resolve("other.example.com", "/", &upstreams)
        .unwrap()
        .route
        .name,
      "fallback"
    );
  }

  #[test]
  fn equal_host_and_path_score_keeps_route_order() {
    let routes = vec![
      route("first", &["api.example.com"], "/api", "first"),
      route("second", &["api.example.com"], "/api", "second"),
    ];
    let upstreams = vec![upstream("first"), upstream("second")];
    let table = RouteTable::from_routes_for_tests(routes);

    let resolved = table
      .resolve("api.example.com", "/api/users", &upstreams)
      .unwrap();

    assert_eq!(resolved.route.name, "first");
  }
}
