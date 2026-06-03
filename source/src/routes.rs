//! Route lookup and per-route execution planning.
//! Host and path matching stay deterministic because routing decides which policy boundary applies.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::config::{Config, RouteConfig, UpstreamConfig};
use crate::waf::WafEngine;

mod plan;
use self::plan::route_execution_plan;
pub use self::plan::{FastPathPlan, RouteExecutionPlan, RouteWafExecutionPlan, WafExecutionPlan};

/// Immutable route index built from validated configuration.
#[derive(Debug, Clone)]
pub struct RouteTable {
  routes: Vec<RouteEntry>,
  exact_hosts: HashMap<String, Vec<usize>>,
  wildcard_hosts: WildcardHostTrie,
  catch_all_hosts: Vec<usize>,
}

#[derive(Debug, Clone)]
struct RouteEntry {
  route: RouteConfig,
  execution_plan: RouteExecutionPlan,
  upstream_index: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct WildcardHostEntry {
  suffix_len: usize,
  route_index: usize,
}

#[derive(Debug, Clone, Default)]
struct WildcardHostTrie {
  root: WildcardHostTrieNode,
}

#[derive(Debug, Clone, Default)]
struct WildcardHostTrieNode {
  routes: Vec<WildcardHostEntry>,
  children: HashMap<String, WildcardHostTrieNode>,
}

impl WildcardHostTrie {
  fn insert(&mut self, suffix: &str, route_index: usize) {
    let mut node = &mut self.root;
    for label in suffix.rsplit('.') {
      node = node.children.entry(label.to_string()).or_default();
    }
    node.routes.push(WildcardHostEntry {
      suffix_len: suffix.len(),
      route_index,
    });
  }

  fn for_each_match(&self, host: &str, mut visit: impl FnMut(WildcardHostEntry)) {
    if host.split('.').any(str::is_empty) {
      return;
    }

    let host_label_count = host.split('.').count();
    let mut node = &self.root;
    for (depth, label) in host.rsplit('.').enumerate() {
      let Some(child) = node.children.get(label) else {
        break;
      };
      node = child;

      if depth + 1 < host_label_count {
        for &route in &node.routes {
          visit(route);
        }
      }
    }
  }
}

/// Borrowed route resolution result used by request handlers.
#[derive(Debug, Clone)]
pub struct ResolvedRoute<'a> {
  pub route: &'a RouteConfig,
  pub upstream: Option<&'a UpstreamConfig>,
  pub upstream_index: Option<usize>,
  pub execution_plan: &'a RouteExecutionPlan,
}

impl RouteTable {
  pub fn new(config: &Config) -> Self {
    Self::new_with_waf_plan(config, |_| RouteWafExecutionPlan::disabled())
  }

  pub fn new_with_waf(config: &Config, waf: &WafEngine) -> Self {
    Self::new_with_waf_plan(config, |route| {
      RouteWafExecutionPlan::from_waf(&route.name, waf)
    })
  }

  fn new_with_waf_plan(
    config: &Config,
    mut waf_plan_for_route: impl FnMut(&RouteConfig) -> RouteWafExecutionPlan,
  ) -> Self {
    let upstream_indices: HashMap<&str, usize> = config
      .upstreams
      .iter()
      .enumerate()
      .map(|(index, upstream)| (upstream.name.as_str(), index))
      .collect();
    let mut table = Self::empty();
    for route in &config.routes {
      let waf = waf_plan_for_route(route);
      let execution_plan = route_execution_plan(config, route, waf);
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
      wildcard_hosts: WildcardHostTrie::default(),
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
        self.wildcard_hosts.insert(suffix, route_index);
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
    self.resolve_normalized_host(&normalized_host, path, upstreams)
  }

  pub(crate) fn resolve_normalized_host<'a>(
    &'a self,
    normalized_host: &str,
    path: &str,
    upstreams: &'a [UpstreamConfig],
  ) -> Option<ResolvedRoute<'a>> {
    let mut best = None;

    if let Some(route_indices) = self.exact_hosts.get(normalized_host) {
      let host_score = 10_000 + normalized_host.len();
      for &route_index in route_indices {
        self.consider_route(&mut best, route_index, host_score, path);
      }
      if let Some(route_match) = best {
        return Some(self.resolve_match(route_match, upstreams));
      }
    }

    self
      .wildcard_hosts
      .for_each_match(normalized_host, |wildcard| {
        self.consider_route(
          &mut best,
          wildcard.route_index,
          1_000 + wildcard.suffix_len,
          path,
        );
      });
    if let Some(route_match) = best {
      return Some(self.resolve_match(route_match, upstreams));
    }

    for &route_index in &self.catch_all_hosts {
      self.consider_route(&mut best, route_index, 1, path);
    }

    Some(self.resolve_match(best?, upstreams))
  }

  fn resolve_match<'a>(
    &'a self,
    route_match: RouteMatch,
    upstreams: &'a [UpstreamConfig],
  ) -> ResolvedRoute<'a> {
    let entry = &self.routes[route_match.route_index];
    let route = &entry.route;
    let (upstream_index, upstream) = match (entry.upstream_index, route.upstream.as_deref()) {
      (Some(index), Some(name)) => match upstreams
        .get(index)
        .filter(|upstream| upstream.name == name)
      {
        Some(upstream) => (Some(index), Some(upstream)),
        None => upstreams
          .iter()
          .enumerate()
          .find(|(_, item)| item.name == name)
          .map(|(index, upstream)| (Some(index), Some(upstream)))
          .unwrap_or((None, None)),
      },
      (Some(index), None) => (upstreams.get(index).map(|_| index), upstreams.get(index)),
      (None, Some(name)) => upstreams
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == name)
        .map(|(index, upstream)| (Some(index), Some(upstream)))
        .unwrap_or((None, None)),
      (None, None) => (None, None),
    };
    ResolvedRoute {
      route,
      upstream,
      upstream_index,
      execution_plan: &entry.execution_plan,
    }
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

/// Normalizes a host value for route matching without validating ownership.
pub fn normalize_host(raw: &str) -> String {
  normalize_host_cow(raw).into_owned()
}

pub fn normalize_host_cow(raw: &str) -> Cow<'_, str> {
  let trimmed = raw.trim().trim_end_matches('.');
  if trimmed.starts_with('[')
    && let Some(end) = trimmed.find(']')
  {
    return ascii_lower_cow(&trimmed[1..end]);
  }

  if let Some((host, port)) = trimmed.rsplit_once(':')
    && !host.contains(':')
    && !port.is_empty()
    && port.chars().all(|ch| ch.is_ascii_digit())
  {
    return ascii_lower_cow(host);
  }

  ascii_lower_cow(trimmed)
}

fn ascii_lower_cow(value: &str) -> Cow<'_, str> {
  if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
    Cow::Owned(value.to_ascii_lowercase())
  } else {
    Cow::Borrowed(value)
  }
}

/// Returns whether a request path is within a configured route prefix boundary.
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
      pool_max_idle_per_host: 128,
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
      external_auth: None,
      ipm: Default::default(),
      cache: None,
      compression: None,
      buffering: Default::default(),
      timeouts: Default::default(),
      retry: None,
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
        external_auth: None,
        ipm: Default::default(),
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        retry: None,
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
        external_auth: None,
        ipm: Default::default(),
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        retry: None,
        waf: Default::default(),
      },
    ];
    let upstreams = vec![upstream("wild"), upstream("exact")];
    let table = RouteTable::from_routes_for_tests(routes);

    let resolved = table.resolve("api.example.com", "/v1", &upstreams).unwrap();
    assert_eq!(resolved.route.name, "exact");
  }

  #[test]
  fn normalized_host_resolve_matches_raw_resolve() {
    let routes = vec![
      route("fallback", &["*"], "/", "fallback"),
      route("exact", &["api.example.com"], "/v1", "exact"),
    ];
    let upstreams = vec![upstream("fallback"), upstream("exact")];
    let table = RouteTable::from_routes_for_tests(routes);

    let raw = table
      .resolve("API.example.com:8443", "/v1/users", &upstreams)
      .unwrap();
    let normalized = table
      .resolve_normalized_host("api.example.com", "/v1/users", &upstreams)
      .unwrap();

    assert_eq!(raw.route.name, normalized.route.name);
    assert_eq!(normalized.route.name, "exact");
    assert_eq!(
      raw.upstream.unwrap().name,
      normalized.upstream.unwrap().name
    );
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
        external_auth: None,
        ipm: Default::default(),
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        retry: None,
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
        external_auth: None,
        ipm: Default::default(),
        cache: None,
        compression: None,
        buffering: Default::default(),
        timeouts: Default::default(),
        retry: None,
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
  fn normalize_host_cow_borrows_common_normalized_hosts() {
    assert!(matches!(
      normalize_host_cow("example.com"),
      std::borrow::Cow::Borrowed("example.com")
    ));
    assert!(matches!(
      normalize_host_cow("example.com:8443"),
      std::borrow::Cow::Borrowed("example.com")
    ));
    assert!(matches!(
      normalize_host_cow("Example.com"),
      std::borrow::Cow::Owned(value) if value == "example.com"
    ));
    assert_eq!(normalize_host("Example.com."), "example.com");
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
  fn wildcard_hosts_ignore_empty_request_labels() {
    let routes = vec![
      route("fallback", &["*"], "/", "fallback"),
      route("wild", &["*.example.com"], "/", "wild"),
    ];
    let upstreams = vec![upstream("fallback"), upstream("wild")];
    let table = RouteTable::from_routes_for_tests(routes);

    for host in [".example.com", "api..example.com", "example.com"] {
      let resolved = table.resolve(host, "/", &upstreams).unwrap();

      assert_eq!(resolved.route.name, "fallback");
      assert_eq!(resolved.upstream.unwrap().name, "fallback");
    }

    for host in ["api.example.com", "v1.api.example.com"] {
      let resolved = table.resolve(host, "/", &upstreams).unwrap();

      assert_eq!(resolved.route.name, "wild");
      assert_eq!(resolved.upstream.unwrap().name, "wild");
    }
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

  #[test]
  fn many_wildcards_preserve_priority_rules() {
    let mut routes = Vec::new();
    for index in 0..512 {
      let name = format!("noise-{index}");
      let host = format!("*.tenant-{index}.noise.example.net");
      routes.push(route(&name, &[host.as_str()], "/", &name));
    }
    routes.extend([
      route("fallback", &["*"], "/", "fallback"),
      route("broad", &["*.example.com"], "/", "broad"),
      route("narrow", &["*.api.example.com"], "/", "narrow"),
      route("path-root", &["*.path.example.com"], "/", "path-root"),
      route("path-api", &["*.path.example.com"], "/api", "path-api"),
      route("tie-first", &["*.tie.example.com"], "/api", "tie-first"),
      route("tie-second", &["*.tie.example.com"], "/api", "tie-second"),
      route(
        "target-wild",
        &["*.target.example.com"],
        "/api",
        "target-wild",
      ),
      route(
        "target-exact",
        &["exact.target.example.com"],
        "/",
        "target-exact",
      ),
    ]);
    let upstreams = routes
      .iter()
      .map(|route| upstream(route.upstream.as_deref().unwrap()))
      .collect::<Vec<_>>();
    let table = RouteTable::from_routes_for_tests(routes);

    assert_eq!(
      table
        .resolve("v1.api.example.com", "/", &upstreams)
        .unwrap()
        .route
        .name,
      "narrow"
    );
    assert_eq!(
      table
        .resolve("api.example.com", "/", &upstreams)
        .unwrap()
        .route
        .name,
      "broad"
    );
    assert_eq!(
      table
        .resolve("svc.path.example.com", "/api/users", &upstreams)
        .unwrap()
        .route
        .name,
      "path-api"
    );
    assert_eq!(
      table
        .resolve("svc.tie.example.com", "/api/users", &upstreams)
        .unwrap()
        .route
        .name,
      "tie-first"
    );
    assert_eq!(
      table
        .resolve("exact.target.example.com", "/api/users", &upstreams)
        .unwrap()
        .route
        .name,
      "target-exact"
    );
    assert_eq!(
      table
        .resolve("unmatched.example.org", "/anything", &upstreams)
        .unwrap()
        .route
        .name,
      "fallback"
    );
  }
}
