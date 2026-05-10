use crate::config::{RouteConfig, UpstreamConfig};

#[derive(Debug, Clone)]
pub struct RouteTable {
  routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone)]
pub struct ResolvedRoute<'a> {
  pub route: &'a RouteConfig,
  pub upstream: Option<&'a UpstreamConfig>,
}

impl RouteTable {
  pub fn new(routes: Vec<RouteConfig>) -> Self {
    Self { routes }
  }

  pub fn resolve<'a>(
    &'a self,
    host: &str,
    path: &str,
    upstreams: &'a [UpstreamConfig],
  ) -> Option<ResolvedRoute<'a>> {
    let normalized_host = normalize_host(host);
    let mut best: Option<(&RouteConfig, usize, usize)> = None;

    for route in &self.routes {
      let Some(host_score) = route
        .hosts
        .iter()
        .filter_map(|pattern| match_host_pattern(pattern, &normalized_host))
        .max()
      else {
        continue;
      };

      if !path_prefix_matches(&route.path_prefix, path) {
        continue;
      }

      let score = (host_score, route.path_prefix.len());
      match best {
        Some((_, best_host_score, best_path_len))
          if best_host_score > score.0
            || (best_host_score == score.0 && best_path_len >= score.1) => {}
        _ => best = Some((route, score.0, score.1)),
      }
    }

    let (route, _, _) = best?;
    let upstream = route
      .upstream
      .as_deref()
      .and_then(|name| upstreams.iter().find(|item| item.name == name));
    Some(ResolvedRoute { route, upstream })
  }
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

fn match_host_pattern(pattern: &str, host: &str) -> Option<usize> {
  let pattern = normalize_host(pattern);
  if pattern == "*" {
    return Some(1);
  }
  if pattern == host {
    return Some(10_000 + pattern.len());
  }
  if let Some(suffix) = pattern.strip_prefix("*.") {
    return host
      .strip_suffix(suffix)
      .filter(|prefix| prefix.ends_with('.') && prefix.len() > 1)
      .map(|_| 1_000 + suffix.len());
  }
  None
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
    let table = RouteTable::new(routes);

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
    let table = RouteTable::new(routes);

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
}
