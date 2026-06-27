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
    max_lifetime_ms: 3_600_000,
    pool_max_idle_per_host: 128,
    preserve_host: false,
    websocket: true,
    webrtc: true,
    webtransport: true,
    proxy_protocol_egress: ProxyProtocolEgressMode::Off,
    tls: Default::default(),
    extra_trusted_ca_certs: Vec::new(),
  }
}

fn route(name: &str, hosts: &[&str], path_prefix: &str, upstream: &str) -> RouteConfig {
  RouteConfig {
    name: name.into(),
    hosts: hosts.iter().map(|host| (*host).into()).collect(),
    path_prefix: path_prefix.into(),
    r#match: Default::default(),
    replace_prefix_with: None,
    actions: Default::default(),
    upstream: Some(upstream.into()),
    upstream_pool: None,
    static_root: None,
    static_files: Default::default(),
    upstream_http_version: None,
    generic_http_upgrade: false,
    connect_tunneling: false,
    grpc_web: false,
    external_auth: None,
    ipm: Default::default(),
    cache: None,
    compression: None,
    buffering: Default::default(),
    limits: Default::default(),
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
      r#match: Default::default(),
      replace_prefix_with: None,
      actions: Default::default(),
      upstream: Some("wild".into()),
      upstream_pool: None,
      static_root: None,
      static_files: Default::default(),
      upstream_http_version: None,
      generic_http_upgrade: false,
      connect_tunneling: false,
      grpc_web: false,
      external_auth: None,
      ipm: Default::default(),
      cache: None,
      compression: None,
      buffering: Default::default(),
      limits: Default::default(),
      timeouts: Default::default(),
      retry: None,
      waf: Default::default(),
    },
    RouteConfig {
      name: "exact".into(),
      hosts: vec!["api.example.com".into()],
      path_prefix: "/".into(),
      r#match: Default::default(),
      replace_prefix_with: None,
      actions: Default::default(),
      upstream: Some("exact".into()),
      upstream_pool: None,
      static_root: None,
      static_files: Default::default(),
      upstream_http_version: None,
      generic_http_upgrade: false,
      connect_tunneling: false,
      grpc_web: false,
      external_auth: None,
      ipm: Default::default(),
      cache: None,
      compression: None,
      buffering: Default::default(),
      limits: Default::default(),
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
fn simple_exact_host_resolution_keeps_full_resolution_route_index() {
  let routes = vec![
    route("root", &["example.com"], "/", "root"),
    route("api", &["example.com"], "/api", "api"),
  ];
  let upstreams = vec![upstream("root"), upstream("api")];
  let table = RouteTable::from_routes_for_tests(routes);

  let simple = table
    .try_resolve_simple_exact_host("example.com", "/api/users", &upstreams)
    .expect("simple exact host should resolve");
  let full = table
    .resolve_normalized_host("example.com", "/api/users", &upstreams)
    .expect("full route lookup should resolve");

  assert_eq!(simple.route.name, "api");
  assert_eq!(simple.route_index, full.route_index);
  assert_eq!(simple.upstream.unwrap().name, full.upstream.unwrap().name);
}

#[test]
fn longer_path_prefix_wins() {
  let routes = vec![
    RouteConfig {
      name: "root".into(),
      hosts: vec!["example.com".into()],
      path_prefix: "/".into(),
      r#match: Default::default(),
      replace_prefix_with: None,
      actions: Default::default(),
      upstream: Some("root".into()),
      upstream_pool: None,
      static_root: None,
      static_files: Default::default(),
      upstream_http_version: None,
      generic_http_upgrade: false,
      connect_tunneling: false,
      grpc_web: false,
      external_auth: None,
      ipm: Default::default(),
      cache: None,
      compression: None,
      buffering: Default::default(),
      limits: Default::default(),
      timeouts: Default::default(),
      retry: None,
      waf: Default::default(),
    },
    RouteConfig {
      name: "api".into(),
      hosts: vec!["example.com".into()],
      path_prefix: "/api".into(),
      r#match: Default::default(),
      replace_prefix_with: None,
      actions: Default::default(),
      upstream: Some("api".into()),
      upstream_pool: None,
      static_root: None,
      static_files: Default::default(),
      upstream_http_version: None,
      generic_http_upgrade: false,
      connect_tunneling: false,
      grpc_web: false,
      external_auth: None,
      ipm: Default::default(),
      cache: None,
      compression: None,
      buffering: Default::default(),
      limits: Default::default(),
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
fn simple_exact_host_shortcut_matches_prefix_only_routes() {
  let routes = vec![
    route("root", &["example.com"], "/", "root"),
    route("api", &["example.com"], "/api", "api"),
  ];
  let upstreams = vec![upstream("root"), upstream("api")];
  let table = RouteTable::from_routes_for_tests(routes);

  let shortcut = table
    .try_resolve_simple_exact_host("example.com", "/api/users", &upstreams)
    .expect("simple exact host should resolve");
  let full = table
    .resolve_normalized_host("example.com", "/api/users", &upstreams)
    .expect("full route lookup should resolve");

  assert_eq!(shortcut.route.name, "api");
  assert_eq!(shortcut.route.name, full.route.name);
  assert!(shortcut.path_captures.is_empty());
}

#[test]
fn simple_exact_host_shortcut_opts_out_when_wildcards_can_compete() {
  let routes = vec![
    route("exact", &["api.example.com"], "/", "exact"),
    route("wild", &["*.example.com"], "/", "wild"),
  ];
  let upstreams = vec![upstream("exact"), upstream("wild")];
  let table = RouteTable::from_routes_for_tests(routes);

  assert!(
    table
      .try_resolve_simple_exact_host("api.example.com", "/", &upstreams)
      .is_none()
  );
  assert_eq!(
    table
      .resolve_normalized_host("api.example.com", "/", &upstreams)
      .unwrap()
      .route
      .name,
    "exact"
  );
}

#[test]
fn simple_exact_host_shortcut_opts_out_for_context_matchers() {
  let mut method_route = route("method", &["api.example.com"], "/", "method");
  method_route.r#match.methods = vec!["GET".into()];
  let routes = vec![method_route];
  let upstreams = vec![upstream("method")];
  let table = RouteTable::from_routes_for_tests(routes);

  assert!(
    table
      .try_resolve_simple_exact_host("api.example.com", "/", &upstreams)
      .is_none()
  );
}
