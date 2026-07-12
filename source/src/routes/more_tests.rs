use http::{HeaderMap, HeaderValue, Method};
use pretty_assertions::assert_eq;
use url::Url;

use super::*;
use crate::config::{
  HttpVersion, ProxyProtocolEgressMode, RouteConfig, RouteNamedValueMatchConfig,
  RouteValueMatchConfig, UpstreamConfig,
};
use crate::waf::{WafTlsMetadata, metadata::WafClientCertificateMetadata};

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
    security_headers: None,
    priority_class: Default::default(),
    buffering: Default::default(),
    limits: Default::default(),
    timeouts: Default::default(),
    retry: None,
    circuit_breaker: None,
    tls: Default::default(),
    waf: Default::default(),
  }
}

#[test]
fn extended_matchers_filter_candidates() {
  let mut matched = route("matched", &["api.example.com"], "/", "matched");
  matched.r#match.methods = vec!["POST".to_string()];
  matched.r#match.headers.push(RouteNamedValueMatchConfig {
    name: "x-tenant".to_string(),
    value: RouteValueMatchConfig {
      exact: Some("blue".to_string()),
      ..RouteValueMatchConfig::default()
    },
  });
  matched.r#match.queries.push(RouteNamedValueMatchConfig {
    name: "mode".to_string(),
    value: RouteValueMatchConfig {
      regex: Some("^canary-[0-9]+$".to_string()),
      ..RouteValueMatchConfig::default()
    },
  });
  matched.r#match.source_cidrs = vec!["203.0.113.0/24".to_string()];
  matched.r#match.protocols = vec!["http2".to_string()];
  matched.r#match.tls.client_cert.present = Some(true);
  matched.r#match.tls.client_cert.fingerprint_sha256.exact = Some("abc123".to_string());
  let routes = vec![route("fallback", &["*"], "/", "fallback"), matched];
  let upstreams = vec![upstream("fallback"), upstream("matched")];
  let table = RouteTable::from_routes_for_tests(routes);
  let mut headers = HeaderMap::new();
  headers.insert("x-tenant", HeaderValue::from_static("blue"));
  let tls = WafTlsMetadata {
    client_certificate: Some(WafClientCertificateMetadata {
      fingerprint_sha256: "abc123".to_string(),
      subject_common_names: Vec::new(),
      san_dns_names: Vec::new(),
      san_ip_addresses: Vec::new(),
    }),
    ..WafTlsMetadata::default()
  };

  let resolved = table
    .resolve_normalized_host_with_context(
      "api.example.com",
      RouteMatchContext {
        path: "/",
        method: Some(&Method::POST),
        headers: Some(&headers),
        query: Some("mode=canary-7"),
        source_ip: Some("203.0.113.10".parse().unwrap()),
        protocol: Some(RouteRequestProtocol::Http2),
        tls: Some(&tls),
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved.route.name, "matched");

  let resolved_without_cert = table
    .resolve_normalized_host_with_context(
      "api.example.com",
      RouteMatchContext {
        path: "/",
        method: Some(&Method::POST),
        headers: Some(&headers),
        query: Some("mode=canary-7"),
        source_ip: Some("203.0.113.10".parse().unwrap()),
        protocol: Some(RouteRequestProtocol::Http2),
        tls: Some(&WafTlsMetadata::default()),
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved_without_cert.route.name, "fallback");
}

#[test]
fn regex_path_match_exposes_bounded_captures() {
  let mut matched = route("matched", &["api.example.com"], "/api", "matched");
  matched.r#match.path.regex = Some("^/api/items/([0-9]+)$".to_string());
  let routes = vec![route("fallback", &["*"], "/", "fallback"), matched];
  let upstreams = vec![upstream("fallback"), upstream("matched")];
  let table = RouteTable::from_routes_for_tests(routes);

  let resolved = table
    .resolve("api.example.com", "/api/items/42", &upstreams)
    .unwrap();

  assert_eq!(resolved.route.name, "matched");
  assert_eq!(resolved.path_captures, vec!["/api/items/42", "42"]);
}

#[test]
fn static_sendfile_prefix_metadata_matches_only_origin_form_targets() {
  let mut static_route = route("static", &["api.example.com"], "/static", "static");
  static_route.static_root = Some("/srv/static".into());
  static_route.upstream = None;
  let routes = vec![
    static_route,
    route("fallback", &["api.example.com"], "/", "fallback"),
  ];
  let table = RouteTable::from_routes_for_tests(routes);

  assert!(table.has_static_sendfile_candidates());
  assert!(table.static_sendfile_target_can_match("/static/app.txt"));
  assert!(table.static_sendfile_target_can_match("/static?etag=1"));
  assert!(!table.static_sendfile_target_can_match("/perf/h1?body=ok"));
  assert!(table.static_sendfile_target_can_match("https://api.example.com/static/app.txt"));
  assert!(table.static_sendfile_target_can_match("//api.example.com/static/app.txt"));
}

#[test]
fn query_absence_matcher_accepts_missing_query_string() {
  let mut absent = route("absent-query", &["example.com"], "/", "absent-query");
  absent.r#match.queries.push(RouteNamedValueMatchConfig {
    name: "debug".to_string(),
    value: RouteValueMatchConfig {
      present: Some(false),
      ..RouteValueMatchConfig::default()
    },
  });
  let routes = vec![route("fallback", &["example.com"], "/", "fallback"), absent];
  let upstreams = vec![upstream("fallback"), upstream("absent-query")];
  let table = RouteTable::from_routes_for_tests(routes);

  let resolved = table
    .resolve_normalized_host_with_context(
      "example.com",
      RouteMatchContext {
        path: "/",
        query: None,
        ..RouteMatchContext::default()
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved.route.name, "absent-query");

  let resolved = table
    .resolve_normalized_host_with_context(
      "example.com",
      RouteMatchContext {
        path: "/",
        query: Some("debug=true"),
        ..RouteMatchContext::default()
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved.route.name, "fallback");
}

#[test]
fn header_presence_matcher_counts_raw_header_values() {
  let mut present = route("present-header", &["example.com"], "/", "present-header");
  present.r#match.headers.push(RouteNamedValueMatchConfig {
    name: "x-route-flag".to_string(),
    value: RouteValueMatchConfig {
      present: Some(true),
      ..RouteValueMatchConfig::default()
    },
  });
  let routes = vec![
    route("fallback", &["example.com"], "/", "fallback"),
    present,
  ];
  let upstreams = vec![upstream("fallback"), upstream("present-header")];
  let table = RouteTable::from_routes_for_tests(routes);
  let mut headers = HeaderMap::new();
  headers.insert(
    "x-route-flag",
    HeaderValue::from_bytes(b"flag\xfa").expect("raw header value should be accepted"),
  );

  let resolved = table
    .resolve_normalized_host_with_context(
      "example.com",
      RouteMatchContext {
        path: "/",
        headers: Some(&headers),
        ..RouteMatchContext::default()
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved.route.name, "present-header");
}

#[test]
fn header_absence_matcher_rejects_raw_header_values() {
  let mut absent = route("absent-header", &["example.com"], "/", "absent-header");
  absent.r#match.headers.push(RouteNamedValueMatchConfig {
    name: "x-route-flag".to_string(),
    value: RouteValueMatchConfig {
      present: Some(false),
      ..RouteValueMatchConfig::default()
    },
  });
  let routes = vec![route("fallback", &["example.com"], "/", "fallback"), absent];
  let upstreams = vec![upstream("fallback"), upstream("absent-header")];
  let table = RouteTable::from_routes_for_tests(routes);
  let mut headers = HeaderMap::new();
  headers.insert(
    "x-route-flag",
    HeaderValue::from_bytes(b"flag\xfa").expect("raw header value should be accepted"),
  );

  let resolved = table
    .resolve_normalized_host_with_context(
      "example.com",
      RouteMatchContext {
        path: "/",
        headers: Some(&headers),
        ..RouteMatchContext::default()
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved.route.name, "fallback");

  let empty_headers = HeaderMap::new();
  let resolved = table
    .resolve_normalized_host_with_context(
      "example.com",
      RouteMatchContext {
        path: "/",
        headers: Some(&empty_headers),
        ..RouteMatchContext::default()
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved.route.name, "absent-header");
}

#[test]
fn client_cert_absence_fails_closed_when_http3_metadata_is_unavailable() {
  let mut no_cert = route("no-cert", &["example.com"], "/", "no-cert");
  no_cert.r#match.tls.client_cert.present = Some(false);
  let routes = vec![
    route("fallback", &["example.com"], "/", "fallback"),
    no_cert,
  ];
  let upstreams = vec![upstream("fallback"), upstream("no-cert")];
  let table = RouteTable::from_routes_for_tests(routes);
  let tls = WafTlsMetadata::default();

  let resolved = table
    .resolve_normalized_host_with_context(
      "example.com",
      RouteMatchContext {
        path: "/",
        protocol: Some(RouteRequestProtocol::Http2),
        tls: Some(&tls),
        ..RouteMatchContext::default()
      },
      &upstreams,
    )
    .unwrap();
  assert_eq!(resolved.route.name, "no-cert");

  for protocol in [
    RouteRequestProtocol::Http3,
    RouteRequestProtocol::Webtransport,
  ] {
    let resolved = table
      .resolve_normalized_host_with_context(
        "example.com",
        RouteMatchContext {
          path: "/",
          protocol: Some(protocol),
          tls: Some(&tls),
          ..RouteMatchContext::default()
        },
        &upstreams,
      )
      .unwrap();
    assert_eq!(resolved.route.name, "fallback");
  }
}

#[test]
fn priority_can_beat_host_specificity() {
  let mut wildcard = route("priority", &["*"], "/", "priority");
  wildcard.r#match.priority = 10;
  let routes = vec![route("exact", &["api.example.com"], "/", "exact"), wildcard];
  let upstreams = vec![upstream("exact"), upstream("priority")];
  let table = RouteTable::from_routes_for_tests(routes);

  let resolved = table.resolve("api.example.com", "/", &upstreams).unwrap();

  assert_eq!(resolved.route.name, "priority");
}

#[test]
fn match_path_prefix_is_effective_prefix() {
  let mut api = route("api", &["example.com"], "/", "api");
  api.r#match.path.prefix = Some("/v2".to_string());
  let routes = vec![route("root", &["example.com"], "/", "root"), api];
  let upstreams = vec![upstream("root"), upstream("api")];
  let table = RouteTable::from_routes_for_tests(routes);

  let resolved = table
    .resolve("example.com", "/v2/users", &upstreams)
    .unwrap();
  assert_eq!(resolved.route.name, "api");

  let resolved = table
    .resolve("example.com", "/v1/users", &upstreams)
    .unwrap();
  assert_eq!(resolved.route.name, "root");
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
