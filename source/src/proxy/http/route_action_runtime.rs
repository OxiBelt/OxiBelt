//! Runtime application for route-level header, CORS, and mirror actions.
//! Config validation guarantees header names and values are syntactically safe.

use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};

use crate::config::{
  RouteConfig, RouteCorsActionConfig, RouteHeaderModifierConfig, RouteRequestMirrorConfig,
};
use crate::waf::{HeaderMutation, apply_header_mutations};

use super::body::ProxyBody;
use super::response::text_response;

const ACCESS_CONTROL_ALLOW_CREDENTIALS: HeaderName =
  HeaderName::from_static("access-control-allow-credentials");
const ACCESS_CONTROL_ALLOW_HEADERS: HeaderName =
  HeaderName::from_static("access-control-allow-headers");
const ACCESS_CONTROL_ALLOW_METHODS: HeaderName =
  HeaderName::from_static("access-control-allow-methods");
const ACCESS_CONTROL_ALLOW_ORIGIN: HeaderName =
  HeaderName::from_static("access-control-allow-origin");
const ACCESS_CONTROL_EXPOSE_HEADERS: HeaderName =
  HeaderName::from_static("access-control-expose-headers");
const ACCESS_CONTROL_MAX_AGE: HeaderName = HeaderName::from_static("access-control-max-age");
const ACCESS_CONTROL_REQUEST_METHOD: HeaderName =
  HeaderName::from_static("access-control-request-method");
const ORIGIN: HeaderName = HeaderName::from_static("origin");
const VARY: HeaderName = HeaderName::from_static("vary");

pub(super) fn request_header_mutations(route: &RouteConfig) -> Vec<HeaderMutation> {
  header_mutations(&route.actions.request_headers)
}

pub(super) fn apply_response_actions(
  headers: &mut HeaderMap,
  route: &RouteConfig,
  request_headers: &HeaderMap,
) {
  let mutations = header_mutations(&route.actions.response_headers);
  apply_header_mutations(headers, &mutations);
  apply_cors_response_headers(headers, route.actions.cors.as_ref(), request_headers);
}

pub(super) fn cors_preflight_response(
  route: &RouteConfig,
  method: &Method,
  request_headers: &HeaderMap,
) -> Option<Response<ProxyBody>> {
  if method != Method::OPTIONS {
    return None;
  }
  let cors = route.actions.cors.as_ref()?;
  let origin = request_headers.get(&ORIGIN)?.to_str().ok()?;
  let requested_method = request_headers
    .get(&ACCESS_CONTROL_REQUEST_METHOD)?
    .to_str()
    .ok()?;
  if !origin_allowed(cors, origin) || !method_allowed(cors, requested_method) {
    return Some(text_response(
      StatusCode::FORBIDDEN,
      "CORS preflight denied",
    ));
  }

  let mut response = text_response(StatusCode::NO_CONTENT, "");
  apply_preflight_headers(response.headers_mut(), cors, origin);
  Some(response)
}

pub(super) fn enabled_mirrors(route: &RouteConfig) -> &[RouteRequestMirrorConfig] {
  &route.actions.request_mirrors
}

pub(super) fn mirror_sample_allows(
  mirror: &RouteRequestMirrorConfig,
  route_name: &str,
  uri: &http::Uri,
) -> bool {
  if mirror.sample_percent >= 100.0 {
    return true;
  }
  let mut hash = 0xcbf29ce484222325u64;
  for byte in route_name.as_bytes() {
    hash ^= u64::from(*byte);
    hash = hash.wrapping_mul(0x100000001b3);
  }
  let uri = uri.to_string();
  for byte in uri.as_bytes() {
    hash ^= u64::from(*byte);
    hash = hash.wrapping_mul(0x100000001b3);
  }
  let bucket = (hash % 10_000) as f64 / 100.0;
  bucket < mirror.sample_percent
}

fn header_mutations(modifier: &RouteHeaderModifierConfig) -> Vec<HeaderMutation> {
  let mut mutations = Vec::new();
  for entry in &modifier.set {
    if let (Ok(name), Ok(value)) = (
      HeaderName::from_bytes(entry.name.as_bytes()),
      HeaderValue::from_str(&entry.value),
    ) {
      mutations.push(HeaderMutation::Set { name, value });
    }
  }
  for entry in &modifier.add {
    if let (Ok(name), Ok(value)) = (
      HeaderName::from_bytes(entry.name.as_bytes()),
      HeaderValue::from_str(&entry.value),
    ) {
      mutations.push(HeaderMutation::Append { name, value });
    }
  }
  for name in &modifier.remove {
    if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
      mutations.push(HeaderMutation::Remove { name });
    }
  }
  mutations
}

fn apply_cors_response_headers(
  headers: &mut HeaderMap,
  cors: Option<&RouteCorsActionConfig>,
  request_headers: &HeaderMap,
) {
  let Some(cors) = cors else {
    return;
  };
  let Some(origin) = request_headers
    .get(&ORIGIN)
    .and_then(|value| value.to_str().ok())
  else {
    return;
  };
  if !origin_allowed(cors, origin) {
    return;
  }
  insert_origin(headers, cors, origin);
  if cors.allow_credentials {
    headers.insert(
      ACCESS_CONTROL_ALLOW_CREDENTIALS,
      HeaderValue::from_static("true"),
    );
  }
  if !cors.expose_headers.is_empty() {
    insert_header_value(
      headers,
      ACCESS_CONTROL_EXPOSE_HEADERS,
      &cors.expose_headers.join(", "),
    );
  }
  append_vary(headers, "Origin");
}

fn apply_preflight_headers(headers: &mut HeaderMap, cors: &RouteCorsActionConfig, origin: &str) {
  insert_origin(headers, cors, origin);
  insert_header_value(
    headers,
    ACCESS_CONTROL_ALLOW_METHODS,
    &cors.allow_methods.join(", "),
  );
  if !cors.allow_headers.is_empty() {
    insert_header_value(
      headers,
      ACCESS_CONTROL_ALLOW_HEADERS,
      &cors.allow_headers.join(", "),
    );
  }
  if cors.allow_credentials {
    headers.insert(
      ACCESS_CONTROL_ALLOW_CREDENTIALS,
      HeaderValue::from_static("true"),
    );
  }
  if let Some(max_age) = cors.max_age_seconds {
    insert_header_value(headers, ACCESS_CONTROL_MAX_AGE, &max_age.to_string());
  }
  append_vary(headers, "Origin");
  append_vary(headers, "Access-Control-Request-Method");
  append_vary(headers, "Access-Control-Request-Headers");
}

fn insert_origin(headers: &mut HeaderMap, cors: &RouteCorsActionConfig, origin: &str) {
  let value = if cors.allow_origins.iter().any(|candidate| candidate == "*") {
    "*"
  } else {
    origin
  };
  insert_header_value(headers, ACCESS_CONTROL_ALLOW_ORIGIN, value);
}

fn origin_allowed(cors: &RouteCorsActionConfig, origin: &str) -> bool {
  cors
    .allow_origins
    .iter()
    .any(|candidate| candidate == "*" || candidate == origin)
}

fn method_allowed(cors: &RouteCorsActionConfig, method: &str) -> bool {
  cors
    .allow_methods
    .iter()
    .any(|candidate| candidate.eq_ignore_ascii_case(method))
}

fn append_vary(headers: &mut HeaderMap, value: &str) {
  let next = match headers
    .get(&VARY)
    .and_then(|existing| existing.to_str().ok())
  {
    Some(existing)
      if existing
        .split(',')
        .any(|item| item.trim().eq_ignore_ascii_case(value)) =>
    {
      return;
    }
    Some(existing) if !existing.is_empty() => format!("{existing}, {value}"),
    _ => value.to_string(),
  };
  insert_header_value(headers, VARY, &next);
}

fn insert_header_value(headers: &mut HeaderMap, name: HeaderName, value: &str) {
  match HeaderValue::from_str(value) {
    Ok(value) => {
      headers.insert(name, value);
    }
    Err(error) => {
      tracing::error!(header = %name, error = %error, "validated route header became invalid");
    }
  }
}

#[cfg(test)]
mod tests {
  use http::header::ORIGIN;

  use super::*;
  use crate::config::{RouteActionsConfig, RouteHeaderValueConfig, RouteMatchConfig};

  fn route_with_actions(actions: RouteActionsConfig) -> RouteConfig {
    RouteConfig {
      name: "edge".to_string(),
      hosts: vec!["*".to_string()],
      path_prefix: "/".to_string(),
      r#match: RouteMatchConfig::default(),
      replace_prefix_with: None,
      actions,
      upstream: Some("app".to_string()),
      upstream_pool: None,
      static_root: None,
      ct_log: None,
      ct_surface: Default::default(),
      static_files: Default::default(),
      upstream_http_version: None,
      upstream_http_version_mode: Default::default(),
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
  fn request_header_mutations_apply_set_add_remove_order() {
    let route = route_with_actions(RouteActionsConfig {
      request_headers: RouteHeaderModifierConfig {
        set: vec![RouteHeaderValueConfig {
          name: "x-route".to_string(),
          value: "edge".to_string(),
        }],
        add: vec![RouteHeaderValueConfig {
          name: "x-route".to_string(),
          value: "mirror".to_string(),
        }],
        remove: vec!["x-remove".to_string()],
      },
      ..Default::default()
    });

    let mutations = request_header_mutations(&route);

    assert_eq!(mutations.len(), 3);
    assert!(matches!(mutations[0], HeaderMutation::Set { .. }));
    assert!(matches!(mutations[1], HeaderMutation::Append { .. }));
    assert!(matches!(mutations[2], HeaderMutation::Remove { .. }));
  }

  #[test]
  fn cors_preflight_returns_no_content_with_allow_headers() {
    let route = route_with_actions(RouteActionsConfig {
      cors: Some(RouteCorsActionConfig {
        allow_origins: vec!["https://app.example.com".to_string()],
        allow_methods: vec!["GET".to_string()],
        allow_headers: vec!["authorization".to_string()],
        expose_headers: Vec::new(),
        allow_credentials: true,
        max_age_seconds: Some(600),
      }),
      ..Default::default()
    });
    let mut headers = HeaderMap::new();
    headers.insert(ORIGIN, HeaderValue::from_static("https://app.example.com"));
    headers.insert(
      ACCESS_CONTROL_REQUEST_METHOD,
      HeaderValue::from_static("GET"),
    );

    let response = cors_preflight_response(&route, &Method::OPTIONS, &headers)
      .expect("preflight should be handled");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
      response.headers()[ACCESS_CONTROL_ALLOW_ORIGIN],
      "https://app.example.com"
    );
    assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_METHODS], "GET");
    assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
  }

  #[test]
  fn response_actions_apply_header_modifier_and_cors() {
    let route = route_with_actions(RouteActionsConfig {
      response_headers: RouteHeaderModifierConfig {
        set: vec![RouteHeaderValueConfig {
          name: "x-response".to_string(),
          value: "ok".to_string(),
        }],
        add: Vec::new(),
        remove: vec!["server".to_string()],
      },
      cors: Some(RouteCorsActionConfig {
        allow_origins: vec!["*".to_string()],
        allow_methods: vec!["GET".to_string()],
        allow_headers: Vec::new(),
        expose_headers: vec!["x-response".to_string()],
        allow_credentials: false,
        max_age_seconds: None,
      }),
      ..Default::default()
    });
    let mut request_headers = HeaderMap::new();
    request_headers.insert(ORIGIN, HeaderValue::from_static("https://client.example"));
    let mut response_headers = HeaderMap::new();
    response_headers.insert("server", HeaderValue::from_static("backend"));

    apply_response_actions(&mut response_headers, &route, &request_headers);

    assert!(!response_headers.contains_key("server"));
    assert_eq!(response_headers["x-response"], "ok");
    assert_eq!(response_headers[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(
      response_headers[ACCESS_CONTROL_EXPOSE_HEADERS],
      "x-response"
    );
  }
}
