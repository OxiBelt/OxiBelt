use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{
  ACCEPT_ENCODING, CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE,
  PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use tracing::{debug, warn};
use url::Url;

use crate::config::HttpVersion;
use crate::routes::normalize_host;
use crate::state::AppState;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, BoxError>;

pub async fn handle(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  state: Arc<AppState>,
) -> Response<ProxyBody> {
  if request.method() == Method::CONNECT {
    return text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "CONNECT tunneling is not implemented in this build",
    );
  }

  if is_upgrade_request(&request) {
    return text_response(
      StatusCode::NOT_IMPLEMENTED,
      "WebSocket and generic HTTP upgrade tunneling are reserved but not implemented yet",
    );
  }

  let host = extract_host(&request).unwrap_or_default();
  let path = request.uri().path().to_string();

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };

  let upstream_version = select_upstream_http_version(
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    resolved.upstream.max_http_version,
  );

  if upstream_version == HttpVersion::H3 {
    return text_response(
      StatusCode::NOT_IMPLEMENTED,
      "upstream HTTP/3 forwarding is reserved but not implemented yet",
    );
  }

  let target_uri = match rewrite_uri(
    &resolved.upstream.origin,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
  ) {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
      return text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite");
    }
  };

  let preserve_host = resolved.upstream.preserve_host;
  let outbound = rebuild_request(
    request,
    target_uri,
    &state.config.compression,
    peer_addr,
    &host,
    preserve_host,
  );

  debug!(
      route = %resolved.route.name,
      upstream = %resolved.upstream.name,
      method = %outbound.method(),
      uri = %outbound.uri(),
      "proxying downstream request"
  );

  let client = state.clients.for_version(upstream_version);
  let upstream_response = match client.request(outbound).await {
    Ok(response) => response,
    Err(error) => {
      warn!(
          error = %error,
          upstream = %resolved.upstream.name,
          "upstream request failed"
      );
      return text_response(StatusCode::BAD_GATEWAY, "upstream request failed");
    }
  };

  let (mut parts, body) = upstream_response.into_parts();
  strip_hop_by_hop_headers(&mut parts.headers);

  Response::from_parts(parts, body.map_err(boxed_error).boxed())
}

fn rebuild_request(
  request: Request<Incoming>,
  target_uri: Uri,
  compression: &crate::config::CompressionConfig,
  peer_addr: std::net::SocketAddr,
  downstream_host: &str,
  preserve_host: bool,
) -> Request<Incoming> {
  let (mut parts, body) = request.into_parts();
  parts.uri = target_uri;
  strip_hop_by_hop_headers(&mut parts.headers);

  if !preserve_host {
    parts.headers.remove(HOST);
  }

  add_forwarded_headers(&mut parts.headers, peer_addr, downstream_host);

  if !parts.headers.contains_key(ACCEPT_ENCODING) {
    if let Some(accept_encoding) = compression.accept_encoding_value() {
      if let Ok(value) = HeaderValue::from_str(&accept_encoding) {
        parts.headers.insert(ACCEPT_ENCODING, value);
      }
    }
  }

  Request::from_parts(parts, body)
}

fn rewrite_uri(
  origin: &Url,
  route_prefix: &str,
  replace_prefix_with: Option<&str>,
  downstream_uri: &Uri,
) -> anyhow::Result<Uri> {
  let incoming_path = downstream_uri.path();
  let rewritten_path = if let Some(replacement) = replace_prefix_with {
    let suffix = if route_prefix == "/" {
      incoming_path
    } else {
      incoming_path
        .strip_prefix(route_prefix)
        .unwrap_or(incoming_path)
    };
    join_paths(replacement, suffix)
  } else {
    incoming_path.to_string()
  };

  let upstream_path = join_paths(origin.path(), &rewritten_path);

  let mut rewritten = origin.clone();
  rewritten.set_path(&upstream_path);
  rewritten.set_query(downstream_uri.query());
  rewritten
    .as_str()
    .parse()
    .map_err(|error| anyhow::anyhow!("failed to parse rewritten URI {}: {error}", rewritten))
}

fn join_paths(base: &str, suffix: &str) -> String {
  let normalized_base = if base.is_empty() { "/" } else { base };
  let left = normalized_base.trim_end_matches('/');
  let right = suffix.trim_start_matches('/');

  match (left.is_empty(), right.is_empty()) {
    (true, true) => "/".to_string(),
    (true, false) => format!("/{right}"),
    (false, true) => left.to_string(),
    (false, false) => format!("{left}/{right}"),
  }
}

fn extract_host(request: &Request<Incoming>) -> Option<String> {
  if let Some(authority) = request.uri().authority() {
    return Some(normalize_host(authority.as_str()));
  }

  request
    .headers()
    .get(HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host)
}

fn add_forwarded_headers(headers: &mut HeaderMap, peer_addr: std::net::SocketAddr, host: &str) {
  append_csv_header(headers, "x-forwarded-for", &peer_addr.ip().to_string());
  headers.insert(
    HeaderName::from_static("x-forwarded-proto"),
    HeaderValue::from_static("https"),
  );

  if let Ok(value) = HeaderValue::from_str(host) {
    headers.insert(HeaderName::from_static("x-forwarded-host"), value);
  }

  if let Ok(value) = HeaderValue::from_str(&peer_addr.port().to_string()) {
    headers.insert(HeaderName::from_static("x-forwarded-port"), value);
  }
}

fn append_csv_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
  let header_name = HeaderName::from_static(name);
  let next_value = match headers
    .get(&header_name)
    .and_then(|item| item.to_str().ok())
  {
    Some(existing) if !existing.is_empty() => format!("{existing}, {value}"),
    _ => value.to_string(),
  };

  if let Ok(header_value) = HeaderValue::from_str(&next_value) {
    headers.insert(header_name, header_value);
  }
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
  let connection_tokens = headers
    .get_all(CONNECTION)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .filter_map(|value| HeaderName::from_str(value).ok())
    .collect::<Vec<_>>();

  for token in connection_tokens {
    headers.remove(token);
  }

  headers.remove(CONNECTION);
  headers.remove(HeaderName::from_static("keep-alive"));
  headers.remove(PROXY_AUTHENTICATE);
  headers.remove(PROXY_AUTHORIZATION);
  headers.remove(TRAILER);
  headers.remove(TRANSFER_ENCODING);
  headers.remove(UPGRADE);

  let remove_te = headers
    .get(TE)
    .and_then(|value| value.to_str().ok())
    .map(|value| !value.eq_ignore_ascii_case("trailers"))
    .unwrap_or(false);
  if remove_te {
    headers.remove(TE);
  }
}

fn is_upgrade_request(request: &Request<Incoming>) -> bool {
  request.headers().contains_key(UPGRADE)
    || request
      .headers()
      .get(CONNECTION)
      .and_then(|value| value.to_str().ok())
      .map(|value| {
        value
          .split(',')
          .any(|item| item.trim().eq_ignore_ascii_case("upgrade"))
      })
      .unwrap_or(false)
}

fn select_upstream_http_version(
  auto_upgrade_enabled: bool,
  configured_max: HttpVersion,
  upstream_max: HttpVersion,
) -> HttpVersion {
  if !auto_upgrade_enabled {
    return upstream_max;
  }
  std::cmp::min(configured_max, upstream_max)
}

fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
  let body = Full::new(Bytes::copy_from_slice(message.as_bytes()))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
  response
}

#[allow(dead_code)]
fn empty_response(status: StatusCode) -> Response<ProxyBody> {
  let body = Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
  response
}

fn boxed_error(error: hyper::Error) -> BoxError {
  Box::new(error)
}

#[cfg(test)]
mod tests {
  use pretty_assertions::assert_eq;
  use url::Url;

  use super::*;

  #[test]
  fn join_paths_handles_slashes() {
    assert_eq!(join_paths("/", "/api"), "/api");
    assert_eq!(join_paths("/base", "/api"), "/base/api");
    assert_eq!(join_paths("/base/", "api"), "/base/api");
  }

  #[test]
  fn rewrite_uri_replaces_prefix() {
    let origin = Url::parse("https://backend.internal/root").unwrap();
    let uri = Uri::from_str("https://example.com/v1/users?id=1").unwrap();

    let rewritten = rewrite_uri(&origin, "/v1", Some("/"), &uri).unwrap();
    assert_eq!(
      rewritten.to_string(),
      "https://backend.internal/root/users?id=1"
    );
  }
}
