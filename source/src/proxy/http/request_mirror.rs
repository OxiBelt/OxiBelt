//! Best-effort route request mirroring.
//! Mirrors are fire-and-forget and never affect the primary response path.

use std::sync::Arc;

use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use tracing::warn;

use crate::config::{HttpVersion, ProxyProtocolEgressMode, RouteConfig, UpstreamConfig};
use crate::state::AppSnapshot;

use super::EffectiveTimeouts;
use super::body::ProxyBody;
use super::retry::send_one_shot_with_state;
use super::route_action_runtime;
use super::route_actions::{self, RouteActionRenderContext};
use super::upstream::select_pool_upstream;
use super::version::{select_upstream_http_version, upstream_request_version};

pub(super) fn spawn_request_mirrors(
  state: Arc<AppSnapshot>,
  route: &RouteConfig,
  outbound: &Request<ProxyBody>,
  request_uri: &http::Uri,
  client_addr: std::net::SocketAddr,
  host: &str,
  downstream_scheme: &str,
) {
  if state.overload.request_mirroring_disabled() {
    state.metrics.record_request_mirror_skip();
    return;
  }
  for mirror in route_action_runtime::enabled_mirrors(route) {
    if !matches!(*outbound.method(), Method::GET | Method::HEAD) {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    if !route_action_runtime::mirror_sample_allows(mirror, &route.name, request_uri) {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    let mirror_state = state.clone();
    let route = route.clone();
    let pool_name = mirror.upstream_pool.clone();
    let route_name = route.name.clone();
    let hash_key = format!("{host}{request_uri}");
    let downstream_scheme = downstream_scheme.to_string();
    let downstream_host = host.to_string();
    let downstream_uri = request_uri.clone();
    let mut mirror_request = empty_request_from(outbound);
    tokio::spawn(async move {
      let selected = match select_pool_upstream(
        mirror_state.as_ref(),
        &pool_name,
        client_addr,
        &hash_key,
        None,
        None,
      )
      .await
      {
        Ok(selected) => selected,
        Err(error) => {
          mirror_state.metrics.record_request_mirror_error();
          warn!(route = %route_name, pool = %pool_name, error = ?error, "failed to select request mirror upstream");
          return;
        }
      };
      let upstream = selected.upstream.clone();
      let _selection = selected.into_pool_selection();
      let upstream_version = mirror_upstream_version(&mirror_state, &route, &upstream);
      if upstream_version == HttpVersion::H3
        || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
      {
        mirror_state.metrics.record_request_mirror_skip();
        return;
      }
      let Some(upstream_uri) = mirror_state.upstream_uri_parts.get(&upstream.name) else {
        mirror_state.metrics.record_request_mirror_error();
        warn!(route = %route_name, upstream = %upstream.name, "missing request mirror upstream URI parts");
        return;
      };
      let target_uri = match route_actions::build_upstream_uri(
        upstream_uri,
        &route,
        RouteActionRenderContext {
          route_prefix: route.effective_path_prefix(),
          path_captures: &[],
          downstream_scheme: &downstream_scheme,
          downstream_host: &downstream_host,
          downstream_uri: &downstream_uri,
        },
      ) {
        Ok(uri) => uri,
        Err(error) => {
          mirror_state.metrics.record_request_mirror_error();
          warn!(route = %route_name, upstream = %upstream.name, error = %error, "failed to build request mirror URI");
          return;
        }
      };
      *mirror_request.uri_mut() = target_uri;
      *mirror_request.version_mut() = upstream_request_version(upstream_version);
      let timeouts = EffectiveTimeouts::new(&mirror_state.config, &route, &upstream);
      let Some(client) = mirror_state.clients.for_upstream_version(
        &upstream.name,
        upstream.origin.scheme(),
        upstream_version,
      ) else {
        mirror_state.metrics.record_request_mirror_skip();
        return;
      };
      match send_one_shot_with_state(
        client,
        mirror_request,
        timeouts,
        mirror_state.as_ref(),
        None,
      )
      .await
      {
        Ok(_) => mirror_state.metrics.record_request_mirror_success(),
        Err(error) => {
          mirror_state.metrics.record_request_mirror_error();
          warn!(upstream = %upstream.name, error = %error, "request mirror dispatch failed");
        }
      }
    });
  }
}

fn mirror_upstream_version(
  state: &AppSnapshot,
  route: &RouteConfig,
  upstream: &UpstreamConfig,
) -> HttpVersion {
  route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      state.config.proxy.auto_upgrade.enabled,
      state.config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  })
}

#[allow(
  clippy::expect_used,
  reason = "all request builder inputs are cloned from an existing valid request"
)]
fn empty_request_from<B>(request: &Request<B>) -> Request<ProxyBody> {
  let mut builder = Request::builder()
    .method(request.method().clone())
    .uri(request.uri().clone())
    .version(request.version());
  *builder.headers_mut().expect("request builder headers") = request.headers().clone();
  builder
    .body(full_body(bytes::Bytes::new()))
    .expect("request clone builds")
}

fn full_body(bytes: bytes::Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> super::body::BoxError { match never {} })
    .boxed()
}
