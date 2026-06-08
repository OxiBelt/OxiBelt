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
use super::retry::send_one_shot;
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
  for mirror in route_action_runtime::enabled_mirrors(route) {
    if !matches!(*outbound.method(), Method::GET | Method::HEAD) {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    if !route_action_runtime::mirror_sample_allows(mirror, &route.name, request_uri) {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    let selected = match select_pool_upstream(
      state.as_ref(),
      &mirror.upstream_pool,
      client_addr,
      &format!("{host}{request_uri}"),
      None,
      None,
    ) {
      Ok(selected) => selected,
      Err(error) => {
        state.metrics.record_request_mirror_error();
        warn!(
          route = %route.name,
          pool = %mirror.upstream_pool,
          error = ?error,
          "failed to select request mirror upstream"
        );
        continue;
      }
    };
    let upstream = selected.upstream.clone();
    let upstream_version = mirror_upstream_version(&state, route, &upstream);
    if upstream_version == HttpVersion::H3
      || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
    {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
      state.metrics.record_request_mirror_error();
      warn!(
        route = %route.name,
        upstream = %upstream.name,
        "missing request mirror upstream URI parts"
      );
      continue;
    };
    let target_uri = match route_actions::build_upstream_uri(
      upstream_uri,
      route,
      RouteActionRenderContext {
        route_prefix: route.effective_path_prefix(),
        path_captures: &[],
        downstream_scheme,
        downstream_host: host,
        downstream_uri: request_uri,
      },
    ) {
      Ok(uri) => uri,
      Err(error) => {
        state.metrics.record_request_mirror_error();
        warn!(
          route = %route.name,
          upstream = %upstream.name,
          error = %error,
          "failed to build request mirror URI"
        );
        continue;
      }
    };
    let mut mirror_request = empty_request_from(outbound);
    *mirror_request.uri_mut() = target_uri;
    *mirror_request.version_mut() = upstream_request_version(upstream_version);
    let timeouts = EffectiveTimeouts::new(&state.config, route, &upstream);
    let mirror_state = state.clone();
    tokio::spawn(async move {
      let Some(client) = mirror_state.clients.for_upstream_version(
        &upstream.name,
        upstream.origin.scheme(),
        upstream_version,
      ) else {
        mirror_state.metrics.record_request_mirror_skip();
        return;
      };
      match send_one_shot(client, mirror_request, timeouts).await {
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
