//! Reload-time fast-path action compilation.
//! Stable route and upstream facts live here so request handling only checks dynamic guards.

use std::sync::Arc;

use http::{Method, Request, Uri};
use hyper::body::Body;

use crate::config::{
  Config, ForwardedHeaderMode, HttpVersion, PriorityMode, ProxyProtocolEgressMode, RouteConfig,
  UpstreamConfig,
};
use crate::proxy::http::uri::{self, UpstreamUriParts};
use crate::proxy::http::version::select_upstream_http_version;
use crate::proxy::http::{EffectiveRetryPolicy, EffectiveTimeouts};
use crate::routes::{RouteExecutionPlan, RouteTable};
use crate::state::AppSnapshot;

#[derive(Clone, Default)]
pub(crate) struct CompiledRouteFastPathActions {
  h1: Option<CompiledFastPathAction>,
  h2: Option<CompiledFastPathAction>,
  h3: Option<CompiledFastPathAction>,
  #[allow(dead_code)]
  static_hot_bytes: Option<CompiledFastPathAction>,
}

#[derive(Clone)]
pub(crate) enum CompiledFastPathAction {
  ProxyH1DownstreamToH1Upstream(CompiledProxyAction),
  ProxyH2DownstreamToH1Upstream(CompiledProxyAction),
  ProxyH3DownstreamToH1Upstream(CompiledProxyAction),
  #[allow(dead_code)]
  StaticHotBytes(CompiledStaticAction),
}

#[derive(Clone)]
pub(crate) struct CompiledProxyAction {
  pub(super) upstream_index: usize,
  pub(super) upstream_name: Arc<str>,
  pub(super) upstream_version: HttpVersion,
  pub(super) upstream_uri_parts: UpstreamUriParts,
  pub(super) route_prefix: Arc<str>,
  pub(super) replace_prefix_with: Option<Arc<str>>,
  pub(super) preserve_host: bool,
  pub(super) forwarded_header_mode: ForwardedHeaderMode,
  pub(super) priority: PriorityMode,
  pub(super) timeouts: EffectiveTimeouts,
  pub(super) response_waf_enabled: bool,
}

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct CompiledStaticAction {
  route_name: Arc<str>,
  path_prefix: Arc<str>,
}

pub(super) struct SelectedCompiledProxyAction<'a> {
  pub(super) upstream: &'a UpstreamConfig,
  pub(super) upstream_index: usize,
  pub(super) upstream_version: HttpVersion,
  pub(super) target_uri: Uri,
  pub(super) preserve_host: bool,
  pub(super) forwarded_header_mode: ForwardedHeaderMode,
  pub(super) priority: PriorityMode,
  pub(super) timeouts: EffectiveTimeouts,
  pub(super) response_waf_enabled: bool,
}

impl CompiledRouteFastPathActions {
  pub(crate) fn proxy_for_version(&self, version: http::Version) -> Option<&CompiledProxyAction> {
    match self.action_for_version(version)? {
      CompiledFastPathAction::ProxyH1DownstreamToH1Upstream(action)
      | CompiledFastPathAction::ProxyH2DownstreamToH1Upstream(action)
      | CompiledFastPathAction::ProxyH3DownstreamToH1Upstream(action) => Some(action),
      CompiledFastPathAction::StaticHotBytes(_) => None,
    }
  }

  pub(crate) fn action_for_version(
    &self,
    version: http::Version,
  ) -> Option<&CompiledFastPathAction> {
    match version {
      http::Version::HTTP_10 | http::Version::HTTP_11 => self.h1.as_ref(),
      http::Version::HTTP_2 => self.h2.as_ref(),
      http::Version::HTTP_3 => self.h3.as_ref(),
      _ => None,
    }
  }

  #[cfg(test)]
  fn static_hot_bytes(&self) -> Option<&CompiledStaticAction> {
    match self.static_hot_bytes.as_ref()? {
      CompiledFastPathAction::StaticHotBytes(action) => Some(action),
      _ => None,
    }
  }
}

impl CompiledProxyAction {
  pub(super) fn target_uri(&self, downstream_uri: &Uri) -> anyhow::Result<Uri> {
    uri::rewrite_uri(
      &self.upstream_uri_parts,
      &self.route_prefix,
      self.replace_prefix_with.as_deref().map(AsRef::as_ref),
      downstream_uri,
    )
  }

  pub(super) fn supports_direct_request(
    &self,
    method: &Method,
    request_waf_has_override: bool,
    state_upstream: Option<&UpstreamConfig>,
  ) -> bool {
    if !matches!(method, &Method::GET | &Method::HEAD) || request_waf_has_override {
      return false;
    }
    state_upstream.is_some_and(|upstream| upstream.name == self.upstream_name.as_ref())
  }
}

pub(super) fn select_compiled_proxy_action<'a, B>(
  state: &'a AppSnapshot,
  actions: Option<&'a CompiledRouteFastPathActions>,
  request: &Request<B>,
  request_version: http::Version,
  request_waf_has_upstream_override: bool,
) -> anyhow::Result<Option<SelectedCompiledProxyAction<'a>>>
where
  B: Body,
{
  let Some(action) = actions.and_then(|actions| {
    actions.proxy_for_version(request_version).filter(|action| {
      action.supports_direct_request(
        request.method(),
        request_waf_has_upstream_override,
        state.upstreams.get(action.upstream_index),
      )
    })
  }) else {
    return Ok(None);
  };
  let Some(upstream) = state.upstreams.get(action.upstream_index) else {
    return Ok(None);
  };
  let target_uri = action.target_uri(request.uri())?;
  Ok(Some(SelectedCompiledProxyAction {
    upstream,
    upstream_index: action.upstream_index,
    upstream_version: action.upstream_version,
    target_uri,
    preserve_host: action.preserve_host,
    forwarded_header_mode: action.forwarded_header_mode,
    priority: action.priority,
    timeouts: action.timeouts,
    response_waf_enabled: action.response_waf_enabled,
  }))
}

pub(crate) fn build_compiled_fast_path_actions(
  config: &Config,
  route_table: &RouteTable,
  upstreams: &[UpstreamConfig],
  upstream_uri_parts_by_index: &[UpstreamUriParts],
) -> Arc<Vec<CompiledRouteFastPathActions>> {
  Arc::new(
    route_table
      .route_execution_entries()
      .map(|(_, route, upstream_index, plan)| {
        compile_route_actions(
          config,
          route,
          plan,
          upstream_index,
          upstreams,
          upstream_uri_parts_by_index,
        )
      })
      .collect::<Vec<_>>(),
  )
}

fn compile_route_actions(
  config: &Config,
  route: &RouteConfig,
  plan: &RouteExecutionPlan,
  upstream_index: Option<usize>,
  upstreams: &[UpstreamConfig],
  upstream_uri_parts_by_index: &[UpstreamUriParts],
) -> CompiledRouteFastPathActions {
  let proxy = compile_proxy_action(
    config,
    route,
    plan,
    upstream_index,
    upstreams,
    upstream_uri_parts_by_index,
  );
  let static_hot_bytes = plan
    .fast_path
    .static_small_object
    .then(|| CompiledFastPathAction::StaticHotBytes(compile_static_action(route)));
  CompiledRouteFastPathActions {
    h1: proxy.as_ref().and_then(|action| {
      plan
        .fast_path
        .plain_proxy_h1
        .then(|| CompiledFastPathAction::ProxyH1DownstreamToH1Upstream(action.clone()))
    }),
    h2: proxy.as_ref().and_then(|action| {
      plan
        .fast_path
        .plain_proxy_h2
        .then(|| CompiledFastPathAction::ProxyH2DownstreamToH1Upstream(action.clone()))
    }),
    h3: proxy.as_ref().and_then(|action| {
      plan
        .fast_path
        .plain_proxy_h3
        .then(|| CompiledFastPathAction::ProxyH3DownstreamToH1Upstream(action.clone()))
    }),
    static_hot_bytes,
  }
}

fn compile_proxy_action(
  config: &Config,
  route: &RouteConfig,
  plan: &RouteExecutionPlan,
  upstream_index: Option<usize>,
  upstreams: &[UpstreamConfig],
  upstream_uri_parts_by_index: &[UpstreamUriParts],
) -> Option<CompiledProxyAction> {
  if !plan.fast_path.plain_proxy_h1
    && !plan.fast_path.plain_proxy_h2
    && !plan.fast_path.plain_proxy_h3
  {
    return None;
  }
  if route.upstream_pool.is_some()
    || EffectiveRetryPolicy::http_retry_enabled(config, route, &Method::GET)
    || EffectiveRetryPolicy::http_retry_enabled(config, route, &Method::HEAD)
  {
    return None;
  }

  let upstream_index = upstream_index?;
  let upstream = upstreams.get(upstream_index)?;
  if route
    .upstream
    .as_deref()
    .is_some_and(|name| name != upstream.name)
  {
    return None;
  }

  let upstream_version = route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      config.proxy.auto_upgrade.enabled,
      config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  });
  if upstream_version != HttpVersion::H1
    || upstream.origin.scheme() != "http"
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return None;
  }

  let upstream_uri_parts = upstream_uri_parts_by_index.get(upstream_index)?.clone();
  Some(CompiledProxyAction {
    upstream_index,
    upstream_name: Arc::from(upstream.name.as_str()),
    upstream_version,
    upstream_uri_parts,
    route_prefix: Arc::from(route.effective_path_prefix()),
    replace_prefix_with: route.replace_prefix_with.as_deref().map(Arc::<str>::from),
    preserve_host: upstream.preserve_host,
    forwarded_header_mode: config.proxy.forwarded_headers.mode,
    priority: config.proxy.http.priority,
    timeouts: EffectiveTimeouts::new(config, route, upstream),
    response_waf_enabled: plan.waf.response.enabled(),
  })
}

fn compile_static_action(route: &RouteConfig) -> CompiledStaticAction {
  CompiledStaticAction {
    route_name: Arc::from(route.name.as_str()),
    path_prefix: Arc::from(route.effective_path_prefix()),
  }
}

#[cfg(test)]
mod tests {
  use pretty_assertions::assert_eq;

  use super::*;
  use crate::routes::RouteTable;
  use crate::waf::WafEngine;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  fn proxy_config(extra: &str) -> Config {
    let temp_dir = common::TempDir::new("compiled-fast-path-proxy");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "compiled-fast-path-proxy");
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
      .replace(
        "origin = \"https://app.internal.example\"\nmax_http_version = \"h2\"",
        "origin = \"http://app.internal.example\"\nmax_http_version = \"h1\"",
      )
      + extra;
    parse_config(&raw)
  }

  fn compiled(config: &Config) -> CompiledRouteFastPathActions {
    let waf = WafEngine::new(config).expect("WAF engine should build");
    let route_table = RouteTable::new_with_waf(config, &waf);
    let upstream_uri_parts = config
      .upstreams
      .iter()
      .map(|upstream| UpstreamUriParts::from_url(&upstream.origin).unwrap())
      .collect::<Vec<_>>();
    build_compiled_fast_path_actions(config, &route_table, &config.upstreams, &upstream_uri_parts)
      .first()
      .cloned()
      .expect("route action should exist")
  }

  #[test]
  fn compiles_plain_proxy_h1_h2_and_h3_to_direct_h1_upstream() {
    let config = proxy_config("");
    let actions = compiled(&config);

    assert!(matches!(
      actions.action_for_version(http::Version::HTTP_11),
      Some(CompiledFastPathAction::ProxyH1DownstreamToH1Upstream(_))
    ));
    assert!(matches!(
      actions.action_for_version(http::Version::HTTP_2),
      Some(CompiledFastPathAction::ProxyH2DownstreamToH1Upstream(_))
    ));
    assert!(matches!(
      actions.action_for_version(http::Version::HTTP_3),
      Some(CompiledFastPathAction::ProxyH3DownstreamToH1Upstream(_))
    ));
  }

  #[test]
  fn compiled_proxy_action_keeps_dynamic_request_guards() {
    let config = proxy_config("");
    let actions = compiled(&config);
    let action = actions
      .proxy_for_version(http::Version::HTTP_2)
      .expect("H2 downstream action should compile");

    assert!(action.supports_direct_request(&Method::GET, false, config.upstreams.first()));
    assert!(action.supports_direct_request(&Method::HEAD, false, config.upstreams.first()));
    assert!(!action.supports_direct_request(&Method::POST, false, config.upstreams.first()));
    assert!(!action.supports_direct_request(&Method::GET, true, config.upstreams.first()));
    assert!(!action.supports_direct_request(&Method::GET, false, None));
  }

  #[test]
  fn disables_direct_proxy_action_for_retry_pool_and_h3_upstream() {
    let retry = compiled(&proxy_config(
      r#"

[proxy.retry]
enabled = true
"#,
    ));
    assert!(retry.action_for_version(http::Version::HTTP_11).is_none());

    let pool_config = proxy_config(
      r#"

[[upstream_pools]]
name = "pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
origin = "http://pool.internal.example"
"#,
    );
    let mut pool_config = pool_config;
    pool_config.routes[0].upstream = None;
    pool_config.routes[0].upstream_pool = Some("pool".to_string());
    let pool = compiled(&pool_config);
    assert!(pool.action_for_version(http::Version::HTTP_11).is_none());

    let mut h3_config = proxy_config("");
    h3_config.routes[0].upstream_http_version = Some(HttpVersion::H3);
    h3_config.upstreams[0].max_http_version = HttpVersion::H3;
    let h3 = compiled(&h3_config);
    assert!(h3.action_for_version(http::Version::HTTP_11).is_none());
  }

  #[test]
  fn compiles_static_small_object_metadata_only() {
    let temp_dir = common::TempDir::new("compiled-fast-path-static");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "compiled-fast-path-static");
    let root = temp_dir.path().join("public");
    std::fs::create_dir_all(&root).expect("static root should exist");
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
      .replace(
        "path_prefix = \"/\"\nupstream = \"app\"",
        &format!(
          "path_prefix = \"/assets\"\nstatic_root = \"{}\"",
          root.display()
        ),
      );
    let config = parse_config(&raw);
    let route_name = config.routes[0].name.clone();
    let actions = compiled(&config);
    let static_action = actions
      .static_hot_bytes()
      .expect("static metadata action should compile");

    assert_eq!(static_action.route_name.as_ref(), route_name);
    assert_eq!(static_action.path_prefix.as_ref(), "/assets");
  }
}
