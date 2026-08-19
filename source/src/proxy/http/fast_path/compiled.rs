//! Reload-time fast-path action compilation.
//! Stable route and upstream facts live here so request handling only checks dynamic guards.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http::uri::PathAndQuery;
use http::{Method, Request, Uri};
use hyper::body::Body;

use crate::config::{
  Config, ForwardedHeaderMode, HttpVersion, PriorityMode, ProxyProtocolEgressMode, RouteConfig,
  RouteStaticFilesConfig, StaticFilesSendfileMode, UpstreamConfig,
};
use crate::proxy::http::uri::{self, UpstreamUriParts};
use crate::proxy::http::version::select_route_upstream_http_version;
use crate::proxy::http::{EffectiveRetryPolicy, EffectiveTimeouts};
use crate::routes::{RouteExecutionPlan, RouteTable};
use crate::state::AppSnapshot;

#[derive(Clone, Default)]
pub(crate) struct CompiledRouteFastPathActions {
  h1: Option<CompiledFastPathAction>,
  h2: Option<CompiledFastPathAction>,
  h3: Option<CompiledFastPathAction>,
  static_hot_bytes: Option<CompiledFastPathAction>,
}

#[derive(Clone)]
pub(crate) enum CompiledFastPathAction {
  ProxyH1DownstreamToH1Upstream(CompiledProxyAction),
  ProxyH2DownstreamToH1Upstream(CompiledProxyAction),
  ProxyH3DownstreamToH1Upstream(CompiledProxyAction),
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
  pub(super) finalize_fast_path: Option<CompiledResponseFinalizeFastPath>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompiledResponseFinalizeFastPath {
  pub(super) request_body_proven_empty_for_safe_methods: bool,
  pub(super) response_waf_disabled: bool,
  pub(super) request_header_mutations_empty: bool,
  pub(super) response_header_mutations_empty: bool,
  pub(super) security_response_headers_noop: bool,
  pub(super) alt_svc_noop: bool,
  pub(super) sticky_cookie_noop: bool,
  pub(super) downstream_timeout_wrapper_noop_for_known_small: bool,
  pub(super) trailers_noop_for_known_small: bool,
  pub(super) compression_noop: bool,
  pub(super) priority_noop: bool,
}

#[derive(Clone)]
pub(crate) struct CompiledStaticAction {
  route_name: Arc<str>,
  path_prefix: Arc<str>,
  static_root: Arc<std::path::PathBuf>,
  static_options: Arc<RouteStaticFilesConfig>,
  response_send_timeout: Duration,
}

pub(super) struct SelectedCompiledProxyAction<'a> {
  action: &'a CompiledProxyAction,
  pub(super) upstream: &'a UpstreamConfig,
  pub(super) upstream_index: usize,
  pub(super) upstream_version: HttpVersion,
  pub(super) preserve_host: bool,
  pub(super) forwarded_header_mode: ForwardedHeaderMode,
  pub(super) priority: PriorityMode,
  pub(super) timeouts: EffectiveTimeouts,
  pub(super) response_waf_enabled: bool,
  pub(super) finalize_fast_path: Option<CompiledResponseFinalizeFastPath>,
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

  pub(crate) fn static_hot_bytes(&self) -> Option<&CompiledStaticAction> {
    match self.static_hot_bytes.as_ref()? {
      CompiledFastPathAction::StaticHotBytes(action) => Some(action),
      _ => None,
    }
  }
}

impl CompiledStaticAction {
  pub(crate) fn route_name(&self) -> &str {
    &self.route_name
  }

  pub(crate) fn path_prefix(&self) -> &str {
    &self.path_prefix
  }

  pub(crate) fn static_root(&self) -> &Path {
    self.static_root.as_path()
  }

  pub(crate) fn static_options(&self) -> &RouteStaticFilesConfig {
    &self.static_options
  }

  pub(crate) fn response_send_timeout(&self) -> Duration {
    self.response_send_timeout
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

  pub(super) fn target_path_and_query(&self, downstream_uri: &Uri) -> anyhow::Result<PathAndQuery> {
    uri::rewrite_path_and_query(
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

impl SelectedCompiledProxyAction<'_> {
  pub(super) fn target_uri(&self, downstream_uri: &Uri) -> anyhow::Result<Uri> {
    self.action.target_uri(downstream_uri)
  }

  pub(super) fn target_path_and_query(&self, downstream_uri: &Uri) -> anyhow::Result<PathAndQuery> {
    self.action.target_path_and_query(downstream_uri)
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
  Ok(Some(SelectedCompiledProxyAction {
    action,
    upstream,
    upstream_index: action.upstream_index,
    upstream_version: action.upstream_version,
    preserve_host: action.preserve_host,
    forwarded_header_mode: action.forwarded_header_mode,
    priority: action.priority,
    timeouts: action.timeouts,
    response_waf_enabled: action.response_waf_enabled,
    finalize_fast_path: action.finalize_fast_path,
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
  let static_hot_bytes =
    compile_static_action(config, route, plan).map(CompiledFastPathAction::StaticHotBytes);
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

  let upstream_version = select_route_upstream_http_version(
    route,
    config.proxy.auto_upgrade.enabled,
    config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );
  if upstream_version != HttpVersion::H1
    || upstream.origin.scheme() != "http"
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return None;
  }

  let upstream_uri_parts = upstream_uri_parts_by_index.get(upstream_index)?.clone();
  let finalize_fast_path = compile_response_finalize_fast_path(config, route, plan);
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
    finalize_fast_path,
  })
}

fn compile_response_finalize_fast_path(
  config: &Config,
  route: &RouteConfig,
  plan: &RouteExecutionPlan,
) -> Option<CompiledResponseFinalizeFastPath> {
  let candidate = CompiledResponseFinalizeFastPath {
    request_body_proven_empty_for_safe_methods: true,
    response_waf_disabled: !plan.waf.response.enabled(),
    request_header_mutations_empty: !route.actions.request_headers.has_actions(),
    response_header_mutations_empty: !route.actions.response_headers.has_actions()
      && route.actions.cors.is_none(),
    security_response_headers_noop: !config
      .security
      .response_headers_enabled_for_route(route.security_headers.as_deref()),
    alt_svc_noop: !config.listeners.http3 || !config.quic.alt_svc.enabled,
    sticky_cookie_noop: route.upstream_pool.is_none(),
    downstream_timeout_wrapper_noop_for_known_small: true,
    trailers_noop_for_known_small: true,
    compression_noop: !config.compression.enabled || route.compression.as_deref() == Some("off"),
    priority_noop: config.proxy.http.priority == PriorityMode::Pass,
  };
  candidate
    .can_skip_known_small_noop_work()
    .then_some(candidate)
}

impl CompiledResponseFinalizeFastPath {
  pub(super) fn can_skip_known_small_noop_work(self) -> bool {
    self.request_body_proven_empty_for_safe_methods
      && self.response_waf_disabled
      && self.request_header_mutations_empty
      && self.response_header_mutations_empty
      && self.security_response_headers_noop
      && self.sticky_cookie_noop
      && self.downstream_timeout_wrapper_noop_for_known_small
      && self.trailers_noop_for_known_small
      && self.compression_noop
      && self.priority_noop
  }
}

fn compile_static_action(
  config: &Config,
  route: &RouteConfig,
  plan: &RouteExecutionPlan,
) -> Option<CompiledStaticAction> {
  if !plan.fast_path.static_small_object
    || config.proxy.static_files.sendfile != StaticFilesSendfileMode::Auto
    || !config.rate_limits.is_empty()
    || config.dynamic_policy.enabled
    || config.compression.enabled
    || route.external_auth.is_some()
    || !static_hot_object_cache_enabled(config)
    || route.static_files.has_convenience_options()
  {
    return None;
  }
  Some(CompiledStaticAction {
    route_name: Arc::from(route.name.as_str()),
    path_prefix: Arc::from(route.effective_path_prefix()),
    static_root: Arc::new(route.static_root.clone()?),
    static_options: Arc::new(route.static_files.clone()),
    response_send_timeout: Duration::from_millis(
      route
        .timeouts
        .response_send_timeout_ms
        .unwrap_or(config.limits.response_send_timeout_ms),
    ),
  })
}

fn static_hot_object_cache_enabled(config: &Config) -> bool {
  let static_files = config.proxy.static_files;
  static_files.open_file_cache_max_entries > 0
    && static_files.open_file_cache_ttl_ms > 0
    && static_files.hot_object_cache_max_bytes > 0
    && static_files.hot_object_cache_max_file_bytes > 0
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
    proxy_config_with_raw(|raw| raw + extra)
  }

  fn proxy_config_with_raw(modify: impl FnOnce(String) -> String) -> Config {
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
      );
    parse_config(&modify(raw))
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
  fn compiled_proxy_action_carries_noop_finalize_plan() {
    let config = proxy_config("");
    let actions = compiled(&config);

    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
      let action = actions
        .proxy_for_version(version)
        .expect("downstream action should compile");
      let plan = action
        .finalize_fast_path
        .expect("plain proxy action should carry no-op finalization proofs");

      assert!(plan.can_skip_known_small_noop_work());
      assert!(plan.response_waf_disabled);
      assert!(plan.request_header_mutations_empty);
      assert!(plan.response_header_mutations_empty);
      assert!(plan.security_response_headers_noop);
      assert!(plan.alt_svc_noop);
      assert!(plan.sticky_cookie_noop);
      assert!(plan.trailers_noop_for_known_small);
      assert!(plan.compression_noop);
      assert!(plan.priority_noop);
    }
  }

  #[test]
  fn enabled_security_headers_disable_noop_finalize_plan_only() {
    let config = proxy_config_with_raw(|raw| {
      format!(
        "{raw}{}",
        r#"

[security.headers]
x_content_type_options = "nosniff"
"#
      )
    });
    let actions = compiled(&config);
    let action = actions
      .proxy_for_version(http::Version::HTTP_2)
      .expect("proxy action itself should still compile");

    assert!(config.security.headers.enabled());
    assert!(action.finalize_fast_path.is_none());
  }

  #[test]
  fn route_security_headers_off_preserves_noop_finalize_plan() {
    let config = proxy_config_with_raw(|raw| {
      format!(
        "{}{}",
        raw.replace(
          "upstream = \"app\"",
          "upstream = \"app\"\nsecurity_headers = \"off\""
        ),
        r#"

[security.headers]
x_content_type_options = "nosniff"
"#
      )
    });
    let actions = compiled(&config);
    let action = actions
      .proxy_for_version(http::Version::HTTP_2)
      .expect("proxy action itself should still compile");
    let plan = action
      .finalize_fast_path
      .expect("route security_headers=off should keep security headers a no-op");

    assert!(config.security.headers.enabled());
    assert!(plan.security_response_headers_noop);
    assert!(plan.can_skip_known_small_noop_work());
  }

  #[test]
  fn named_route_security_header_policy_disables_noop_finalize_plan() {
    let config = proxy_config_with_raw(|raw| {
      format!(
        "{}{}",
        raw.replace(
          "upstream = \"app\"",
          "upstream = \"app\"\nsecurity_headers = \"api\""
        ),
        r#"

[[security.header_policies]]
name = "api"
referrer_policy = "same-origin"
"#
      )
    });
    let actions = compiled(&config);
    let action = actions
      .proxy_for_version(http::Version::HTTP_2)
      .expect("proxy action itself should still compile");

    assert!(config.security.header_policies[0].headers.enabled());
    assert!(action.finalize_fast_path.is_none());
  }

  #[test]
  fn alt_svc_finalize_fact_remains_a_runtime_guard() {
    let mut config = proxy_config("");
    config.listeners.http3 = true;
    let actions = compiled(&config);
    let plan = actions
      .proxy_for_version(http::Version::HTTP_3)
      .expect("H3 downstream action should compile")
      .finalize_fast_path
      .expect("H3 can still use runtime Alt-Svc guard");

    assert!(!plan.alt_svc_noop);
    assert!(plan.can_skip_known_small_noop_work());
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
      )
      + r#"

[proxy.static_files]
sendfile = "auto"
open_file_cache_max_entries = 8
open_file_cache_ttl_ms = 1000
hot_object_cache_max_bytes = 65536
hot_object_cache_max_file_bytes = 65536
"#;
    let config = parse_config(&raw);
    let route_name = config.routes[0].name.clone();
    let actions = compiled(&config);
    let static_action = actions
      .static_hot_bytes()
      .expect("static metadata action should compile");

    assert_eq!(static_action.route_name.as_ref(), route_name);
    assert_eq!(static_action.path_prefix.as_ref(), "/assets");
  }

  #[test]
  fn disables_static_hot_bytes_without_hot_object_cache_or_for_convenience_options() {
    let temp_dir = common::TempDir::new("compiled-fast-path-static-disabled");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "compiled-fast-path-static-disabled");
    let root = temp_dir.path().join("public");
    std::fs::create_dir_all(&root).expect("static root should exist");
    let static_raw = common::minimal_config_toml(&cert_path, &key_path)
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
    let without_cache = compiled(&parse_config(&static_raw));
    assert!(without_cache.static_hot_bytes().is_none());

    let with_convenience = compiled(&parse_config(&format!(
      "{}{}",
      static_raw,
      r#"

[proxy.static_files]
sendfile = "auto"
open_file_cache_max_entries = 8
open_file_cache_ttl_ms = 1000
hot_object_cache_max_bytes = 65536
hot_object_cache_max_file_bytes = 65536

[routes.static_files]
cache_control = "public, max-age=60"
"#
    )));
    assert!(with_convenience.static_hot_bytes().is_none());
  }
}
