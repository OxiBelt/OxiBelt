//! Route execution-plan derivation.
//! Plans capture fast-path and WAF requirements before request handling begins.

use crate::config::{
  BufferingMode, Config, ErrorResponseMode, RouteConfig, StaticFilesSendfileMode,
};
use crate::waf::{BodyNeed, WafEngine};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RouteExecutionPlan {
  pub fast_path: FastPathPlan,
  pub features: RouteFeaturePlan,
  pub waf: RouteWafExecutionPlan,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct FastPathPlan {
  pub plain_proxy_h1: bool,
  pub plain_proxy_h2: bool,
  pub plain_proxy_h3: bool,
  pub static_small_object: bool,
  pub static_sendfile_like: bool,
  pub cache_hit: bool,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RouteFeaturePlan {
  pub cache: bool,
  pub compression: bool,
  pub connect_tunneling: bool,
  pub external_auth: bool,
  pub generic_http_upgrade: bool,
  pub grpc_web: bool,
  pub ipm: bool,
  pub redirect_action: bool,
  pub rewrite_action: bool,
  pub static_files: bool,
  pub upstream_pool: bool,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RouteWafExecutionPlan {
  pub request: WafExecutionPlan,
  pub response: WafExecutionPlan,
  pub stream_enabled: bool,
  pub plain_proxy_fast_path_safe: bool,
  pub static_sendfile_fast_path_safe: bool,
}

impl RouteWafExecutionPlan {
  pub(super) fn disabled() -> Self {
    Self {
      plain_proxy_fast_path_safe: true,
      static_sendfile_fast_path_safe: true,
      ..Self::default()
    }
  }

  pub(super) fn from_waf(route_name: &str, waf: &WafEngine) -> Self {
    let request_body_need = waf.request_body_need(route_name);
    let response_body_need = waf.response_body_need(route_name);
    Self {
      request: waf_execution_plan(waf.has_request_rules(route_name), request_body_need),
      response: waf_execution_plan(waf.has_response_rules(route_name), response_body_need),
      stream_enabled: waf.requires_stream_inspection(route_name),
      plain_proxy_fast_path_safe: waf.plain_proxy_fast_path_safe(route_name),
      static_sendfile_fast_path_safe: waf.static_sendfile_fast_path_safe(route_name),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum WafExecutionPlan {
  #[default]
  None,
  HeaderOnly,
  SizeOnly,
  PrefixBody,
  FullBody,
}

impl WafExecutionPlan {
  pub fn enabled(self) -> bool {
    self != Self::None
  }

  pub fn body_need(self) -> BodyNeed {
    match self {
      Self::None | Self::HeaderOnly => BodyNeed::None,
      Self::SizeOnly => BodyNeed::SizeOnly,
      Self::PrefixBody | Self::FullBody => BodyNeed::PrefixBytes,
    }
  }
}

pub(super) fn route_execution_plan(
  config: &Config,
  route: &RouteConfig,
  waf: RouteWafExecutionPlan,
) -> RouteExecutionPlan {
  let features = route_feature_plan(config, route);
  let can_plain_proxy = can_plain_proxy_fast_path(config, route) && waf.plain_proxy_fast_path_safe;
  let can_static_sendfile =
    can_static_sendfile_fast_path(config, route) && waf.static_sendfile_fast_path_safe;
  let can_static_small_object = route.static_root.is_some()
    && !crate::waf::route_http_body_compression_transform_enabled(config, route)
    && !route.actions.has_actions()
    && route
      .compression
      .as_deref()
      .is_none_or(|value| value == "off")
    && waf.static_sendfile_fast_path_safe;
  RouteExecutionPlan {
    fast_path: FastPathPlan {
      plain_proxy_h1: can_plain_proxy,
      plain_proxy_h2: can_plain_proxy,
      plain_proxy_h3: can_plain_proxy,
      static_small_object: can_static_small_object,
      static_sendfile_like: can_static_sendfile,
      cache_hit: route.cache.is_some(),
    },
    features,
    waf,
  }
}

fn route_feature_plan(config: &Config, route: &RouteConfig) -> RouteFeaturePlan {
  RouteFeaturePlan {
    cache: config.cache.enabled && route.static_root.is_none(),
    compression: config.compression.enabled && route.compression.as_deref() != Some("off"),
    connect_tunneling: route.connect_tunneling,
    external_auth: route.external_auth.is_some(),
    generic_http_upgrade: route.generic_http_upgrade,
    grpc_web: route.grpc_web,
    ipm: route.ipm.enabled,
    redirect_action: route.actions.redirect.is_some(),
    rewrite_action: route.actions.rewrite.is_some(),
    static_files: route.static_root.is_some(),
    upstream_pool: route.upstream_pool.is_some(),
  }
}

fn can_plain_proxy_fast_path(config: &Config, route: &RouteConfig) -> bool {
  config.rate_limits.is_empty()
    && !config.dynamic_policy.enabled
    && !crate::waf::route_http_body_compression_transform_enabled(config, route)
    && route.external_auth.is_none()
    && (!config.compression.enabled || route.compression.as_deref() == Some("off"))
    && route.static_root.is_none()
    && !route.actions.has_actions()
    && !route.grpc_web
    && !route.generic_http_upgrade
    && !route.connect_tunneling
    && route.buffering.request.is_none()
    && route.buffering.response.is_none()
    && config.proxy.buffering.request == BufferingMode::Streaming
    && config.proxy.buffering.response == BufferingMode::Streaming
    && config.proxy.http.errors.mode != ErrorResponseMode::Json
}

fn can_static_sendfile_fast_path(config: &Config, route: &RouteConfig) -> bool {
  config.proxy.static_files.sendfile == StaticFilesSendfileMode::Auto
    && config.rate_limits.is_empty()
    && !config.dynamic_policy.enabled
    && !crate::waf::route_http_body_compression_transform_enabled(config, route)
    && route.external_auth.is_none()
    && !config.compression.enabled
    && route.static_root.is_some()
    && !route.actions.has_actions()
    && route
      .compression
      .as_deref()
      .is_none_or(|value| value == "off")
}

fn waf_execution_plan(enabled: bool, body_need: BodyNeed) -> WafExecutionPlan {
  match (enabled, body_need) {
    (false, BodyNeed::None) => WafExecutionPlan::None,
    (_, BodyNeed::None) => WafExecutionPlan::HeaderOnly,
    (_, BodyNeed::SizeOnly) => WafExecutionPlan::SizeOnly,
    (_, BodyNeed::PrefixBytes) => WafExecutionPlan::PrefixBody,
  }
}

#[cfg(test)]
mod tests {
  use pretty_assertions::assert_eq;

  use super::*;
  use crate::routes::RouteTable;

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

  fn minimal_proxy_config(extra: &str) -> Config {
    let temp_dir = common::TempDir::new("route-plan-proxy");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "route-plan");
    let raw = format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path).replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      ),
      extra
    );
    parse_config(&raw)
  }

  fn minimal_static_config(extra: &str) -> Config {
    let temp_dir = common::TempDir::new("route-plan-static");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "route-plan-static");
    let root = temp_dir.path().join("public");
    std::fs::create_dir_all(&root).expect("static root should be created");
    std::fs::write(root.join("app.txt"), "hello static").expect("static file should be created");
    let raw = format!(
      "{}{}{}",
      common::minimal_config_toml(&cert_path, &key_path)
        .replace(
          "[compression]\nenabled = true",
          "[compression]\nenabled = false",
        )
        .replace(
          "path_prefix = \"/\"\nupstream = \"app\"",
          &format!("path_prefix = \"/\"\nstatic_root = \"{}\"", root.display()),
        ),
      r#"

[proxy.static_files]
sendfile = "auto"
"#,
      extra
    );
    parse_config(&raw)
  }

  fn execution_plan(config: &Config) -> RouteExecutionPlan {
    let waf = WafEngine::new(config).expect("WAF engine should build");
    let table = RouteTable::new_with_waf(config, &waf);
    *table
      .resolve("example.com", "/", &config.upstreams)
      .expect("route should resolve")
      .execution_plan
  }

  #[test]
  fn no_waf_plain_proxy_has_h1_h2_and_h3_fast_path_plan() {
    let plan = execution_plan(&minimal_proxy_config(""));

    assert!(plan.fast_path.plain_proxy_h1);
    assert!(plan.fast_path.plain_proxy_h2);
    assert!(plan.fast_path.plain_proxy_h3);
    assert_eq!(plan.features, RouteFeaturePlan::default());
    assert_eq!(plan.waf.request, WafExecutionPlan::None);
    assert_eq!(plan.waf.response, WafExecutionPlan::None);
  }

  #[test]
  fn waf_body_compression_transform_disables_proxy_and_static_fast_paths() {
    let transform = r#"

[waf.http_body_compression]
mode = "transform"
"#;
    let proxy = execution_plan(&minimal_proxy_config(transform));
    let static_plan = execution_plan(&minimal_static_config(transform));

    assert!(!proxy.fast_path.plain_proxy_h1);
    assert!(!proxy.fast_path.plain_proxy_h2);
    assert!(!proxy.fast_path.plain_proxy_h3);
    assert!(!static_plan.fast_path.static_small_object);
    assert!(!static_plan.fast_path.static_sendfile_like);
  }

  #[test]
  fn rewrite_action_disables_plain_proxy_fast_path_plan() {
    let plan = execution_plan(&minimal_proxy_config(
      r#"

[routes.actions.rewrite]
path = "/edge{path_suffix}"
"#,
    ));

    assert!(plan.features.rewrite_action);
    assert!(!plan.fast_path.plain_proxy_h1);
    assert!(!plan.fast_path.plain_proxy_h2);
    assert!(!plan.fast_path.plain_proxy_h3);
  }

  #[test]
  fn redirect_action_is_tracked_as_terminal_route_feature() {
    let temp_dir = common::TempDir::new("route-plan-redirect-action");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "route-plan-redirect-action");
    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
      "path_prefix = \"/\"\nupstream = \"app\"",
      r#"path_prefix = "/"

[routes.actions.redirect]
status = 308
location_template = "/new{path_suffix}""#,
    );

    let plan = execution_plan(&parse_config(&raw));

    assert!(plan.features.redirect_action);
    assert!(!plan.fast_path.plain_proxy_h1);
    assert!(!plan.fast_path.plain_proxy_h2);
    assert!(!plan.fast_path.plain_proxy_h3);
  }

  #[test]
  fn route_feature_plan_tracks_cache_compression_and_route_controls() {
    let plan = execution_plan(&minimal_proxy_config(
      r#"

[cache]
enabled = true
store = "memory"
default_ttl_seconds = 60
cache_methods = ["GET"]

[routes.ipm]
enabled = true
action = "route:Invoke"
"#,
    ));

    assert!(plan.features.cache);
    assert!(plan.features.ipm);
    assert!(!plan.features.static_files);
    assert!(!plan.features.external_auth);

    let temp_dir = common::TempDir::new("route-plan-compression-feature");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "route-plan-compression-feature");
    let compression_plan = execution_plan(&parse_config(&format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path),
      r#"
compression = "default"
"#
    )));
    assert!(compression_plan.features.compression);
  }

  #[test]
  fn static_routes_do_not_enable_cache_feature_from_default_policy() {
    let plan = execution_plan(&minimal_static_config(
      r#"

[cache]
enabled = true
store = "memory"
default_ttl_seconds = 60
cache_methods = ["GET"]
"#,
    ));

    assert!(plan.features.static_files);
    assert!(!plan.features.cache);
    assert!(plan.fast_path.static_sendfile_like);
  }

  #[test]
  fn header_only_waf_keeps_plain_proxy_and_static_sendfile_fast_paths() {
    let waf = r#"

[waf]
enabled = true

[[waf.rules]]
name = "header-only"
phase = "request"
priority = 10
when = "Request.Http.Path == '/blocked'"

[[waf.rules.actions]]
type = "reject"
status = 403
"#;
    let proxy = execution_plan(&minimal_proxy_config(waf));
    let static_plan = execution_plan(&minimal_static_config(waf));

    assert_eq!(proxy.waf.request, WafExecutionPlan::HeaderOnly);
    assert!(proxy.fast_path.plain_proxy_h1);
    assert!(proxy.fast_path.plain_proxy_h2);
    assert!(proxy.fast_path.plain_proxy_h3);
    assert_eq!(static_plan.waf.request, WafExecutionPlan::HeaderOnly);
    assert!(static_plan.fast_path.static_sendfile_like);
  }

  #[test]
  fn size_only_waf_keeps_static_sendfile_but_disables_plain_proxy_fast_path() {
    let waf = r#"

[waf]
enabled = true

[[waf.rules]]
name = "size-only"
phase = "request"
priority = 10
when = "Request.Body.Size > 8"

[[waf.rules.actions]]
type = "reject"
status = 413
"#;
    let proxy = execution_plan(&minimal_proxy_config(waf));
    let static_plan = execution_plan(&minimal_static_config(waf));

    assert_eq!(proxy.waf.request, WafExecutionPlan::SizeOnly);
    assert!(!proxy.fast_path.plain_proxy_h1);
    assert!(!proxy.fast_path.plain_proxy_h2);
    assert!(!proxy.fast_path.plain_proxy_h3);
    assert_eq!(static_plan.waf.request, WafExecutionPlan::SizeOnly);
    assert!(static_plan.fast_path.static_sendfile_like);
  }

  #[test]
  fn prefix_body_and_stream_waf_disable_fast_paths() {
    let prefix_waf = r#"

[waf]
enabled = true

[[waf.rules]]
name = "prefix"
phase = "request"
priority = 10
when = "Request.Body.contains('secret')"

[[waf.rules.actions]]
type = "reject"
status = 403
"#;
    let prefix = execution_plan(&minimal_static_config(prefix_waf));
    let prefix_proxy = execution_plan(&minimal_proxy_config(prefix_waf));
    assert_eq!(prefix.waf.request, WafExecutionPlan::PrefixBody);
    assert!(!prefix.fast_path.static_sendfile_like);
    assert_eq!(prefix_proxy.waf.request, WafExecutionPlan::PrefixBody);
    assert!(!prefix_proxy.fast_path.plain_proxy_h3);

    let stream_waf = r#"

[waf]
enabled = true

[[waf.rules]]
name = "stream"
phase = "stream"
priority = 10
when = "Stream.Payload.Size > 8"

[[waf.rules.actions]]
type = "close_stream"
"#;
    let stream = execution_plan(&minimal_proxy_config(stream_waf));
    assert!(stream.waf.stream_enabled);
    assert!(!stream.fast_path.plain_proxy_h1);
    assert!(!stream.fast_path.plain_proxy_h3);
  }

  #[test]
  fn waf_upstream_selection_action_disables_plain_proxy_fast_path() {
    let waf = r#"

[waf]
enabled = true

[[waf.rules]]
name = "route"
phase = "request"
priority = 10
when = "Request.Http.Path == '/'"

[[waf.rules.actions]]
type = "route_to_upstream"
upstream = "app"
"#;
    let plan = execution_plan(&minimal_proxy_config(waf));

    assert_eq!(plan.waf.request, WafExecutionPlan::HeaderOnly);
    assert!(!plan.fast_path.plain_proxy_h1);
    assert!(!plan.fast_path.plain_proxy_h3);
  }
}
