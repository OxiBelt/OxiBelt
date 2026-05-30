use http::Method;

use super::super::{EffectiveRetryPolicy, select_direct_fast_path_upstream};
use super::{common, parse_config, resolved_route};
use crate::state::AppSnapshot;
use crate::waf::RequestWafDecision;

#[tokio::test]
async fn direct_upstream_fast_path_selects_pre_resolved_upstream_when_retry_is_off() {
  let temp_dir = common::TempDir::new("plain-fast-path-direct-select");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-direct-select");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  let request_waf = RequestWafDecision::default();
  let retry_policy =
    EffectiveRetryPolicy::for_direct_http_request(&state.config, resolved.route, &Method::GET);

  assert!(!retry_policy.enabled);
  let selected = select_direct_fast_path_upstream(&state, &resolved, &request_waf, &retry_policy)
    .expect("direct upstream should use pre-resolved selection");

  assert_eq!(selected.upstream.name, "app");
  assert_eq!(selected.upstream_index, resolved.upstream_index.unwrap());
}

#[tokio::test]
async fn direct_upstream_fast_path_falls_back_for_waf_pool_and_retry_selection() {
  let temp_dir = common::TempDir::new("plain-fast-path-direct-fallbacks");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-direct-fallbacks");
  let base = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );

  let direct_state = AppSnapshot::new(parse_config(&base))
    .await
    .expect("snapshot should initialize");
  let direct_resolved = resolved_route(&direct_state);
  let retry_off = EffectiveRetryPolicy::for_direct_http_request(
    &direct_state.config,
    direct_resolved.route,
    &Method::GET,
  );
  let waf_override = RequestWafDecision {
    upstream_override: Some("app".to_string()),
    ..RequestWafDecision::default()
  };
  assert!(
    select_direct_fast_path_upstream(&direct_state, &direct_resolved, &waf_override, &retry_off)
      .is_none()
  );

  let pool_raw = format!(
    "{}{}",
    base.replace("upstream = \"app\"\n", "upstream_pool = \"app-pool\"\n"),
    r#"

[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
origin = "https://app.internal.example"
"#
  );
  let pool_state = AppSnapshot::new(parse_config(&pool_raw))
    .await
    .expect("snapshot should initialize");
  let pool_resolved = resolved_route(&pool_state);
  let retry_off = EffectiveRetryPolicy::for_direct_http_request(
    &pool_state.config,
    pool_resolved.route,
    &Method::GET,
  );
  assert!(
    select_direct_fast_path_upstream(
      &pool_state,
      &pool_resolved,
      &RequestWafDecision::default(),
      &retry_off,
    )
    .is_none()
  );

  let retry_raw = format!(
    "{base}{}",
    r#"

[proxy.retry]
enabled = true
"#
  );
  let retry_state = AppSnapshot::new(parse_config(&retry_raw))
    .await
    .expect("snapshot should initialize");
  let retry_resolved = resolved_route(&retry_state);
  let retry_on = EffectiveRetryPolicy::for_direct_http_request(
    &retry_state.config,
    retry_resolved.route,
    &Method::GET,
  );

  assert!(retry_on.enabled);
  assert!(
    select_direct_fast_path_upstream(
      &retry_state,
      &retry_resolved,
      &RequestWafDecision::default(),
      &retry_on,
    )
    .is_none()
  );
}
