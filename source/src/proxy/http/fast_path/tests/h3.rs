use http::Request;

use super::super::PlainProxyFastPath;
use super::{PanicBody, common, parse_config, resolved_route};
use crate::state::AppSnapshot;

#[tokio::test]
async fn plain_request_is_fast_path_eligible_when_optional_features_are_off() {
  let temp_dir = common::TempDir::new("plain-fast-path-h3");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-h3");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  let request = Request::builder()
    .version(http::Version::HTTP_3)
    .uri("https://example.com/perf/h3?body=ok")
    .body(PanicBody)
    .expect("request should build");

  assert!(resolved.execution_plan.fast_path.plain_proxy_h3);
  assert!(PlainProxyFastPath::eligible(&request, &state, &resolved));
}

#[tokio::test]
async fn body_inspecting_waf_disables_plain_proxy_fast_path() {
  let temp_dir = common::TempDir::new("plain-fast-path-h3-body-waf");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-h3-body-waf");
  let raw = format!(
    "{}{}",
    common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    ),
    r#"

[waf]
enabled = true

[[waf.rules]]
name = "body-inspection"
phase = "request"
priority = 10
when = "Request.Body.contains('secret')"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  let request = Request::builder()
    .version(http::Version::HTTP_3)
    .uri("https://example.com/perf/h3?body=ok")
    .body(PanicBody)
    .expect("request should build");

  assert_eq!(
    resolved.execution_plan.waf.request,
    crate::routes::WafExecutionPlan::PrefixBody
  );
  assert!(!resolved.execution_plan.fast_path.plain_proxy_h3);
  assert!(!PlainProxyFastPath::eligible(&request, &state, &resolved));
}
