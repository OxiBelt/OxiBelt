use std::future::Future;

use http::Request;

use super::super::{PlainProxyFastPathMissReason, plain_proxy_fast_path_decision};
use super::{common, empty_proxy_body, parse_config, request, resolved_route};
use crate::state::AppSnapshot;

fn run_async_on_larger_stack<F, Fut>(name: &str, test: F)
where
  F: FnOnce() -> Fut + Send + 'static,
  Fut: Future<Output = ()> + 'static,
{
  std::thread::Builder::new()
    .name(name.to_owned())
    .stack_size(32 * 1024 * 1024)
    .spawn(move || {
      tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime should build")
        .block_on(test());
    })
    .expect("test thread should spawn")
    .join()
    .expect("test thread should finish");
}

#[test]
fn plain_fast_path_decision_reports_plan_disabled() {
  run_async_on_larger_stack("plain-fast-path-plan-disabled", || async {
    plain_fast_path_decision_reports_plan_disabled_inner().await;
  });
}

async fn plain_fast_path_decision_reports_plan_disabled_inner() {
  let temp_dir = common::TempDir::new("plain-fast-path-plan-disabled");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-plan-disabled");
  let raw = common::minimal_config_toml(&cert_path, &key_path);
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);

  assert_eq!(
    plain_proxy_fast_path_decision(&request(), &state, &resolved),
    Err(PlainProxyFastPathMissReason::PlanDisabled)
  );
}

#[test]
fn plain_fast_path_decision_reports_upgrade_miss() {
  run_async_on_larger_stack("plain-fast-path-upgrade-miss", || async {
    plain_fast_path_decision_reports_upgrade_miss_inner().await;
  });
}

async fn plain_fast_path_decision_reports_upgrade_miss_inner() {
  let temp_dir = common::TempDir::new("plain-fast-path-upgrade-miss");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-upgrade-miss");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  let upgrade = Request::builder()
    .uri("https://example.com/")
    .header(http::header::CONNECTION, "upgrade")
    .header(http::header::UPGRADE, "websocket")
    .body(empty_proxy_body())
    .expect("request should build");

  assert_eq!(
    plain_proxy_fast_path_decision(&upgrade, &state, &resolved),
    Err(PlainProxyFastPathMissReason::Upgrade)
  );
}
