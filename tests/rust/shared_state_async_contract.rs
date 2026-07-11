use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live under the repository root")
    .to_path_buf()
}

fn read_repo_file(path: &str) -> String {
  fs::read_to_string(repo_root().join(path))
    .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
}

fn assert_absent(path: &str, source: &str, forbidden: &str) {
  assert!(
    !source.contains(forbidden),
    "{path} must not reintroduce the synchronous shared-state escape hatch {forbidden:?}"
  );
}

#[test]
fn shared_state_backend_implementation_has_no_blocking_bridge() {
  let files = [
    "source/src/shared_state.rs",
    "source/src/shared_state/cache_store.rs",
    "source/src/shared_state/feature_flags.rs",
    "source/src/shared_state/person_proof.rs",
    "source/src/shared_state/rate_limits.rs",
    "source/src/shared_state/redis_protocol.rs",
    "source/src/shared_state/runtime.rs",
    "source/src/shared_state/sticky_sessions.rs",
  ];
  let forbidden = [
    "tokio::task::block_in_place",
    "Handle::block_on",
    ".block_on(",
    "std::net::TcpStream",
  ];

  for path in files {
    let source = read_repo_file(path);
    for marker in forbidden {
      assert_absent(path, &source, marker);
    }
  }
}

#[test]
fn request_callers_reuse_async_person_proof_snapshots() {
  for path in [
    "source/src/proxy/http.rs",
    "source/src/proxy/http/fast_path/finalize.rs",
    "source/src/proxy/http/fast_path/response_waf.rs",
    "source/src/proxy/http/response.rs",
    "source/src/proxy/http/static_files/finalize.rs",
    "source/src/server/plain_http/static_waf.rs",
    "source/src/proxy/stream_waf/context.rs",
  ] {
    let source = read_repo_file(path);
    assert_absent(path, &source, ".evaluate_response_async(");
    assert_absent(path, &source, ".evaluate_stream_async(");
    assert_absent(path, &source, ".evaluate_response(");
    assert_absent(path, &source, ".evaluate_stream(");
  }

  for path in [
    "source/src/proxy/http.rs",
    "source/src/proxy/http/webtransport.rs",
  ] {
    let source = read_repo_file(path);
    assert!(
      source.contains("evaluate_dynamic_person_proof_challenge_with_status_async("),
      "{path} must use asynchronous dynamic Person proof evaluation"
    );
  }

  let flow_helpers = read_repo_file("source/src/proxy/http/flow_helpers.rs");
  let static_access_log = read_repo_file("source/src/server/plain_http/static_access_log.rs");
  assert!(flow_helpers.contains(".emit_async("));
  assert!(static_access_log.contains(".emit_async("));
}

#[test]
fn cache_and_pool_callers_publish_shared_results_asynchronously() {
  let proxy = read_repo_file("source/src/proxy/http.rs");
  let fast_path = read_repo_file("source/src/proxy/http/fast_path/handler.rs");

  assert!(proxy.contains("update_from_not_modified_async("));
  assert_absent(
    "source/src/proxy/http.rs",
    &proxy,
    ".update_from_not_modified(",
  );
  for marker in [
    ".report_success(",
    ".report_failure(",
    ".report_success_latency(",
  ] {
    assert_absent("source/src/proxy/http.rs", &proxy, marker);
    assert_absent(
      "source/src/proxy/http/fast_path/handler.rs",
      &fast_path,
      marker,
    );
  }
}
