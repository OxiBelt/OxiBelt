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

fn function_source<'a>(path: &str, source: &'a str, signature: &str) -> &'a str {
  let (_, function) = source
    .split_once(signature)
    .unwrap_or_else(|| panic!("{path} should contain {signature}"));
  let (function, _) = function
    .split_once("\n}\n")
    .unwrap_or_else(|| panic!("{path} should terminate {signature}"));
  function
}

#[test]
fn postgres_schema_initialization_is_transactionally_serialized() {
  let backend_path = "source/src/shared_state/backend_postgres.rs";
  let backend = read_repo_file(backend_path);
  let backend_init = function_source(
    backend_path,
    &backend,
    "pub(super) async fn init_postgres(pool: &Pool<Postgres>)",
  );
  let begin = backend_init
    .find("let mut tx = pool.begin().await?;")
    .expect("shared-state PostgreSQL schema initialization should begin a transaction");
  let lock = backend_init
    .find("pg_advisory_xact_lock(hashtextextended('oxibelt-shared-state-schema', 0))")
    .expect("shared-state PostgreSQL schema initialization should acquire its stable lock");
  let first_ddl = backend_init
    .find("CREATE TABLE IF NOT EXISTS oxibelt_shared_state")
    .expect("shared-state PostgreSQL schema initialization should create the base table");
  let udp = backend_init
    .find("udp_flows::init_postgres_udp_flows(&mut tx).await?;")
    .expect("UDP schema initialization should share the schema transaction");
  let commit = backend_init
    .find("tx.commit().await?;")
    .expect("shared-state PostgreSQL schema initialization should commit its transaction");
  assert!(
    begin < lock && lock < first_ddl && first_ddl < udp && udp < commit,
    "shared-state PostgreSQL schema initialization must lock before DDL and commit after UDP DDL"
  );
  assert!(
    !backend_init.contains(".execute(pool)"),
    "{backend_path} must not execute schema statements outside the locked transaction"
  );
  for (offset, _) in backend_init.match_indices(".execute(") {
    assert!(
      backend_init[offset..].starts_with(".execute(&mut *tx)"),
      "{backend_path} must execute every schema statement through the locked transaction"
    );
  }

  let udp_path = "source/src/shared_state/udp_flows/postgres.rs";
  let udp_source = read_repo_file(udp_path);
  let udp_init = function_source(
    udp_path,
    &udp_source,
    "pub(in crate::shared_state) async fn init_postgres_udp_flows(",
  );
  assert!(
    udp_init.contains("tx: &mut Transaction<'_, Postgres>"),
    "{udp_path} should receive the enclosing schema transaction"
  );
  assert!(
    !udp_init.contains("pool: &Pool<Postgres>"),
    "{udp_path} must receive the enclosing schema transaction instead of a pool"
  );
  assert!(
    !udp_init.contains(".execute(pool)"),
    "{udp_path} must not execute schema statements outside the enclosing transaction"
  );
  for (offset, _) in udp_init.match_indices(".execute(") {
    assert!(
      udp_init[offset..].starts_with(".execute(&mut **tx)"),
      "{udp_path} must execute every schema statement through the enclosing transaction"
    );
  }
}

#[test]
fn shared_state_backend_implementation_has_no_blocking_bridge() {
  let files = [
    "source/src/shared_state.rs",
    "source/src/shared_state/atomic_updates.rs",
    "source/src/shared_state/atomic_updates/postgres.rs",
    "source/src/shared_state/atomic_updates/memory.rs",
    "source/src/shared_state/backend_dispatch.rs",
    "source/src/shared_state/backend_memory.rs",
    "source/src/shared_state/backend_postgres.rs",
    "source/src/shared_state/backend_redis.rs",
    "source/src/shared_state/cache_lock.rs",
    "source/src/shared_state/cache_store.rs",
    "source/src/shared_state/enumeration.rs",
    "source/src/shared_state/failure_policy.rs",
    "source/src/shared_state/feature_flags.rs",
    "source/src/shared_state/helpers.rs",
    "source/src/shared_state/person_proof.rs",
    "source/src/shared_state/rate_limits.rs",
    "source/src/shared_state/redis_connection.rs",
    "source/src/shared_state/redis_pool.rs",
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
fn shared_state_enumeration_never_issues_the_redis_keys_command() {
  for path in [
    "source/src/shared_state.rs",
    "source/src/shared_state/atomic_updates.rs",
    "source/src/shared_state/backend_dispatch.rs",
    "source/src/shared_state/backend_redis.rs",
    "source/src/shared_state/cache_store.rs",
    "source/src/shared_state/enumeration.rs",
    "source/src/shared_state/person_proof.rs",
  ] {
    let source = read_repo_file(path);
    assert_absent(path, &source, "b\"KEYS\"");
  }
}

#[test]
fn request_callers_reuse_async_person_proof_snapshots() {
  for path in [
    "source/src/proxy/http.rs",
    "source/src/proxy/http/pipeline.rs",
    "source/src/proxy/http/pipeline/exchange.rs",
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
    "source/src/proxy/http/pipeline.rs",
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
  let exchange_path = "source/src/proxy/http/pipeline/exchange.rs";
  let exchange = read_repo_file(exchange_path);
  let tunnel_path = "source/src/proxy/http/tunnel.rs";
  let tunnel = read_repo_file(tunnel_path);
  let fast_path_path = "source/src/proxy/http/fast_path/handler.rs";
  let fast_path = read_repo_file(fast_path_path);

  assert!(exchange.contains("update_from_not_modified_async("));
  assert_absent(exchange_path, &exchange, ".update_from_not_modified(");
  for marker in [
    ".report_success(",
    ".report_failure(",
    ".report_success_latency(",
  ] {
    assert_absent(exchange_path, &exchange, marker);
    assert_absent(tunnel_path, &tunnel, marker);
    assert_absent(fast_path_path, &fast_path, marker);
  }
}
