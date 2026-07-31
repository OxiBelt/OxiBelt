use super::*;

const PARALLELISM: WorkerParallelism = WorkerParallelism {
  available: 4,
  fallback_error: None,
};

fn resolve(input: &str) -> anyhow::Result<RuntimeConfig> {
  let raw = toml::from_str::<RawRuntimeConfig>(input)?;
  RuntimeConfig::resolve(raw, PARALLELISM)
}

#[test]
fn defaults_to_canonical_hybrid_with_per_owner_workers() {
  let runtime = resolve("").unwrap();

  assert_eq!(runtime.main_runtime, RuntimeMainRuntimeMode::HybridCompio);
  assert_eq!(
    runtime.topology_policy,
    RuntimeTopologyPolicy::AllowFallback
  );
  assert_eq!(runtime.worker_threads, 4);
  assert_eq!(runtime.workers.tokio, 4);
  assert_eq!(runtime.workers.compio_direct_h1, 4);
}

#[test]
fn legacy_worker_fields_fill_only_missing_owner_values() {
  let runtime = resolve(
    r#"
worker_threads = "auto"

[workers]
tokio = 3

[worker_multipliers]
runtime = 2.0
compio_direct_h1 = 0.5
"#,
  )
  .unwrap();

  assert_eq!(runtime.worker_threads, 3);
  assert_eq!(runtime.workers.tokio, 3);
  assert_eq!(runtime.workers.compio_direct_h1, 2);
  assert_eq!(runtime.worker_multipliers.runtime, 2.0);
  assert_eq!(runtime.worker_multipliers.tokio, 2.0);
  assert_eq!(runtime.worker_multipliers.compio_direct_h1, 0.5);
}

#[test]
fn canonical_worker_count_overrides_only_its_owner() {
  let runtime = resolve(
    r#"
worker_threads = 7

[workers]
compio_direct_h1 = 5
"#,
  )
  .unwrap();

  assert_eq!(runtime.worker_threads, 7);
  assert_eq!(runtime.workers.tokio, 7);
  assert_eq!(runtime.workers.compio_direct_h1, 5);
}

#[test]
fn canonical_multiplier_overrides_only_its_owner() {
  let runtime = resolve(
    r#"
[worker_multipliers]
runtime = 2.0
tokio = 0.5
"#,
  )
  .unwrap();

  assert_eq!(runtime.worker_threads, 2);
  assert_eq!(runtime.workers.tokio, 2);
  assert_eq!(runtime.workers.compio_direct_h1, 8);
}

#[test]
fn preserves_legacy_compio_request_for_introspection() {
  let runtime = resolve(
    r#"
main_runtime = "compio"
topology_policy = "require_exact"
"#,
  )
  .unwrap();

  assert_eq!(runtime.main_runtime, RuntimeMainRuntimeMode::Compio);
  assert_eq!(
    runtime.main_runtime.canonical(),
    RuntimeMainRuntimeMode::HybridCompio
  );
  assert_eq!(runtime.topology_policy, RuntimeTopologyPolicy::RequireExact);
}

#[test]
fn rejects_zero_canonical_worker_count_with_owner_path() {
  let error = resolve(
    r#"
[workers]
compio_direct_h1 = 0
"#,
  )
  .unwrap_err();

  assert_eq!(
    error.to_string(),
    "runtime.workers.compio_direct_h1 must be greater than 0"
  );
}
