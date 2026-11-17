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
fn resolves_tokio_workers_and_retained_multipliers() {
  let runtime = resolve(
    r#"
worker_threads = "auto"

[workers]
tokio = 3

[worker_multipliers]
runtime = 2.0
tokio = 0.5
accept = 1.25
"#,
  )
  .unwrap();

  assert_eq!(runtime.worker_threads, 3);
  assert_eq!(runtime.workers.tokio, 3);
  assert_eq!(runtime.worker_multipliers.runtime, 2.0);
  assert_eq!(runtime.worker_multipliers.tokio, 0.5);
  assert_eq!(runtime.worker_multipliers.accept, 1.25);
}

#[test]
fn legacy_worker_count_still_supplies_tokio_when_omitted() {
  let runtime = resolve("worker_threads = 7").unwrap();
  assert_eq!(runtime.worker_threads, 7);
  assert_eq!(runtime.workers.tokio, 7);
}

#[test]
fn rejects_zero_tokio_worker_count_with_owner_path() {
  let error = resolve(
    r#"
[workers]
tokio = 0
"#,
  )
  .unwrap_err();

  assert_eq!(
    error.to_string(),
    "runtime.workers.tokio must be greater than 0"
  );
}
