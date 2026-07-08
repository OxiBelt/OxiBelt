//! Compio runtime boundary for OxiBelt-owned async execution.

use std::time::Instant;

use anyhow::Context;

use super::tokio_island::TokioIslandRuntime;

pub struct CompioRuntime {
  runtime: compio::runtime::Runtime,
  tokio_island: TokioIslandRuntime,
}

impl CompioRuntime {
  pub fn build(worker_threads: usize) -> anyhow::Result<Self> {
    let runtime = build_driver_runtime()?;
    let tokio_island = TokioIslandRuntime::build(worker_threads)?;
    Ok(Self {
      runtime,
      tokio_island,
    })
  }

  pub fn block_on_tokio_island<F>(&self, future: F) -> F::Output
  where
    F: std::future::Future,
  {
    self
      .runtime
      .block_on(async move { self.tokio_island.block_on(future) })
  }
}

pub fn build_driver_runtime() -> anyhow::Result<compio::runtime::Runtime> {
  let started = Instant::now();
  tracing::info!(
    startup_stage = "compio_runtime_builder_build",
    "startup stage started"
  );
  let runtime = compio::runtime::RuntimeBuilder::new()
    .build()
    .context("failed to build Compio runtime");
  match &runtime {
    Ok(_) => tracing::info!(
      startup_stage = "compio_runtime_builder_build",
      elapsed_ms = started.elapsed().as_millis(),
      "startup stage completed"
    ),
    Err(error) => tracing::error!(
      startup_stage = "compio_runtime_builder_build",
      elapsed_ms = started.elapsed().as_millis(),
      error = %error,
      "startup stage failed"
    ),
  }
  runtime
}

pub fn build_runtime(worker_threads: usize) -> anyhow::Result<CompioRuntime> {
  CompioRuntime::build(worker_threads)
}
