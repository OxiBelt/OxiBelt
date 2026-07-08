//! Tokio compatibility island for dependencies that still require Tokio types.

use std::time::Instant;

use anyhow::Context;
use tokio::runtime::{Builder, Runtime};

pub struct TokioIslandRuntime {
  runtime: Runtime,
}

impl TokioIslandRuntime {
  pub fn build(worker_threads: usize) -> anyhow::Result<Self> {
    let started = Instant::now();
    tracing::info!(
      startup_stage = "tokio_compatibility_island_build",
      worker_threads,
      "startup stage started"
    );
    let mut builder = Builder::new_multi_thread();
    builder.enable_all();
    builder.worker_threads(worker_threads);
    builder.thread_stack_size(super::TOKIO_RUNTIME_THREAD_STACK_SIZE);
    let runtime = builder
      .build()
      .context("failed to build Tokio compatibility island");
    match &runtime {
      Ok(_) => tracing::info!(
        startup_stage = "tokio_compatibility_island_build",
        worker_threads,
        elapsed_ms = started.elapsed().as_millis(),
        "startup stage completed"
      ),
      Err(error) => tracing::error!(
        startup_stage = "tokio_compatibility_island_build",
        worker_threads,
        elapsed_ms = started.elapsed().as_millis(),
        error = %error,
        "startup stage failed"
      ),
    }
    let runtime = runtime?;
    Ok(Self { runtime })
  }

  pub fn block_on<F>(&self, future: F) -> F::Output
  where
    F: std::future::Future,
  {
    self.runtime.block_on(future)
  }
}
