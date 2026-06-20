//! Compio runtime boundary for OxiBelt-owned async execution.

use anyhow::Context;

use super::tokio_island::TokioIslandRuntime;

pub struct CompioRuntime {
  runtime: compio::runtime::Runtime,
  tokio_island: TokioIslandRuntime,
}

impl CompioRuntime {
  pub fn build(worker_threads: usize) -> anyhow::Result<Self> {
    let runtime = compio::runtime::RuntimeBuilder::new()
      .build()
      .context("failed to build Compio runtime")?;
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

pub fn build_runtime(worker_threads: usize) -> anyhow::Result<CompioRuntime> {
  CompioRuntime::build(worker_threads)
}
