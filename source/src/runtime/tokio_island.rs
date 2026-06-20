//! Tokio compatibility island for dependencies that still require Tokio types.

use anyhow::Context;
use tokio::runtime::{Builder, Runtime};

pub struct TokioIslandRuntime {
  runtime: Runtime,
}

impl TokioIslandRuntime {
  pub fn build(worker_threads: usize) -> anyhow::Result<Self> {
    let mut builder = Builder::new_multi_thread();
    builder.enable_all();
    builder.worker_threads(worker_threads);
    let runtime = builder
      .build()
      .context("failed to build Tokio compatibility island")?;
    Ok(Self { runtime })
  }

  pub fn block_on<F>(&self, future: F) -> F::Output
  where
    F: std::future::Future,
  {
    self.runtime.block_on(future)
  }
}
