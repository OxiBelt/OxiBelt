//! Main async runtime selection for OxiBelt startup.

use std::future::Future;
use std::time::Instant;

use anyhow::Context;
use tokio::runtime::{Builder, Runtime};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ActiveMainRuntime {
  TokioHyper,
}

impl ActiveMainRuntime {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::TokioHyper => "tokio_hyper",
    }
  }
}

pub struct MainRuntime {
  active: ActiveMainRuntime,
  inner: Runtime,
}

impl MainRuntime {
  pub fn build_tokio(worker_threads: usize) -> anyhow::Result<Self> {
    let started = Instant::now();
    tracing::info!(
      startup_stage = "tokio_main_runtime_build",
      worker_threads,
      "startup stage started"
    );
    let mut builder = Builder::new_multi_thread();
    builder.enable_all();
    builder.worker_threads(worker_threads);
    builder.thread_stack_size(super::TOKIO_RUNTIME_THREAD_STACK_SIZE);
    let runtime = builder
      .build()
      .context("failed to build Tokio main runtime");
    match &runtime {
      Ok(_) => tracing::info!(
        startup_stage = "tokio_main_runtime_build",
        worker_threads,
        elapsed_ms = started.elapsed().as_millis(),
        "startup stage completed"
      ),
      Err(error) => tracing::error!(
        startup_stage = "tokio_main_runtime_build",
        worker_threads,
        elapsed_ms = started.elapsed().as_millis(),
        error = %error,
        "startup stage failed"
      ),
    }
    let runtime = runtime?;
    Ok(Self {
      active: ActiveMainRuntime::TokioHyper,
      inner: runtime,
    })
  }

  pub const fn active(&self) -> ActiveMainRuntime {
    self.active
  }

  pub fn block_on<F>(&self, future: F) -> F::Output
  where
    F: Future,
  {
    self.inner.block_on(future)
  }
}
