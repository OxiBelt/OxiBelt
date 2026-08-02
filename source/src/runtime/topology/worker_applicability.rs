//! Worker-setting applicability for owned and externally managed runtimes.

use serde::Serialize;

use super::RuntimeWorkerPool;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeWorkerApplicability {
  Applied,
  Inapplicable,
}

impl RuntimeWorkerApplicability {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Applied => "applied",
      Self::Inapplicable => "inapplicable",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeWorkerApplicabilities {
  pub tokio_executor_workers: RuntimeWorkerApplicability,
  pub tcp_accept_workers: RuntimeWorkerApplicability,
  pub quic_socket_workers: RuntimeWorkerApplicability,
  pub compio_direct_h1_workers: RuntimeWorkerApplicability,
  pub tokio_blocking_worker_limit: RuntimeWorkerApplicability,
}

impl RuntimeWorkerApplicabilities {
  pub const fn applied() -> Self {
    Self {
      tokio_executor_workers: RuntimeWorkerApplicability::Applied,
      tcp_accept_workers: RuntimeWorkerApplicability::Applied,
      quic_socket_workers: RuntimeWorkerApplicability::Applied,
      compio_direct_h1_workers: RuntimeWorkerApplicability::Applied,
      tokio_blocking_worker_limit: RuntimeWorkerApplicability::Applied,
    }
  }

  pub const fn embedded() -> Self {
    Self {
      tokio_executor_workers: RuntimeWorkerApplicability::Inapplicable,
      tcp_accept_workers: RuntimeWorkerApplicability::Applied,
      quic_socket_workers: RuntimeWorkerApplicability::Applied,
      compio_direct_h1_workers: RuntimeWorkerApplicability::Inapplicable,
      tokio_blocking_worker_limit: RuntimeWorkerApplicability::Inapplicable,
    }
  }

  pub(super) const fn for_pool(self, pool: RuntimeWorkerPool) -> RuntimeWorkerApplicability {
    match pool {
      RuntimeWorkerPool::TokioExecutor => self.tokio_executor_workers,
      RuntimeWorkerPool::TcpAccept => self.tcp_accept_workers,
      RuntimeWorkerPool::QuicSocket => self.quic_socket_workers,
      RuntimeWorkerPool::CompioDirectH1 => self.compio_direct_h1_workers,
    }
  }
}
