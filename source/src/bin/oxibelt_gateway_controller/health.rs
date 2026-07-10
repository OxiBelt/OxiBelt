use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::rollout_status::RolloutStatus;

#[derive(Debug, Clone, Default)]
pub struct ControllerHealth {
  state: Arc<RwLock<HealthState>>,
}

#[derive(Debug, Default)]
struct HealthState {
  reconciled: bool,
  ready: bool,
  last_error: Option<String>,
}

impl ControllerHealth {
  pub fn mark_reconciled(&self, status: RolloutStatus) {
    if let Ok(mut state) = self.state.write() {
      state.reconciled = true;
      state.ready = status.is_committed();
      state.last_error = status.reason;
    }
  }

  pub fn mark_failed(&self, error: String) {
    if let Ok(mut state) = self.state.write() {
      state.reconciled = false;
      state.ready = false;
      state.last_error = Some(error);
    }
  }

  fn ready(&self) -> bool {
    self
      .state
      .read()
      .map(|state| state.reconciled && state.ready)
      .unwrap_or(false)
  }
}

pub async fn spawn_if_configured(
  bind: Option<SocketAddr>,
  health: ControllerHealth,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
  let Some(bind) = bind else {
    return Ok(None);
  };
  let listener = TcpListener::bind(bind).await?;
  let handle = tokio::spawn(async move {
    loop {
      let Ok((mut stream, _)) = listener.accept().await else {
        continue;
      };
      let health = health.clone();
      tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).await.unwrap_or_default();
        let path = std::str::from_utf8(&buffer[..read])
          .ok()
          .and_then(|request| request.split_whitespace().nth(1))
          .unwrap_or("/");
        let (status, body) = match path {
          "/healthz" => ("200 OK", "ok\n"),
          "/readyz" if health.ready() => ("200 OK", "ready\n"),
          "/readyz" => ("503 Service Unavailable", "not ready\n"),
          _ => ("404 Not Found", "not found\n"),
        };
        let response = format!(
          "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
          body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body.as_bytes()).await;
      });
    }
  });
  Ok(Some(handle))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::rollout::RolloutPhase;

  #[test]
  fn readiness_requires_a_committed_reconciliation() {
    let health = ControllerHealth::default();
    assert!(!health.ready());
    health.mark_reconciled(RolloutStatus::pending("Pending"));
    assert!(!health.ready());
    health.mark_reconciled(RolloutStatus {
      phase: RolloutPhase::Committed,
      desired_revision: Some("revision".to_string()),
      desired_content_digest: Some("digest".to_string()),
      reason: None,
    });
    assert!(health.ready());
  }
}
