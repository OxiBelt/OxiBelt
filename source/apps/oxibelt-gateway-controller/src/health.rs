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
  election_participant: bool,
  leader: bool,
  reconciled: bool,
  reconcile_ready: bool,
  last_error: Option<String>,
}

impl ControllerHealth {
  pub fn mark_reconciled(&self, status: RolloutStatus) {
    if let Ok(mut state) = self.state.write() {
      state.reconciled = true;
      state.reconcile_ready = status.is_committed();
      state.last_error = status.reason;
    }
  }

  pub fn mark_failed(&self, error: String) {
    if let Ok(mut state) = self.state.write() {
      state.reconciled = false;
      state.reconcile_ready = false;
      state.last_error = Some(error);
    }
  }

  pub fn mark_election(&self, participant: bool, leader: bool, error: Option<String>) {
    if let Ok(mut state) = self.state.write() {
      state.election_participant = participant;
      state.leader = participant && leader;
      if error.is_some() {
        state.last_error = error;
      }
      if !state.leader {
        state.reconciled = false;
        state.reconcile_ready = false;
      }
    }
  }

  fn ready(&self) -> bool {
    self
      .state
      .read()
      .map(|state| state.election_participant)
      .unwrap_or(false)
  }

  fn leader(&self) -> bool {
    self.state.read().map(|state| state.leader).unwrap_or(false)
  }

  fn reconcile_ready(&self) -> bool {
    self
      .state
      .read()
      .map(|state| state.leader && state.reconciled && state.reconcile_ready)
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
          "/leaderz" if health.leader() => ("200 OK", "leader\n"),
          "/leaderz" => ("503 Service Unavailable", "not leader\n"),
          "/reconcilez" if health.reconcile_ready() => ("200 OK", "reconciled\n"),
          "/reconcilez" => ("503 Service Unavailable", "not reconciled\n"),
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
  fn readiness_distinguishes_election_participation_from_leadership_and_reconciliation() {
    let health = ControllerHealth::default();
    assert!(!health.ready());
    health.mark_election(true, false, None);
    assert!(health.ready());
    assert!(!health.leader());
    assert!(!health.reconcile_ready());
    health.mark_election(true, true, None);
    health.mark_reconciled(RolloutStatus::pending("Pending"));
    assert!(health.ready());
    assert!(health.leader());
    assert!(!health.reconcile_ready());
    health.mark_reconciled(RolloutStatus {
      phase: RolloutPhase::Committed,
      desired_revision: Some("revision".to_string()),
      desired_content_digest: Some("digest".to_string()),
      reason: None,
      proof: Some(crate::rollout_status::CommitProof::test()),
    });
    assert!(health.ready());
    assert!(health.reconcile_ready());
  }
}
