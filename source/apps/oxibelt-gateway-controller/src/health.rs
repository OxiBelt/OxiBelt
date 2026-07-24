use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::compatibility::CompatibilityPolicy;
use super::rollout_status::RolloutStatus;

#[derive(Debug, Clone)]
pub struct ControllerHealth {
  state: Arc<RwLock<HealthState>>,
  support: Arc<SupportMetadata>,
}

#[derive(Debug, Default)]
struct HealthState {
  election_participant: bool,
  leader: bool,
  reconciled: bool,
  reconcile_ready: bool,
  last_error: Option<String>,
}

#[derive(Debug)]
struct SupportMetadata {
  current_version: String,
  previous_version: Option<String>,
  deadline: Option<String>,
  compatibility_mode: &'static str,
}

impl Default for ControllerHealth {
  fn default() -> Self {
    Self {
      state: Arc::new(RwLock::new(HealthState::default())),
      support: Arc::new(SupportMetadata {
        current_version: oxibelt_build_identity::current()
          .effective_version
          .to_string(),
        previous_version: None,
        deadline: None,
        compatibility_mode: "exact",
      }),
    }
  }
}

impl ControllerHealth {
  pub fn new(policy: &CompatibilityPolicy) -> Self {
    Self {
      state: Arc::new(RwLock::new(HealthState::default())),
      support: Arc::new(SupportMetadata {
        current_version: policy.current_version.clone(),
        previous_version: policy.previous_version.clone(),
        deadline: policy.deadline.clone(),
        compatibility_mode: policy.mode.as_str(),
      }),
    }
  }

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
      .map(|state| {
        state.election_participant && (!state.leader || (state.reconciled && state.reconcile_ready))
      })
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

  fn response(&self, path: &str) -> (&'static str, &'static str, String) {
    match path {
      "/healthz" => ("200 OK", "text/plain", "ok\n".to_string()),
      "/readyz" if self.ready() => ("200 OK", "text/plain", "ready\n".to_string()),
      "/readyz" => (
        "503 Service Unavailable",
        "text/plain",
        "not ready\n".to_string(),
      ),
      "/leaderz" if self.leader() => ("200 OK", "text/plain", "leader\n".to_string()),
      "/leaderz" => (
        "503 Service Unavailable",
        "text/plain",
        "not leader\n".to_string(),
      ),
      "/reconcilez" if self.reconcile_ready() => {
        ("200 OK", "text/plain", "reconciled\n".to_string())
      }
      "/reconcilez" => (
        "503 Service Unavailable",
        "text/plain",
        "not reconciled\n".to_string(),
      ),
      "/supportz" => ("200 OK", "application/json", self.support_json()),
      _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    }
  }

  fn support_json(&self) -> String {
    let identity = oxibelt_build_identity::current();
    let state = self.state.read();
    let (participant, leader, reconciled, reconcile_ready, last_error) = state
      .as_deref()
      .map(|state| {
        (
          state.election_participant,
          state.leader,
          state.reconciled,
          state.reconcile_ready,
          state.last_error.is_some(),
        )
      })
      .unwrap_or((false, false, false, false, true));
    let value = serde_json::json!({
      "schemaVersion": 1,
      "featureState": "experimental",
      "policyVersion": 1,
      "build": {
        "effectiveVersion": identity.effective_version,
        "sourceRevision": identity.source_revision_or_unknown(),
        "kind": identity.kind.as_str(),
        "dirty": identity.dirty.as_str(),
      },
      "compatibility": {
        "mode": self.support.compatibility_mode,
        "currentVersion": self.support.current_version,
        "previousVersion": self.support.previous_version,
        "deadline": self.support.deadline,
      },
      "status": {
        "electionParticipant": participant,
        "leader": leader,
        "reconciled": reconciled,
        "reconcileReady": reconcile_ready,
        "lastError": last_error,
      }
    });
    format!("{value}\n")
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
        let (status, content_type, body) = health.response(path);
        let response = format!(
          "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
    assert!(!health.ready());
    health.mark_reconciled(RolloutStatus::pending("Pending"));
    assert!(!health.ready());
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

  #[test]
  fn failed_leader_reconciliation_fails_readiness_but_not_liveness() {
    let health = ControllerHealth::default();
    health.mark_election(true, true, None);
    health.mark_failed("sensitive object name".to_string());

    assert_eq!(health.response("/healthz").0, "200 OK");
    assert_eq!(health.response("/readyz").0, "503 Service Unavailable");
    assert_eq!(health.response("/reconcilez").0, "503 Service Unavailable");
  }

  #[test]
  fn support_projection_is_json_and_redacts_error_details() {
    let health = ControllerHealth::default();
    health.mark_election(true, true, None);
    health.mark_failed("Secret/private-key".to_string());

    let (status, content_type, body) = health.response("/supportz");
    assert_eq!(status, "200 OK");
    assert_eq!(content_type, "application/json");
    let value: serde_json::Value = serde_json::from_str(&body).expect("support JSON");
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["featureState"], "experimental");
    assert_eq!(value["compatibility"]["mode"], "exact");
    assert_eq!(value["status"]["lastError"], true);
    assert!(!body.contains("Secret/private-key"));
  }
}
