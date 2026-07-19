//! Before-image checkpoints used by fixed-member Admin rollouts.
//!
//! Checkpoint payloads may contain configuration or rule material. They must
//! only be persisted through the rollout artifact cipher; this module keeps
//! plaintext buffers zeroized and deliberately omits their contents from
//! `Debug` output.

use std::fmt;

use anyhow::{bail, ensure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::state::AppSnapshot;

const CHECKPOINT_FORMAT: &str = "oxibelt-admin-checkpoint-v1";
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckpointOperation {
  ConfigLoad,
  ConfigRollback,
  FileSync,
  DownstreamTlsReload,
  KeyRotation,
  SecretReference,
}

#[derive(Clone)]
pub(crate) struct CheckpointBinding {
  pub(crate) operation: CheckpointOperation,
  pub(crate) principal: String,
  pub(crate) actor_name: String,
  pub(crate) admin_update_config: bool,
  pub(crate) ipm_update_config: bool,
  pub(crate) runtime_rollback: bool,
  pub(crate) previous_revision: String,
  pub(crate) previous_digest: String,
  pub(crate) candidate_revision: String,
  pub(crate) candidate_digest: String,
}

impl fmt::Debug for CheckpointBinding {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CheckpointBinding")
      .field("operation", &self.operation)
      .field("principal", &self.principal)
      .field("actor_name", &self.actor_name)
      .field("previous_revision", &self.previous_revision)
      .field("previous_digest", &self.previous_digest)
      .field("candidate_revision", &self.candidate_revision)
      .field("candidate_digest", &self.candidate_digest)
      .finish()
  }
}

#[derive(Clone)]
pub(crate) struct FileBeforeImage {
  pub(crate) root: String,
  pub(crate) path: String,
  pub(crate) previous: Option<Zeroizing<Vec<u8>>>,
  pub(crate) applied_digest: Option<String>,
}

impl fmt::Debug for FileBeforeImage {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("FileBeforeImage")
      .field("root", &self.root)
      .field("path", &self.path)
      .field("previous_present", &self.previous.is_some())
      .field(
        "previous_len",
        &self.previous.as_ref().map(|value| value.len()),
      )
      .field("applied_digest", &self.applied_digest)
      .finish()
  }
}

#[derive(Clone)]
pub(crate) struct MutationCheckpoint {
  binding: CheckpointBinding,
  snapshot: Option<AppSnapshot>,
  files: Vec<FileBeforeImage>,
  encoded: Zeroizing<Vec<u8>>,
  integrity_digest: String,
}

impl fmt::Debug for MutationCheckpoint {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("MutationCheckpoint")
      .field("binding", &self.binding)
      .field("files", &self.files)
      .field("encoded_len", &self.encoded.len())
      .field("integrity_digest", &self.integrity_digest)
      .finish_non_exhaustive()
  }
}

impl MutationCheckpoint {
  pub(crate) fn new(
    binding: CheckpointBinding,
    snapshot: AppSnapshot,
    files: Vec<FileBeforeImage>,
  ) -> anyhow::Result<Self> {
    validate_binding(&binding)?;
    let wire = CheckpointWire::from_parts(&binding, &files);
    let encoded = Zeroizing::new(serde_json::to_vec(&wire)?);
    ensure!(
      encoded.len() <= MAX_CHECKPOINT_BYTES,
      "Admin mutation checkpoint exceeds its encrypted artifact bound"
    );
    let integrity_digest = format!("sha256:{}", sha256_hex(&encoded));
    Ok(Self {
      binding,
      snapshot: Some(snapshot),
      files,
      encoded,
      integrity_digest,
    })
  }

  pub(crate) fn binding(&self) -> &CheckpointBinding {
    &self.binding
  }

  pub(crate) fn snapshot(&self) -> Option<&AppSnapshot> {
    self.snapshot.as_ref()
  }

  pub(crate) fn files(&self) -> &[FileBeforeImage] {
    &self.files
  }

  /// Returns plaintext that must be sealed before leaving the process.
  pub(crate) fn encoded_plaintext(&self) -> &[u8] {
    &self.encoded
  }

  pub(crate) fn verify_binding(&self, expected: &CheckpointBinding) -> anyhow::Result<()> {
    validate_binding(expected)?;
    ensure!(
      self.binding.operation == expected.operation
        && self.binding.principal == expected.principal
        && self.binding.actor_name == expected.actor_name
        && self.binding.admin_update_config == expected.admin_update_config
        && self.binding.ipm_update_config == expected.ipm_update_config
        && self.binding.runtime_rollback == expected.runtime_rollback
        && self.binding.previous_revision == expected.previous_revision
        && self.binding.previous_digest == expected.previous_digest
        && self.binding.candidate_revision == expected.candidate_revision
        && self.binding.candidate_digest == expected.candidate_digest,
      "Admin mutation checkpoint binding does not match the assigned rollout"
    );
    ensure!(
      format!("sha256:{}", sha256_hex(&self.encoded)) == self.integrity_digest,
      "Admin mutation checkpoint integrity digest does not match"
    );
    Ok(())
  }

  pub(crate) fn decode_authenticated(
    expected: CheckpointBinding,
    encoded: Zeroizing<Vec<u8>>,
    integrity_digest: &str,
  ) -> anyhow::Result<Self> {
    validate_binding(&expected)?;
    ensure!(
      encoded.len() <= MAX_CHECKPOINT_BYTES,
      "Admin mutation checkpoint exceeds its bound"
    );
    ensure!(
      format!("sha256:{}", sha256_hex(&encoded)) == integrity_digest,
      "Admin mutation checkpoint integrity digest does not match"
    );
    let wire: CheckpointWireOwned = serde_json::from_slice(&encoded)?;
    ensure!(
      wire.format == CHECKPOINT_FORMAT,
      "unsupported Admin mutation checkpoint format"
    );
    ensure!(
      wire.operation == expected.operation
        && wire.principal == expected.principal
        && wire.actor_name == expected.actor_name
        && wire.admin_update_config == expected.admin_update_config
        && wire.ipm_update_config == expected.ipm_update_config
        && wire.runtime_rollback == expected.runtime_rollback
        && wire.previous_revision == expected.previous_revision
        && wire.previous_digest == expected.previous_digest
        && wire.candidate_revision == expected.candidate_revision
        && wire.candidate_digest == expected.candidate_digest,
      "Admin mutation checkpoint binding does not match its encrypted payload"
    );
    let files = wire
      .files
      .into_iter()
      .map(|file| FileBeforeImage {
        root: file.root,
        path: file.path,
        previous: file.previous.map(Zeroizing::new),
        applied_digest: file.applied_digest,
      })
      .collect();
    Ok(Self {
      binding: expected,
      snapshot: None,
      files,
      encoded,
      integrity_digest: integrity_digest.to_string(),
    })
  }
}

fn validate_binding(binding: &CheckpointBinding) -> anyhow::Result<()> {
  for (field, value) in [
    ("principal", binding.principal.as_str()),
    ("actor name", binding.actor_name.as_str()),
    ("previous revision", binding.previous_revision.as_str()),
    ("candidate revision", binding.candidate_revision.as_str()),
  ] {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
      bail!("checkpoint {field} is invalid");
    }
  }
  validate_digest("previous", &binding.previous_digest)?;
  validate_digest("candidate", &binding.candidate_digest)
}

fn validate_digest(field: &str, digest: &str) -> anyhow::Result<()> {
  ensure!(
    digest.len() == 71
      && digest.starts_with("sha256:")
      && digest[7..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
    "checkpoint {field} digest is invalid"
  );
  Ok(())
}

#[derive(Serialize)]
struct CheckpointWire<'a> {
  format: &'static str,
  operation: CheckpointOperation,
  principal: &'a str,
  actor_name: &'a str,
  admin_update_config: bool,
  ipm_update_config: bool,
  runtime_rollback: bool,
  previous_revision: &'a str,
  previous_digest: &'a str,
  candidate_revision: &'a str,
  candidate_digest: &'a str,
  files: Vec<FileBeforeImageWire<'a>>,
}

impl<'a> CheckpointWire<'a> {
  fn from_parts(binding: &'a CheckpointBinding, files: &'a [FileBeforeImage]) -> Self {
    Self {
      format: CHECKPOINT_FORMAT,
      operation: binding.operation,
      principal: &binding.principal,
      actor_name: &binding.actor_name,
      admin_update_config: binding.admin_update_config,
      ipm_update_config: binding.ipm_update_config,
      runtime_rollback: binding.runtime_rollback,
      previous_revision: &binding.previous_revision,
      previous_digest: &binding.previous_digest,
      candidate_revision: &binding.candidate_revision,
      candidate_digest: &binding.candidate_digest,
      files: files
        .iter()
        .map(|file| FileBeforeImageWire {
          root: &file.root,
          path: &file.path,
          previous: file.previous.as_ref().map(|value| value.as_slice()),
          applied_digest: file.applied_digest.as_deref(),
        })
        .collect(),
    }
  }
}

#[derive(Deserialize)]
struct CheckpointWireOwned {
  format: String,
  operation: CheckpointOperation,
  principal: String,
  actor_name: String,
  admin_update_config: bool,
  ipm_update_config: bool,
  runtime_rollback: bool,
  previous_revision: String,
  previous_digest: String,
  candidate_revision: String,
  candidate_digest: String,
  files: Vec<FileBeforeImageOwned>,
}

#[derive(Deserialize)]
struct FileBeforeImageOwned {
  root: String,
  path: String,
  previous: Option<Vec<u8>>,
  applied_digest: Option<String>,
}

#[derive(Serialize)]
struct FileBeforeImageWire<'a> {
  root: &'a str,
  path: &'a str,
  previous: Option<&'a [u8]>,
  applied_digest: Option<&'a str>,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
  let digest = crate::crypto::sha256(bytes);
  let mut output = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(output, "{byte:02x}");
  }
  output
}

#[cfg(test)]
mod tests {
  use super::*;

  fn binding() -> CheckpointBinding {
    CheckpointBinding {
      operation: CheckpointOperation::FileSync,
      principal: "spiffe://example.test/admin".to_string(),
      actor_name: "deployer".to_string(),
      admin_update_config: false,
      ipm_update_config: false,
      runtime_rollback: false,
      previous_revision: "r1".to_string(),
      previous_digest: format!("sha256:{}", "1".repeat(64)),
      candidate_revision: "r2".to_string(),
      candidate_digest: format!("sha256:{}", "2".repeat(64)),
    }
  }

  #[test]
  fn debug_never_contains_before_image_bytes() {
    let image = FileBeforeImage {
      root: "config".to_string(),
      path: "private.toml".to_string(),
      previous: Some(Zeroizing::new(b"do-not-log-this-value".to_vec())),
      applied_digest: None,
    };
    let debug = format!("{image:?}");
    assert!(!debug.contains("do-not-log-this-value"));
    assert!(debug.contains("previous_len"));
  }

  #[test]
  fn encrypted_plaintext_reconstructs_file_before_images() {
    let binding = binding();
    let files = vec![FileBeforeImage {
      root: "config".to_string(),
      path: "edge.toml".to_string(),
      previous: Some(Zeroizing::new(b"before".to_vec())),
      applied_digest: Some("a".repeat(64)),
    }];
    let encoded = Zeroizing::new(
      serde_json::to_vec(&CheckpointWire::from_parts(&binding, &files)).expect("checkpoint wire"),
    );
    let digest = format!("sha256:{}", sha256_hex(&encoded));
    let recovered = MutationCheckpoint::decode_authenticated(binding, encoded, &digest)
      .expect("authenticated checkpoint");
    assert!(recovered.snapshot().is_none());
    assert_eq!(
      recovered.files()[0]
        .previous
        .as_ref()
        .map(|value| value.as_slice()),
      Some(b"before".as_slice())
    );
  }

  #[test]
  fn canonical_digests_are_required() {
    let mut binding = binding();
    binding.candidate_digest = "2".repeat(64);
    assert!(validate_binding(&binding).is_err());
  }
}
