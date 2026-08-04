//! Authenticated staged Admin membership documents and lifecycle state.
//!
//! These types are deliberately side-effect free. Durable authority is
//! established only by PostgreSQL transactions in `membership_store`.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ledger::validate_identifier;

pub(crate) const MEMBERSHIP_DOCUMENT_VERSION: u32 = 2;
pub(crate) const LEGACY_MEMBERSHIP_DOCUMENT_VERSION: u32 = 1;
pub(crate) const MAX_MEMBERSHIP_MEMBERS: usize = 1_024;
pub(crate) const MEMBERSHIP_CAPABILITY_VERSION: &str = "admin-membership-epoch-v2";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipMember {
  pub(crate) id: String,
  pub(crate) readiness_ed25519_public_key: String,
  pub(crate) catchup_x25519_public_key: String,
}

impl MembershipMember {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    validate_identifier("membership member ID", &self.id, 253)?;
    validate_public_key(
      "membership readiness Ed25519 public key",
      &self.readiness_ed25519_public_key,
    )?;
    validate_public_key(
      "membership catch-up X25519 public key",
      &self.catchup_x25519_public_key,
    )?;
    ensure!(
      self.readiness_ed25519_public_key != self.catchup_x25519_public_key,
      "membership readiness and catch-up public keys must be distinct"
    );
    Ok(())
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipEpoch {
  pub(crate) version: u32,
  pub(crate) cluster_id: String,
  pub(crate) sequence: u64,
  pub(crate) predecessor: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) artifact_key_fingerprint: Option<String>,
  pub(crate) members: Vec<MembershipMember>,
  pub(crate) authorized_by_request_id: String,
}

impl MembershipEpoch {
  #[cfg(test)]
  pub(crate) fn new(
    cluster_id: String,
    sequence: u64,
    predecessor: Option<String>,
    members: Vec<MembershipMember>,
    authorized_by_request_id: String,
  ) -> anyhow::Result<Self> {
    let value = Self {
      version: LEGACY_MEMBERSHIP_DOCUMENT_VERSION,
      cluster_id,
      sequence,
      predecessor,
      artifact_key_fingerprint: None,
      members,
      authorized_by_request_id,
    };
    value.validate()?;
    Ok(value)
  }

  pub(crate) fn new_v2(
    cluster_id: String,
    sequence: u64,
    predecessor: Option<String>,
    artifact_key_fingerprint: String,
    members: Vec<MembershipMember>,
    authorized_by_request_id: String,
  ) -> anyhow::Result<Self> {
    let value = Self {
      version: MEMBERSHIP_DOCUMENT_VERSION,
      cluster_id,
      sequence,
      predecessor,
      artifact_key_fingerprint: Some(artifact_key_fingerprint),
      members,
      authorized_by_request_id,
    };
    value.validate()?;
    Ok(value)
  }

  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      matches!(
        self.version,
        LEGACY_MEMBERSHIP_DOCUMENT_VERSION | MEMBERSHIP_DOCUMENT_VERSION
      ),
      "unsupported membership epoch version"
    );
    match self.version {
      LEGACY_MEMBERSHIP_DOCUMENT_VERSION => ensure!(
        self.artifact_key_fingerprint.is_none(),
        "legacy membership epoch cannot name an epoch artifact key"
      ),
      MEMBERSHIP_DOCUMENT_VERSION => ensure!(
        self
          .artifact_key_fingerprint
          .as_deref()
          .is_some_and(is_sha256_digest),
        "membership epoch v2 requires a canonical artifact-key fingerprint"
      ),
      _ => bail!("unsupported membership epoch version"),
    }
    validate_identifier("membership cluster ID", &self.cluster_id, 253)?;
    validate_identifier(
      "membership authorization request ID",
      &self.authorized_by_request_id,
      256,
    )?;
    ensure!(
      (2..=MAX_MEMBERSHIP_MEMBERS).contains(&self.members.len()),
      "membership epoch must contain between 2 and {MAX_MEMBERSHIP_MEMBERS} members"
    );
    if self.sequence == 0 {
      ensure!(
        self.predecessor.is_none(),
        "genesis membership epoch must not name a predecessor"
      );
    } else {
      ensure!(
        self.predecessor.as_deref().is_some_and(is_sha256_digest),
        "non-genesis membership epoch requires a canonical predecessor digest"
      );
    }
    let mut ids = BTreeSet::new();
    let mut readiness_keys = BTreeSet::new();
    let mut catchup_keys = BTreeSet::new();
    for member in &self.members {
      member.validate()?;
      ensure!(
        ids.insert(member.id.as_str()),
        "membership epoch contains duplicate member {}",
        member.id
      );
      ensure!(
        readiness_keys.insert(member.readiness_ed25519_public_key.as_str()),
        "membership epoch contains a duplicate readiness public key"
      );
      ensure!(
        catchup_keys.insert(member.catchup_x25519_public_key.as_str()),
        "membership epoch contains a duplicate catch-up public key"
      );
    }
    ensure!(
      readiness_keys.is_disjoint(&catchup_keys),
      "membership epoch readiness and catch-up public keys must be globally distinct"
    );
    Ok(())
  }

  pub(crate) fn canonical_members(&self) -> Vec<&MembershipMember> {
    let mut members = self.members.iter().collect::<Vec<_>>();
    members.sort_by(|left, right| left.id.cmp(&right.id));
    members
  }

  pub(crate) fn digest(&self) -> anyhow::Result<String> {
    self.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(if self.version == LEGACY_MEMBERSHIP_DOCUMENT_VERSION {
      b"OXIBELT-ADMIN-MEMBERSHIP-EPOCH-V1\0".as_slice()
    } else {
      b"OXIBELT-ADMIN-MEMBERSHIP-EPOCH-V2\0".as_slice()
    });
    hash_field(&mut hasher, &self.version.to_string());
    hash_field(&mut hasher, &self.cluster_id);
    hash_field(&mut hasher, &self.sequence.to_string());
    hash_field(&mut hasher, self.predecessor.as_deref().unwrap_or(""));
    if self.version == MEMBERSHIP_DOCUMENT_VERSION {
      hash_field(
        &mut hasher,
        self
          .artifact_key_fingerprint
          .as_deref()
          .context("validated membership epoch v2 key fingerprint is missing")?,
      );
    }
    hash_field(&mut hasher, &self.authorized_by_request_id);
    for member in self.canonical_members() {
      hash_field(&mut hasher, &member.id);
      hash_field(&mut hasher, &member.readiness_ed25519_public_key);
      hash_field(&mut hasher, &member.catchup_x25519_public_key);
    }
    Ok(format_digest(hasher.finalize()))
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MembershipTransitionKind {
  Initialize,
  Join,
  Maintenance,
  Remove,
  Rejoin,
}

impl MembershipTransitionKind {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Initialize => "initialize",
      Self::Join => "join",
      Self::Maintenance => "maintenance",
      Self::Remove => "remove",
      Self::Rejoin => "rejoin",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MembershipTransitionState {
  Proposed,
  Learner,
  CatchingUp,
  Ready,
  ActivationAuthorized,
  Fencing,
  Active,
  Cancelled,
  Indeterminate,
}

impl MembershipTransitionState {
  pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
    match value {
      "proposed" => Ok(Self::Proposed),
      "learner" => Ok(Self::Learner),
      "catching_up" => Ok(Self::CatchingUp),
      "ready" => Ok(Self::Ready),
      "activation_authorized" => Ok(Self::ActivationAuthorized),
      "fencing" => Ok(Self::Fencing),
      "active" => Ok(Self::Active),
      "cancelled" => Ok(Self::Cancelled),
      "indeterminate" => Ok(Self::Indeterminate),
      _ => bail!("unsupported membership transition state"),
    }
  }

  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Proposed => "proposed",
      Self::Learner => "learner",
      Self::CatchingUp => "catching_up",
      Self::Ready => "ready",
      Self::ActivationAuthorized => "activation_authorized",
      Self::Fencing => "fencing",
      Self::Active => "active",
      Self::Cancelled => "cancelled",
      Self::Indeterminate => "indeterminate",
    }
  }

  pub(crate) const fn may_transition_to(self, next: Self) -> bool {
    match self {
      Self::Proposed => matches!(next, Self::Learner | Self::Ready | Self::Cancelled),
      Self::Learner => matches!(next, Self::CatchingUp | Self::Cancelled),
      Self::CatchingUp => matches!(next, Self::Ready | Self::Cancelled | Self::Indeterminate),
      Self::Ready => matches!(next, Self::ActivationAuthorized | Self::Cancelled),
      Self::ActivationAuthorized => {
        matches!(next, Self::Fencing | Self::Active | Self::Indeterminate)
      }
      Self::Fencing => matches!(next, Self::Active | Self::Indeterminate),
      Self::Active | Self::Cancelled | Self::Indeterminate => false,
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipTransitionRequest {
  pub(crate) version: u32,
  pub(crate) kind: MembershipTransitionKind,
  pub(crate) expected_active_epoch: Option<String>,
  pub(crate) member: Option<MembershipMember>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipReadinessReceipt {
  pub(crate) version: u32,
  pub(crate) transition_id: String,
  pub(crate) target_epoch: String,
  pub(crate) member_id: String,
  pub(crate) catchup_cursor: u32,
  pub(crate) catchup_digest: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) source_epoch: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) artifact_key_fingerprint: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) checkpoint_digest: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) journal_tail_digest: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) verified_position: Option<u64>,
  pub(crate) build_version: String,
  pub(crate) capability_version: String,
  pub(crate) issued_at_unix_seconds: i64,
  pub(crate) signature: String,
}

impl MembershipReadinessReceipt {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      matches!(self.version, 1 | 2),
      "unsupported membership readiness receipt version"
    );
    validate_identifier("membership transition ID", &self.transition_id, 256)?;
    validate_identifier("membership readiness member ID", &self.member_id, 253)?;
    validate_identifier(
      "membership readiness build version",
      &self.build_version,
      256,
    )?;
    validate_identifier(
      "membership readiness capability version",
      &self.capability_version,
      256,
    )?;
    ensure!(
      is_sha256_digest(&self.target_epoch),
      "readiness target epoch is invalid"
    );
    ensure!(
      is_sha256_digest(&self.catchup_digest),
      "readiness catch-up digest is invalid"
    );
    ensure!(
      self.catchup_cursor > 0,
      "readiness catch-up cursor must be positive"
    );
    if self.version == 1 {
      ensure!(
        self.source_epoch.is_none()
          && self.artifact_key_fingerprint.is_none()
          && self.checkpoint_digest.is_none()
          && self.journal_tail_digest.is_none()
          && self.verified_position.is_none(),
        "legacy readiness receipt cannot contain v2 verification evidence"
      );
    } else {
      for (name, digest) in [
        ("readiness source epoch", self.source_epoch.as_deref()),
        (
          "readiness artifact-key fingerprint",
          self.artifact_key_fingerprint.as_deref(),
        ),
        (
          "readiness checkpoint digest",
          self.checkpoint_digest.as_deref(),
        ),
        (
          "readiness journal-tail digest",
          self.journal_tail_digest.as_deref(),
        ),
      ] {
        ensure!(digest.is_some_and(is_sha256_digest), "{name} is invalid");
      }
      ensure!(
        self.verified_position.is_some(),
        "readiness verified position is missing"
      );
      ensure!(
        self.capability_version == MEMBERSHIP_CAPABILITY_VERSION,
        "membership learner capability is incompatible"
      );
    }
    validate_base64_len("membership readiness signature", &self.signature, 64)
  }

  pub(crate) fn transcript(&self, cluster_id: &str) -> anyhow::Result<Vec<u8>> {
    self.validate()?;
    validate_identifier("membership cluster ID", cluster_id, 253)?;
    let mut transcript = if self.version == 1 {
      b"OXIBELT-ADMIN-MEMBERSHIP-READINESS-V1\0".to_vec()
    } else {
      b"OXIBELT-ADMIN-MEMBERSHIP-READINESS-V2\0".to_vec()
    };
    for field in [
      cluster_id,
      self.transition_id.as_str(),
      self.target_epoch.as_str(),
      self.member_id.as_str(),
      self.catchup_digest.as_str(),
      self.build_version.as_str(),
      self.capability_version.as_str(),
    ] {
      transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
      transcript.extend_from_slice(field.as_bytes());
    }
    transcript.extend_from_slice(&self.catchup_cursor.to_be_bytes());
    if self.version == 2 {
      let source_epoch = self
        .source_epoch
        .as_deref()
        .context("validated readiness source epoch is missing")?;
      let artifact_key_fingerprint = self
        .artifact_key_fingerprint
        .as_deref()
        .context("validated readiness artifact-key fingerprint is missing")?;
      let checkpoint_digest = self
        .checkpoint_digest
        .as_deref()
        .context("validated readiness checkpoint digest is missing")?;
      let journal_tail_digest = self
        .journal_tail_digest
        .as_deref()
        .context("validated readiness journal-tail digest is missing")?;
      for field in [
        source_epoch,
        artifact_key_fingerprint,
        checkpoint_digest,
        journal_tail_digest,
      ] {
        transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
        transcript.extend_from_slice(field.as_bytes());
      }
      transcript.extend_from_slice(
        &self
          .verified_position
          .context("validated readiness verified position is missing")?
          .to_be_bytes(),
      );
    }
    transcript.extend_from_slice(&self.issued_at_unix_seconds.to_be_bytes());
    Ok(transcript)
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipKeyProof {
  pub(crate) version: u32,
  pub(crate) transition_id: String,
  pub(crate) target_epoch: String,
  pub(crate) member_id: String,
  pub(crate) artifact_key_fingerprint: String,
  pub(crate) build_version: String,
  pub(crate) capability_version: String,
  pub(crate) issued_at_unix_seconds: i64,
  pub(crate) signature: String,
}

impl MembershipKeyProof {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      self.version == 2,
      "unsupported membership key-proof version"
    );
    validate_identifier("membership transition ID", &self.transition_id, 256)?;
    validate_identifier("membership key-proof member ID", &self.member_id, 253)?;
    validate_identifier(
      "membership key-proof build version",
      &self.build_version,
      256,
    )?;
    ensure!(
      self.capability_version == MEMBERSHIP_CAPABILITY_VERSION,
      "membership key-proof capability is incompatible"
    );
    ensure!(
      is_sha256_digest(&self.target_epoch) && is_sha256_digest(&self.artifact_key_fingerprint),
      "membership key-proof target or key fingerprint is invalid"
    );
    validate_base64_len("membership key-proof signature", &self.signature, 64)
  }

  pub(crate) fn transcript(&self, cluster_id: &str) -> anyhow::Result<Vec<u8>> {
    self.validate()?;
    validate_identifier("membership cluster ID", cluster_id, 253)?;
    let mut transcript = b"OXIBELT-ADMIN-MEMBERSHIP-KEY-PROOF-V2\0".to_vec();
    for field in [
      cluster_id,
      self.transition_id.as_str(),
      self.target_epoch.as_str(),
      self.member_id.as_str(),
      self.artifact_key_fingerprint.as_str(),
      self.build_version.as_str(),
      self.capability_version.as_str(),
    ] {
      transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
      transcript.extend_from_slice(field.as_bytes());
    }
    transcript.extend_from_slice(&self.issued_at_unix_seconds.to_be_bytes());
    Ok(transcript)
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipActivationRequest {
  pub(crate) version: u32,
  pub(crate) transition_id: String,
  pub(crate) expected_target_epoch: String,
}

impl MembershipActivationRequest {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      self.version == 1,
      "unsupported membership activation request version"
    );
    validate_identifier("membership transition ID", &self.transition_id, 256)?;
    ensure!(
      is_sha256_digest(&self.expected_target_epoch),
      "membership activation target epoch is invalid"
    );
    Ok(())
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipCancelRequest {
  pub(crate) version: u32,
  pub(crate) transition_id: String,
  pub(crate) expected_target_epoch: String,
}

impl MembershipCancelRequest {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      self.version == 1,
      "unsupported membership cancellation request version"
    );
    validate_identifier("membership transition ID", &self.transition_id, 256)?;
    ensure!(
      is_sha256_digest(&self.expected_target_epoch),
      "membership cancellation target epoch is invalid"
    );
    Ok(())
  }
}

impl MembershipTransitionRequest {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      self.version == 1,
      "unsupported membership transition request version"
    );
    if let Some(epoch) = self.expected_active_epoch.as_deref() {
      ensure!(
        is_sha256_digest(epoch),
        "expected active epoch must be canonical SHA-256"
      );
    }
    match self.kind {
      MembershipTransitionKind::Initialize => {
        ensure!(
          self.expected_active_epoch.is_none(),
          "initialization must not name an active epoch"
        );
        ensure!(
          self.member.is_none(),
          "initialization must not name one member"
        );
      }
      MembershipTransitionKind::Join | MembershipTransitionKind::Rejoin => {
        ensure!(
          self.expected_active_epoch.is_some(),
          "join requires the active epoch precondition"
        );
        self
          .member
          .as_ref()
          .ok_or_else(|| anyhow::anyhow!("join requires member trust material"))?
          .validate()?;
      }
      MembershipTransitionKind::Maintenance | MembershipTransitionKind::Remove => {
        ensure!(
          self.expected_active_epoch.is_some(),
          "membership removal requires the active epoch precondition"
        );
        let member = self
          .member
          .as_ref()
          .ok_or_else(|| anyhow::anyhow!("membership removal requires a member identity"))?;
        member.validate()?;
      }
    }
    Ok(())
  }
}

fn validate_public_key(name: &str, value: &str) -> anyhow::Result<()> {
  validate_base64_len(name, value, 32)
}

fn validate_base64_len(name: &str, value: &str, expected_len: usize) -> anyhow::Result<()> {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(value)
    .map_err(|_| anyhow::anyhow!("{name} must be canonical base64"))?;
  if decoded.len() != expected_len
    || base64::engine::general_purpose::STANDARD.encode(decoded) != value
  {
    bail!("{name} must encode exactly {expected_len} bytes using canonical base64");
  }
  Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
  value.len() == 71
    && value.starts_with("sha256:")
    && value[7..]
      .bytes()
      .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hash_field(hasher: &mut Sha256, value: &str) {
  hasher.update((value.len() as u64).to_be_bytes());
  hasher.update(value.as_bytes());
}

fn format_digest(bytes: impl AsRef<[u8]>) -> String {
  let mut output = String::from("sha256:");
  for byte in bytes.as_ref() {
    let _ = write!(output, "{byte:02x}");
  }
  output
}

#[cfg(test)]
mod tests {
  use super::*;

  fn member(id: &str, key: u8) -> MembershipMember {
    MembershipMember {
      id: id.to_string(),
      readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD.encode([key; 32]),
      catchup_x25519_public_key: base64::engine::general_purpose::STANDARD
        .encode([key.wrapping_add(100); 32]),
    }
  }

  #[test]
  fn epoch_digest_is_order_independent_and_chain_bound() {
    let left = MembershipEpoch::new(
      "primary".into(),
      0,
      None,
      vec![member("a", 1), member("b", 2)],
      "initialize-1".into(),
    )
    .expect("epoch");
    let right = MembershipEpoch::new(
      "primary".into(),
      0,
      None,
      vec![member("b", 2), member("a", 1)],
      "initialize-1".into(),
    )
    .expect("epoch");
    assert_eq!(
      left.digest().expect("digest"),
      right.digest().expect("digest")
    );
    let mut different = right;
    different.authorized_by_request_id = "initialize-2".into();
    assert_ne!(
      left.digest().expect("digest"),
      different.digest().expect("digest")
    );
  }

  #[test]
  fn learner_never_skips_readiness_or_activation_authorization() {
    assert!(
      !MembershipTransitionState::Learner.may_transition_to(MembershipTransitionState::Ready)
    );
    assert!(!MembershipTransitionState::Ready.may_transition_to(MembershipTransitionState::Active));
    assert!(
      MembershipTransitionState::CatchingUp.may_transition_to(MembershipTransitionState::Ready)
    );
    assert!(
      MembershipTransitionState::Ready
        .may_transition_to(MembershipTransitionState::ActivationAuthorized)
    );
  }

  #[test]
  fn epoch_rejects_cross_member_and_cross_purpose_key_reuse() {
    let mut members = vec![member("a", 1), member("b", 2)];
    members[1].readiness_ed25519_public_key = members[0].readiness_ed25519_public_key.clone();
    assert!(
      MembershipEpoch::new("primary".into(), 0, None, members, "initialize-1".into()).is_err()
    );

    let mut members = vec![member("a", 1), member("b", 2)];
    members[1].catchup_x25519_public_key = members[0].readiness_ed25519_public_key.clone();
    assert!(
      MembershipEpoch::new("primary".into(), 0, None, members, "initialize-1".into()).is_err()
    );
  }

  #[test]
  fn v1_digest_remains_stable_while_v2_binds_the_artifact_key() {
    let legacy = MembershipEpoch::new(
      "primary".into(),
      0,
      None,
      vec![member("a", 1), member("b", 2)],
      "initialize-1".into(),
    )
    .expect("legacy epoch");
    let v2 = MembershipEpoch::new_v2(
      "primary".into(),
      0,
      None,
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
      legacy.members.clone(),
      "initialize-1".into(),
    )
    .expect("v2 epoch");
    assert_eq!(legacy.version, 1);
    assert_eq!(v2.version, 2);
    assert_eq!(
      legacy.digest().expect("legacy digest"),
      "sha256:d1a297ecdfdeff456d9713d82eacc5c8da0ca727515306556e02df436986bf94"
    );
    assert_ne!(
      legacy.digest().expect("legacy digest"),
      v2.digest().expect("v2 digest")
    );
  }
}
