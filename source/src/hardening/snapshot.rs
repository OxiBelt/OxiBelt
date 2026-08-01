//! Bounded, redaction-safe runtime-hardening contract types.

use serde::{Deserialize, Serialize};

use crate::config::{HardeningAutoMode, RuntimeLandlockMode, RuntimeSeccompExpectation};

pub const RUNTIME_HARDENING_SNAPSHOT_SCHEMA_VERSION: u32 = 3;
const MAX_HARDENING_REASONS: usize = 16;
pub(super) const MAX_EFFECTIVE_LANDLOCK_RULE_SUMMARIES: usize = 64;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHardeningOutcome {
  Satisfied,
  Degraded,
  Blocked,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHardeningReason {
  CloseRangeUnavailable,
  LandlockRightsDowngraded,
  ProcessStatusUnavailable,
  ProcessStatusMalformed,
  SeccompFilterNotActive,
  NoNewPrivilegesNotActive,
  ProfileAssertionUnavailable,
  ProfileAssertionMalformed,
  ProfileIdentityMismatch,
  ProfileDigestMismatch,
  FilesystemManifestUnavailable,
  FilesystemManifestDigestMismatch,
  FilesystemWritablePathsMismatch,
  ReadOnlyRootfsIncompatible,
}

impl RuntimeHardeningReason {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::CloseRangeUnavailable => "close_range_unavailable",
      Self::LandlockRightsDowngraded => "landlock_rights_downgraded",
      Self::ProcessStatusUnavailable => "process_status_unavailable",
      Self::ProcessStatusMalformed => "process_status_malformed",
      Self::SeccompFilterNotActive => "seccomp_filter_not_active",
      Self::NoNewPrivilegesNotActive => "no_new_privileges_not_active",
      Self::ProfileAssertionUnavailable => "profile_assertion_unavailable",
      Self::ProfileAssertionMalformed => "profile_assertion_malformed",
      Self::ProfileIdentityMismatch => "profile_identity_mismatch",
      Self::ProfileDigestMismatch => "profile_digest_mismatch",
      Self::FilesystemManifestUnavailable => "filesystem_manifest_unavailable",
      Self::FilesystemManifestDigestMismatch => "filesystem_manifest_digest_mismatch",
      Self::FilesystemWritablePathsMismatch => "filesystem_writable_paths_mismatch",
      Self::ReadOnlyRootfsIncompatible => "read_only_rootfs_incompatible",
    }
  }

  const fn is_filesystem_manifest(self) -> bool {
    matches!(
      self,
      Self::FilesystemManifestUnavailable
        | Self::FilesystemManifestDigestMismatch
        | Self::FilesystemWritablePathsMismatch
    )
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseRangeEffectiveState {
  Off,
  Applied,
  Unavailable,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloseRangeSnapshot {
  pub requested: HardeningAutoMode,
  pub effective: CloseRangeEffectiveState,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockEnforcementState {
  Off,
  Active,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockFilesystemRight {
  Execute,
  WriteFile,
  ReadFile,
  ReadDir,
  RemoveDir,
  RemoveFile,
  MakeChar,
  MakeDir,
  MakeReg,
  MakeSock,
  MakeFifo,
  MakeBlock,
  MakeSym,
  Refer,
  Truncate,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockRuleScope {
  Exact,
  Descendants,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct LandlockEffectiveRuleSummary {
  pub rule_id: String,
  pub access: Vec<LandlockFilesystemRight>,
  pub scope: LandlockRuleScope,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct LandlockSnapshot {
  pub requested_mode: RuntimeLandlockMode,
  pub enforcement: LandlockEnforcementState,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub requested_abi: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub kernel_abi: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub effective_abi: Option<u32>,
  pub requested_rights: Vec<LandlockFilesystemRight>,
  pub effective_rights: Vec<LandlockFilesystemRight>,
  pub unsupported_rights: Vec<LandlockFilesystemRight>,
  pub rule_count: u32,
  #[serde(default)]
  pub effective_rules: Vec<LandlockEffectiveRuleSummary>,
  #[serde(default)]
  pub effective_rules_truncated: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub manifest_digest: Option<String>,
  #[serde(default)]
  pub manifest_digest_withheld: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub policy_digest: Option<String>,
  #[serde(default)]
  pub policy_digest_withheld: bool,
  #[serde(skip, default)]
  pub(crate) installed_authority: Option<super::InstalledLandlockAuthority>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEvidenceState {
  Observed,
  Unavailable,
  Malformed,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompVerificationState {
  NotRequired,
  Satisfied,
  Degraded,
  Blocked,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileAssertionBasis {
  ExternalAssertion,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOnlyRootfsCompatibility {
  Compatible,
  Incompatible,
  Unknown,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeSeccompSnapshot {
  pub expectation: RuntimeSeccompExpectation,
  pub evidence: ProcessEvidenceState,
  pub observed_mode: super::ObservedSeccompMode,
  pub no_new_privs: super::ObservedNoNewPrivileges,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub seccomp_filters: Option<u32>,
  pub verification: SeccompVerificationState,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub expected_profile_identity: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub expected_profile_digest: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub asserted_profile_identity: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub asserted_profile_digest: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub assertion_basis: Option<ProfileAssertionBasis>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub profile_assertions_match: Option<bool>,
  pub profile_identity_kernel_verified: bool,
  pub reasons: Vec<RuntimeHardeningReason>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct FilesystemManifestVerificationSnapshot {
  pub expectation_present: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub digest_matches: Option<bool>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub writable_paths_match: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeHardeningSnapshot {
  pub schema_version: u32,
  pub outcome: RuntimeHardeningOutcome,
  pub close_range: CloseRangeSnapshot,
  pub landlock: LandlockSnapshot,
  pub seccomp: RuntimeSeccompSnapshot,
  pub filesystem_manifest: FilesystemManifestVerificationSnapshot,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub filesystem_manifest_digest: Option<String>,
  #[serde(default)]
  pub filesystem_manifest_digest_withheld: bool,
  pub read_only_rootfs: ReadOnlyRootfsCompatibility,
  pub degraded_reasons: Vec<RuntimeHardeningReason>,
  pub blocking_reasons: Vec<RuntimeHardeningReason>,
}

impl RuntimeHardeningSnapshot {
  /// Carries irreversible enforcement evidence forward while recording the
  /// manifest required by the newly activated, already-admitted snapshot.
  pub fn with_current_manifest(
    &self,
    _manifest_digest: String,
    read_only_rootfs: ReadOnlyRootfsCompatibility,
    filesystem_manifest: FilesystemManifestVerificationSnapshot,
    filesystem_blocking_reasons: Vec<RuntimeHardeningReason>,
  ) -> Self {
    let mut next = self.clone();
    next.filesystem_manifest = filesystem_manifest;
    next.filesystem_manifest_digest = None;
    next.filesystem_manifest_digest_withheld = true;
    next.read_only_rootfs = read_only_rootfs;
    next
      .blocking_reasons
      .retain(|reason| !reason.is_filesystem_manifest());
    for reason in filesystem_blocking_reasons {
      push_reason(&mut next.blocking_reasons, reason);
    }

    next.degraded_reasons.clear();
    if next.close_range.effective == CloseRangeEffectiveState::Unavailable {
      push_reason(
        &mut next.degraded_reasons,
        RuntimeHardeningReason::CloseRangeUnavailable,
      );
    }
    if !next.landlock.unsupported_rights.is_empty() {
      push_reason(
        &mut next.degraded_reasons,
        RuntimeHardeningReason::LandlockRightsDowngraded,
      );
    }
    if next.seccomp.verification == SeccompVerificationState::Degraded {
      for reason in &next.seccomp.reasons {
        push_reason(&mut next.degraded_reasons, *reason);
      }
    }
    if read_only_rootfs == ReadOnlyRootfsCompatibility::Incompatible {
      push_reason(
        &mut next.degraded_reasons,
        RuntimeHardeningReason::ReadOnlyRootfsIncompatible,
      );
    }
    next.outcome = if !next.blocking_reasons.is_empty() {
      next.degraded_reasons.clear();
      RuntimeHardeningOutcome::Blocked
    } else if next.degraded_reasons.is_empty() {
      RuntimeHardeningOutcome::Satisfied
    } else {
      RuntimeHardeningOutcome::Degraded
    };
    next
  }
}

pub(super) fn push_reason(
  reasons: &mut Vec<RuntimeHardeningReason>,
  reason: RuntimeHardeningReason,
) {
  if reasons.len() < MAX_HARDENING_REASONS && !reasons.contains(&reason) {
    reasons.push(reason);
  }
}
