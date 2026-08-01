//! Linux runtime hardening hooks and externally verifiable process evidence.

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use tracing::warn;

mod process_status;
mod profile_assertion;
mod snapshot;
#[cfg(target_os = "linux")]
mod syscalls;

pub use process_status::{
  ObservedNoNewPrivileges, ObservedSeccompMode, ProcSelfStatusSource, ProcessHardeningEvidence,
  ProcessStatusObservationError, ProcessStatusParseError, ProcessStatusSource,
  observe_process_hardening, parse_process_status,
};
pub use profile_assertion::{
  EnvironmentProfileAssertionSource, ExternalProfileAssertions, ProfileAssertionError,
  ProfileAssertionSource, SECCOMP_PROFILE_DIGEST_ENV, SECCOMP_PROFILE_IDENTITY_ENV,
};
use snapshot::push_reason;
pub use snapshot::{
  CloseRangeEffectiveState, CloseRangeSnapshot, LandlockEnforcementState, LandlockFilesystemRight,
  LandlockSnapshot, ProcessEvidenceState, ProfileAssertionBasis,
  RUNTIME_HARDENING_SNAPSHOT_SCHEMA_VERSION, ReadOnlyRootfsCompatibility, RuntimeHardeningOutcome,
  RuntimeHardeningReason, RuntimeHardeningSnapshot, RuntimeSeccompSnapshot,
  SeccompVerificationState,
};

use crate::config::{
  HardeningAutoMode, RuntimeHardeningConfig, RuntimeLandlockConfig, RuntimeLandlockMode,
  RuntimeSeccompConfig, RuntimeSeccompExpectation,
};

const MAX_SUPPORTED_LANDLOCK_ABI: u32 = 3;

/// Normalized filesystem requirements supplied by the configuration-manifest layer.
///
/// Paths are deliberately absent from serialized hardening snapshots. The digest is
/// the stable public comparison handle; callers retain the complete manifest for
/// explanation and activation planning.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LandlockManifestRule {
  pub path: PathBuf,
  pub access: Vec<LandlockFilesystemRight>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LandlockManifestProjection {
  pub manifest_digest: String,
  pub read_paths: Vec<PathBuf>,
  pub read_write_paths: Vec<PathBuf>,
  pub rules: Vec<LandlockManifestRule>,
  pub read_only_rootfs: ReadOnlyRootfsCompatibility,
  pub parent_scope_representable: bool,
}

impl LandlockManifestProjection {
  fn validate(&self) -> anyhow::Result<()> {
    validate_sha256_digest(&self.manifest_digest, "Landlock manifest digest")?;
    if self
      .read_paths
      .iter()
      .chain(&self.read_write_paths)
      .any(|path| path.as_os_str().is_empty())
    {
      bail!("Landlock manifest projection contains an empty path");
    }
    if self.rules.iter().any(|rule| {
      rule.path.as_os_str().is_empty()
        || rule.access.is_empty()
        || !rule.access.windows(2).all(|pair| pair[0] < pair[1])
        || rule.access.iter().any(|right| {
          matches!(
            right,
            LandlockFilesystemRight::Execute
              | LandlockFilesystemRight::MakeChar
              | LandlockFilesystemRight::MakeFifo
              | LandlockFilesystemRight::MakeBlock
              | LandlockFilesystemRight::MakeSym
          )
        })
    }) {
      bail!("Landlock manifest projection contains an invalid path rule");
    }
    Ok(())
  }
}

/// Preserves the existing startup API while discarding the new bounded snapshot.
pub fn apply_runtime_hardening(config: &RuntimeHardeningConfig) -> anyhow::Result<()> {
  apply_runtime_hardening_with_manifest(config, None).map(|_| ())
}

/// Verifies external seccomp state before local mutation, applies configured
/// process hardening, and returns redaction-safe evidence.
pub fn apply_runtime_hardening_with_manifest(
  config: &RuntimeHardeningConfig,
  manifest: Option<&LandlockManifestProjection>,
) -> anyhow::Result<RuntimeHardeningSnapshot> {
  apply_runtime_hardening_with_sources(
    config,
    manifest,
    &ProcSelfStatusSource,
    &EnvironmentProfileAssertionSource,
  )
}

/// Builds the bounded observation used by callers that construct application
/// state after process hardening was managed elsewhere. This function does not
/// mutate the process and therefore never claims active Landlock enforcement.
pub fn observe_runtime_hardening(
  config: &RuntimeHardeningConfig,
  manifest: Option<&LandlockManifestProjection>,
) -> RuntimeHardeningSnapshot {
  let seccomp = assess_external_seccomp(&config.seccomp, &ProcSelfStatusSource);
  let (outcome, degraded_reasons, blocking_reasons) = match seccomp.verification {
    SeccompVerificationState::Blocked => (
      RuntimeHardeningOutcome::Blocked,
      Vec::new(),
      seccomp.reasons.clone(),
    ),
    SeccompVerificationState::Degraded => (
      RuntimeHardeningOutcome::Degraded,
      seccomp.reasons.clone(),
      Vec::new(),
    ),
    SeccompVerificationState::NotRequired | SeccompVerificationState::Satisfied => {
      (RuntimeHardeningOutcome::Satisfied, Vec::new(), Vec::new())
    }
  };
  let manifest_digest = manifest.map(|manifest| manifest.manifest_digest.clone());
  RuntimeHardeningSnapshot {
    schema_version: RUNTIME_HARDENING_SNAPSHOT_SCHEMA_VERSION,
    outcome,
    close_range: CloseRangeSnapshot {
      requested: config.close_range,
      effective: if config.close_range == HardeningAutoMode::Off {
        CloseRangeEffectiveState::Off
      } else {
        CloseRangeEffectiveState::Unavailable
      },
    },
    landlock: LandlockSnapshot {
      requested_mode: config.landlock.mode,
      enforcement: LandlockEnforcementState::Off,
      requested_abi: None,
      kernel_abi: None,
      effective_abi: None,
      requested_rights: Vec::new(),
      effective_rights: Vec::new(),
      unsupported_rights: Vec::new(),
      rule_count: 0,
      manifest_digest: manifest_digest.clone(),
      policy_digest: None,
    },
    seccomp,
    filesystem_manifest_digest: manifest_digest,
    read_only_rootfs: manifest
      .map(|manifest| manifest.read_only_rootfs)
      .unwrap_or(ReadOnlyRootfsCompatibility::Unknown),
    degraded_reasons,
    blocking_reasons,
  }
}

fn apply_runtime_hardening_with_sources(
  config: &RuntimeHardeningConfig,
  manifest: Option<&LandlockManifestProjection>,
  process_status: &dyn ProcessStatusSource,
  profile_assertions: &dyn ProfileAssertionSource,
) -> anyhow::Result<RuntimeHardeningSnapshot> {
  // This observation must precede Landlock, because Landlock sets no_new_privs
  // for its own installation and must not be credited to the external seccomp contract.
  let seccomp =
    assess_external_seccomp_with_assertions(&config.seccomp, process_status, profile_assertions);
  if seccomp.verification == SeccompVerificationState::Blocked {
    let reason = seccomp
      .reasons
      .first()
      .copied()
      .unwrap_or(RuntimeHardeningReason::ProcessStatusUnavailable);
    bail!("runtime hardening blocked: {}", reason.as_str());
  }

  let (close_range, close_range_reason) = apply_close_range(config.close_range)?;
  let (landlock, landlock_reason) = apply_landlock(&config.landlock, manifest)?;

  let mut degraded_reasons = Vec::new();
  if let Some(reason) = close_range_reason {
    push_reason(&mut degraded_reasons, reason);
  }
  if let Some(reason) = landlock_reason {
    push_reason(&mut degraded_reasons, reason);
  }
  if seccomp.verification == SeccompVerificationState::Degraded {
    for reason in &seccomp.reasons {
      push_reason(&mut degraded_reasons, *reason);
    }
  }
  let read_only_rootfs = manifest
    .map(|manifest| manifest.read_only_rootfs)
    .unwrap_or(ReadOnlyRootfsCompatibility::Unknown);
  if read_only_rootfs == ReadOnlyRootfsCompatibility::Incompatible {
    push_reason(
      &mut degraded_reasons,
      RuntimeHardeningReason::ReadOnlyRootfsIncompatible,
    );
  }
  let outcome = if degraded_reasons.is_empty() {
    RuntimeHardeningOutcome::Satisfied
  } else {
    RuntimeHardeningOutcome::Degraded
  };

  Ok(RuntimeHardeningSnapshot {
    schema_version: RUNTIME_HARDENING_SNAPSHOT_SCHEMA_VERSION,
    outcome,
    close_range,
    landlock,
    seccomp,
    filesystem_manifest_digest: manifest.map(|manifest| manifest.manifest_digest.clone()),
    read_only_rootfs,
    degraded_reasons,
    blocking_reasons: Vec::new(),
  })
}

/// Produces a bounded assessment without changing process state. Profile names
/// and digests are reported as external assertions, never as kernel-verified facts.
pub fn assess_external_seccomp(
  config: &RuntimeSeccompConfig,
  source: &dyn ProcessStatusSource,
) -> RuntimeSeccompSnapshot {
  assess_external_seccomp_with_assertions(config, source, &EnvironmentProfileAssertionSource)
}

pub fn assess_external_seccomp_with_assertions(
  config: &RuntimeSeccompConfig,
  source: &dyn ProcessStatusSource,
  assertion_source: &dyn ProfileAssertionSource,
) -> RuntimeSeccompSnapshot {
  let observation = observe_process_hardening(source);
  let (evidence, observed_mode, no_new_privs, seccomp_filters, observation_reason) =
    match observation {
      Ok(observed) => (
        ProcessEvidenceState::Observed,
        observed.seccomp_mode,
        observed.no_new_privs,
        observed.seccomp_filters,
        None,
      ),
      Err(error) => (
        if error.is_read_error() {
          ProcessEvidenceState::Unavailable
        } else {
          ProcessEvidenceState::Malformed
        },
        ObservedSeccompMode::Unknown,
        ObservedNoNewPrivileges::Unknown,
        None,
        Some(if error.is_read_error() {
          RuntimeHardeningReason::ProcessStatusUnavailable
        } else {
          RuntimeHardeningReason::ProcessStatusMalformed
        }),
      ),
    };

  let mut reasons = Vec::new();
  if config.expectation != RuntimeSeccompExpectation::Off {
    if let Some(reason) = observation_reason {
      push_reason(&mut reasons, reason);
    } else {
      if observed_mode != ObservedSeccompMode::Filter {
        push_reason(&mut reasons, RuntimeHardeningReason::SeccompFilterNotActive);
      }
      if no_new_privs != ObservedNoNewPrivileges::Enabled {
        push_reason(
          &mut reasons,
          RuntimeHardeningReason::NoNewPrivilegesNotActive,
        );
      }
    }
  }

  let assertion_result = assertion_source.read_profile_assertions();
  let assertions = assertion_result.as_ref().ok();
  let asserted_profile_identity = assertions.and_then(|value| value.profile_identity.clone());
  let asserted_profile_digest = assertions.and_then(|value| value.profile_digest.clone());
  let expects_profile_assertion =
    config.profile_identity.is_some() || config.profile_digest.is_some();
  if config.expectation != RuntimeSeccompExpectation::Off {
    if assertion_result.is_err() {
      push_reason(
        &mut reasons,
        RuntimeHardeningReason::ProfileAssertionMalformed,
      );
    } else {
      if config.profile_identity.is_some() && config.profile_identity != asserted_profile_identity {
        push_reason(
          &mut reasons,
          RuntimeHardeningReason::ProfileIdentityMismatch,
        );
      }
      if config.profile_digest.is_some() && config.profile_digest != asserted_profile_digest {
        push_reason(&mut reasons, RuntimeHardeningReason::ProfileDigestMismatch);
      }
    }
  }

  let verification = match config.expectation {
    RuntimeSeccompExpectation::Off => SeccompVerificationState::NotRequired,
    RuntimeSeccompExpectation::Optional if reasons.is_empty() => {
      SeccompVerificationState::Satisfied
    }
    RuntimeSeccompExpectation::Optional => SeccompVerificationState::Degraded,
    RuntimeSeccompExpectation::Required if reasons.is_empty() => {
      SeccompVerificationState::Satisfied
    }
    RuntimeSeccompExpectation::Required => SeccompVerificationState::Blocked,
  };
  let assertion_basis = (asserted_profile_identity.is_some() || asserted_profile_digest.is_some())
    .then_some(ProfileAssertionBasis::ExternalAssertion);
  let profile_assertions_match = expects_profile_assertion.then(|| {
    assertion_result.is_ok()
      && config.profile_identity == asserted_profile_identity
      && config.profile_digest == asserted_profile_digest
  });

  RuntimeSeccompSnapshot {
    expectation: config.expectation,
    evidence,
    observed_mode,
    no_new_privs,
    seccomp_filters,
    verification,
    expected_profile_identity: config.profile_identity.clone(),
    expected_profile_digest: config.profile_digest.clone(),
    asserted_profile_identity,
    asserted_profile_digest,
    assertion_basis,
    profile_assertions_match,
    profile_identity_kernel_verified: false,
    reasons,
  }
}

fn apply_close_range(
  mode: HardeningAutoMode,
) -> anyhow::Result<(CloseRangeSnapshot, Option<RuntimeHardeningReason>)> {
  if mode == HardeningAutoMode::Off {
    return Ok((
      CloseRangeSnapshot {
        requested: mode,
        effective: CloseRangeEffectiveState::Off,
      },
      None,
    ));
  }
  match close_range_cloexec() {
    Ok(()) => Ok((
      CloseRangeSnapshot {
        requested: mode,
        effective: CloseRangeEffectiveState::Applied,
      },
      None,
    )),
    Err(error) if mode == HardeningAutoMode::Auto => {
      warn!(error = %error, "close_range(CLOSE_RANGE_CLOEXEC) unavailable; continuing");
      Ok((
        CloseRangeSnapshot {
          requested: mode,
          effective: CloseRangeEffectiveState::Unavailable,
        },
        Some(RuntimeHardeningReason::CloseRangeUnavailable),
      ))
    }
    Err(error) => Err(error).context("close_range(CLOSE_RANGE_CLOEXEC) failed"),
  }
}

#[cfg(target_os = "linux")]
fn close_range_cloexec() -> anyhow::Result<()> {
  syscalls::close_range_cloexec().map_err(Into::into)
}

#[cfg(not(target_os = "linux"))]
fn close_range_cloexec() -> anyhow::Result<()> {
  bail!("close_range is Linux-only")
}

fn apply_landlock(
  config: &RuntimeLandlockConfig,
  manifest: Option<&LandlockManifestProjection>,
) -> anyhow::Result<(LandlockSnapshot, Option<RuntimeHardeningReason>)> {
  if let Some(manifest) = manifest {
    manifest.validate()?;
  }
  let manifest_digest = manifest.map(|manifest| manifest.manifest_digest.clone());
  match config.mode {
    RuntimeLandlockMode::Off => Ok((
      LandlockSnapshot {
        requested_mode: RuntimeLandlockMode::Off,
        enforcement: LandlockEnforcementState::Off,
        requested_abi: None,
        kernel_abi: None,
        effective_abi: None,
        requested_rights: Vec::new(),
        effective_rights: Vec::new(),
        unsupported_rights: Vec::new(),
        rule_count: 0,
        manifest_digest,
        policy_digest: None,
      },
      None,
    )),
    RuntimeLandlockMode::Enforce => install_landlock(
      config.mode,
      Vec::new(),
      config.read_paths.clone(),
      config.read_write_paths.clone(),
      manifest_digest,
    )
    .context("failed to install manual Landlock filesystem sandbox"),
    RuntimeLandlockMode::Manifest => {
      let manifest = manifest.ok_or_else(|| {
        anyhow::anyhow!(
          "runtime.hardening.landlock.mode = \"manifest\" requires a generated manifest projection"
        )
      })?;
      if !manifest.parent_scope_representable {
        bail!(
          "manifest_landlock_parent_scope_unrepresentable: pre-create manifest write directories before enabling manifest mode"
        );
      }
      let mut read_paths = canonicalize_landlock_additions(&config.read_paths)?;
      let mut read_write_paths = canonicalize_landlock_additions(&config.read_write_paths)?;
      normalize_projected_paths(&mut read_paths, &mut read_write_paths);
      install_landlock(
        config.mode,
        manifest.rules.clone(),
        read_paths,
        read_write_paths,
        Some(manifest.manifest_digest.clone()),
      )
      .context("failed to install manifest-derived Landlock filesystem sandbox")
    }
  }
}

fn canonicalize_landlock_additions(paths: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
  paths
    .iter()
    .map(|path| {
      path.canonicalize().with_context(|| {
        format!(
          "failed to canonicalize explicit manifest-mode Landlock addition {}",
          path.display()
        )
      })
    })
    .collect()
}

fn normalize_projected_paths(read_paths: &mut Vec<PathBuf>, read_write_paths: &mut Vec<PathBuf>) {
  read_paths.sort();
  read_paths.dedup();
  read_write_paths.sort();
  read_write_paths.dedup();
  read_paths.retain(|path| read_write_paths.binary_search(path).is_err());
}

#[cfg(target_os = "linux")]
fn build_landlock_path_rules(
  mode: RuntimeLandlockMode,
  manifest_rules: Vec<LandlockManifestRule>,
  read_paths: Vec<PathBuf>,
  read_write_paths: Vec<PathBuf>,
) -> anyhow::Result<BTreeMap<PathBuf, u64>> {
  if mode != RuntimeLandlockMode::Manifest && !manifest_rules.is_empty() {
    bail!("manual Landlock mode cannot receive manifest path rules");
  }
  let maximum_access = syscalls::landlock_handled_access_fs(i64::from(MAX_SUPPORTED_LANDLOCK_ABI));
  let read_access = if mode == RuntimeLandlockMode::Manifest {
    maximum_access
      & (syscalls::LANDLOCK_ACCESS_FS_READ_FILE | syscalls::LANDLOCK_ACCESS_FS_READ_DIR)
  } else {
    syscalls::landlock_read_access_fs(maximum_access)
  };
  let read_write_access = if mode == RuntimeLandlockMode::Manifest {
    manifest_operator_access(MAX_SUPPORTED_LANDLOCK_ABI)
  } else {
    syscalls::landlock_read_write_access_fs(maximum_access)
  };
  let mut rules = BTreeMap::<PathBuf, u64>::new();
  for rule in manifest_rules {
    let access = rule
      .access
      .into_iter()
      .fold(0, |combined, right| combined | landlock_right_mask(right));
    rules
      .entry(rule.path)
      .and_modify(|combined| *combined |= access)
      .or_insert(access);
  }
  for path in read_paths {
    rules
      .entry(path)
      .and_modify(|combined| *combined |= read_access)
      .or_insert(read_access);
  }
  for path in read_write_paths {
    rules
      .entry(path)
      .and_modify(|combined| *combined |= read_write_access)
      .or_insert(read_write_access);
  }
  if rules.is_empty() || rules.values().any(|access| *access == 0) {
    bail!("Landlock enforcement requires at least one non-empty filesystem path rule");
  }
  Ok(rules)
}

#[cfg(target_os = "linux")]
fn install_landlock(
  mode: RuntimeLandlockMode,
  manifest_rules: Vec<LandlockManifestRule>,
  read_paths: Vec<PathBuf>,
  read_write_paths: Vec<PathBuf>,
  manifest_digest: Option<String>,
) -> anyhow::Result<(LandlockSnapshot, Option<RuntimeHardeningReason>)> {
  use std::fs::OpenOptions;
  use std::os::fd::AsFd;
  use std::os::unix::fs::OpenOptionsExt;

  let raw_abi = syscalls::landlock_abi_version().context("Landlock ABI version probe failed")?;
  let kernel_abi = u32::try_from(raw_abi).context("Landlock returned an invalid ABI version")?;
  let effective_abi = kernel_abi.min(MAX_SUPPORTED_LANDLOCK_ABI);
  let path_rules = build_landlock_path_rules(mode, manifest_rules, read_paths, read_write_paths)?;
  let requested_access = if mode == RuntimeLandlockMode::Manifest {
    manifest_operator_access(MAX_SUPPORTED_LANDLOCK_ABI)
  } else {
    syscalls::landlock_handled_access_fs(i64::from(MAX_SUPPORTED_LANDLOCK_ABI))
  };
  let kernel_supported_access = syscalls::landlock_handled_access_fs(i64::from(effective_abi));
  let effective_access = requested_access & kernel_supported_access;
  let unsupported_access = requested_access & !effective_access;
  if mode == RuntimeLandlockMode::Manifest && unsupported_access != 0 {
    bail!(
      "Landlock kernel ABI {kernel_abi} cannot enforce every filesystem right required by manifest mode"
    );
  }
  let ruleset = syscalls::create_landlock_ruleset(effective_access)
    .context("landlock_create_ruleset failed")?;
  let policy_digest = landlock_policy_digest(
    mode,
    manifest_digest.as_deref(),
    &path_rules,
    requested_access,
  );

  for (path, access) in &path_rules {
    let file = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
      .open(path)
      .with_context(|| format!("failed to open Landlock path {}", path.display()))?;
    let metadata = file
      .metadata()
      .with_context(|| format!("failed to inspect Landlock path {}", path.display()))?;
    if metadata.file_type().is_symlink() {
      bail!("Landlock path changed to a symlink after manifest resolution");
    }
    let allowed_access = access & effective_access;
    syscalls::add_landlock_path_rule(ruleset.as_fd(), file.as_fd(), allowed_access)
      .with_context(|| format!("failed to add Landlock path {}", path.display()))?;
  }

  enable_no_new_privs().context("failed to set no_new_privs before Landlock")?;
  syscalls::restrict_landlock(ruleset.as_fd()).context("landlock_restrict_self failed")?;
  let rule_count = path_rules.len();
  Ok((
    LandlockSnapshot {
      requested_mode: mode,
      enforcement: LandlockEnforcementState::Active,
      requested_abi: Some(MAX_SUPPORTED_LANDLOCK_ABI),
      kernel_abi: Some(kernel_abi),
      effective_abi: Some(effective_abi),
      requested_rights: landlock_rights(requested_access),
      effective_rights: landlock_rights(effective_access),
      unsupported_rights: landlock_rights(unsupported_access),
      rule_count: u32::try_from(rule_count).unwrap_or(u32::MAX),
      manifest_digest,
      policy_digest: Some(policy_digest),
    },
    (unsupported_access != 0).then_some(RuntimeHardeningReason::LandlockRightsDowngraded),
  ))
}

#[cfg(target_os = "linux")]
fn landlock_policy_digest(
  mode: RuntimeLandlockMode,
  manifest_digest: Option<&str>,
  path_rules: &BTreeMap<PathBuf, u64>,
  requested_access: u64,
) -> String {
  use std::os::unix::ffi::OsStrExt;

  let mut hasher = Sha256::new();
  hasher.update(b"oxibelt-landlock-policy-v1\0");
  hasher.update(format!("{mode:?}\0").as_bytes());
  hasher.update(manifest_digest.unwrap_or("").as_bytes());
  hasher.update([0]);
  hasher.update(requested_access.to_be_bytes());
  for (path, access) in path_rules {
    hasher.update(path.as_os_str().as_bytes());
    hasher.update([0]);
    hasher.update(access.to_be_bytes());
  }
  let digest = hasher.finalize();
  let mut encoded = String::with_capacity(64);
  const HEX: &[u8; 16] = b"0123456789abcdef";
  for byte in digest {
    encoded.push(char::from(HEX[usize::from(byte >> 4)]));
    encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
  }
  format!("sha256:{encoded}")
}

#[cfg(target_os = "linux")]
fn manifest_operator_access(abi: u32) -> u64 {
  let supported = syscalls::landlock_handled_access_fs(i64::from(abi));
  supported
    & (syscalls::LANDLOCK_ACCESS_FS_WRITE_FILE
      | syscalls::LANDLOCK_ACCESS_FS_READ_FILE
      | syscalls::LANDLOCK_ACCESS_FS_READ_DIR
      | syscalls::LANDLOCK_ACCESS_FS_REMOVE_DIR
      | syscalls::LANDLOCK_ACCESS_FS_REMOVE_FILE
      | syscalls::LANDLOCK_ACCESS_FS_MAKE_DIR
      | syscalls::LANDLOCK_ACCESS_FS_MAKE_REG
      | syscalls::LANDLOCK_ACCESS_FS_MAKE_SOCK
      | syscalls::LANDLOCK_ACCESS_FS_REFER
      | syscalls::LANDLOCK_ACCESS_FS_TRUNCATE)
}

#[cfg(target_os = "linux")]
const fn landlock_right_mask(right: LandlockFilesystemRight) -> u64 {
  match right {
    LandlockFilesystemRight::Execute => syscalls::LANDLOCK_ACCESS_FS_EXECUTE,
    LandlockFilesystemRight::WriteFile => syscalls::LANDLOCK_ACCESS_FS_WRITE_FILE,
    LandlockFilesystemRight::ReadFile => syscalls::LANDLOCK_ACCESS_FS_READ_FILE,
    LandlockFilesystemRight::ReadDir => syscalls::LANDLOCK_ACCESS_FS_READ_DIR,
    LandlockFilesystemRight::RemoveDir => syscalls::LANDLOCK_ACCESS_FS_REMOVE_DIR,
    LandlockFilesystemRight::RemoveFile => syscalls::LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LandlockFilesystemRight::MakeChar => syscalls::LANDLOCK_ACCESS_FS_MAKE_CHAR,
    LandlockFilesystemRight::MakeDir => syscalls::LANDLOCK_ACCESS_FS_MAKE_DIR,
    LandlockFilesystemRight::MakeReg => syscalls::LANDLOCK_ACCESS_FS_MAKE_REG,
    LandlockFilesystemRight::MakeSock => syscalls::LANDLOCK_ACCESS_FS_MAKE_SOCK,
    LandlockFilesystemRight::MakeFifo => syscalls::LANDLOCK_ACCESS_FS_MAKE_FIFO,
    LandlockFilesystemRight::MakeBlock => syscalls::LANDLOCK_ACCESS_FS_MAKE_BLOCK,
    LandlockFilesystemRight::MakeSym => syscalls::LANDLOCK_ACCESS_FS_MAKE_SYM,
    LandlockFilesystemRight::Refer => syscalls::LANDLOCK_ACCESS_FS_REFER,
    LandlockFilesystemRight::Truncate => syscalls::LANDLOCK_ACCESS_FS_TRUNCATE,
  }
}

#[cfg(not(target_os = "linux"))]
fn install_landlock(
  _mode: RuntimeLandlockMode,
  _manifest_rules: Vec<LandlockManifestRule>,
  _read_paths: Vec<PathBuf>,
  _read_write_paths: Vec<PathBuf>,
  _manifest_digest: Option<String>,
) -> anyhow::Result<(LandlockSnapshot, Option<RuntimeHardeningReason>)> {
  bail!("Landlock is Linux-only")
}

#[cfg(target_os = "linux")]
fn landlock_rights(mask: u64) -> Vec<LandlockFilesystemRight> {
  [
    (
      syscalls::LANDLOCK_ACCESS_FS_EXECUTE,
      LandlockFilesystemRight::Execute,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_WRITE_FILE,
      LandlockFilesystemRight::WriteFile,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_READ_FILE,
      LandlockFilesystemRight::ReadFile,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_READ_DIR,
      LandlockFilesystemRight::ReadDir,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_REMOVE_DIR,
      LandlockFilesystemRight::RemoveDir,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_REMOVE_FILE,
      LandlockFilesystemRight::RemoveFile,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_MAKE_CHAR,
      LandlockFilesystemRight::MakeChar,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_MAKE_DIR,
      LandlockFilesystemRight::MakeDir,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_MAKE_REG,
      LandlockFilesystemRight::MakeReg,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_MAKE_SOCK,
      LandlockFilesystemRight::MakeSock,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_MAKE_FIFO,
      LandlockFilesystemRight::MakeFifo,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_MAKE_BLOCK,
      LandlockFilesystemRight::MakeBlock,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_MAKE_SYM,
      LandlockFilesystemRight::MakeSym,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_REFER,
      LandlockFilesystemRight::Refer,
    ),
    (
      syscalls::LANDLOCK_ACCESS_FS_TRUNCATE,
      LandlockFilesystemRight::Truncate,
    ),
  ]
  .into_iter()
  .filter_map(|(bit, right)| (mask & bit != 0).then_some(right))
  .collect()
}

#[cfg(not(target_os = "linux"))]
fn landlock_rights(_mask: u64) -> Vec<LandlockFilesystemRight> {
  Vec::new()
}

#[cfg(target_os = "linux")]
fn enable_no_new_privs() -> anyhow::Result<()> {
  nix::sys::prctl::set_no_new_privs().map_err(Into::into)
}

#[cfg(all(target_os = "linux", feature = "fuzzing"))]
pub(crate) fn fuzz_syscall_boundary(abi: u8) {
  let handled = syscalls::landlock_handled_access_fs(i64::from(abi));
  let _ = syscalls::landlock_read_access_fs(handled);
  let _ = syscalls::landlock_read_write_access_fs(handled);
  let _ = syscalls::landlock_layout();
}

#[cfg(not(target_os = "linux"))]
fn enable_no_new_privs() -> anyhow::Result<()> {
  bail!("no_new_privs is Linux-only")
}

fn validate_sha256_digest(value: &str, label: &str) -> anyhow::Result<()> {
  let Some(encoded) = value.strip_prefix("sha256:") else {
    bail!("{label} must use sha256:<lowercase-hex>");
  };
  if encoded.len() != 64
    || !encoded
      .bytes()
      .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
  {
    bail!("{label} must use sha256:<lowercase-hex>");
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::io;

  use super::*;
  use crate::config::{RuntimeLandlockConfig, RuntimeSeccompMode};

  struct StaticStatus(&'static str);

  impl ProcessStatusSource for StaticStatus {
    fn read_process_status(&self) -> io::Result<String> {
      Ok(self.0.to_string())
    }
  }

  struct MissingStatus;

  impl ProcessStatusSource for MissingStatus {
    fn read_process_status(&self) -> io::Result<String> {
      Err(io::Error::new(io::ErrorKind::NotFound, "missing procfs"))
    }
  }

  #[derive(Default)]
  struct StaticAssertions(ExternalProfileAssertions);

  impl ProfileAssertionSource for StaticAssertions {
    fn read_profile_assertions(&self) -> Result<ExternalProfileAssertions, ProfileAssertionError> {
      Ok(self.0.clone())
    }
  }

  fn seccomp(expectation: RuntimeSeccompExpectation) -> RuntimeSeccompConfig {
    RuntimeSeccompConfig {
      expectation,
      mode: match expectation {
        RuntimeSeccompExpectation::Off => RuntimeSeccompMode::Off,
        RuntimeSeccompExpectation::Optional => RuntimeSeccompMode::Log,
        RuntimeSeccompExpectation::Required => RuntimeSeccompMode::Enforce,
      },
      ..RuntimeSeccompConfig::default()
    }
  }

  #[test]
  fn off_modes_return_bounded_observed_evidence() {
    let config = RuntimeHardeningConfig {
      close_range: HardeningAutoMode::Off,
      seccomp: RuntimeSeccompConfig::default(),
      landlock: RuntimeLandlockConfig::default(),
    };
    let snapshot = apply_runtime_hardening_with_sources(
      &config,
      None,
      &StaticStatus("Seccomp: 0\nNoNewPrivs: 0\n"),
      &StaticAssertions::default(),
    )
    .expect("off hardening should not require Linux mutations");
    assert_eq!(snapshot.outcome, RuntimeHardeningOutcome::Satisfied);
    assert_eq!(
      snapshot.seccomp.verification,
      SeccompVerificationState::NotRequired
    );
    assert_eq!(
      snapshot.seccomp.observed_mode,
      ObservedSeccompMode::Disabled
    );
  }

  #[test]
  fn required_seccomp_accepts_only_filter_mode_with_no_new_privs() {
    let config = seccomp(RuntimeSeccompExpectation::Required);
    let satisfied = assess_external_seccomp_with_assertions(
      &config,
      &StaticStatus("NoNewPrivs: 1\nSeccomp: 2\nSeccomp_filters: 1\n"),
      &StaticAssertions::default(),
    );
    assert_eq!(satisfied.verification, SeccompVerificationState::Satisfied);

    for status in [
      "NoNewPrivs: 0\nSeccomp: 2\n",
      "NoNewPrivs: 1\nSeccomp: 1\n",
      "NoNewPrivs: 1\nSeccomp: 0\n",
    ] {
      let blocked = assess_external_seccomp_with_assertions(
        &config,
        &StaticStatus(status),
        &StaticAssertions::default(),
      );
      assert_eq!(blocked.verification, SeccompVerificationState::Blocked);
    }
  }

  #[test]
  fn required_seccomp_blocks_before_local_hardening_with_a_stable_reason() {
    let config = RuntimeHardeningConfig {
      close_range: HardeningAutoMode::Required,
      seccomp: seccomp(RuntimeSeccompExpectation::Required),
      landlock: RuntimeLandlockConfig::default(),
    };
    let error = apply_runtime_hardening_with_sources(
      &config,
      None,
      &StaticStatus("NoNewPrivs: 0\nSeccomp: 0\n"),
      &StaticAssertions::default(),
    )
    .expect_err("required external seccomp must fail before local mutation");
    assert!(error.to_string().contains("seccomp_filter_not_active"));
  }

  #[test]
  fn optional_seccomp_degrades_when_process_evidence_is_unavailable() {
    let snapshot = assess_external_seccomp_with_assertions(
      &seccomp(RuntimeSeccompExpectation::Optional),
      &MissingStatus,
      &StaticAssertions::default(),
    );
    assert_eq!(snapshot.verification, SeccompVerificationState::Degraded);
    assert_eq!(snapshot.evidence, ProcessEvidenceState::Unavailable);
    assert_eq!(
      snapshot.reasons,
      vec![RuntimeHardeningReason::ProcessStatusUnavailable]
    );
  }

  #[test]
  fn profile_metadata_is_explicitly_not_kernel_verified() {
    let mut config = seccomp(RuntimeSeccompExpectation::Required);
    config.profile_identity = Some("kubernetes/runtime-default".to_string());
    config.profile_digest =
      Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
    let assertions = StaticAssertions(ExternalProfileAssertions {
      profile_identity: config.profile_identity.clone(),
      profile_digest: config.profile_digest.clone(),
    });
    let snapshot = assess_external_seccomp_with_assertions(
      &config,
      &StaticStatus("NoNewPrivs: 1\nSeccomp: 2\n"),
      &assertions,
    );
    assert_eq!(
      snapshot.assertion_basis,
      Some(ProfileAssertionBasis::ExternalAssertion)
    );
    assert!(!snapshot.profile_identity_kernel_verified);
    assert_eq!(snapshot.profile_assertions_match, Some(true));
  }

  #[test]
  fn required_profile_assertion_mismatch_blocks() {
    let mut config = seccomp(RuntimeSeccompExpectation::Required);
    config.profile_identity = Some("kubernetes/runtime-default".to_string());
    let snapshot = assess_external_seccomp_with_assertions(
      &config,
      &StaticStatus("NoNewPrivs: 1\nSeccomp: 2\n"),
      &StaticAssertions(ExternalProfileAssertions {
        profile_identity: Some("kubernetes/localhost/custom".to_string()),
        profile_digest: None,
      }),
    );
    assert_eq!(snapshot.verification, SeccompVerificationState::Blocked);
    assert_eq!(snapshot.profile_assertions_match, Some(false));
    assert!(
      snapshot
        .reasons
        .contains(&RuntimeHardeningReason::ProfileIdentityMismatch)
    );
  }

  #[test]
  fn manifest_mode_requires_a_valid_projection_before_mutation() {
    let config = RuntimeHardeningConfig {
      close_range: HardeningAutoMode::Off,
      seccomp: RuntimeSeccompConfig::default(),
      landlock: RuntimeLandlockConfig {
        mode: RuntimeLandlockMode::Manifest,
        read_paths: Vec::new(),
        read_write_paths: Vec::new(),
      },
    };
    let error = apply_runtime_hardening_with_sources(
      &config,
      None,
      &StaticStatus("NoNewPrivs: 0\nSeccomp: 0\n"),
      &StaticAssertions::default(),
    )
    .expect_err("manifest mode must not silently become manual mode");
    assert!(error.to_string().contains("generated manifest projection"));
  }

  #[test]
  fn projection_summary_is_reported_even_when_landlock_is_off() {
    let config = RuntimeHardeningConfig {
      close_range: HardeningAutoMode::Off,
      seccomp: RuntimeSeccompConfig::default(),
      landlock: RuntimeLandlockConfig::default(),
    };
    let digest = format!("sha256:{}", "b".repeat(64));
    let manifest = LandlockManifestProjection {
      manifest_digest: digest.clone(),
      read_paths: Vec::new(),
      read_write_paths: Vec::new(),
      rules: Vec::new(),
      read_only_rootfs: ReadOnlyRootfsCompatibility::Compatible,
      parent_scope_representable: true,
    };
    let snapshot = apply_runtime_hardening_with_sources(
      &config,
      Some(&manifest),
      &StaticStatus("NoNewPrivs: 0\nSeccomp: 0\n"),
      &StaticAssertions::default(),
    )
    .expect("an off Landlock mode should still report the manifest summary");
    assert_eq!(snapshot.filesystem_manifest_digest, Some(digest.clone()));
    assert_eq!(snapshot.landlock.manifest_digest, Some(digest));
    assert_eq!(
      snapshot.read_only_rootfs,
      ReadOnlyRootfsCompatibility::Compatible
    );
  }

  #[test]
  fn projection_deduplicates_exact_read_write_paths() {
    let mut read = vec![
      PathBuf::from("/a"),
      PathBuf::from("/b"),
      PathBuf::from("/a"),
    ];
    let mut read_write = vec![PathBuf::from("/b"), PathBuf::from("/c")];
    normalize_projected_paths(&mut read, &mut read_write);
    assert_eq!(read, vec![PathBuf::from("/a")]);
    assert_eq!(read_write, vec![PathBuf::from("/b"), PathBuf::from("/c")]);
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn manifest_landlock_rights_exclude_execution_and_special_file_creation() {
    let requested = manifest_operator_access(3);
    assert_eq!(requested & syscalls::LANDLOCK_ACCESS_FS_EXECUTE, 0);
    assert_eq!(requested & syscalls::LANDLOCK_ACCESS_FS_MAKE_CHAR, 0);
    assert_eq!(requested & syscalls::LANDLOCK_ACCESS_FS_MAKE_BLOCK, 0);
    assert_eq!(requested & syscalls::LANDLOCK_ACCESS_FS_MAKE_FIFO, 0);
    assert_eq!(requested & syscalls::LANDLOCK_ACCESS_FS_MAKE_SYM, 0);
    assert_ne!(requested & syscalls::LANDLOCK_ACCESS_FS_MAKE_REG, 0);
    assert_ne!(requested & syscalls::LANDLOCK_ACCESS_FS_MAKE_SOCK, 0);
    assert_ne!(requested & syscalls::LANDLOCK_ACCESS_FS_REFER, 0);
    assert_ne!(requested & syscalls::LANDLOCK_ACCESS_FS_TRUNCATE, 0);

    let abi_one = manifest_operator_access(1);
    assert_eq!(abi_one & syscalls::LANDLOCK_ACCESS_FS_REFER, 0);
    assert_eq!(abi_one & syscalls::LANDLOCK_ACCESS_FS_TRUNCATE, 0);
  }
}
