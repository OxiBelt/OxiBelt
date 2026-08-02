//! Explicit ownership and fixed reporting for process-global runtime hooks.
//!
//! Library callers select whether OxiBelt may apply a hook, must only verify it,
//! or leaves it under caller ownership. This module intentionally keeps the
//! inventory fixed so diagnostics do not omit globals that OxiBelt does not
//! currently install.

use std::fmt;

use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePolicy {
  FromConfig,
  CurrentRuntime,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPolicy {
  Standalone,
  Embedded(ProcessGlobalHooks),
}

impl ProcessPolicy {
  pub const fn global_hooks(self) -> ProcessGlobalHooks {
    match self {
      Self::Standalone => ProcessGlobalHooks::ApplySelected(ProcessGlobalSelection::all()),
      Self::Embedded(hooks) => hooks,
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessGlobalHooks {
  CallerManaged,
  VerifyOnly,
  ApplySelected(ProcessGlobalSelection),
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
pub struct ProcessGlobalSelection {
  pub crypto: bool,
  pub tracing: bool,
  pub signals: bool,
  pub close_range: bool,
  pub landlock: bool,
}

impl ProcessGlobalSelection {
  pub const fn all() -> Self {
    Self {
      crypto: true,
      tracing: true,
      signals: true,
      close_range: true,
      landlock: true,
    }
  }

  const fn selects(self, hook: ProcessGlobalHook) -> bool {
    match hook {
      ProcessGlobalHook::CryptoPrimitives | ProcessGlobalHook::RustlsDefault => self.crypto,
      ProcessGlobalHook::Tracing => self.tracing,
      ProcessGlobalHook::Signals => self.signals,
      ProcessGlobalHook::CloseRange => self.close_range,
      ProcessGlobalHook::Landlock => self.landlock,
      ProcessGlobalHook::Seccomp
      | ProcessGlobalHook::Environment
      | ProcessGlobalHook::PanicHook
      | ProcessGlobalHook::Allocator
      | ProcessGlobalHook::Profiler
      | ProcessGlobalHook::BackgroundThreads => false,
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessGlobalHook {
  CryptoPrimitives,
  RustlsDefault,
  Tracing,
  Signals,
  CloseRange,
  Seccomp,
  Landlock,
  Environment,
  PanicHook,
  Allocator,
  Profiler,
  BackgroundThreads,
}

impl ProcessGlobalHook {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::CryptoPrimitives => "crypto_primitives",
      Self::RustlsDefault => "rustls_default",
      Self::Tracing => "tracing",
      Self::Signals => "signals",
      Self::CloseRange => "close_range",
      Self::Seccomp => "seccomp",
      Self::Landlock => "landlock",
      Self::Environment => "environment",
      Self::PanicHook => "panic_hook",
      Self::Allocator => "allocator",
      Self::Profiler => "profiler",
      Self::BackgroundThreads => "background_threads",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessGlobalHookStatus {
  Applied,
  AlreadyMatching,
  Verified,
  CallerManaged,
  NotConfigured,
  Inapplicable,
  Unsupported,
  Unverifiable,
  Rejected,
  Conflict,
}

impl ProcessGlobalHookStatus {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Applied => "applied",
      Self::AlreadyMatching => "already_matching",
      Self::Verified => "verified",
      Self::CallerManaged => "caller_managed",
      Self::NotConfigured => "not_configured",
      Self::Inapplicable => "inapplicable",
      Self::Unsupported => "unsupported",
      Self::Unverifiable => "unverifiable",
      Self::Rejected => "rejected",
      Self::Conflict => "conflict",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessGlobalReason {
  AppliedByOxibelt,
  ExistingStateMatches,
  ExistingStateConflicts,
  CallerOwnsHook,
  VerificationUnavailable,
  NotUsedByOxibelt,
  RequiresLifecycleAuthority,
  InvalidConfiguration,
  ExistingRuntimeThreads,
}

impl ProcessGlobalReason {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::AppliedByOxibelt => "applied_by_oxibelt",
      Self::ExistingStateMatches => "existing_state_matches",
      Self::ExistingStateConflicts => "existing_state_conflicts",
      Self::CallerOwnsHook => "caller_owns_hook",
      Self::VerificationUnavailable => "verification_unavailable",
      Self::NotUsedByOxibelt => "not_used_by_oxibelt",
      Self::RequiresLifecycleAuthority => "requires_lifecycle_authority",
      Self::InvalidConfiguration => "invalid_configuration",
      Self::ExistingRuntimeThreads => "existing_runtime_threads",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct ProcessGlobalHookReport {
  pub status: ProcessGlobalHookStatus,
  pub reason: ProcessGlobalReason,
}

impl ProcessGlobalHookReport {
  pub const fn new(status: ProcessGlobalHookStatus, reason: ProcessGlobalReason) -> Self {
    Self { status, reason }
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ProcessGlobalReport {
  pub crypto_primitives: ProcessGlobalHookReport,
  pub rustls_default: ProcessGlobalHookReport,
  pub tracing: ProcessGlobalHookReport,
  pub signals: ProcessGlobalHookReport,
  pub close_range: ProcessGlobalHookReport,
  pub seccomp: ProcessGlobalHookReport,
  pub landlock: ProcessGlobalHookReport,
  pub environment: ProcessGlobalHookReport,
  pub panic_hook: ProcessGlobalHookReport,
  pub allocator: ProcessGlobalHookReport,
  pub profiler: ProcessGlobalHookReport,
  pub background_threads: ProcessGlobalHookReport,
}

impl ProcessGlobalReport {
  pub fn for_hooks(hooks: ProcessGlobalHooks) -> Self {
    let report_for = |hook| report_for_action(action_for(hooks, hook));
    let not_used = ProcessGlobalHookReport::new(
      ProcessGlobalHookStatus::NotConfigured,
      ProcessGlobalReason::NotUsedByOxibelt,
    );
    Self {
      crypto_primitives: report_for(ProcessGlobalHook::CryptoPrimitives),
      rustls_default: report_for(ProcessGlobalHook::RustlsDefault),
      tracing: report_for(ProcessGlobalHook::Tracing),
      signals: report_for(ProcessGlobalHook::Signals),
      close_range: report_for(ProcessGlobalHook::CloseRange),
      seccomp: ProcessGlobalHookReport::new(
        ProcessGlobalHookStatus::Unverifiable,
        ProcessGlobalReason::RequiresLifecycleAuthority,
      ),
      landlock: report_for(ProcessGlobalHook::Landlock),
      environment: not_used,
      panic_hook: not_used,
      allocator: not_used,
      profiler: not_used,
      background_threads: ProcessGlobalHookReport::new(
        ProcessGlobalHookStatus::NotConfigured,
        ProcessGlobalReason::RequiresLifecycleAuthority,
      ),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct ProcessGlobalError {
  pub hook: ProcessGlobalHook,
  pub reason: ProcessGlobalReason,
}

impl ProcessGlobalError {
  const fn conflict(hook: ProcessGlobalHook) -> Self {
    Self {
      hook,
      reason: ProcessGlobalReason::ExistingStateConflicts,
    }
  }

  const fn invalid(hook: ProcessGlobalHook) -> Self {
    Self {
      hook,
      reason: ProcessGlobalReason::InvalidConfiguration,
    }
  }
}

impl fmt::Display for ProcessGlobalError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "process-global hook {} rejected: {}",
      self.hook.as_str(),
      self.reason.as_str(),
    )
  }
}

impl std::error::Error for ProcessGlobalError {}

/// Applies or verifies the tracing and crypto hooks covered by this module.
///
/// Signal ownership and process hardening are completed by the lifecycle
/// startup authority, which updates their corresponding fixed report fields.
pub(crate) fn configure_startup_hooks(
  config: &Config,
  hooks: ProcessGlobalHooks,
) -> Result<ProcessGlobalReport, ProcessGlobalError> {
  let mut report = ProcessGlobalReport::for_hooks(hooks);

  configure_tracing(&config.logging, hooks, &mut report)?;
  configure_crypto(&config.crypto, hooks, &mut report)?;
  Ok(report)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HookAction {
  CallerManaged,
  VerifyOnly,
  Apply,
}

const fn action_for(hooks: ProcessGlobalHooks, hook: ProcessGlobalHook) -> HookAction {
  match hooks {
    ProcessGlobalHooks::CallerManaged => HookAction::CallerManaged,
    ProcessGlobalHooks::VerifyOnly => HookAction::VerifyOnly,
    ProcessGlobalHooks::ApplySelected(selection) => {
      if selection.selects(hook) {
        HookAction::Apply
      } else {
        HookAction::VerifyOnly
      }
    }
  }
}

const fn report_for_action(action: HookAction) -> ProcessGlobalHookReport {
  match action {
    HookAction::CallerManaged => ProcessGlobalHookReport::new(
      ProcessGlobalHookStatus::CallerManaged,
      ProcessGlobalReason::CallerOwnsHook,
    ),
    HookAction::VerifyOnly => ProcessGlobalHookReport::new(
      ProcessGlobalHookStatus::Unverifiable,
      ProcessGlobalReason::VerificationUnavailable,
    ),
    HookAction::Apply => ProcessGlobalHookReport::new(
      ProcessGlobalHookStatus::NotConfigured,
      ProcessGlobalReason::RequiresLifecycleAuthority,
    ),
  }
}

fn configure_tracing(
  config: &crate::config::LoggingConfig,
  hooks: ProcessGlobalHooks,
  report: &mut ProcessGlobalReport,
) -> Result<(), ProcessGlobalError> {
  match action_for(hooks, ProcessGlobalHook::Tracing) {
    HookAction::CallerManaged => {}
    HookAction::VerifyOnly => {
      report.tracing = ProcessGlobalHookReport::new(
        ProcessGlobalHookStatus::Unverifiable,
        ProcessGlobalReason::VerificationUnavailable,
      );
    }
    HookAction::Apply => match crate::runtime::install_startup_logging(config) {
      Ok(crate::runtime::TracingInstall::Applied) => {
        report.tracing = ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::Applied,
          ProcessGlobalReason::AppliedByOxibelt,
        );
      }
      Ok(crate::runtime::TracingInstall::AlreadyMatching) => {
        report.tracing = ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::AlreadyMatching,
          ProcessGlobalReason::ExistingStateMatches,
        );
      }
      Err(crate::runtime::TracingInstallError::AlreadyInitialized) => {
        return Err(ProcessGlobalError::conflict(ProcessGlobalHook::Tracing));
      }
      Err(crate::runtime::TracingInstallError::InvalidFilter(_)) => {
        return Err(ProcessGlobalError::invalid(ProcessGlobalHook::Tracing));
      }
    },
  }
  Ok(())
}

fn configure_crypto(
  config: &crate::config::CryptoConfig,
  hooks: ProcessGlobalHooks,
  report: &mut ProcessGlobalReport,
) -> Result<(), ProcessGlobalError> {
  match action_for(hooks, ProcessGlobalHook::CryptoPrimitives) {
    HookAction::CallerManaged => {
      if !crate::crypto::runtime_matches(config) {
        return Err(ProcessGlobalError::conflict(
          ProcessGlobalHook::CryptoPrimitives,
        ));
      }
    }
    HookAction::VerifyOnly => {
      if !crate::crypto::runtime_matches(config) {
        return Err(ProcessGlobalError::conflict(
          ProcessGlobalHook::CryptoPrimitives,
        ));
      }
      report.crypto_primitives = ProcessGlobalHookReport::new(
        ProcessGlobalHookStatus::Verified,
        ProcessGlobalReason::ExistingStateMatches,
      );
    }
    HookAction::Apply => {
      report.crypto_primitives = match crate::crypto::configure_runtime(config) {
        Ok(crate::crypto::CryptoPrimitiveClaim::Applied) => ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::Applied,
          ProcessGlobalReason::AppliedByOxibelt,
        ),
        Ok(crate::crypto::CryptoPrimitiveClaim::AlreadyMatching) => ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::AlreadyMatching,
          ProcessGlobalReason::ExistingStateMatches,
        ),
        Err(_) => {
          return Err(ProcessGlobalError::conflict(
            ProcessGlobalHook::CryptoPrimitives,
          ));
        }
      };
    }
  }

  match action_for(hooks, ProcessGlobalHook::RustlsDefault) {
    HookAction::CallerManaged => {}
    HookAction::VerifyOnly => match crate::tls::configured_provider_state(config) {
      Ok(crate::tls::ConfiguredProviderState::Missing) => {
        report.rustls_default = ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::Unverifiable,
          ProcessGlobalReason::VerificationUnavailable,
        );
      }
      Ok(crate::tls::ConfiguredProviderState::Matching) => {
        report.rustls_default = ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::Verified,
          ProcessGlobalReason::ExistingStateMatches,
        );
      }
      Ok(crate::tls::ConfiguredProviderState::Conflicting) => {
        return Err(ProcessGlobalError::conflict(
          ProcessGlobalHook::RustlsDefault,
        ));
      }
      Err(_) => {
        return Err(ProcessGlobalError::invalid(
          ProcessGlobalHook::RustlsDefault,
        ));
      }
    },
    HookAction::Apply => {
      report.rustls_default = match crate::tls::ensure_configured_provider(config) {
        Ok(crate::tls::ConfiguredProviderInstall::Applied) => ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::Applied,
          ProcessGlobalReason::AppliedByOxibelt,
        ),
        Ok(crate::tls::ConfiguredProviderInstall::AlreadyMatching) => ProcessGlobalHookReport::new(
          ProcessGlobalHookStatus::AlreadyMatching,
          ProcessGlobalReason::ExistingStateMatches,
        ),
        Err(crate::tls::ConfiguredProviderInstallError::Conflict) => {
          return Err(ProcessGlobalError::conflict(
            ProcessGlobalHook::RustlsDefault,
          ));
        }
        Err(crate::tls::ConfiguredProviderInstallError::Unavailable(_)) => {
          return Err(ProcessGlobalError::invalid(
            ProcessGlobalHook::RustlsDefault,
          ));
        }
      };
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn standalone_selects_every_owned_hook() {
    assert_eq!(
      ProcessPolicy::Standalone.global_hooks(),
      ProcessGlobalHooks::ApplySelected(ProcessGlobalSelection::all())
    );
  }

  #[test]
  fn caller_managed_report_has_a_fixed_complete_inventory() {
    let report = ProcessGlobalReport::for_hooks(ProcessGlobalHooks::CallerManaged);
    assert_eq!(
      report.crypto_primitives.status,
      ProcessGlobalHookStatus::CallerManaged
    );
    assert_eq!(
      report.signals.status,
      ProcessGlobalHookStatus::CallerManaged
    );
    assert_eq!(
      report.environment.reason,
      ProcessGlobalReason::NotUsedByOxibelt
    );
    assert_eq!(
      report.background_threads.reason,
      ProcessGlobalReason::RequiresLifecycleAuthority
    );
  }

  #[test]
  fn unselected_apply_hooks_are_verify_only() {
    let hooks = ProcessGlobalHooks::ApplySelected(ProcessGlobalSelection {
      tracing: true,
      ..ProcessGlobalSelection::default()
    });
    let report = ProcessGlobalReport::for_hooks(hooks);
    assert_eq!(
      report.tracing.reason,
      ProcessGlobalReason::RequiresLifecycleAuthority
    );
    assert_eq!(
      report.crypto_primitives.status,
      ProcessGlobalHookStatus::Unverifiable
    );
    assert_eq!(report.signals.status, ProcessGlobalHookStatus::Unverifiable);
  }
}
