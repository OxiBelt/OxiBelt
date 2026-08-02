//! Shared staged startup before listener publication.

use anyhow::Context;

use super::{RunOptions, StartupReport};
use crate::config::{Config, RuntimeLandlockMode};
use crate::hardening::{
  CloseRangeEffectiveState, LandlockEnforcementState, RuntimeHardeningSnapshot,
  SeccompVerificationState,
};
use crate::process_globals::{
  ProcessGlobalHookReport, ProcessGlobalHookStatus, ProcessGlobalHooks, ProcessGlobalReason,
  ProcessGlobalReport, ProcessPolicy, RuntimePolicy, configure_startup_hooks,
};
use crate::runtime::topology::RuntimeTopologySnapshot;
use crate::state::{AppHandle, AppSnapshot};
use crate::telemetry::TelemetryRuntime;

pub(crate) struct PreparedStartup {
  pub(crate) config: Config,
  pub(crate) options: RunOptions,
  pub(crate) telemetry: TelemetryRuntime,
  pub(crate) hardening: RuntimeHardeningSnapshot,
  pub(crate) process_globals: ProcessGlobalReport,
  pub(crate) runtime_policy: RuntimePolicy,
  pub(crate) process_policy: ProcessPolicy,
}

pub(crate) fn prepare_owned(
  config: Config,
  options: RunOptions,
) -> anyhow::Result<PreparedStartup> {
  prepare(config, options, ProcessPolicy::Standalone)
}

pub(crate) fn prepare_embedded(
  config: Config,
  options: RunOptions,
  hooks: ProcessGlobalHooks,
) -> anyhow::Result<PreparedStartup> {
  tokio::runtime::Handle::try_current()
    .context("embedded runtime startup requires a current Tokio runtime")?;
  validate_embedded_authority(&config, hooks)?;
  prepare(config, options, ProcessPolicy::Embedded(hooks))
}

fn validate_embedded_authority(config: &Config, hooks: ProcessGlobalHooks) -> anyhow::Result<()> {
  if matches!(hooks, ProcessGlobalHooks::ApplySelected(selection) if selection.landlock) {
    anyhow::bail!(
      "embedded_runtime_landlock_existing_runtime_threads: use the owned-runtime API to apply Landlock before OxiBelt worker creation"
    );
  }
  if config.runtime.netport_switcher.enabled {
    anyhow::bail!(
      "embedded_runtime_netport_switcher_process_ownership_required: use the owned-runtime API when the privileged socket broker is enabled"
    );
  }
  Ok(())
}

fn prepare(
  mut config: Config,
  options: RunOptions,
  process_policy: ProcessPolicy,
) -> anyhow::Result<PreparedStartup> {
  config.resolve_rollout_identity_from_environment()?;
  let override_warnings = config.apply_runtime_overrides(&options.runtime_overrides);
  config.validate()?;

  let hooks = process_policy.global_hooks();
  let mut process_globals = configure_startup_hooks(&config, hooks)?;
  for warning in override_warnings {
    tracing::warn!("{warning}");
  }
  if let Some(mode) = config.runtime.hardening.seccomp.legacy_mode() {
    tracing::warn!(
      code = "CFG_RUNTIME_SECCOMP_MODE_COMPATIBILITY_ALIAS",
      legacy_mode = ?mode,
      expectation = config.runtime.hardening.seccomp.expectation.as_str(),
      "legacy runtime.hardening.seccomp.mode maps to runtime.hardening.seccomp.expectation"
    );
  }
  crate::tls::preload_native_redis_roots(&config)
    .context("failed to preload native Redis trust roots before runtime confinement")?;

  if process_policy == ProcessPolicy::Standalone {
    crate::netport_switcher::ensure_required_runtime_socket(&config)?;
  }
  let filesystem_manifest =
    crate::filesystem_access::FilesystemAccessManifest::from_config(&config)
      .context("failed to generate filesystem-access manifest")?;
  let projection = filesystem_manifest.landlock_projection();
  let hardening = match process_policy {
    ProcessPolicy::Standalone => {
      crate::hardening::apply_runtime_hardening_with_manifest_and_policy(
        &config.runtime.hardening,
        Some(&projection),
        crate::hardening::RequiredHardeningFailurePolicy::for_operational_profile(
          config.operational_profile.as_ref(),
        ),
      )?
    }
    ProcessPolicy::Embedded(hooks) => {
      embedded_hardening(&config, &projection, hooks, &mut process_globals)?
    }
  };
  update_hardening_report(&hardening, process_policy, &mut process_globals);
  tracing::info!(
    hardening = %serde_json::to_string(&hardening)?,
    "resolved runtime hardening contract"
  );

  let telemetry = crate::runtime::init_telemetry(&config)?;
  process_globals.background_threads = if telemetry.enabled() {
    report(
      ProcessGlobalHookStatus::Applied,
      ProcessGlobalReason::AppliedByOxibelt,
    )
  } else {
    report(
      ProcessGlobalHookStatus::NotConfigured,
      ProcessGlobalReason::NotUsedByOxibelt,
    )
  };
  Ok(PreparedStartup {
    config,
    options,
    telemetry,
    hardening,
    process_globals,
    runtime_policy: if process_policy == ProcessPolicy::Standalone {
      RuntimePolicy::FromConfig
    } else {
      RuntimePolicy::CurrentRuntime
    },
    process_policy,
  })
}

fn embedded_hardening(
  config: &Config,
  projection: &crate::hardening::LandlockManifestProjection,
  hooks: ProcessGlobalHooks,
  process_globals: &mut ProcessGlobalReport,
) -> anyhow::Result<RuntimeHardeningSnapshot> {
  let apply_close_range =
    matches!(hooks, ProcessGlobalHooks::ApplySelected(selection) if selection.close_range);
  if !apply_close_range {
    return Ok(crate::hardening::observe_runtime_hardening(
      &config.runtime.hardening,
      Some(projection),
    ));
  }

  let observed =
    crate::hardening::observe_runtime_hardening(&config.runtime.hardening, Some(projection));
  let mut selected = config.runtime.hardening.clone();
  selected.landlock.mode = RuntimeLandlockMode::Off;
  let mut applied = crate::hardening::apply_runtime_hardening_with_manifest_and_policy(
    &selected,
    Some(projection),
    crate::hardening::RequiredHardeningFailurePolicy::for_operational_profile(
      config.operational_profile.as_ref(),
    ),
  )?;
  applied.landlock = observed.landlock;
  process_globals.landlock = report(
    ProcessGlobalHookStatus::Unverifiable,
    ProcessGlobalReason::ExistingRuntimeThreads,
  );
  Ok(applied)
}

fn update_hardening_report(
  hardening: &RuntimeHardeningSnapshot,
  process_policy: ProcessPolicy,
  process_globals: &mut ProcessGlobalReport,
) {
  process_globals.close_range = match (process_policy, hardening.close_range.effective) {
    (ProcessPolicy::Embedded(ProcessGlobalHooks::CallerManaged), _) => report(
      ProcessGlobalHookStatus::CallerManaged,
      ProcessGlobalReason::CallerOwnsHook,
    ),
    (_, CloseRangeEffectiveState::Applied) => report(
      ProcessGlobalHookStatus::Applied,
      ProcessGlobalReason::AppliedByOxibelt,
    ),
    (_, CloseRangeEffectiveState::Off) => report(
      ProcessGlobalHookStatus::NotConfigured,
      ProcessGlobalReason::NotUsedByOxibelt,
    ),
    (_, CloseRangeEffectiveState::Unavailable) => report(
      ProcessGlobalHookStatus::Unverifiable,
      ProcessGlobalReason::VerificationUnavailable,
    ),
  };
  process_globals.seccomp = match hardening.seccomp.verification {
    SeccompVerificationState::Satisfied => report(
      ProcessGlobalHookStatus::Verified,
      ProcessGlobalReason::ExistingStateMatches,
    ),
    SeccompVerificationState::NotRequired => report(
      ProcessGlobalHookStatus::NotConfigured,
      ProcessGlobalReason::NotUsedByOxibelt,
    ),
    SeccompVerificationState::Degraded | SeccompVerificationState::Blocked => report(
      ProcessGlobalHookStatus::Unverifiable,
      ProcessGlobalReason::VerificationUnavailable,
    ),
  };
  process_globals.landlock = match (process_policy, hardening.landlock.enforcement) {
    (ProcessPolicy::Embedded(ProcessGlobalHooks::CallerManaged), _) => report(
      ProcessGlobalHookStatus::CallerManaged,
      ProcessGlobalReason::CallerOwnsHook,
    ),
    (ProcessPolicy::Embedded(_), _)
      if hardening.landlock.requested_mode != RuntimeLandlockMode::Off =>
    {
      report(
        ProcessGlobalHookStatus::Unverifiable,
        ProcessGlobalReason::ExistingRuntimeThreads,
      )
    }
    (_, LandlockEnforcementState::Active) => report(
      ProcessGlobalHookStatus::Applied,
      ProcessGlobalReason::AppliedByOxibelt,
    ),
    (_, LandlockEnforcementState::Off) => report(
      ProcessGlobalHookStatus::NotConfigured,
      ProcessGlobalReason::NotUsedByOxibelt,
    ),
  };
  process_globals.signals = match process_policy {
    ProcessPolicy::Standalone => report(
      ProcessGlobalHookStatus::Applied,
      ProcessGlobalReason::AppliedByOxibelt,
    ),
    ProcessPolicy::Embedded(ProcessGlobalHooks::CallerManaged) => report(
      ProcessGlobalHookStatus::CallerManaged,
      ProcessGlobalReason::CallerOwnsHook,
    ),
    ProcessPolicy::Embedded(ProcessGlobalHooks::VerifyOnly) => report(
      ProcessGlobalHookStatus::Unverifiable,
      ProcessGlobalReason::VerificationUnavailable,
    ),
    ProcessPolicy::Embedded(ProcessGlobalHooks::ApplySelected(selection)) => {
      if selection.signals {
        report(
          ProcessGlobalHookStatus::Applied,
          ProcessGlobalReason::AppliedByOxibelt,
        )
      } else {
        report(
          ProcessGlobalHookStatus::Unverifiable,
          ProcessGlobalReason::VerificationUnavailable,
        )
      }
    }
  };
}

const fn report(
  status: ProcessGlobalHookStatus,
  reason: ProcessGlobalReason,
) -> ProcessGlobalHookReport {
  ProcessGlobalHookReport::new(status, reason)
}

pub(crate) async fn build_state(
  prepared: PreparedStartup,
  topology: RuntimeTopologySnapshot,
) -> anyhow::Result<(AppHandle, RunOptions, StartupReport)> {
  let PreparedStartup {
    config,
    options,
    telemetry,
    hardening,
    process_globals,
    runtime_policy,
    process_policy,
  } = prepared;
  let report = StartupReport {
    runtime_policy,
    process_policy,
    process_globals,
    hardening: hardening.clone(),
    runtime_topology: topology.clone(),
  };
  let snapshot = AppSnapshot::new_with_telemetry_and_topology_and_hardening(
    config, telemetry, topology, hardening,
  )
  .await
  .context("failed to initialize application state")?;
  Ok((AppHandle::new(snapshot), options, report))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn config() -> Config {
    toml::from_str(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
"#,
    )
    .expect("minimal config should deserialize")
  }

  #[test]
  fn caller_managed_embedded_policy_never_requests_landlock_application() {
    let mut config = config();
    config.runtime.hardening.landlock.mode = RuntimeLandlockMode::Manifest;
    validate_embedded_authority(&config, ProcessGlobalHooks::CallerManaged)
      .expect("caller-managed Landlock should remain host-owned");
  }

  #[test]
  fn selected_embedded_landlock_is_rejected_before_startup() {
    let selection = crate::process_globals::ProcessGlobalSelection {
      landlock: true,
      ..crate::process_globals::ProcessGlobalSelection::default()
    };
    let error =
      validate_embedded_authority(&config(), ProcessGlobalHooks::ApplySelected(selection))
        .expect_err("current-runtime Landlock application must be rejected");
    assert!(error.to_string().contains("existing_runtime_threads"));
  }

  #[test]
  fn embedded_netport_broker_requires_owned_process_authority() {
    let mut config = config();
    config.runtime.netport_switcher.enabled = true;
    let error = validate_embedded_authority(&config, ProcessGlobalHooks::CallerManaged)
      .expect_err("the privileged socket broker must remain owned-runtime only");
    assert!(error.to_string().contains("process_ownership_required"));
  }
}
