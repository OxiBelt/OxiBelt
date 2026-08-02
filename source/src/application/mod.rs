//! Explicit owned-runtime and caller-runtime application entrypoints.

mod runtime_plan;
mod startup;

use std::fmt;
use std::sync::mpsc;

use serde::Serialize;

use crate::config::{Config, RuntimeOverrides};
use crate::hardening::RuntimeHardeningSnapshot;
use crate::process_globals::{ProcessGlobalReport, ProcessPolicy, RuntimePolicy};
use crate::runtime::topology::{RuntimeTopologyCapabilities, RuntimeTopologySnapshot};
use crate::server::{ServerHandle, ShutdownResult, SignalMode};

pub(crate) use runtime_plan::activate_owned_runtime;
pub(crate) use startup::{build_state, prepare_embedded, prepare_owned};

/// Runtime metadata that is not part of persistent OxiBelt configuration.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
  pub config_path: Option<std::path::PathBuf>,
  pub runtime_overrides: RuntimeOverrides,
}

/// Fixed startup evidence retained by a running server handle.
#[derive(Debug, Clone, Serialize)]
pub struct StartupReport {
  pub runtime_policy: RuntimePolicy,
  pub process_policy: ProcessPolicy,
  pub process_globals: ProcessGlobalReport,
  pub hardening: RuntimeHardeningSnapshot,
  pub runtime_topology: RuntimeTopologySnapshot,
}

#[doc = include_str!("../../../docs/Embedding.md")]
/// Namespace for constructing explicit OxiBelt server modes.
#[derive(Debug, Clone, Copy, Default)]
pub struct OxiBelt;

impl OxiBelt {
  pub fn builder(config: Config) -> OxiBeltBuilder {
    OxiBeltBuilder {
      config,
      options: RunOptions::default(),
      runtime_policy: None,
      process_policy: None,
      runtime_capabilities: None,
    }
  }
}

pub struct OxiBeltBuilder {
  config: Config,
  options: RunOptions,
  runtime_policy: Option<RuntimePolicy>,
  process_policy: Option<ProcessPolicy>,
  runtime_capabilities: Option<RuntimeTopologyCapabilities>,
}

impl OxiBeltBuilder {
  pub fn run_options(mut self, options: RunOptions) -> Self {
    self.options = options;
    self
  }

  pub fn runtime_policy(mut self, policy: RuntimePolicy) -> Self {
    self.runtime_policy = Some(policy);
    self
  }

  pub fn process_policy(mut self, policy: ProcessPolicy) -> Self {
    self.process_policy = Some(policy);
    self
  }

  /// Supplies capability evidence produced by an isolated owned-runtime probe.
  ///
  /// Callers which omit this value do not implicitly execute hidden commands in
  /// their host binary. Compio is reported unavailable and normal topology
  /// fallback or exact-policy rejection applies.
  pub fn runtime_capabilities(mut self, capabilities: RuntimeTopologyCapabilities) -> Self {
    self.runtime_capabilities = Some(capabilities);
    self
  }

  pub fn build_owned(self) -> Result<OwnedServer, ApplicationBuildError> {
    let runtime_policy = self
      .runtime_policy
      .ok_or(ApplicationBuildError::MissingRuntimePolicy)?;
    let process_policy = self
      .process_policy
      .ok_or(ApplicationBuildError::MissingProcessPolicy)?;
    if runtime_policy != RuntimePolicy::FromConfig {
      return Err(ApplicationBuildError::ModeMismatch);
    }
    if process_policy != ProcessPolicy::Standalone {
      return Err(ApplicationBuildError::ModeMismatch);
    }
    Ok(OwnedServer {
      config: self.config,
      options: self.options,
      runtime_capabilities: self.runtime_capabilities,
    })
  }

  pub fn build_embedded(self) -> Result<EmbeddedServer, ApplicationBuildError> {
    let runtime_policy = self
      .runtime_policy
      .ok_or(ApplicationBuildError::MissingRuntimePolicy)?;
    let process_policy = self
      .process_policy
      .ok_or(ApplicationBuildError::MissingProcessPolicy)?;
    if runtime_policy != RuntimePolicy::CurrentRuntime {
      return Err(ApplicationBuildError::ModeMismatch);
    }
    let ProcessPolicy::Embedded(global_hooks) = process_policy else {
      return Err(ApplicationBuildError::ModeMismatch);
    };
    if self.runtime_capabilities.is_some() {
      return Err(ApplicationBuildError::ModeMismatch);
    }
    Ok(EmbeddedServer {
      config: self.config,
      options: self.options,
      global_hooks,
    })
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ApplicationBuildError {
  MissingRuntimePolicy,
  MissingProcessPolicy,
  ModeMismatch,
}

impl fmt::Display for ApplicationBuildError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::MissingRuntimePolicy => formatter.write_str("runtime policy must be selected"),
      Self::MissingProcessPolicy => formatter.write_str("process policy must be selected"),
      Self::ModeMismatch => formatter.write_str(
        "runtime and process policies do not match the selected owned or embedded builder",
      ),
    }
  }
}

impl std::error::Error for ApplicationBuildError {}

pub struct OwnedServer {
  pub(crate) config: Config,
  pub(crate) options: RunOptions,
  pub(crate) runtime_capabilities: Option<RuntimeTopologyCapabilities>,
}

pub struct EmbeddedServer {
  pub(crate) config: Config,
  pub(crate) options: RunOptions,
  pub(crate) global_hooks: crate::process_globals::ProcessGlobalHooks,
}

impl OwnedServer {
  /// Runs the server on an OxiBelt-owned runtime until shutdown completes.
  pub fn run(self) -> anyhow::Result<ShutdownResult> {
    let prepared = prepare_owned(self.config, self.options)?;
    let activated = activate_owned_runtime(
      &prepared.config,
      owned_capabilities(self.runtime_capabilities),
    )?;
    record_owned_topology(&activated.topology);
    let topology = activated.topology;
    activated.runtime.block_on(async move {
      let (state, options, report) = build_state(prepared, topology).await?;
      let handle = crate::server::prepare_controlled(
        state,
        options.config_path,
        options.runtime_overrides,
        SignalMode::Process,
      )
      .await?
      .with_startup_report(report)
      .spawn();
      handle.wait().await
    })
  }

  /// Starts a server on a dedicated owned-runtime thread and returns its lifecycle handle.
  pub fn start(self) -> anyhow::Result<ServerHandle> {
    let prepared = prepare_owned(self.config, self.options)?;
    let capabilities = owned_capabilities(self.runtime_capabilities);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let (runtime_done_tx, runtime_done_rx) = tokio::sync::watch::channel(false);
    std::thread::Builder::new()
      .name("oxibelt-owned-runtime".to_string())
      .spawn(move || {
        let startup_tx = result_tx.clone();
        let result = (|| {
          let activated = activate_owned_runtime(&prepared.config, capabilities)?;
          record_owned_topology(&activated.topology);
          let topology = activated.topology;
          activated.runtime.block_on(async move {
            let (state, options, report) = build_state(prepared, topology).await?;
            let prepared_server = crate::server::prepare_controlled(
              state,
              options.config_path,
              options.runtime_overrides,
              SignalMode::Process,
            )
            .await?
            .with_startup_report(report);
            let (handle, driver) = prepared_server.into_parts();
            let handle = handle.with_owned_runtime_completion(runtime_done_rx);
            startup_tx
              .send(Ok(handle))
              .map_err(|_| anyhow::anyhow!("owned server handle receiver closed"))?;
            driver.await;
            Ok::<(), anyhow::Error>(())
          })
        })();
        runtime_done_tx.send_replace(true);
        if let Err(error) = result {
          let _ = result_tx.send(Err(error));
        }
      })
      .map_err(|error| anyhow::anyhow!("failed to start owned runtime thread: {error}"))?;
    result_rx
      .recv()
      .map_err(|_| anyhow::anyhow!("owned runtime thread stopped before listener startup"))?
  }
}

impl EmbeddedServer {
  /// Starts OxiBelt on the caller's current Tokio runtime.
  pub async fn start(self) -> anyhow::Result<ServerHandle> {
    let signal_mode = embedded_signal_mode(self.global_hooks);
    let prepared = prepare_embedded(self.config, self.options, self.global_hooks)?;
    let topology = crate::runtime::topology_config::external_topology(&prepared.config);
    let (state, options, report) = build_state(prepared, topology).await?;
    Ok(
      crate::server::prepare_controlled(
        state,
        options.config_path,
        options.runtime_overrides,
        signal_mode,
      )
      .await?
      .with_startup_report(report)
      .spawn(),
    )
  }
}

fn owned_capabilities(
  capabilities: Option<RuntimeTopologyCapabilities>,
) -> RuntimeTopologyCapabilities {
  capabilities.unwrap_or_else(|| {
    let mut capabilities = crate::runtime::topology_config::available_capabilities(None);
    capabilities.compio_main = crate::runtime::topology::RuntimeCapability::Unavailable(
      crate::runtime::topology::RuntimeTopologyReason::CompioProbeFailed,
    );
    capabilities
  })
}

fn embedded_signal_mode(hooks: crate::process_globals::ProcessGlobalHooks) -> SignalMode {
  match hooks {
    crate::process_globals::ProcessGlobalHooks::ApplySelected(selection) if selection.signals => {
      SignalMode::Process
    }
    _ => SignalMode::CallerManaged,
  }
}

fn record_owned_topology(topology: &RuntimeTopologySnapshot) {
  crate::runtime::backend::set_runtime_backend_snapshot(topology.legacy_backend_snapshot());
  tracing::info!(
    requested_preset = topology.requested_preset.as_str(),
    resolved_preset = topology.resolved_preset.as_str(),
    topology_policy = topology.policy.as_str(),
    outcome = topology.outcome.as_str(),
    reason = topology.reason.as_str(),
    compatibility_island_count = topology.compatibility_boundaries.compatibility_island_count,
    tokio_executor_workers = topology.workers.tokio_executor_workers,
    compio_direct_h1_workers = topology.workers.compio_direct_h1_workers,
    direct_h1_backend = topology.direct_h1.resolved.as_str(),
    "resolved async runtime topology"
  );
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
  fn builder_rejects_ambiguous_or_crossed_ownership() {
    assert_eq!(
      OxiBelt::builder(config()).build_owned().err(),
      Some(ApplicationBuildError::MissingRuntimePolicy)
    );
    assert_eq!(
      OxiBelt::builder(config())
        .runtime_policy(RuntimePolicy::CurrentRuntime)
        .process_policy(ProcessPolicy::Standalone)
        .build_owned()
        .err(),
      Some(ApplicationBuildError::ModeMismatch)
    );
  }

  #[test]
  fn embedded_builder_accepts_only_explicit_current_runtime_ownership() {
    let server = OxiBelt::builder(config())
      .runtime_policy(RuntimePolicy::CurrentRuntime)
      .process_policy(ProcessPolicy::Embedded(
        crate::process_globals::ProcessGlobalHooks::CallerManaged,
      ))
      .build_embedded();
    assert!(server.is_ok());
  }

  #[test]
  #[allow(deprecated)]
  fn deprecated_async_wrapper_remains_source_compatible() {
    let future = crate::run(config());
    drop(future);
  }

  #[test]
  fn selected_signal_policy_maps_to_process_signal_ownership() {
    let selection = crate::process_globals::ProcessGlobalSelection {
      signals: true,
      ..crate::process_globals::ProcessGlobalSelection::default()
    };
    assert_eq!(
      embedded_signal_mode(crate::process_globals::ProcessGlobalHooks::ApplySelected(
        selection
      )),
      SignalMode::Process
    );
    assert_eq!(
      embedded_signal_mode(crate::process_globals::ProcessGlobalHooks::VerifyOnly),
      SignalMode::CallerManaged
    );
  }
}
