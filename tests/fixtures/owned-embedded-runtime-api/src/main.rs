#![deny(warnings)]
// The deterministic fixture extractor maps these function names to the public
// `Type::method` surface. They intentionally encode exported Rust type names.
#![allow(non_snake_case)]

use std::net::SocketAddr;
use std::time::Instant;

use oxibelt::config::Config;
use oxibelt::runtime::topology::{RuntimeTopologyCapabilities, RuntimeTopologySnapshot};
use oxibelt::server::{
  BoundListener, BoundListenerKind, BoundListenerTransport, ReadinessReason, ReadinessSnapshot,
  ServerControl, ServerControlClosed, ServerHandle, ServerReadiness, ShutdownOutcome,
  ShutdownReason, ShutdownResult, WaitReadyError,
};
use oxibelt::{
  ApplicationBuildError, EmbeddedServer, OwnedServer, OxiBelt, OxiBeltBuilder, ProcessGlobalHooks,
  ProcessGlobalSelection, ProcessPolicy, RunOptions, RuntimePolicy, StartupReport,
};

fn surface_OxiBelt__builder(config: Config) -> OxiBeltBuilder {
  OxiBelt::builder(config)
}

fn surface_OxiBeltBuilder__runtime_policy(builder: OxiBeltBuilder) -> OxiBeltBuilder {
  builder.runtime_policy(RuntimePolicy::FromConfig)
}

fn surface_OxiBeltBuilder__process_policy(builder: OxiBeltBuilder) -> OxiBeltBuilder {
  builder.process_policy(ProcessPolicy::Standalone)
}

fn surface_OxiBeltBuilder__run_options(
  builder: OxiBeltBuilder,
  options: RunOptions,
) -> OxiBeltBuilder {
  builder.run_options(options)
}

fn surface_OxiBeltBuilder__runtime_capabilities(
  builder: OxiBeltBuilder,
  capabilities: RuntimeTopologyCapabilities,
) -> OxiBeltBuilder {
  builder.runtime_capabilities(capabilities)
}

fn surface_OxiBeltBuilder__build_owned(
  builder: OxiBeltBuilder,
) -> Result<OwnedServer, ApplicationBuildError> {
  builder.build_owned()
}

fn surface_OwnedServer__start(server: OwnedServer) -> anyhow::Result<ServerHandle> {
  server.start()
}

fn surface_OwnedServer__run(server: OwnedServer) -> anyhow::Result<ShutdownResult> {
  server.run()
}

fn surface_OxiBeltBuilder__build_embedded(
  builder: OxiBeltBuilder,
) -> Result<EmbeddedServer, ApplicationBuildError> {
  builder.build_embedded()
}

async fn surface_EmbeddedServer__start(server: EmbeddedServer) -> anyhow::Result<ServerHandle> {
  server.start().await
}

fn explicit_owned_builder(
  config: Config,
  options: RunOptions,
) -> Result<OwnedServer, ApplicationBuildError> {
  OxiBelt::builder(config)
    .runtime_policy(RuntimePolicy::FromConfig)
    .process_policy(ProcessPolicy::Standalone)
    .run_options(options)
    .build_owned()
}

fn explicit_embedded_builder(config: Config) -> Result<EmbeddedServer, ApplicationBuildError> {
  OxiBelt::builder(config)
    .runtime_policy(RuntimePolicy::CurrentRuntime)
    .process_policy(ProcessPolicy::Embedded(ProcessGlobalHooks::CallerManaged))
    .build_embedded()
}

fn explicit_process_hook_variants() {
  let _: ProcessGlobalHooks = ProcessGlobalHooks::VerifyOnly;
  let _: ProcessGlobalHooks = ProcessGlobalHooks::ApplySelected(ProcessGlobalSelection::default());
}

fn surface_ServerHandle__readiness(handle: &ServerHandle) -> ReadinessSnapshot {
  handle.readiness()
}

fn surface_ServerHandle__subscribe_readiness(
  handle: &ServerHandle,
) -> tokio::sync::watch::Receiver<ReadinessSnapshot> {
  handle.subscribe_readiness()
}

async fn surface_ServerHandle__wait_ready(
  handle: &mut ServerHandle,
  deadline: Instant,
) -> Result<ReadinessSnapshot, WaitReadyError> {
  handle.wait_ready(deadline).await
}

fn surface_ServerHandle__runtime_topology(handle: &ServerHandle) -> &RuntimeTopologySnapshot {
  handle.runtime_topology()
}

fn surface_ServerHandle__startup_report(handle: &ServerHandle) -> Option<&StartupReport> {
  handle.startup_report()
}

fn surface_ServerHandle__bound_listeners(handle: &ServerHandle) -> &[BoundListener] {
  handle.bound_listeners()
}

fn surface_ServerHandle__control(handle: &ServerHandle) -> ServerControl {
  handle.control()
}

fn surface_ServerHandle__cancel(handle: &ServerHandle) -> Result<(), ServerControlClosed> {
  handle.cancel()
}

async fn surface_ServerHandle__shutdown(
  handle: ServerHandle,
  deadline: Instant,
) -> anyhow::Result<ShutdownResult> {
  handle.shutdown(deadline).await
}

async fn surface_ServerHandle__wait(handle: ServerHandle) -> anyhow::Result<ShutdownResult> {
  handle.wait().await
}

fn surface_ServerControl__readiness(control: &ServerControl) -> ReadinessSnapshot {
  control.readiness()
}

fn surface_ServerControl__subscribe_readiness(
  control: &ServerControl,
) -> tokio::sync::watch::Receiver<ReadinessSnapshot> {
  control.subscribe_readiness()
}

async fn surface_ServerControl__pre_drain(
  control: &ServerControl,
) -> Result<(), ServerControlClosed> {
  control.pre_drain().await
}

async fn surface_ServerControl__reload(control: &ServerControl) -> Result<(), ServerControlClosed> {
  control.reload().await
}

async fn surface_ServerControl__shutdown(
  control: &ServerControl,
  deadline: Instant,
) -> Result<(), ServerControlClosed> {
  control.shutdown(deadline).await
}

fn surface_ServerControl__cancel(control: &ServerControl) -> Result<(), ServerControlClosed> {
  control.cancel()
}

fn lifecycle_value_types(
  listener: BoundListener,
  result: ShutdownResult,
  readiness: ReadinessSnapshot,
) {
  let _: BoundListenerKind = listener.kind;
  let _: BoundListenerTransport = listener.transport;
  let _: SocketAddr = listener.address;
  let _: ShutdownOutcome = result.outcome;
  let _: ShutdownReason = result.reason;
  let _: ServerReadiness = readiness.state;
  let _: ReadinessReason = readiness.reason;
}

fn main() {
  let _ = surface_OxiBelt__builder;
  let _ = surface_OxiBeltBuilder__runtime_policy;
  let _ = surface_OxiBeltBuilder__process_policy;
  let _ = surface_OxiBeltBuilder__run_options;
  let _ = surface_OxiBeltBuilder__runtime_capabilities;
  let _ = surface_OxiBeltBuilder__build_owned;
  let _ = surface_OwnedServer__start;
  let _ = surface_OwnedServer__run;
  let _ = surface_OxiBeltBuilder__build_embedded;
  let _ = surface_EmbeddedServer__start;
  let _ = explicit_owned_builder;
  let _ = explicit_embedded_builder;
  let _ = explicit_process_hook_variants;
  let _ = surface_ServerHandle__readiness;
  let _ = surface_ServerHandle__subscribe_readiness;
  let _ = surface_ServerHandle__wait_ready;
  let _ = surface_ServerHandle__runtime_topology;
  let _ = surface_ServerHandle__startup_report;
  let _ = surface_ServerHandle__bound_listeners;
  let _ = surface_ServerHandle__control;
  let _ = surface_ServerHandle__cancel;
  let _ = surface_ServerHandle__shutdown;
  let _ = surface_ServerHandle__wait;
  let _ = surface_ServerControl__readiness;
  let _ = surface_ServerControl__subscribe_readiness;
  let _ = surface_ServerControl__pre_drain;
  let _ = surface_ServerControl__reload;
  let _ = surface_ServerControl__shutdown;
  let _ = surface_ServerControl__cancel;
  let _ = lifecycle_value_types;
}
