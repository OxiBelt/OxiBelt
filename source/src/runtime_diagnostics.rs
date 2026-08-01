//! Startup runtime diagnostic CLI support.

use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use oxibelt::config::{Config, HttpListenerMode, RuntimeOverrides};
use oxibelt::runtime::backend::CompioDriverSelection;
use oxibelt::runtime::topology::{
  RuntimeCapability, RuntimeRequestedPreset, RuntimeTopologyPolicy, RuntimeTopologyReason,
  resolve_runtime_topology,
};
use oxibelt::runtime::topology_config::{available_capabilities, request_from_config};
use serde::Serialize;
use serde_json::json;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Debug, Args)]
pub(crate) struct RuntimeCheckCommand {
  #[arg(long, value_name = "FILE")]
  config: Option<PathBuf>,
  #[arg(long, value_name = "FORMAT", value_parser = parse_runtime_check_output_format, default_value = "text")]
  format: RuntimeCheckOutputFormat,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RuntimeCheckOutputFormat {
  Text,
  Json,
}

#[derive(Debug, Args)]
pub(crate) struct RuntimeProbeCommand {
  #[command(subcommand)]
  command: RuntimeProbeSubcommand,
}

#[derive(Debug, Subcommand)]
enum RuntimeProbeSubcommand {
  #[command(name = "compio-probe")]
  CompioProbe,
  #[command(name = "compio-main")]
  CompioMain {
    #[arg(long)]
    worker_threads: usize,
  },
  #[command(name = "tracing")]
  Tracing {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
  },
  #[command(name = "hardening")]
  Hardening {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
  },
}

#[derive(Debug, Serialize)]
struct RuntimeCheckReport {
  schema_version: u32,
  ok: bool,
  stages: Vec<RuntimeCheckStage>,
  #[serde(skip_serializing_if = "Option::is_none")]
  hardening: Option<oxibelt::hardening::RuntimeHardeningSnapshot>,
  #[serde(skip_serializing_if = "Option::is_none")]
  topology_resolution: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct RuntimeCheckStage {
  name: &'static str,
  status: &'static str,
  required: bool,
  elapsed_ms: u128,
  message: String,
}

impl RuntimeCheckReport {
  fn new() -> Self {
    Self {
      schema_version: 1,
      ok: true,
      stages: Vec::new(),
      hardening: None,
      topology_resolution: None,
    }
  }

  fn stage<T>(
    &mut self,
    name: &'static str,
    required: bool,
    action: impl FnOnce() -> anyhow::Result<T>,
  ) -> Option<T> {
    let started = Instant::now();
    match action() {
      Ok(value) => {
        self.stages.push(RuntimeCheckStage {
          name,
          status: "ok",
          required,
          elapsed_ms: started.elapsed().as_millis(),
          message: "ok".to_string(),
        });
        Some(value)
      }
      Err(error) => {
        if required {
          self.ok = false;
        }
        self.stages.push(RuntimeCheckStage {
          name,
          status: "failed",
          required,
          elapsed_ms: started.elapsed().as_millis(),
          message: format!("{error:#}"),
        });
        None
      }
    }
  }

  fn capability_stage<T>(
    &mut self,
    name: &'static str,
    required: bool,
    failure_reason: RuntimeTopologyReason,
    action: impl FnOnce() -> anyhow::Result<T>,
  ) -> Option<T> {
    let started = Instant::now();
    match action() {
      Ok(value) => {
        self.stages.push(RuntimeCheckStage {
          name,
          status: "ok",
          required,
          elapsed_ms: started.elapsed().as_millis(),
          message: "ok".to_string(),
        });
        Some(value)
      }
      Err(_) => {
        if required {
          self.ok = false;
        }
        self.stages.push(RuntimeCheckStage {
          name,
          status: "failed",
          required,
          elapsed_ms: started.elapsed().as_millis(),
          message: failure_reason.as_str().to_string(),
        });
        None
      }
    }
  }

  fn skip(&mut self, name: &'static str, required: bool, message: impl Into<String>) {
    self.stages.push(RuntimeCheckStage {
      name,
      status: "skipped",
      required,
      elapsed_ms: 0,
      message: message.into(),
    });
  }
}

pub(crate) fn handle_runtime_check_command(
  command: &RuntimeCheckCommand,
  global_config_path: Option<&PathBuf>,
) -> anyhow::Result<()> {
  let config_path = command
    .config
    .as_ref()
    .or(global_config_path)
    .ok_or_else(|| anyhow::anyhow!("--config is required"))?;
  let report = run_runtime_check(config_path);
  match command.format {
    RuntimeCheckOutputFormat::Text => print_runtime_check_text(&report),
    RuntimeCheckOutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
  }
  if !report.ok {
    std::process::exit(1);
  }
  Ok(())
}

fn run_runtime_check(config_path: &Path) -> RuntimeCheckReport {
  let mut report = RuntimeCheckReport::new();
  let mut config = match report.stage("config_load", true, || {
    Config::load(config_path).with_context(|| format!("failed to load {}", config_path.display()))
  }) {
    Some(config) => config,
    None => {
      report.skip("config_validation", true, "config did not load");
      report.skip("tracing_init", true, "config did not load");
      report.skip("crypto_provider_init", true, "config did not load");
      report.skip("hardening_application", true, "config did not load");
      report.skip("compio_probe_runtime_build", true, "config did not load");
      report.skip("main_compio_runtime_build", true, "config did not load");
      report.skip(
        "tokio_compatibility_island_build",
        true,
        "config did not load",
      );
      report.skip("tls_certificate_key_load", true, "config did not load");
      report.skip("listener_bind_dry_run", true, "config did not load");
      report.skip("runtime_topology_resolution", true, "config did not load");
      return report;
    }
  };
  let overrides = RuntimeOverrides::default();
  for warning in config.apply_runtime_overrides(&overrides) {
    report.stages.push(RuntimeCheckStage {
      name: "config_load",
      status: "ok",
      required: false,
      elapsed_ms: 0,
      message: warning,
    });
  }
  let validation_ok = report
    .stage("config_validation", true, || config.validate())
    .is_some();
  if validation_ok {
    report.stage("tracing_init", true, || run_tracing_child(config_path));
    report.stage("crypto_provider_init", true, || {
      oxibelt::configure_crypto_runtime(&config);
      oxibelt::tls::install_configured_provider(&config.crypto)
    });
    report.hardening = report.stage("hardening_application", true, || {
      run_hardening_child(config_path)
    });
  } else {
    report.skip("tracing_init", true, "config validation failed");
    report.skip("crypto_provider_init", true, "config validation failed");
    report.skip("hardening_application", true, "config validation failed");
  }

  let topology_request = request_from_config(&config);
  let compio_requested = topology_request.requested_preset != RuntimeRequestedPreset::TokioHyper;
  let compio_required = compio_requested
    && (topology_request.requested_preset != RuntimeRequestedPreset::Auto
      || topology_request.policy == RuntimeTopologyPolicy::RequireExact);
  let driver = if compio_requested {
    report.capability_stage(
      "compio_probe_runtime_build",
      compio_required,
      RuntimeTopologyReason::CompioProbeFailed,
      run_compio_probe_child,
    )
  } else {
    report.skip(
      "compio_probe_runtime_build",
      false,
      "Compio main topology was not requested",
    );
    None
  };
  let unsafe_auto_driver = topology_request.requested_preset == RuntimeRequestedPreset::Auto
    && driver.is_some_and(|driver| !super::compio_driver_safe_for_auto_main_runtime(driver));
  let compio_main_ok = if driver.is_some() && !unsafe_auto_driver {
    report
      .capability_stage(
        "main_compio_runtime_build",
        compio_required,
        RuntimeTopologyReason::CompioRuntimeBuildFailed,
        || run_compio_main_child(config.runtime.workers.tokio),
      )
      .is_some()
  } else {
    report.skip(
      "main_compio_runtime_build",
      compio_required,
      if unsafe_auto_driver {
        RuntimeTopologyReason::UnsafeCompioDriver.as_str()
      } else if compio_requested {
        RuntimeTopologyReason::CompioProbeFailed.as_str()
      } else {
        "Compio main topology was not requested"
      },
    );
    false
  };
  report.stage("tokio_compatibility_island_build", true, || {
    oxibelt::runtime::tokio_island::TokioIslandRuntime::build(config.runtime.workers.tokio)
      .map(|_| ())
  });

  if validation_ok {
    let mut capabilities = available_capabilities(driver);
    if compio_requested {
      capabilities.compio_main = if driver.is_none() {
        RuntimeCapability::Unavailable(RuntimeTopologyReason::CompioProbeFailed)
      } else if unsafe_auto_driver {
        RuntimeCapability::Unavailable(RuntimeTopologyReason::UnsafeCompioDriver)
      } else if !compio_main_ok {
        RuntimeCapability::Unavailable(RuntimeTopologyReason::CompioRuntimeBuildFailed)
      } else {
        RuntimeCapability::Available
      };
    }
    let started = Instant::now();
    match resolve_runtime_topology(topology_request, capabilities) {
      Ok(topology) => {
        report.stages.push(RuntimeCheckStage {
          name: "runtime_topology_resolution",
          status: "ok",
          required: true,
          elapsed_ms: started.elapsed().as_millis(),
          message: topology.outcome.as_str().to_string(),
        });
        report.topology_resolution = Some(json!({
          "basis": "preflight",
          "activated": false,
          "topology": topology,
        }));
      }
      Err(rejection) => {
        report.ok = false;
        report.stages.push(RuntimeCheckStage {
          name: "runtime_topology_resolution",
          status: "failed",
          required: true,
          elapsed_ms: started.elapsed().as_millis(),
          message: rejection.reason.as_str().to_string(),
        });
        report.topology_resolution = Some(json!({
          "basis": "preflight",
          "activated": false,
          "rejection": rejection,
        }));
      }
    }
  } else {
    report.skip(
      "runtime_topology_resolution",
      true,
      "config validation failed",
    );
  }

  if validation_ok {
    report.stage("tls_certificate_key_load", true, || {
      load_tls_material_for_check(&config)
    });
    report.stage("listener_bind_dry_run", true, || {
      dry_run_listener_binds(&config)
    });
  } else {
    report.skip("tls_certificate_key_load", true, "config validation failed");
    report.skip("listener_bind_dry_run", true, "config validation failed");
  }
  report
}

fn print_runtime_check_text(report: &RuntimeCheckReport) {
  println!(
    "OxiBelt runtime check: {}",
    if report.ok { "ok" } else { "not ok" }
  );
  for stage in &report.stages {
    println!(
      "- [{}] {}{}: {}",
      stage.status,
      stage.name,
      if stage.required { "" } else { " (optional)" },
      stage.message
    );
  }
  if let Some(topology_resolution) = &report.topology_resolution {
    println!(
      "- runtime_topology: {}",
      serde_json::to_string(topology_resolution).unwrap_or_else(|_| "unavailable".to_string())
    );
  }
  if let Some(hardening) = &report.hardening {
    println!(
      "- hardening: {}",
      serde_json::to_string(hardening).unwrap_or_else(|_| "unavailable".to_string())
    );
  }
}

pub(crate) fn handle_runtime_probe_command(command: &RuntimeProbeCommand) -> anyhow::Result<()> {
  match &command.command {
    RuntimeProbeSubcommand::CompioProbe => {
      let runtime = oxibelt::runtime::compio::build_driver_runtime()?;
      let driver = CompioDriverSelection::from(runtime.driver_type());
      runtime.block_on(async {});
      println!("driver={}", driver.as_str());
      Ok(())
    }
    RuntimeProbeSubcommand::CompioMain { worker_threads } => {
      let runtime = oxibelt::runtime::compio::build_runtime(*worker_threads)?;
      runtime.block_on_tokio_island(async {});
      Ok(())
    }
    RuntimeProbeSubcommand::Tracing { config } => {
      let config =
        Config::load(config).with_context(|| format!("failed to load {}", config.display()))?;
      config.validate()?;
      oxibelt::runtime::init_observability(&config).map(|_| ())
    }
    RuntimeProbeSubcommand::Hardening { config } => {
      let config =
        Config::load(config).with_context(|| format!("failed to load {}", config.display()))?;
      config.validate()?;
      let manifest = oxibelt::filesystem_access::FilesystemAccessManifest::from_config(&config)?;
      let projection = manifest.landlock_projection();
      let snapshot = oxibelt::hardening::apply_runtime_hardening_with_manifest(
        &config.runtime.hardening,
        Some(&projection),
      )?;
      println!("{}", serde_json::to_string(&snapshot)?);
      Ok(())
    }
  }
}

pub(crate) fn run_compio_probe_child() -> anyhow::Result<CompioDriverSelection> {
  let stdout = run_probe_child(&["__runtime-probe", "compio-probe"])?;
  parse_compio_probe_driver(&stdout)
}

pub(crate) fn run_compio_main_child(worker_threads: usize) -> anyhow::Result<()> {
  let worker_threads = worker_threads.to_string();
  run_probe_child(&[
    "__runtime-probe",
    "compio-main",
    "--worker-threads",
    &worker_threads,
  ])
  .map(|_| ())
}

fn run_hardening_child(
  config_path: &Path,
) -> anyhow::Result<oxibelt::hardening::RuntimeHardeningSnapshot> {
  let config_path = config_path.display().to_string();
  let stdout = run_probe_child(&["__runtime-probe", "hardening", "--config", &config_path])?;
  serde_json::from_str(stdout.trim()).context("hardening probe output was not valid JSON")
}

fn run_tracing_child(config_path: &Path) -> anyhow::Result<()> {
  let config_path = config_path.display().to_string();
  run_probe_child(&["__runtime-probe", "tracing", "--config", &config_path]).map(|_| ())
}

fn run_probe_child(args: &[&str]) -> anyhow::Result<String> {
  let output = Command::new(std::env::current_exe().context("failed to locate oxibelt binary")?)
    .args(args)
    .output()
    .with_context(|| format!("failed to run internal runtime probe: {}", args.join(" ")))?;
  if output.status.success() {
    return String::from_utf8(output.stdout).context("runtime probe stdout was not UTF-8");
  }
  let stderr = String::from_utf8_lossy(&output.stderr);
  if let Some(signal) = output.status.signal() {
    bail!(
      "runtime probe exited due to signal {signal}: {}",
      stderr.trim()
    );
  }
  bail!(
    "runtime probe exited with status {:?}: {}",
    output.status.code(),
    stderr.trim()
  )
}

fn parse_compio_probe_driver(stdout: &str) -> anyhow::Result<CompioDriverSelection> {
  let value = stdout
    .lines()
    .find_map(|line| line.strip_prefix("driver="))
    .ok_or_else(|| anyhow::anyhow!("runtime probe did not report Compio driver"))?;
  match value.trim() {
    "io_uring" => Ok(CompioDriverSelection::IoUring),
    "polling" => Ok(CompioDriverSelection::Polling),
    "iocp" => Ok(CompioDriverSelection::Iocp),
    other => bail!("runtime probe reported unsupported Compio driver {other}"),
  }
}

fn load_tls_material_for_check(config: &Config) -> anyhow::Result<()> {
  oxibelt::tls::build_server_config(&config.tls, &config.listeners)
    .context("failed to build downstream TCP TLS config")?;
  if config.listeners.http3 {
    oxibelt::tls::build_quic_server_config(
      &config.tls,
      &config.quic,
      config.source_paths.cert_dir.as_deref(),
    )
    .context("failed to build downstream QUIC TLS config")?;
  }
  #[cfg(not(oxibelt_strict_artifact))]
  if config.admin.enabled && config.admin.tls.enabled {
    oxibelt::tls::build_admin_server_config(&config.admin.tls)
      .context("failed to build admin TLS config")?;
  }
  for listener in &config.webrtc_turn_listeners {
    if listener.bind_tls.is_some() {
      oxibelt::tls::build_turn_server_config(&listener.tls, &config.tls)
        .with_context(|| format!("failed to build TURN TLS config for {}", listener.name))?;
    }
  }
  Ok(())
}

fn dry_run_listener_binds(config: &Config) -> anyhow::Result<()> {
  let mut checked = 0usize;
  if config.needs_https_listener() {
    for bind in &config.listeners.https_binds {
      dry_run_tcp_bind(
        *bind,
        config.runtime.accept.workers,
        config.runtime.accept.reuse_port,
      )?;
      checked += 1;
    }
  }
  if config.listeners.http_mode != HttpListenerMode::Off {
    for bind in &config.listeners.http_binds {
      dry_run_tcp_bind(
        *bind,
        config.runtime.accept.workers,
        config.runtime.accept.reuse_port,
      )?;
      checked += 1;
    }
  }
  if config.listeners.http3 {
    for bind in &config.listeners.https_binds {
      dry_run_udp_bind(
        *bind,
        config.quic.socket.workers,
        config.quic.socket.reuse_port,
      )?;
      checked += 1;
    }
  }
  if checked == 0 {
    return Ok(());
  }
  Ok(())
}

fn dry_run_tcp_bind(bind: SocketAddr, workers: usize, reuse_port: bool) -> anyhow::Result<()> {
  let first = bind_one_tcp(bind, reuse_port)?;
  let assigned = first
    .local_addr()
    .context("failed to read TCP dry-run listener address")?;
  if workers <= 1 {
    return Ok(());
  }
  let bind = SocketAddr::new(bind.ip(), assigned.port());
  let mut listeners = Vec::with_capacity(workers.saturating_sub(1));
  for _ in 1..workers {
    listeners.push(bind_one_tcp(bind, reuse_port)?);
  }
  drop(listeners);
  Ok(())
}

fn bind_one_tcp(bind: SocketAddr, reuse_port: bool) -> anyhow::Result<std::net::TcpListener> {
  let socket = Socket::new(Domain::for_address(bind), Type::STREAM, Some(Protocol::TCP))
    .with_context(|| format!("failed to create TCP dry-run socket for {bind}"))?;
  socket
    .set_reuse_address(true)
    .context("failed to set TCP dry-run SO_REUSEADDR")?;
  if bind.is_ipv6() {
    socket
      .set_only_v6(true)
      .context("failed to set TCP dry-run IPV6_V6ONLY")?;
  }
  if reuse_port {
    socket
      .set_reuse_port(true)
      .context("failed to set TCP dry-run SO_REUSEPORT")?;
  }
  socket
    .bind(&SockAddr::from(bind))
    .with_context(|| format!("failed to bind TCP dry-run socket to {bind}"))?;
  socket
    .listen(1)
    .context("failed to listen on TCP dry-run socket")?;
  Ok(socket.into())
}

fn dry_run_udp_bind(bind: SocketAddr, workers: usize, reuse_port: bool) -> anyhow::Result<()> {
  let first = bind_one_udp(bind, reuse_port)?;
  let assigned = first
    .local_addr()
    .context("failed to read UDP dry-run socket address")?;
  if workers <= 1 {
    return Ok(());
  }
  let bind = SocketAddr::new(bind.ip(), assigned.port());
  let mut sockets = Vec::with_capacity(workers.saturating_sub(1));
  for _ in 1..workers {
    sockets.push(bind_one_udp(bind, reuse_port)?);
  }
  drop(sockets);
  Ok(())
}

fn bind_one_udp(bind: SocketAddr, reuse_port: bool) -> anyhow::Result<std::net::UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))
    .with_context(|| format!("failed to create UDP dry-run socket for {bind}"))?;
  if bind.is_ipv6() {
    socket
      .set_only_v6(true)
      .context("failed to set UDP dry-run IPV6_V6ONLY")?;
  }
  if reuse_port {
    socket
      .set_reuse_port(true)
      .context("failed to set UDP dry-run SO_REUSEPORT")?;
  }
  socket
    .bind(&SockAddr::from(bind))
    .with_context(|| format!("failed to bind UDP dry-run socket to {bind}"))?;
  Ok(socket.into())
}

fn parse_runtime_check_output_format(value: &str) -> Result<RuntimeCheckOutputFormat, String> {
  match value {
    "text" => Ok(RuntimeCheckOutputFormat::Text),
    "json" => Ok(RuntimeCheckOutputFormat::Json),
    _ => Err(format!(
      "unsupported runtime-check format {value}; expected text or json"
    )),
  }
}
