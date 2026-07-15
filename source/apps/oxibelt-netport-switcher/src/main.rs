//! Root wrapper that brokers privileged data-plane binds for an unprivileged OxiBelt child.

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::{
  Arc,
  atomic::{AtomicBool, Ordering},
};

use anyhow::Context;
use clap::Parser;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use oxibelt::config::{Config, HotReloadMode, RuntimeOverrides};
use oxibelt::netport_switcher::{NetportBroker, SOCKET_ENV};
use tokio::signal::unix::{SignalKind, signal};

#[derive(Debug, Parser)]
#[command(name = "oxibelt-netport-switcher")]
#[command(about = "OxiBelt privileged port socket broker")]
struct Cli {
  #[arg(long, value_name = "FILE")]
  config: PathBuf,

  #[arg(long, value_name = "PATH", default_value = "/usr/local/bin/oxibelt")]
  oxibelt_bin: PathBuf,

  #[arg(long, value_name = "MODE", value_parser = parse_hot_reload_mode)]
  hot_reload_mode: Option<HotReloadMode>,

  #[arg(long, value_name = "MILLISECONDS")]
  hot_reload_poll_interval_ms: Option<u64>,
}

#[tokio::main]
async fn main() {
  let exit_code = match run().await {
    Ok(exit_code) => exit_code,
    Err(error) => {
      eprintln!("{error:#}");
      1
    }
  };
  std::process::exit(exit_code);
}

async fn run() -> anyhow::Result<i32> {
  let cli = Cli::parse();
  let overrides = RuntimeOverrides {
    hot_reload_mode: cli.hot_reload_mode,
    hot_reload_poll_interval_ms: cli.hot_reload_poll_interval_ms,
  };
  let mut config = Config::load(&cli.config)
    .with_context(|| format!("failed to load {}", cli.config.display()))?;
  for warning in config.apply_runtime_overrides(&overrides) {
    eprintln!("{warning}");
  }
  config.validate()?;

  let broker = Arc::new(NetportBroker::from_config(&config)?);
  let listener = broker.bind_control_listener()?;
  let stopped = Arc::new(AtomicBool::new(false));
  let broker_thread = {
    let broker = broker.clone();
    let stopped = stopped.clone();
    std::thread::spawn(move || broker.serve_until_stopped(listener, stopped))
  };

  let mut child = spawn_child(&cli, &config, broker.socket_path(), &overrides)?;
  let signal_target = ChildSignalTarget::new(
    child.id(),
    config.runtime.netport_switcher.pidfd_supervision,
  );
  let wait = tokio::task::spawn_blocking(move || child.wait());
  let exit_code = wait_for_child_with_signal_forwarding(wait, signal_target).await;
  stopped.store(true, Ordering::Relaxed);
  broker_thread
    .join()
    .map_err(|_| anyhow::anyhow!("netport switcher broker thread panicked"))??;
  exit_code
}

fn spawn_child(
  cli: &Cli,
  config: &Config,
  socket_path: &std::path::Path,
  overrides: &RuntimeOverrides,
) -> anyhow::Result<std::process::Child> {
  let switcher = &config.runtime.netport_switcher;
  let mut command = Command::new(&cli.oxibelt_bin);
  command.arg("--config").arg(&cli.config);
  if let Some(mode) = overrides.hot_reload_mode {
    command.arg("--hot-reload-mode").arg(mode.to_string());
  }
  if let Some(poll_interval_ms) = overrides.hot_reload_poll_interval_ms {
    command
      .arg("--hot-reload-poll-interval-ms")
      .arg(poll_interval_ms.to_string());
  }
  command
    .env(SOCKET_ENV, socket_path)
    .uid(switcher.main_uid)
    .gid(switcher.main_gid);
  command.spawn().with_context(|| {
    format!(
      "failed to spawn {} as {}:{}",
      cli.oxibelt_bin.display(),
      switcher.main_uid,
      switcher.main_gid
    )
  })
}

async fn wait_for_child_with_signal_forwarding(
  mut wait: tokio::task::JoinHandle<std::io::Result<ExitStatus>>,
  child: ChildSignalTarget,
) -> anyhow::Result<i32> {
  let mut terminate = signal(SignalKind::terminate()).context("failed to register SIGTERM")?;
  let mut interrupt = signal(SignalKind::interrupt()).context("failed to register SIGINT")?;
  let mut hangup = signal(SignalKind::hangup()).context("failed to register SIGHUP")?;
  let mut pre_drain = signal(SignalKind::user_defined1()).context("failed to register SIGUSR1")?;
  loop {
    tokio::select! {
      status = &mut wait => {
        let status = status.context("failed to join OxiBelt child wait task")??;
        return Ok(exit_code_for_status(status));
      }
      _ = terminate.recv() => child.forward(Signal::SIGTERM)?,
      _ = interrupt.recv() => child.forward(Signal::SIGINT)?,
      _ = hangup.recv() => child.forward(Signal::SIGHUP)?,
      _ = pre_drain.recv() => child.forward(Signal::SIGUSR1)?,
    }
  }
}

struct ChildSignalTarget {
  pid: u32,
  #[cfg(target_os = "linux")]
  pidfd: Option<OwnedFd>,
}

impl ChildSignalTarget {
  fn new(pid: u32, pidfd_enabled: bool) -> Self {
    Self {
      pid,
      #[cfg(target_os = "linux")]
      pidfd: pidfd_enabled.then(|| pidfd_open(pid)).and_then(Result::ok),
    }
  }

  fn forward(&self, signal: Signal) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(pidfd) = &self.pidfd {
      match pidfd_send_signal(pidfd, signal) {
        Ok(()) => return Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
        Err(error) => {
          tracing::warn!(
            error = %error,
            child_pid = self.pid,
            signal = ?signal,
            "pidfd signal forwarding failed; falling back to pid"
          );
        }
      }
    }
    match kill(Pid::from_raw(self.pid as i32), signal) {
      Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
      Err(error) => Err(error)
        .with_context(|| format!("failed to forward {signal:?} to OxiBelt child {}", self.pid)),
    }
  }
}

#[cfg(target_os = "linux")]
fn pidfd_open(pid: u32) -> std::io::Result<OwnedFd> {
  let pid = i32::try_from(pid)
    .ok()
    .and_then(rustix::process::Pid::from_raw)
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid child PID"))?;
  rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
    .map_err(std::io::Error::from)
}

#[cfg(target_os = "linux")]
fn pidfd_send_signal(pidfd: &OwnedFd, signal: Signal) -> std::io::Result<()> {
  let signal = match signal {
    Signal::SIGHUP => rustix::process::Signal::HUP,
    Signal::SIGINT => rustix::process::Signal::INT,
    Signal::SIGTERM => rustix::process::Signal::TERM,
    Signal::SIGUSR1 => rustix::process::Signal::USR1,
    _ => {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "pidfd forwarding does not support this signal",
      ));
    }
  };
  rustix::process::pidfd_send_signal(pidfd, signal).map_err(std::io::Error::from)
}

fn exit_code_for_status(status: ExitStatus) -> i32 {
  status.code().unwrap_or_else(|| {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map_or(1, |signal| 128 + signal)
  })
}

fn parse_hot_reload_mode(value: &str) -> Result<HotReloadMode, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}
