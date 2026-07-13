//! Root wrapper that brokers privileged data-plane binds for an unprivileged OxiBelt child.

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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
        Ok(()) | Err(nix::errno::Errno::ESRCH) => return Ok(()),
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
#[allow(unsafe_code)]
fn pidfd_open(pid: u32) -> std::io::Result<OwnedFd> {
  let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
  if fd < 0 {
    Err(std::io::Error::last_os_error())
  } else {
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
  }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn pidfd_send_signal(pidfd: &OwnedFd, signal: Signal) -> Result<(), nix::errno::Errno> {
  let result = unsafe {
    libc::syscall(
      libc::SYS_pidfd_send_signal,
      pidfd.as_raw_fd(),
      signal as libc::c_int,
      std::ptr::null::<libc::siginfo_t>(),
      0_u32,
    )
  };
  if result == 0 {
    Ok(())
  } else {
    Err(nix::errno::Errno::last())
  }
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
