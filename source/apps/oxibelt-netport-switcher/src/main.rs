//! Root wrapper that brokers privileged data-plane binds for an unprivileged OxiBelt child.

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{
  Arc,
  atomic::{AtomicBool, Ordering},
};

use anyhow::Context;
use clap::Parser;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use oxibelt::config::{Config, HotReloadMode, RuntimeArtifact, RuntimeOverrides};
use oxibelt::netport_switcher::{NetportBroker, SOCKET_ENV};
use tokio::signal::unix::{SignalKind, signal};

#[derive(Debug, Parser)]
#[command(name = "oxibelt-netport-switcher")]
#[command(about = "OxiBelt privileged port socket broker")]
#[command(
  version = oxibelt_build_identity::SHORT_VERSION,
  long_version = oxibelt_build_identity::LONG_VERSION
)]
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
  let config = load_and_validate_config(&cli.config, &overrides)?;

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

fn load_and_validate_config(
  config_path: &Path,
  overrides: &RuntimeOverrides,
) -> anyhow::Result<Config> {
  let mut config = Config::load(config_path)
    .with_context(|| format!("failed to load {}", config_path.display()))?;
  for warning in config.apply_runtime_overrides(overrides) {
    eprintln!("{warning}");
  }
  // This wrapper validates the standalone child it will spawn. The broker still
  // independently constrains the privileged listener inventory.
  config.validate_for_artifact(RuntimeArtifact::Standalone)?;
  Ok(config)
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

#[cfg(test)]
mod tests {
  use std::fs;
  use std::path::{Path, PathBuf};
  use std::time::{SystemTime, UNIX_EPOCH};

  use super::{Cli, load_and_validate_config};
  use clap::Parser;
  use oxibelt::config::{RuntimeOverrides, RuntimeSeccompExpectation};

  struct TestDir(PathBuf);

  impl TestDir {
    fn new(label: &str) -> Self {
      let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock should follow the Unix epoch")
        .as_nanos();
      let path = std::env::temp_dir().join(format!(
        "oxibelt-netport-switcher-{label}-{}-{nonce}",
        std::process::id()
      ));
      fs::create_dir_all(&path).expect("test directory should be created");
      Self(path)
    }

    fn path(&self) -> &Path {
      &self.0
    }
  }

  impl Drop for TestDir {
    fn drop(&mut self) {
      let _ = fs::remove_dir_all(&self.0);
    }
  }

  #[test]
  fn version_flag_reports_canonical_build_identity() {
    let error = Cli::try_parse_from(["oxibelt-netport-switcher", "--version"])
      .expect_err("--version should exit through Clap");
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
    assert!(
      error
        .to_string()
        .contains(oxibelt_build_identity::MACHINE_IDENTITY_MARKER)
    );
  }

  #[test]
  fn standalone_child_validation_accepts_default_seccomp_without_binding() {
    let test_dir = TestDir::new("standalone-validation");
    let config_dir = test_dir.path().join("config");
    let cert_dir = test_dir.path().join("cert");
    fs::create_dir_all(&config_dir).expect("test config directory should be created");
    fs::create_dir_all(&cert_dir).expect("test certificate directory should be created");
    fs::write(cert_dir.join("fullchain.pem"), b"unused test certificate")
      .expect("test certificate should be written");
    fs::write(cert_dir.join("privkey.pem"), b"unused test key")
      .expect("test private key should be written");
    let config_path = config_dir.join("oxibelt.toml");
    fs::write(
      &config_path,
      r#"
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

[runtime.netport_switcher]
enabled = true
socket_dir = "/run/oxibelt-netport-switcher"
main_uid = 10001
main_gid = 10001

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[compression]
enabled = true
gzip = true
deflate = true
zstd = true

[[upstreams]]
name = "app"
origin = "http://app.internal.example"
max_http_version = "h1"

[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#,
    )
    .expect("test configuration should be written");

    let config = load_and_validate_config(&config_path, &RuntimeOverrides::default())
      .expect("standalone child configuration should validate");
    assert!(config.runtime.netport_switcher.enabled);
    assert_eq!(
      config.runtime.hardening.seccomp.expectation,
      RuntimeSeccompExpectation::Off
    );
  }
}
