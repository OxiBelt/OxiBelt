use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use tracing::{info, warn};

use crate::config::{Config, HotReloadMode, RuntimeOverrides, TlsConfig};
use crate::routes::RouteTable;
use crate::server::ListenerSupervisor;
use crate::state::{AppHandle, AppSnapshot};
use crate::tls;
use crate::waf::WafEngine;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReloadTrigger {
  Poll,
  Signal,
}

pub(crate) struct ReloadManager {
  config_path: PathBuf,
  runtime_overrides: RuntimeOverrides,
  mode: HotReloadMode,
  poll_interval: Duration,
  last_fingerprints: Vec<FileFingerprint>,
}

impl ReloadManager {
  pub(crate) fn new(
    config_path: PathBuf,
    runtime_overrides: RuntimeOverrides,
    snapshot: &AppSnapshot,
  ) -> anyhow::Result<Self> {
    let mode = snapshot.config.runtime.hot_reload.mode;
    let poll_interval = Duration::from_millis(snapshot.config.runtime.hot_reload.poll_interval_ms);
    let last_fingerprints = fingerprint_files(relevant_files(mode, &snapshot.config));
    Ok(Self {
      config_path,
      runtime_overrides,
      mode,
      poll_interval,
      last_fingerprints,
    })
  }

  pub(crate) fn poll_interval(&self) -> Duration {
    self.poll_interval
  }

  pub(crate) async fn reload_if_changed(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
    listeners: &mut ListenerSupervisor,
  ) {
    let active = state.snapshot();
    self.mode = active.config.runtime.hot_reload.mode;
    self.poll_interval = Duration::from_millis(active.config.runtime.hot_reload.poll_interval_ms);
    if !self.mode.enabled() {
      return;
    }

    let result = match self.mode {
      HotReloadMode::Off => Ok(false),
      HotReloadMode::OxiRule => self.reload_oxirule(trigger, state).await,
      HotReloadMode::Full => self.reload_full(trigger, state, listeners).await,
      HotReloadMode::DownstreamTls => self.reload_downstream_tls(trigger, state, listeners).await,
    };

    match result {
      Ok(true) => info!(mode = %self.mode, "hot reload applied"),
      Ok(false) => {}
      Err(error) => {
        warn!(mode = %self.mode, error = %error, "hot reload failed; keeping previous active state");
      }
    }
  }

  async fn reload_oxirule(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
  ) -> anyhow::Result<bool> {
    let config = self.load_config()?;
    let fingerprints = fingerprint_files(config.source_paths.oxirule_reload_files());
    if matches!(trigger, ReloadTrigger::Poll) && fingerprints == self.last_fingerprints {
      return Ok(false);
    }

    let active = state.snapshot();
    if !active.config.non_waf_equivalent(&config) {
      bail!("OxiRule hot reload rejected because non-WAF OxiBelt configuration changed");
    }
    if active.config.waf_equivalent(&config) {
      self.last_fingerprints = fingerprints;
      return Ok(false);
    }

    let waf = WafEngine::new_with_previous_and_limits(
      &config,
      Some(&active.waf),
      active.shared_state.clone(),
      Some(active.limits.clone()),
    )
    .context("failed to rebuild WAF engine")?;
    let snapshot = AppSnapshot {
      route_table: RouteTable::new(config.routes.clone()),
      upstreams: active.upstreams.clone(),
      config,
      clients: active.clients.clone(),
      h3_clients: active.h3_clients.clone(),
      limits: active.limits.clone(),
      pools: active.pools.clone(),
      cache: active.cache.clone(),
      compression: active.compression.clone(),
      metrics: active.metrics.clone(),
      dynamic_policy: active.dynamic_policy.clone(),
      lifecycle: active.lifecycle.clone(),
      shared_state: active.shared_state.clone(),
      tls_server_config: active.tls_server_config.clone(),
      admin_tls_server_config: active.admin_tls_server_config.clone(),
      quic_server_config: active.quic_server_config.clone(),
      waf,
      access_logs: active.access_logs.clone(),
      system_access_log: active.system_access_log.clone(),
    };
    state.replace(snapshot);
    self.last_fingerprints = fingerprints;
    Ok(true)
  }

  async fn reload_full(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
    listeners: &mut ListenerSupervisor,
  ) -> anyhow::Result<bool> {
    let config = self.load_config()?;
    let fingerprints = fingerprint_files(config.source_paths.all_reload_files());
    let active = state.snapshot();
    if matches!(trigger, ReloadTrigger::Poll)
      && fingerprints == self.last_fingerprints
      && config == active.config
    {
      return Ok(false);
    }

    let snapshot = AppSnapshot::new_with_previous(config, Some(active.as_ref())).await?;
    let pending = listeners.prepare(&snapshot).await?;
    state.replace(snapshot);
    let active = state.snapshot();
    listeners.commit(pending, active.as_ref(), state.clone());
    self.mode = active.config.runtime.hot_reload.mode;
    self.poll_interval = Duration::from_millis(active.config.runtime.hot_reload.poll_interval_ms);
    self.last_fingerprints = fingerprints;
    Ok(true)
  }

  async fn reload_downstream_tls(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
    listeners: &mut ListenerSupervisor,
  ) -> anyhow::Result<bool> {
    let active = state.snapshot();
    let fingerprints = fingerprint_files(active.config.source_paths.downstream_tls_reload_files());
    if matches!(trigger, ReloadTrigger::Poll) && fingerprints == self.last_fingerprints {
      return Ok(false);
    }

    let mut config = active.config.clone();
    reload_downstream_tls_paths(&mut config)?;
    let tls_server_config = tls::build_server_config(&config.tls, &config.listeners)
      .context("failed to rebuild downstream TLS config")?;
    let quic_server_config = if config.listeners.http3 {
      Some(
        tls::build_quic_server_config(
          &config.tls,
          &config.quic,
          config.source_paths.cert_dir.as_deref(),
        )
        .context("failed to rebuild QUIC TLS config")?,
      )
    } else {
      None
    };
    let snapshot = AppSnapshot {
      route_table: active.route_table.clone(),
      upstreams: active.upstreams.clone(),
      config,
      clients: active.clients.clone(),
      h3_clients: active.h3_clients.clone(),
      limits: active.limits.clone(),
      pools: active.pools.clone(),
      cache: active.cache.clone(),
      compression: active.compression.clone(),
      metrics: active.metrics.clone(),
      dynamic_policy: active.dynamic_policy.clone(),
      lifecycle: active.lifecycle.clone(),
      shared_state: active.shared_state.clone(),
      tls_server_config,
      admin_tls_server_config: active.admin_tls_server_config.clone(),
      quic_server_config,
      waf: active.waf.clone(),
      access_logs: active.access_logs.clone(),
      system_access_log: active.system_access_log.clone(),
    };
    let pending = listeners.prepare(&snapshot).await?;
    state.replace(snapshot);
    let active = state.snapshot();
    listeners.commit(pending, active.as_ref(), state.clone());
    self.last_fingerprints = fingerprints;
    Ok(true)
  }

  fn load_config(&self) -> anyhow::Result<Config> {
    let mut config = Config::load(&self.config_path)
      .with_context(|| format!("failed to load {}", self.config_path.display()))?;
    for warning in config.apply_runtime_overrides(&self.runtime_overrides) {
      warn!("{warning}");
    }
    config.validate()?;
    Ok(config)
  }
}

fn reload_downstream_tls_paths(config: &mut Config) -> anyhow::Result<()> {
  let cert_dir = config
    .source_paths
    .cert_dir
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("missing TLS certificate directory for downstream reload"))?;
  let cert_chain = config
    .source_paths
    .downstream_tls_cert_chain
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("missing configured tls.cert_chain path"))?;
  let private_key = config
    .source_paths
    .downstream_tls_private_key
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("missing configured tls.private_key path"))?;

  let ocsp = config
    .source_paths
    .downstream_tls_ocsp_response_file
    .as_ref()
    .map(|path| canonicalize_under_base("tls.ocsp.response_file", cert_dir, path))
    .transpose()?;
  let quic_host_key_file = config
    .source_paths
    .quic_host_key_file
    .as_ref()
    .map(|path| canonicalize_under_base("quic.host_key_file", cert_dir, path))
    .transpose()?;

  let old_tls = config.tls.clone();
  let mut old_quic = config.quic.clone();
  old_quic.host_key_file = quic_host_key_file;
  config.tls = TlsConfig {
    cert_chain: canonicalize_under_base("tls.cert_chain", cert_dir, cert_chain)?,
    private_key: canonicalize_under_base("tls.private_key", cert_dir, private_key)?,
    min_version: old_tls.min_version,
    max_version: old_tls.max_version,
    session_tickets: old_tls.session_tickets,
    session_ticket_rotation_seconds: old_tls.session_ticket_rotation_seconds,
    client_auth: old_tls.client_auth,
    ocsp: crate::config::OcspConfig {
      mode: old_tls.ocsp.mode,
      response_file: ocsp,
    },
  };
  config.quic = old_quic;
  Ok(())
}

fn canonicalize_under_base(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  let canonical_base = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve configured directory {}",
      base_dir.display()
    )
  })?;
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
  if !canonical_path.starts_with(&canonical_base) {
    bail!("{field_name} must stay within the configured directory");
  }
  let metadata = canonical_path.metadata().with_context(|| {
    format!(
      "failed to inspect {field_name} {}",
      canonical_path.display()
    )
  })?;
  if !metadata.is_file() {
    bail!("{field_name} must point to a regular file");
  }
  Ok(canonical_path)
}

fn relevant_files(mode: HotReloadMode, config: &Config) -> Vec<PathBuf> {
  match mode {
    HotReloadMode::Off => Vec::new(),
    HotReloadMode::OxiRule => config.source_paths.oxirule_reload_files(),
    HotReloadMode::Full => config.source_paths.all_reload_files(),
    HotReloadMode::DownstreamTls => config.source_paths.downstream_tls_reload_files(),
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct FileFingerprint {
  path: PathBuf,
  exists: bool,
  len: u64,
  modified: Option<SystemTime>,
  canonical: Option<PathBuf>,
}

fn fingerprint_files(mut paths: Vec<PathBuf>) -> Vec<FileFingerprint> {
  paths.sort();
  paths.dedup();
  paths.into_iter().map(fingerprint_file).collect()
}

fn fingerprint_file(path: PathBuf) -> FileFingerprint {
  match fs::metadata(&path) {
    Ok(metadata) => FileFingerprint {
      canonical: path.canonicalize().ok(),
      path,
      exists: true,
      len: metadata.len(),
      modified: metadata.modified().ok(),
    },
    Err(_) => FileFingerprint {
      path,
      exists: false,
      len: 0,
      modified: None,
      canonical: None,
    },
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicU64, Ordering};

  use super::*;

  static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

  #[test]
  fn fingerprint_changes_when_symlink_target_changes() {
    let root = test_artifact_root().join(format!(
      "fingerprint-symlink-{}",
      NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("failed to create temp dir");
    let first = root.join("first.pem");
    let second = root.join("second.pem");
    let link = root.join("current.pem");
    fs::write(&first, b"first").expect("failed to write first target");
    fs::write(&second, b"second certificate body").expect("failed to write second target");

    std::os::unix::fs::symlink(&first, &link).expect("failed to create symlink");
    let first_fingerprint = fingerprint_files(vec![link.clone()]);
    fs::remove_file(&link).expect("failed to remove symlink");
    std::os::unix::fs::symlink(&second, &link).expect("failed to retarget symlink");
    let second_fingerprint = fingerprint_files(vec![link.clone()]);

    let _ = fs::remove_dir_all(&root);
    assert_ne!(first_fingerprint, second_fingerprint);
  }

  fn test_artifact_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/oxibelt-reload-test-fixtures");
    fs::create_dir_all(&root).expect("failed to create test artifact root");
    root
      .canonicalize()
      .expect("failed to resolve test artifact root")
  }
}
