//! Token loading and rotation for the remote signer IPC protocol.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use subtle::ConstantTimeEq;
use tracing::warn;

#[derive(Clone, Debug)]
pub(super) struct RemoteSignerTokenProvider {
  inner: Arc<Mutex<RemoteSignerTokenState>>,
}

#[derive(Debug)]
struct RemoteSignerTokenState {
  source: RemoteSignerTokenSource,
  token: [u8; 32],
  reload_interval: Duration,
  next_reload: Option<Instant>,
}

#[derive(Debug)]
enum RemoteSignerTokenSource {
  Env {
    name: String,
  },
  File {
    path: PathBuf,
    reload_base_dir: Option<PathBuf>,
  },
}

impl RemoteSignerTokenProvider {
  #[cfg(test)]
  pub(super) fn from_static_token(token: [u8; 32]) -> Self {
    Self {
      inner: Arc::new(Mutex::new(RemoteSignerTokenState {
        source: RemoteSignerTokenSource::Env {
          name: "test-static-token".to_string(),
        },
        token,
        reload_interval: Duration::from_secs(1),
        next_reload: None,
      })),
    }
  }

  pub(super) fn from_sources(
    token_file: Option<PathBuf>,
    token_file_reload_base_dir: Option<PathBuf>,
    token_env: &str,
    reload_interval: Duration,
  ) -> anyhow::Result<Self> {
    if reload_interval.is_zero() {
      bail!("remote signer token reload interval must be greater than 0");
    }

    let now = Instant::now();
    let (source, token, next_reload) = match token_file {
      Some(path) => {
        let token = load_token_from_file(&path, token_file_reload_base_dir.as_deref())?;
        (
          RemoteSignerTokenSource::File {
            path,
            reload_base_dir: token_file_reload_base_dir,
          },
          token,
          Some(next_reload_after(now, reload_interval)),
        )
      }
      None => (
        RemoteSignerTokenSource::Env {
          name: token_env.to_string(),
        },
        load_token_from_env(token_env)?,
        None,
      ),
    };

    Ok(Self {
      inner: Arc::new(Mutex::new(RemoteSignerTokenState {
        source,
        token,
        reload_interval,
        next_reload,
      })),
    })
  }

  pub(super) fn current_token(&self) -> [u8; 32] {
    let mut state = self.lock_state();
    state.refresh_if_due();
    state.token
  }

  pub(super) fn force_refresh(&self) {
    let mut state = self.lock_state();
    state.refresh_file_token(true);
  }

  pub(super) fn reloadable(&self) -> bool {
    matches!(
      &self.lock_state().source,
      RemoteSignerTokenSource::File { .. }
    )
  }

  pub(super) fn source_label(&self) -> String {
    match &self.lock_state().source {
      RemoteSignerTokenSource::Env { name } => format!("env:{name}"),
      RemoteSignerTokenSource::File { path, .. } => format!("file:{}", path.display()),
    }
  }

  fn lock_state(&self) -> std::sync::MutexGuard<'_, RemoteSignerTokenState> {
    self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
  }
}

impl RemoteSignerTokenState {
  fn refresh_if_due(&mut self) {
    if self
      .next_reload
      .is_some_and(|next_reload| Instant::now() >= next_reload)
    {
      self.refresh_file_token(false);
    }
  }

  fn refresh_file_token(&mut self, forced: bool) {
    let RemoteSignerTokenSource::File {
      path,
      reload_base_dir,
    } = &self.source
    else {
      return;
    };
    let now = Instant::now();
    match load_token_from_file(path, reload_base_dir.as_deref()) {
      Ok(token) => {
        self.token = token;
        self.next_reload = Some(next_reload_after(now, self.reload_interval));
      }
      Err(error) => {
        self.next_reload = Some(next_reload_after(now, self.reload_interval));
        if forced {
          warn!(
            path = %path.display(),
            error = %error,
            "remote signer token file force-refresh failed; preserving last good token"
          );
        } else {
          warn!(
            path = %path.display(),
            error = %error,
            "remote signer token file reload failed; preserving last good token"
          );
        }
      }
    }
  }
}

fn next_reload_after(now: Instant, interval: Duration) -> Instant {
  now.checked_add(interval).unwrap_or(now)
}

fn load_token_from_env(env_name: &str) -> anyhow::Result<[u8; 32]> {
  let raw = std::env::var(env_name).with_context(|| format!("failed to read {env_name}"))?;
  parse_token_value(env_name, raw.trim())
}

fn load_token_from_file(path: &Path, reload_base_dir: Option<&Path>) -> anyhow::Result<[u8; 32]> {
  let read_path = resolve_token_file_read_path(path, reload_base_dir)?;
  let raw = std::fs::read_to_string(&read_path)
    .with_context(|| format!("failed to read {}", path.display()))?;
  parse_token_value(&path.display().to_string(), raw.trim())
}

fn resolve_token_file_read_path(
  path: &Path,
  reload_base_dir: Option<&Path>,
) -> anyhow::Result<PathBuf> {
  let Some(base_dir) = reload_base_dir else {
    return Ok(path.to_path_buf());
  };
  let canonical_base_dir = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve remote signer token base directory {}",
      base_dir.display()
    )
  })?;
  let canonical_path = path.canonicalize().with_context(|| {
    format!(
      "failed to resolve remote signer token file {}",
      path.display()
    )
  })?;
  if !canonical_path.starts_with(&canonical_base_dir) {
    bail!("remote signer token file must stay within the configured directory");
  }
  let metadata = canonical_path.metadata().with_context(|| {
    format!(
      "failed to inspect remote signer token file {}",
      path.display()
    )
  })?;
  if !metadata.is_file() {
    bail!("remote signer token file must point to a regular file");
  }
  Ok(canonical_path)
}

fn parse_token_value(field: &str, raw: &str) -> anyhow::Result<[u8; 32]> {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(raw)
    .with_context(|| format!("{field} must contain base64"))?;
  decoded
    .try_into()
    .map_err(|_| anyhow!("{field} must contain exactly 32 bytes"))
}

pub(super) fn token_to_wire(token: &[u8; 32]) -> String {
  base64::engine::general_purpose::STANDARD.encode(token)
}

pub(super) fn request_token_is_valid(raw_token: &str, expected: &[u8; 32]) -> bool {
  let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw_token.trim()) else {
    return false;
  };
  let Ok(decoded) = <[u8; 32]>::try_from(decoded.as_slice()) else {
    return false;
  };
  expected.ct_eq(&decoded).into()
}
