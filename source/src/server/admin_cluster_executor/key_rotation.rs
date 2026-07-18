//! Validation and observation for pre-provisioned downstream key rotation.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::{Component, Path};

use anyhow::{Context, ensure};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::state::AppHandle;

use super::admin_control;

const KEY_BODY_LIMIT: usize = 16 * 1024;
const MAX_PINNED_KEY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum KeyTarget {
  DownstreamTlsDefault,
  DownstreamTlsSni,
}

impl KeyTarget {
  pub(super) const fn as_str(&self) -> &'static str {
    match self {
      Self::DownstreamTlsDefault => "downstream_tls_default",
      Self::DownstreamTlsSni => "downstream_tls_sni",
    }
  }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyRotation {
  pub(super) target: KeyTarget,
  #[serde(default)]
  pub(super) name: Option<String>,
  reference: String,
  sha256: String,
}

pub(super) fn decode_key_rotation(body: &[u8]) -> anyhow::Result<KeyRotation> {
  ensure!(
    body.len() <= KEY_BODY_LIMIT,
    "key rotation body is too large"
  );
  let request: KeyRotation = serde_json::from_slice(body).context("invalid key rotation body")?;
  request.validate_shape()?;
  Ok(request)
}

impl KeyRotation {
  fn validate_shape(&self) -> anyhow::Result<()> {
    ensure!(
      self.sha256.len() == 64
        && self
          .sha256
          .bytes()
          .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
      "sha256 must be lowercase hexadecimal"
    );
    ensure!(
      !self.reference.is_empty()
        && self.reference.len() <= 512
        && !self.reference.contains("://")
        && !self.reference.contains("-----BEGIN")
        && !self.reference.chars().any(char::is_control)
        && Path::new(&self.reference)
          .components()
          .all(|component| matches!(component, Component::Normal(_))),
      "key reference must identify bounded pre-provisioned material"
    );
    match self.target {
      KeyTarget::DownstreamTlsDefault => ensure!(
        self.name.is_none(),
        "name is not valid for the default key target"
      ),
      KeyTarget::DownstreamTlsSni => ensure!(
        self.name.as_deref().is_some_and(|name| !name.is_empty()
          && name.len() <= 256
          && !name.chars().any(char::is_control)),
        "SNI key rotation requires a valid name"
      ),
    };
    Ok(())
  }
}

pub(super) fn validate_key_rotation_state(state: &AppHandle, body: &[u8]) -> anyhow::Result<()> {
  let request = decode_key_rotation(body)?;
  let snapshot = state.snapshot();
  let configured = match request.target {
    KeyTarget::DownstreamTlsDefault => snapshot.config.tls.private_key.as_ref(),
    KeyTarget::DownstreamTlsSni => snapshot
      .config
      .tls
      .certificates
      .iter()
      .find(|certificate| {
        certificate.server_names.iter().any(|name| {
          request
            .name
            .as_ref()
            .is_some_and(|requested| name.eq_ignore_ascii_case(requested))
        })
      })
      .and_then(|certificate| certificate.private_key.as_ref()),
  }
  .context("configured key target was not found")?;
  let base = snapshot
    .config
    .source_paths
    .cert_dir
    .as_ref()
    .context("certificate root is unavailable")?;
  let path = base
    .join(&request.reference)
    .canonicalize()
    .context("pre-provisioned key reference is unavailable")?;
  ensure!(
    path == configured.canonicalize()?,
    "key reference is not the active pre-provisioned target"
  );
  let mut options = OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  let file = options
    .open(&path)
    .context("pre-provisioned key reference is unavailable")?;
  let metadata = file.metadata()?;
  ensure!(
    metadata.is_file() && metadata.len() <= MAX_PINNED_KEY_BYTES,
    "pre-provisioned key reference is not a bounded regular file"
  );
  let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len().try_into().unwrap_or(0)));
  file
    .take(MAX_PINNED_KEY_BYTES + 1)
    .read_to_end(&mut bytes)?;
  ensure!(
    bytes.len() as u64 <= MAX_PINNED_KEY_BYTES
      && admin_control::checkpoint::sha256_hex(&bytes) == request.sha256,
    "pre-provisioned key reference digest mismatch"
  );
  Ok(())
}
