//! TURN long-term credential configuration and validation.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use precis_profiles::OpaqueString;
use precis_profiles::precis_core::profile::PrecisFastInvocation;
use serde::Deserialize;

use crate::config::validate_base64_32_byte_env;

use super::resolve_existing_local_config_file_path_with_logical;

const MAX_TURN_SECRET_FILE_BYTES: usize = 4_096;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnAuthConfig {
  #[serde(default)]
  pub mode: TurnAuthMode,
  #[serde(default)]
  pub static_credentials: Vec<TurnStaticCredentialConfig>,
  #[serde(default)]
  pub rest_shared_secret: Option<String>,
  #[serde(default)]
  pub rest_shared_secret_env: Option<String>,
  #[serde(default)]
  pub rest_shared_secret_file: Option<PathBuf>,
  #[serde(default = "default_turn_password_algorithms")]
  pub password_algorithms: Vec<TurnPasswordAlgorithm>,
  #[serde(default)]
  pub nonce_secret_env: Option<String>,
  #[serde(default)]
  pub nonce_secret_file: Option<PathBuf>,
  #[serde(default)]
  pub previous_nonce_secret_env: Option<String>,
  #[serde(default)]
  pub previous_nonce_secret_file: Option<PathBuf>,
  #[serde(default = "default_turn_nonce_ttl_seconds")]
  pub nonce_ttl_seconds: u64,
}

impl Default for TurnAuthConfig {
  fn default() -> Self {
    Self {
      mode: TurnAuthMode::PassThrough,
      static_credentials: Vec::new(),
      rest_shared_secret: None,
      rest_shared_secret_env: None,
      rest_shared_secret_file: None,
      password_algorithms: default_turn_password_algorithms(),
      nonce_secret_env: None,
      nonce_secret_file: None,
      previous_nonce_secret_env: None,
      previous_nonce_secret_file: None,
      nonce_ttl_seconds: default_turn_nonce_ttl_seconds(),
    }
  }
}

impl TurnAuthConfig {
  pub(in crate::config) fn resolve_relative_paths(
    &mut self,
    cert_dir: &Path,
  ) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    for (field, path) in [
      (
        "webrtc_turn_listeners.auth.rest_shared_secret_file",
        &mut self.rest_shared_secret_file,
      ),
      (
        "webrtc_turn_listeners.auth.nonce_secret_file",
        &mut self.nonce_secret_file,
      ),
      (
        "webrtc_turn_listeners.auth.previous_nonce_secret_file",
        &mut self.previous_nonce_secret_file,
      ),
    ] {
      *path = path
        .take()
        .map(|path| {
          let (resolved, logical) =
            resolve_existing_local_config_file_path_with_logical(field, cert_dir, &path)?;
          source_paths.push(logical);
          Ok::<PathBuf, anyhow::Error>(resolved)
        })
        .transpose()?;
    }
    for credential in &mut self.static_credentials {
      credential.password_file = credential
        .password_file
        .take()
        .map(|path| {
          let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
            "webrtc_turn_listeners.auth.static_credentials.password_file",
            cert_dir,
            &path,
          )?;
          source_paths.push(logical);
          Ok::<PathBuf, anyhow::Error>(resolved)
        })
        .transpose()?;
    }
    Ok(source_paths)
  }

  pub(super) fn validate(&self, listener_name: &str) -> anyhow::Result<()> {
    if self.nonce_ttl_seconds == 0 || self.nonce_ttl_seconds > 3_600 {
      bail!(
        "WebRTC TURN listener {} auth.nonce_ttl_seconds must be between 1 and 3600",
        listener_name
      );
    }
    let rest_secret_sources = usize::from(self.rest_shared_secret.is_some())
      + usize::from(self.rest_shared_secret_env.is_some())
      + usize::from(self.rest_shared_secret_file.is_some());
    if rest_secret_sources > 1 {
      bail!(
        "WebRTC TURN listener {} auth must set at most one REST secret source",
        listener_name
      );
    }
    let has_static = !self.static_credentials.is_empty();
    let has_rest = rest_secret_sources == 1;
    if matches!(self.mode, TurnAuthMode::Validate | TurnAuthMode::Enforce)
      && !has_static
      && !has_rest
    {
      bail!(
        "WebRTC TURN listener {} auth.mode requires static_credentials or rest_shared_secret",
        listener_name
      );
    }
    if let Some(secret) = &self.rest_shared_secret {
      validate_turn_secret_text(listener_name, "rest_shared_secret", secret)?;
    }
    if let Some(path) = self.rest_shared_secret_file.as_deref() {
      validate_turn_secret_file(listener_name, "rest_shared_secret_file", path)?;
    }
    if self.password_algorithms.is_empty() || self.password_algorithms.len() > 2 {
      bail!(
        "WebRTC TURN listener {} auth.password_algorithms must contain one or two algorithms",
        listener_name
      );
    }
    let mut algorithms = HashSet::new();
    for algorithm in &self.password_algorithms {
      if !algorithms.insert(*algorithm) {
        bail!(
          "WebRTC TURN listener {} auth.password_algorithms must not contain duplicates",
          listener_name
        );
      }
    }
    validate_turn_secret_source(
      listener_name,
      "nonce_secret",
      self.nonce_secret_file.as_deref(),
      self.nonce_secret_env.as_deref(),
    )?;
    validate_turn_secret_source(
      listener_name,
      "previous_nonce_secret",
      self.previous_nonce_secret_file.as_deref(),
      self.previous_nonce_secret_env.as_deref(),
    )?;
    if (self.previous_nonce_secret_file.is_some() || self.previous_nonce_secret_env.is_some())
      && self.nonce_secret_file.is_none()
      && self.nonce_secret_env.is_none()
    {
      bail!(
        "WebRTC TURN listener {} auth.previous_nonce_secret requires nonce_secret",
        listener_name
      );
    }
    let mut usernames = HashSet::new();
    for credential in &self.static_credentials {
      if credential.username.trim().is_empty() {
        bail!(
          "WebRTC TURN listener {} static credential username must not be empty",
          listener_name
        );
      }
      let canonical_username = validate_turn_opaque_string(
        listener_name,
        "static_credentials.username",
        &credential.username,
        512,
      )?;
      if !usernames.insert(canonical_username) {
        bail!(
          "WebRTC TURN listener {} has duplicate static credential username {}",
          listener_name,
          credential.username
        );
      }
      let password_sources = usize::from(credential.password.is_some())
        + usize::from(credential.password_env.is_some())
        + usize::from(credential.password_file.is_some());
      if password_sources > 1 {
        bail!(
          "WebRTC TURN listener {} static credential {} must set exactly one password source",
          listener_name,
          credential.username
        );
      }
      if password_sources == 0 {
        bail!(
          "WebRTC TURN listener {} static credential {} requires a password source",
          listener_name,
          credential.username
        );
      }
      if let Some(password) = &credential.password {
        validate_turn_secret_text(listener_name, "static_credentials.password", password)?;
        validate_turn_opaque_string(
          listener_name,
          "static_credentials.password",
          password.trim_end_matches('\0'),
          MAX_TURN_SECRET_FILE_BYTES,
        )?;
      }
      if let Some(path) = credential.password_file.as_deref() {
        validate_turn_static_password_file(listener_name, path)?;
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TurnAuthMode {
  #[default]
  PassThrough,
  Validate,
  Enforce,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TurnPasswordAlgorithm {
  Md5,
  Sha256,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnStaticCredentialConfig {
  pub username: String,
  #[serde(default)]
  pub password: Option<String>,
  #[serde(default)]
  pub password_env: Option<String>,
  #[serde(default)]
  pub password_file: Option<PathBuf>,
}

fn default_turn_nonce_ttl_seconds() -> u64 {
  600
}

fn default_turn_password_algorithms() -> Vec<TurnPasswordAlgorithm> {
  vec![TurnPasswordAlgorithm::Sha256, TurnPasswordAlgorithm::Md5]
}

fn validate_turn_secret_source(
  listener_name: &str,
  field: &str,
  file: Option<&Path>,
  env: Option<&str>,
) -> anyhow::Result<()> {
  if file.is_some() && env.is_some() {
    bail!(
      "WebRTC TURN listener {listener_name} auth.{field} must set one of {field}_file or {field}_env"
    );
  }
  if let Some(env) = env {
    validate_base64_32_byte_env(&format!("webrtc_turn_listeners.auth.{field}_env"), env)?;
  }
  if let Some(file) = file {
    let value = read_bounded_turn_secret_file(file, listener_name, &format!("{field}_file"), 256)?;
    if value.len() > 256 {
      bail!("WebRTC TURN listener {listener_name} auth.{field}_file exceeds 256 bytes");
    }
    let decoded = base64::engine::general_purpose::STANDARD
      .decode(value.trim())
      .with_context(|| {
        format!("WebRTC TURN listener {listener_name} auth.{field}_file must be standard-base64")
      })?;
    if decoded.len() != 32 {
      bail!(
        "WebRTC TURN listener {listener_name} auth.{field}_file must decode to exactly 32 bytes"
      );
    }
  }
  Ok(())
}

fn validate_turn_secret_file(listener_name: &str, field: &str, path: &Path) -> anyhow::Result<()> {
  let value =
    read_bounded_turn_secret_file(path, listener_name, field, MAX_TURN_SECRET_FILE_BYTES)?;
  validate_turn_secret_text(listener_name, field, value.trim_end_matches(['\r', '\n']))
}

fn validate_turn_static_password_file(listener_name: &str, path: &Path) -> anyhow::Result<()> {
  let value = read_bounded_turn_secret_file(
    path,
    listener_name,
    "static_credentials.password_file",
    MAX_TURN_SECRET_FILE_BYTES,
  )?;
  let value = value.trim_end_matches(['\r', '\n']);
  validate_turn_secret_text(listener_name, "static_credentials.password_file", value)?;
  validate_turn_opaque_string(
    listener_name,
    "static_credentials.password_file",
    value.trim_end_matches('\0'),
    MAX_TURN_SECRET_FILE_BYTES,
  )
  .map(|_| ())
}

fn read_bounded_turn_secret_file(
  path: &Path,
  listener_name: &str,
  field: &str,
  maximum_bytes: usize,
) -> anyhow::Result<String> {
  let mut file = std::fs::File::open(path)
    .with_context(|| format!("WebRTC TURN listener {listener_name} auth.{field}"))?;
  let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(maximum_bytes.saturating_add(1)));
  file
    .by_ref()
    .take((maximum_bytes.saturating_add(1)) as u64)
    .read_to_end(&mut bytes)
    .with_context(|| format!("WebRTC TURN listener {listener_name} auth.{field}"))?;
  if bytes.len() > maximum_bytes {
    bail!("WebRTC TURN listener {listener_name} auth.{field} exceeds {maximum_bytes} bytes");
  }
  String::from_utf8(std::mem::take(&mut *bytes)).with_context(|| {
    format!("WebRTC TURN listener {listener_name} auth.{field} must be valid UTF-8")
  })
}

fn validate_turn_secret_text(listener_name: &str, field: &str, value: &str) -> anyhow::Result<()> {
  if value.is_empty() || value.len() > MAX_TURN_SECRET_FILE_BYTES {
    bail!(
      "WebRTC TURN listener {listener_name} auth.{field} must contain 1..={MAX_TURN_SECRET_FILE_BYTES} bytes"
    );
  }
  Ok(())
}

pub(super) fn validate_turn_opaque_string(
  listener_name: &str,
  field: &str,
  value: &str,
  maximum_bytes: usize,
) -> anyhow::Result<String> {
  if value.is_empty() || value.len() > maximum_bytes {
    bail!("WebRTC TURN listener {listener_name} {field} must contain 1..={maximum_bytes} bytes");
  }
  OpaqueString::enforce(value)
    .map(|value| value.into_owned())
    .map_err(|_| anyhow!("WebRTC TURN listener {listener_name} {field} violates RFC 8265"))
}
