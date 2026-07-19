use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use crate::config::Config;

use super::resolver::resolve_contained_file_path;
use super::{
  SecretActivationError, SecretMaterialType, SecretProviderIdentity, SecretReferenceUpdateRequest,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SecretReferenceField {
  TlsRemoteSignerTokenEnv,
  TlsRemoteSignerTokenFile,
  IpmCredentialBearerTokenEnv(String),
  ExternalAuthClientIdEnv(String),
  ExternalAuthClientSecretEnv(String),
  UpstreamDiscoveryTokenEnv(String),
  CacheExternalTokenEnv(String),
  TurnRestSharedSecretEnv(String),
  TurnStaticPasswordEnv { listener: String, username: String },
}

#[derive(Debug)]
pub(super) struct SecretReferenceSpec {
  pub(super) field: SecretReferenceField,
  pub(super) reference: String,
  pub(super) provider: SecretProviderIdentity,
  pub(super) material_type: SecretMaterialType,
  pub(super) file_path: Option<PathBuf>,
}

impl SecretReferenceField {
  pub(crate) fn parse(raw: &str) -> Result<Self, SecretActivationError> {
    match raw {
      "tls.remote_signer.token_env" => return Ok(Self::TlsRemoteSignerTokenEnv),
      "tls.remote_signer.token_file" => return Ok(Self::TlsRemoteSignerTokenFile),
      _ => {}
    }
    let parts = raw.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
      ["ipm.credentials", name, "bearer_token_env"] => {
        checked_component(name).map(Self::IpmCredentialBearerTokenEnv)
      }
      ["external_auth", name, "client_id_env"] => {
        checked_component(name).map(Self::ExternalAuthClientIdEnv)
      }
      ["external_auth", name, "client_secret_env"] => {
        checked_component(name).map(Self::ExternalAuthClientSecretEnv)
      }
      ["upstream_pools", name, "discovery", "token_env"] => {
        checked_component(name).map(Self::UpstreamDiscoveryTokenEnv)
      }
      ["cache.external.handlers", name, "token_env"] => {
        checked_component(name).map(Self::CacheExternalTokenEnv)
      }
      [
        "webrtc_turn_listeners",
        name,
        "auth",
        "rest_shared_secret_env",
      ] => checked_component(name).map(Self::TurnRestSharedSecretEnv),
      [
        "webrtc_turn_listeners",
        listener,
        "auth",
        "static_credentials",
        username,
        "password_env",
      ] => Ok(Self::TurnStaticPasswordEnv {
        listener: checked_component(listener)?,
        username: checked_component(username)?,
      }),
      _ => Err(SecretActivationError::FieldNotAllowlisted),
    }
  }

  pub(crate) const fn is_file(&self) -> bool {
    matches!(self, Self::TlsRemoteSignerTokenFile)
  }

  pub(crate) fn canonical(&self) -> String {
    match self {
      Self::TlsRemoteSignerTokenEnv => "tls.remote_signer.token_env".to_string(),
      Self::TlsRemoteSignerTokenFile => "tls.remote_signer.token_file".to_string(),
      Self::IpmCredentialBearerTokenEnv(name) => {
        format!("ipm.credentials/{name}/bearer_token_env")
      }
      Self::ExternalAuthClientIdEnv(name) => format!("external_auth/{name}/client_id_env"),
      Self::ExternalAuthClientSecretEnv(name) => {
        format!("external_auth/{name}/client_secret_env")
      }
      Self::UpstreamDiscoveryTokenEnv(name) => {
        format!("upstream_pools/{name}/discovery/token_env")
      }
      Self::CacheExternalTokenEnv(name) => {
        format!("cache.external.handlers/{name}/token_env")
      }
      Self::TurnRestSharedSecretEnv(name) => {
        format!("webrtc_turn_listeners/{name}/auth/rest_shared_secret_env")
      }
      Self::TurnStaticPasswordEnv { listener, username } => {
        format!("webrtc_turn_listeners/{listener}/auth/static_credentials/{username}/password_env")
      }
    }
  }

  pub(crate) fn apply(
    &self,
    config: &mut Config,
    update: &SecretReferenceUpdateRequest,
  ) -> Result<(), SecretActivationError> {
    match self {
      Self::TlsRemoteSignerTokenEnv => {
        if !config.tls.remote_signer.enabled {
          return Err(SecretActivationError::TargetNotFound);
        }
        remove_remote_signer_file_tracking(config);
        config.tls.remote_signer.token_material_pinned = true;
        config
          .tls
          .remote_signer
          .token_env
          .clone_from(&update.reference);
        config.tls.remote_signer.token_file = None;
        config.tls.remote_signer.token_file_reload_path = None;
        config.tls.remote_signer.token_file_reload_base_dir = None;
        config.tls.remote_signer.token_file_sha256 = None;
        Ok(())
      }
      Self::TlsRemoteSignerTokenFile => {
        if !config.tls.remote_signer.enabled {
          return Err(SecretActivationError::TargetNotFound);
        }
        let base = config
          .source_paths
          .cert_dir
          .as_ref()
          .ok_or(SecretActivationError::ProviderUnavailable)?
          .clone();
        let logical = PathBuf::from(&update.reference);
        let resolved = resolve_contained_file_path(&base, &logical)?;
        remove_remote_signer_file_tracking(config);
        config.tls.remote_signer.token_material_pinned = true;
        config.tls.remote_signer.token_file = Some(resolved);
        config.tls.remote_signer.token_file_reload_path = Some(logical.clone());
        config.tls.remote_signer.token_file_reload_base_dir = Some(base);
        config
          .tls
          .remote_signer
          .token_file_sha256
          .clone_from(&update.sha256);
        config.source_paths.downstream_tls_remote_signer_token_file = Some(logical.clone());
        config.source_paths.remember_runtime_file(logical.clone());
        config.source_paths.remember_downstream_tls_file(logical);
        Ok(())
      }
      Self::IpmCredentialBearerTokenEnv(name) => {
        if !config.ipm.enabled {
          return Err(SecretActivationError::TargetNotFound);
        }
        config
          .ipm
          .credentials
          .iter_mut()
          .find(|credential| credential.name == *name)
          .map(|credential| credential.bearer_token_env.clone_from(&update.reference))
          .ok_or(SecretActivationError::TargetNotFound)
      }
      Self::ExternalAuthClientIdEnv(name) => config
        .external_auth
        .iter_mut()
        .find(|entry| entry.name == *name)
        .map(|entry| entry.client_id_env = Some(update.reference.clone()))
        .ok_or(SecretActivationError::TargetNotFound),
      Self::ExternalAuthClientSecretEnv(name) => config
        .external_auth
        .iter_mut()
        .find(|entry| entry.name == *name)
        .map(|entry| entry.client_secret_env = Some(update.reference.clone()))
        .ok_or(SecretActivationError::TargetNotFound),
      Self::UpstreamDiscoveryTokenEnv(name) => {
        let pool = config
          .upstream_pools
          .iter_mut()
          .find(|pool| pool.name == *name)
          .ok_or(SecretActivationError::TargetNotFound)?;
        if pool.discovery.len() != 1 {
          return Err(SecretActivationError::TargetAmbiguous);
        }
        pool.discovery[0].token_env = Some(update.reference.clone());
        pool.discovery[0].token_file = None;
        Ok(())
      }
      Self::CacheExternalTokenEnv(name) => config
        .cache
        .external_handlers
        .iter_mut()
        .find(|entry| entry.name == *name)
        .map(|entry| entry.token_env = Some(update.reference.clone()))
        .ok_or(SecretActivationError::TargetNotFound),
      Self::TurnRestSharedSecretEnv(name) => config
        .webrtc_turn_listeners
        .iter_mut()
        .find(|entry| entry.name == *name)
        .map(|entry| {
          entry.auth.rest_shared_secret = None;
          entry.auth.rest_shared_secret_env = Some(update.reference.clone());
        })
        .ok_or(SecretActivationError::TargetNotFound),
      Self::TurnStaticPasswordEnv { listener, username } => {
        let listener = config
          .webrtc_turn_listeners
          .iter_mut()
          .find(|entry| entry.name == *listener)
          .ok_or(SecretActivationError::TargetNotFound)?;
        listener
          .auth
          .static_credentials
          .iter_mut()
          .find(|entry| entry.username == *username)
          .map(|entry| {
            entry.password = None;
            entry.password_env = Some(update.reference.clone());
          })
          .ok_or(SecretActivationError::TargetNotFound)
      }
    }
  }

  pub(super) fn upstream_tls_preflight(&self, config: &Config) -> Option<(Url, Duration)> {
    let (url, timeout_ms) = match self {
      Self::ExternalAuthClientIdEnv(name) | Self::ExternalAuthClientSecretEnv(name) => {
        let entry = config
          .external_auth
          .iter()
          .find(|entry| entry.name == *name)?;
        (entry.endpoint.clone(), entry.timeout_ms)
      }
      Self::UpstreamDiscoveryTokenEnv(name) => {
        let pool = config
          .upstream_pools
          .iter()
          .find(|pool| pool.name == *name)?;
        let entry = pool.discovery.first()?;
        (entry.endpoint.clone()?, 5_000)
      }
      Self::CacheExternalTokenEnv(name) => {
        let entry = config
          .cache
          .external_handlers
          .iter()
          .find(|entry| entry.name == *name)?;
        (entry.endpoint.clone(), entry.connect_timeout_ms)
      }
      _ => return None,
    };
    (url.scheme() == "https").then(|| (url, Duration::from_millis(timeout_ms.clamp(1, 5_000))))
  }
}

pub(super) fn collect_reference_specs(
  config: &Config,
) -> Result<Vec<SecretReferenceSpec>, SecretActivationError> {
  let mut specs = Vec::new();
  if config.tls.remote_signer.enabled {
    if let Some(path) = config.tls.remote_signer.token_file.as_ref() {
      specs.push(SecretReferenceSpec {
        field: SecretReferenceField::TlsRemoteSignerTokenFile,
        reference: config
          .tls
          .remote_signer
          .token_file_reload_path
          .as_ref()
          .unwrap_or(path)
          .to_string_lossy()
          .into_owned(),
        provider: SecretProviderIdentity::ContainedFile,
        material_type: SecretMaterialType::RemoteSignerToken32,
        file_path: Some(path.clone()),
      });
    } else {
      push_env(
        &mut specs,
        SecretReferenceField::TlsRemoteSignerTokenEnv,
        &config.tls.remote_signer.token_env,
        SecretMaterialType::RemoteSignerToken32,
      );
    }
  }
  if config.ipm.enabled {
    for credential in &config.ipm.credentials {
      if !credential.bearer_token_env.is_empty() {
        push_env(
          &mut specs,
          SecretReferenceField::IpmCredentialBearerTokenEnv(credential.name.clone()),
          &credential.bearer_token_env,
          SecretMaterialType::BearerToken,
        );
      }
    }
  }
  for entry in &config.external_auth {
    if let Some(reference) = entry.client_id_env.as_deref() {
      push_env(
        &mut specs,
        SecretReferenceField::ExternalAuthClientIdEnv(entry.name.clone()),
        reference,
        SecretMaterialType::OAuthClientId,
      );
    }
    if let Some(reference) = entry.client_secret_env.as_deref() {
      push_env(
        &mut specs,
        SecretReferenceField::ExternalAuthClientSecretEnv(entry.name.clone()),
        reference,
        SecretMaterialType::OAuthClientSecret,
      );
    }
  }
  for pool in &config.upstream_pools {
    let token_entries = pool
      .discovery
      .iter()
      .filter_map(|entry| entry.token_env.as_deref())
      .collect::<Vec<_>>();
    if token_entries.len() > 1 {
      return Err(SecretActivationError::TargetAmbiguous);
    }
    if let Some(reference) = token_entries.first() {
      push_env(
        &mut specs,
        SecretReferenceField::UpstreamDiscoveryTokenEnv(pool.name.clone()),
        reference,
        SecretMaterialType::DiscoveryToken,
      );
    }
  }
  for entry in &config.cache.external_handlers {
    if let Some(reference) = entry.token_env.as_deref() {
      push_env(
        &mut specs,
        SecretReferenceField::CacheExternalTokenEnv(entry.name.clone()),
        reference,
        SecretMaterialType::BearerToken,
      );
    }
  }
  for listener in &config.webrtc_turn_listeners {
    if let Some(reference) = listener.auth.rest_shared_secret_env.as_deref() {
      push_env(
        &mut specs,
        SecretReferenceField::TurnRestSharedSecretEnv(listener.name.clone()),
        reference,
        SecretMaterialType::TurnSharedSecret,
      );
    }
    for credential in &listener.auth.static_credentials {
      if let Some(reference) = credential.password_env.as_deref() {
        push_env(
          &mut specs,
          SecretReferenceField::TurnStaticPasswordEnv {
            listener: listener.name.clone(),
            username: credential.username.clone(),
          },
          reference,
          SecretMaterialType::TurnPassword,
        );
      }
    }
  }
  Ok(specs)
}

fn push_env(
  specs: &mut Vec<SecretReferenceSpec>,
  field: SecretReferenceField,
  reference: &str,
  material_type: SecretMaterialType,
) {
  specs.push(SecretReferenceSpec {
    field,
    reference: reference.to_string(),
    provider: SecretProviderIdentity::Environment,
    material_type,
    file_path: None,
  });
}

fn checked_component(raw: &str) -> Result<String, SecretActivationError> {
  if raw.is_empty()
    || raw.len() > 256
    || raw == "."
    || raw == ".."
    || raw.chars().any(char::is_control)
  {
    return Err(SecretActivationError::FieldNotAllowlisted);
  }
  Ok(raw.to_string())
}

fn remove_remote_signer_file_tracking(config: &mut Config) {
  let Some(logical) = config
    .source_paths
    .downstream_tls_remote_signer_token_file
    .take()
  else {
    return;
  };
  config
    .source_paths
    .runtime_files
    .retain(|candidate| candidate != &logical);
  config
    .source_paths
    .downstream_tls_files
    .retain(|candidate| candidate != &logical);
}
