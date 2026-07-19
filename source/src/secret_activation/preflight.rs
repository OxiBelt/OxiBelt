use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, Request};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};

use super::SecretActivationError;
use super::field::SecretReferenceField;
use super::resolver::read_bounded_file;
use crate::config::Config;
use crate::control_http::{empty_body, uri_from_url};
use crate::state::AppSnapshot;
use crate::tls::ParsedCertificateMetadata;

pub(super) fn preflight_certificate_material(config: &Config) -> Result<(), SecretActivationError> {
  check_certificate(
    &config.tls.cert_chain,
    (!config.tls.remote_signer.enabled)
      .then_some(config.tls.private_key.as_deref())
      .flatten(),
    &config.tls.server_names,
    config,
  )?;
  for certificate in &config.tls.certificates {
    check_certificate(
      &certificate.cert_chain,
      (!config.tls.remote_signer.enabled)
        .then_some(certificate.private_key.as_deref())
        .flatten(),
      &certificate.server_names,
      config,
    )?;
  }
  if config.admin.enabled && config.admin.tls.enabled {
    for certificate in &config.admin.tls.certificates {
      check_certificate(
        &certificate.cert_chain,
        Some(&certificate.private_key),
        &certificate.server_names,
        config,
      )?;
    }
  }
  for listener in &config.webrtc_turn_listeners {
    if listener.bind_tls.is_some() {
      let private_key = if listener.tls.remote_signer_key_id.is_some()
        || (listener.tls.private_key.is_none() && config.tls.remote_signer.enabled)
      {
        None
      } else {
        listener
          .tls
          .private_key
          .as_deref()
          .or(config.tls.private_key.as_deref())
      };
      check_certificate(
        listener
          .tls
          .cert_chain
          .as_deref()
          .unwrap_or(&config.tls.cert_chain),
        private_key,
        &[],
        config,
      )?;
    }
  }
  for path in config
    .tls
    .client_auth
    .ca_certs
    .iter()
    .chain(config.admin.tls.client_auth.ca_certs.iter())
    .chain(config.proxy.trusted_ca_certs.iter())
  {
    check_ca_bundle(path)?;
  }
  Ok(())
}

pub(super) async fn preflight_upstream_tls(
  snapshot: &AppSnapshot,
  field: &SecretReferenceField,
) -> Result<(), SecretActivationError> {
  let Some((endpoint, timeout)) = field.upstream_tls_preflight(&snapshot.config) else {
    return Ok(());
  };
  let uri = uri_from_url(&endpoint).map_err(|_| SecretActivationError::HostnameValidationFailed)?;
  let request = Request::builder()
    .method(Method::HEAD)
    .uri(uri)
    .body(empty_body())
    .map_err(|_| SecretActivationError::HostnameValidationFailed)?;
  snapshot
    .control_http
    .request_stream(request, timeout)
    .await
    .map_err(|_| SecretActivationError::UpstreamTlsPreflightFailed)?;
  Ok(())
}

fn check_certificate(
  path: &Path,
  private_key: Option<&Path>,
  server_names: &[String],
  config: &Config,
) -> Result<(), SecretActivationError> {
  let certificates = read_certificates(path)?;
  let leaf = certificates
    .first()
    .ok_or(SecretActivationError::CandidateInvalid)?;
  let metadata = crate::tls::parse_certificate_metadata(leaf)
    .map_err(|_| SecretActivationError::CandidateInvalid)?;
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| SecretActivationError::CertificateNotYetValid)?
    .as_secs()
    .min(i64::MAX as u64) as i64;
  validate_certificate_metadata(&metadata, server_names, now)?;
  if let Some(private_key) = private_key {
    crate::tls::validate_local_certificate_key_pair(path, private_key, &config.crypto)
      .map_err(|_| SecretActivationError::CertificateKeyMismatch)?;
  }
  Ok(())
}

pub(super) fn validate_certificate_metadata(
  metadata: &ParsedCertificateMetadata,
  server_names: &[String],
  now: i64,
) -> Result<(), SecretActivationError> {
  if now < metadata.not_before_unix_seconds {
    return Err(SecretActivationError::CertificateNotYetValid);
  }
  if now > metadata.not_after_unix_seconds {
    return Err(SecretActivationError::CertificateExpired);
  }
  if server_names
    .iter()
    .any(|name| !name_covered_by_certificate(name, metadata))
  {
    return Err(SecretActivationError::HostnameValidationFailed);
  }
  Ok(())
}

fn check_ca_bundle(path: &Path) -> Result<(), SecretActivationError> {
  let certificates = read_certificates(path).map_err(|_| SecretActivationError::CaBundleInvalid)?;
  if certificates.is_empty()
    || certificates
      .iter()
      .any(|certificate| crate::tls::parse_certificate_metadata(certificate).is_err())
  {
    return Err(SecretActivationError::CaBundleInvalid);
  }
  Ok(())
}

fn read_certificates(path: &Path) -> Result<Vec<Vec<u8>>, SecretActivationError> {
  let bytes = read_bounded_file(path)?;
  CertificateDer::pem_slice_iter(&bytes)
    .map(|certificate| {
      certificate
        .map(|certificate| certificate.as_ref().to_vec())
        .map_err(|_| SecretActivationError::CandidateInvalid)
    })
    .collect()
}

fn name_covered_by_certificate(name: &str, metadata: &ParsedCertificateMetadata) -> bool {
  if let Ok(ip) = name.parse::<IpAddr>() {
    return metadata.san_ip_addresses.contains(&ip);
  }
  let name = name.to_ascii_lowercase();
  metadata.san_dns_names.iter().any(|candidate| {
    candidate == &name
      || candidate
        .strip_prefix("*.")
        .is_some_and(|suffix| wildcard_matches(&name, suffix))
  })
}

fn wildcard_matches(name: &str, suffix: &str) -> bool {
  let Some(prefix) = name.strip_suffix(suffix) else {
    return false;
  };
  prefix.ends_with('.') && !prefix.trim_end_matches('.').contains('.')
}
