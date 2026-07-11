//! Verified TLS client configuration for Redis-compatible shared-state backends.

use std::fmt;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
  CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, OtherError,
  SignatureScheme,
};
use subtle::ConstantTimeEq;

use crate::config::{CryptoConfig, RedisTlsConfig, RedisTrustStore, TlsCryptoProvider};

use super::certificate_io::{load_certs, load_private_key};
use super::client_roots::load_webpki_root_store;

#[derive(Clone)]
pub(crate) struct RedisTlsClientConfig {
  pub(crate) config: Arc<ClientConfig>,
  pub(crate) server_name: ServerName<'static>,
  pub(crate) identity: RedisTlsIdentity,
}

impl fmt::Debug for RedisTlsClientConfig {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RedisTlsClientConfig")
      .field("server_name", &self.identity.server_name)
      .field("trust_store", &self.identity.trust_store)
      .field("pin_count", &self.identity.server_spki_sha256.len())
      .field("client_auth", &self.identity.client_auth)
      .finish()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RedisTlsIdentity {
  pub(crate) tls_provider: TlsCryptoProvider,
  pub(crate) trust_store: RedisTrustStore,
  pub(crate) server_name: String,
  pub(crate) ca_cert: Option<std::path::PathBuf>,
  pub(crate) client_cert: Option<std::path::PathBuf>,
  pub(crate) client_key: Option<std::path::PathBuf>,
  pub(crate) server_spki_sha256: Vec<[u8; 32]>,
  pub(crate) client_auth: bool,
}

pub(crate) fn build_redis_tls_client_config(
  crypto: &CryptoConfig,
  tls: &RedisTlsConfig,
  endpoint_host: &str,
) -> anyhow::Result<RedisTlsClientConfig> {
  let server_name_text = tls.server_name.as_deref().unwrap_or(endpoint_host);
  let server_name = ServerName::try_from(server_name_text.to_string())
    .map_err(|error| anyhow!("invalid Redis TLS server name: {error}"))?;
  let pins = parse_spki_pins(&tls.server_spki_sha256)?;
  let roots = Arc::new(load_redis_root_store(tls)?);
  let provider = Arc::new(super::provider::crypto_provider(crypto)?);
  let builder = ClientConfig::builder_with_provider(provider.clone())
    .with_safe_default_protocol_versions()
    .context("failed to configure Redis TLS protocol versions")?;
  let client_cert = match (&tls.client_cert, &tls.client_key) {
    (Some(cert), Some(key)) => Some((load_certs(cert)?, load_private_key(key)?)),
    (None, None) => None,
    _ => bail!("Redis TLS client certificate and key must be configured together"),
  };
  let mut config = if pins.is_empty() {
    let builder = builder.with_root_certificates(roots);
    match client_cert {
      Some((cert, key)) => builder
        .with_client_auth_cert(cert, key)
        .context("failed to configure Redis TLS client certificate")?,
      None => builder.with_no_client_auth(),
    }
  } else {
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider)
      .build()
      .context("failed to build Redis WebPKI verifier")?;
    let builder = builder
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(RedisSpkiPinVerifier {
        inner: verifier,
        pins: pins.clone(),
      }));
    match client_cert {
      Some((cert, key)) => builder
        .with_client_auth_cert(cert, key)
        .context("failed to configure Redis TLS client certificate")?,
      None => builder.with_no_client_auth(),
    }
  };
  // Pooled Redis sockets make resumption savings negligible, and disabling it
  // ensures every new physical socket re-runs certificate and pin verification.
  config.resumption = Resumption::disabled();
  Ok(RedisTlsClientConfig {
    config: Arc::new(config),
    server_name,
    identity: RedisTlsIdentity {
      tls_provider: crypto.tls_provider,
      trust_store: tls.trust_store,
      server_name: server_name_text.to_string(),
      ca_cert: tls.ca_cert.clone(),
      client_cert: tls.client_cert.clone(),
      client_key: tls.client_key.clone(),
      server_spki_sha256: pins,
      client_auth: tls.client_cert.is_some(),
    },
  })
}

fn load_redis_root_store(tls: &RedisTlsConfig) -> anyhow::Result<rustls::RootCertStore> {
  match tls.trust_store {
    RedisTrustStore::Webpki => Ok(load_webpki_root_store()),
    RedisTrustStore::Native => {
      let result = rustls_native_certs::load_native_certs();
      let mut roots = rustls::RootCertStore::empty();
      let (added, _ignored) = roots.add_parsable_certificates(result.certs);
      if added == 0 {
        bail!("native Redis TLS trust store did not provide usable root certificates");
      }
      Ok(roots)
    }
    RedisTrustStore::Custom => {
      let path = tls
        .ca_cert
        .as_ref()
        .ok_or_else(|| anyhow!("Redis custom TLS trust store requires ca_cert"))?;
      let mut roots = rustls::RootCertStore::empty();
      let (added, _ignored) = roots.add_parsable_certificates(load_certs(path)?);
      if added == 0 {
        bail!(
          "no parsable Redis TLS root certificates found in {}",
          path.display()
        );
      }
      Ok(roots)
    }
  }
}

fn parse_spki_pins(raw_pins: &[String]) -> anyhow::Result<Vec<[u8; 32]>> {
  use base64::Engine;

  raw_pins
    .iter()
    .map(|pin| {
      let encoded = pin
        .strip_prefix("sha256/")
        .ok_or_else(|| anyhow!("Redis SPKI pin must use sha256/<base64>"))?;
      let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| anyhow!("Redis SPKI pin must use valid base64"))?;
      let digest: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("Redis SPKI pin must decode to 32 bytes"))?;
      Ok(digest)
    })
    .collect()
}

struct RedisSpkiPinVerifier {
  inner: Arc<dyn ServerCertVerifier>,
  pins: Vec<[u8; 32]>,
}

impl fmt::Debug for RedisSpkiPinVerifier {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RedisSpkiPinVerifier")
      .field("pin_count", &self.pins.len())
      .finish()
  }
}

impl ServerCertVerifier for RedisSpkiPinVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, Error> {
    let verified =
      self
        .inner
        .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
    let certificate = webpki::EndEntityCert::try_from(end_entity).map_err(|_| pin_error())?;
    let digest = crate::crypto::sha256(certificate.subject_public_key_info().as_ref());
    if self.pins.iter().any(|pin| bool::from(pin.ct_eq(&digest))) {
      Ok(verified)
    } else {
      Err(pin_error())
    }
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, Error> {
    self.inner.verify_tls12_signature(message, cert, dss)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, Error> {
    self.inner.verify_tls13_signature(message, cert, dss)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.inner.supported_verify_schemes()
  }

  fn requires_raw_public_keys(&self) -> bool {
    self.inner.requires_raw_public_keys()
  }

  fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
    self.inner.root_hint_subjects()
  }
}

#[derive(Debug)]
struct RedisPinError;

impl fmt::Display for RedisPinError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("Redis server certificate pin verification failed")
  }
}

impl std::error::Error for RedisPinError {}

fn pin_error() -> Error {
  Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(RedisPinError))))
}
