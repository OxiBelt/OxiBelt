//! Explicit upstream certificate identity verification.
//!
//! The transport-provided server name remains the SNI value. When explicit
//! SAN identities are configured, only those identities authenticate the
//! certificate; the SNI does not implicitly become another allowed identity.

use std::sync::Arc;

use anyhow::anyhow;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

use crate::config::UpstreamTlsSubjectAltName;

use super::parse_certificate_metadata;

pub(super) fn explicit_subject_alt_name_verifier(
  inner: Arc<rustls::client::WebPkiServerVerifier>,
  subject_alt_names: &[UpstreamTlsSubjectAltName],
) -> anyhow::Result<Arc<dyn ServerCertVerifier>> {
  if subject_alt_names.is_empty() {
    return Ok(inner);
  }

  let mut dns_names = Vec::new();
  let mut uri_names = Vec::new();
  for subject_alt_name in subject_alt_names {
    match subject_alt_name {
      UpstreamTlsSubjectAltName::Dns(value) => {
        ServerName::try_from(value.clone()).map_err(|_| {
          anyhow!("upstream TLS subjectAltName DNS identity is not a valid server name")
        })?;
        dns_names.push(value.clone());
      }
      UpstreamTlsSubjectAltName::Uri(value) => uri_names.push(value.clone()),
    }
  }

  Ok(Arc::new(ExplicitSubjectAltNameVerifier {
    inner,
    dns_names,
    uri_names,
  }))
}

#[derive(Debug)]
struct ExplicitSubjectAltNameVerifier {
  inner: Arc<rustls::client::WebPkiServerVerifier>,
  dns_names: Vec<String>,
  uri_names: Vec<String>,
}

impl ServerCertVerifier for ExplicitSubjectAltNameVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, Error> {
    let explicit_server_name = self
      .dns_names
      .first()
      .map(|expected_name| {
        ServerName::try_from(expected_name.clone())
          .map_err(|_| Error::InvalidCertificate(CertificateError::NotValidForName))
      })
      .transpose()?;
    let verification_name = explicit_server_name.as_ref().unwrap_or(server_name);
    // `WebPkiServerVerifier` validates certificate encoding, the chain,
    // validity, and purpose before it validates `server_name`. Restricting
    // `inner` to that concrete verifier makes a name-only failure safe to
    // treat as successful chain verification for the exact SAN check.
    let last_name_mismatch = match self.inner.verify_server_cert(
      end_entity,
      intermediates,
      verification_name,
      ocsp_response,
      now,
    ) {
      Ok(_) => None,
      Err(error) if is_name_mismatch(&error) => Some(error),
      Err(error) => return Err(error),
    };

    let metadata = parse_certificate_metadata(end_entity.as_ref())
      .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    // Explicit DNS and URI identities are literal SAN matches. WebPKI is used
    // above only for chain, validity and purpose verification: its wildcard
    // hostname matching must not broaden an operator-configured exact DNS SAN.
    if self.dns_names.iter().any(|expected| {
      metadata
        .san_dns_names
        .iter()
        .any(|actual| actual == expected)
    }) || self.uri_names.iter().any(|expected| {
      metadata
        .san_uri_names
        .iter()
        .any(|actual| actual == expected)
    }) {
      return Ok(ServerCertVerified::assertion());
    }

    Err(last_name_mismatch.unwrap_or(Error::InvalidCertificate(CertificateError::NotValidForName)))
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

fn is_name_mismatch(error: &Error) -> bool {
  matches!(
    error,
    Error::InvalidCertificate(CertificateError::NotValidForName)
      | Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })
  )
}
