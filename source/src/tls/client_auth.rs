//! Downstream TLS client-auth verifier construction.
//! Client identity policy is compiled before it can affect request admission.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
  CertificateError, DigitallySignedStruct, DistinguishedName, Error, OtherError, SignatureScheme,
};

pub(super) fn enforce_verify_depth(
  inner: Arc<dyn ClientCertVerifier>,
  verify_depth: u8,
) -> Arc<dyn ClientCertVerifier> {
  Arc::new(VerifyDepthClientCertVerifier {
    inner,
    max_presented_chain_len: usize::from(verify_depth),
  })
}

#[derive(Debug)]
struct VerifyDepthClientCertVerifier {
  inner: Arc<dyn ClientCertVerifier>,
  max_presented_chain_len: usize,
}

impl ClientCertVerifier for VerifyDepthClientCertVerifier {
  fn offer_client_auth(&self) -> bool {
    self.inner.offer_client_auth()
  }

  fn client_auth_mandatory(&self) -> bool {
    self.inner.client_auth_mandatory()
  }

  fn root_hint_subjects(&self) -> &[DistinguishedName] {
    self.inner.root_hint_subjects()
  }

  fn verify_client_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
  ) -> Result<ClientCertVerified, Error> {
    let presented_chain_len = 1 + intermediates.len();
    if presented_chain_len > self.max_presented_chain_len {
      return Err(verify_depth_error(
        presented_chain_len,
        self.max_presented_chain_len,
      ));
    }
    self
      .inner
      .verify_client_cert(end_entity, intermediates, now)
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
}

fn verify_depth_error(presented: usize, max: usize) -> Error {
  Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
    VerifyDepthError { presented, max },
  ))))
}

#[derive(Debug)]
struct VerifyDepthError {
  presented: usize,
  max: usize,
}

impl fmt::Display for VerifyDepthError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "client certificate chain length {} exceeds configured tls.client_auth.verify_depth {}",
      self.presented, self.max
    )
  }
}

impl std::error::Error for VerifyDepthError {}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::time::Duration;

  use super::*;

  #[derive(Debug, Default)]
  struct CountingVerifier {
    verify_calls: AtomicUsize,
  }

  impl ClientCertVerifier for CountingVerifier {
    fn offer_client_auth(&self) -> bool {
      true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
      &[]
    }

    fn verify_client_cert(
      &self,
      _end_entity: &CertificateDer<'_>,
      _intermediates: &[CertificateDer<'_>],
      _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
      self.verify_calls.fetch_add(1, Ordering::Relaxed);
      Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
      &self,
      _message: &[u8],
      _cert: &CertificateDer<'_>,
      _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
      Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
      &self,
      _message: &[u8],
      _cert: &CertificateDer<'_>,
      _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
      Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
      vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
  }

  fn cert() -> CertificateDer<'static> {
    CertificateDer::from(vec![0_u8])
  }

  fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1))
  }

  #[test]
  fn verify_depth_rejects_presented_chain_before_inner_verifier() {
    let inner = Arc::new(CountingVerifier::default());
    let verifier = enforce_verify_depth(inner.clone(), 1);
    let end_entity = cert();
    let intermediate = cert();

    let error = verifier
      .verify_client_cert(&end_entity, &[intermediate], now())
      .expect_err("chain longer than verify_depth should be rejected");

    assert!(matches!(
      error,
      Error::InvalidCertificate(CertificateError::Other(_))
    ));
    assert_eq!(inner.verify_calls.load(Ordering::Relaxed), 0);
  }

  #[test]
  fn verify_depth_allows_chain_within_limit() {
    let inner = Arc::new(CountingVerifier::default());
    let verifier = enforce_verify_depth(inner.clone(), 2);
    let end_entity = cert();
    let intermediate = cert();

    verifier
      .verify_client_cert(&end_entity, &[intermediate], now())
      .expect("chain within verify_depth should delegate to verifier");

    assert_eq!(inner.verify_calls.load(Ordering::Relaxed), 1);
  }
}
