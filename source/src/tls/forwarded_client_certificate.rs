//! Opaque capture and serialization of a TLS-verified downstream client certificate.
//!
//! The request extension deliberately keeps raw certificate material out of WAF metadata and
//! logging types. Only the forwarding boundary may serialize its bounded leaf capture.

use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use http::HeaderValue;
use rustls::pki_types::CertificateDer;

use crate::config::ClientCertificateForwardingFormat;

const MAX_FORWARDED_CLIENT_CERTIFICATE_DER_BYTES: usize = 64 * 1024;

/// A verified client-certificate leaf captured after the transport handshake.
///
/// `Debug` intentionally avoids raw material and stable client identity values.
#[derive(Clone)]
pub(crate) struct ForwardedClientCertificate {
  inner: Arc<ForwardedClientCertificateInner>,
}

enum ForwardedClientCertificateInner {
  Captured {
    der: Box<[u8]>,
    fingerprint_sha256: String,
  },
  Oversized,
}

impl fmt::Debug for ForwardedClientCertificate {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.inner.as_ref() {
      ForwardedClientCertificateInner::Captured { .. } => {
        formatter.write_str("ForwardedClientCertificate { redacted }")
      }
      ForwardedClientCertificateInner::Oversized => {
        formatter.write_str("ForwardedClientCertificate { oversized }")
      }
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ForwardedClientCertificateCaptureError {
  Oversized,
  Encoding,
}

impl ForwardedClientCertificate {
  /// Returns the leaf fingerprint unless the leaf exceeded the capture bound.
  pub(crate) fn fingerprint(&self) -> Result<&str, ForwardedClientCertificateCaptureError> {
    match self.inner.as_ref() {
      ForwardedClientCertificateInner::Captured {
        fingerprint_sha256, ..
      } => Ok(fingerprint_sha256),
      ForwardedClientCertificateInner::Oversized => {
        Err(ForwardedClientCertificateCaptureError::Oversized)
      }
    }
  }

  /// Serializes the verified leaf for a protected upstream request header.
  pub(crate) fn encode(
    &self,
    format: ClientCertificateForwardingFormat,
  ) -> Result<HeaderValue, ForwardedClientCertificateCaptureError> {
    let der = match self.inner.as_ref() {
      ForwardedClientCertificateInner::Captured { der, .. } => der,
      ForwardedClientCertificateInner::Oversized => {
        return Err(ForwardedClientCertificateCaptureError::Oversized);
      }
    };
    let value = match format {
      ClientCertificateForwardingFormat::UrlEncodedPem => percent_encode(&canonical_pem(der)?),
      ClientCertificateForwardingFormat::Rfc9440 => format!(
        ":{}:",
        base64::engine::general_purpose::STANDARD.encode(der)
      ),
    };
    let mut header = HeaderValue::from_str(&value)
      .map_err(|_| ForwardedClientCertificateCaptureError::Encoding)?;
    header.set_sensitive(true);
    Ok(header)
  }
}

/// Captures only the verified leaf from a rustls peer chain.
///
/// The transport must invoke this only after a successful client-auth handshake. A present leaf
/// over the capture limit remains represented by `Oversized` so callers cannot confuse it with
/// an absent client certificate.
pub(crate) fn capture_forwarded_client_certificate(
  certificates: &[CertificateDer<'_>],
) -> Option<ForwardedClientCertificate> {
  let leaf = certificates.first()?;
  if leaf.as_ref().len() > MAX_FORWARDED_CLIENT_CERTIFICATE_DER_BYTES {
    return Some(ForwardedClientCertificate {
      inner: Arc::new(ForwardedClientCertificateInner::Oversized),
    });
  }
  Some(ForwardedClientCertificate {
    inner: Arc::new(ForwardedClientCertificateInner::Captured {
      der: leaf.as_ref().into(),
      fingerprint_sha256: hex_encode(&crate::crypto::sha256(leaf.as_ref())),
    }),
  })
}

fn canonical_pem(der: &[u8]) -> Result<String, ForwardedClientCertificateCaptureError> {
  let base64 = base64::engine::general_purpose::STANDARD.encode(der);
  let mut pem = String::with_capacity(base64.len() + 64);
  pem.push_str("-----BEGIN CERTIFICATE-----\n");
  for chunk in base64.as_bytes().chunks(64) {
    let chunk =
      std::str::from_utf8(chunk).map_err(|_| ForwardedClientCertificateCaptureError::Encoding)?;
    pem.push_str(chunk);
    pem.push('\n');
  }
  pem.push_str("-----END CERTIFICATE-----\n");
  Ok(pem)
}

fn percent_encode(value: &str) -> String {
  const HEX: &[u8; 16] = b"0123456789ABCDEF";
  let mut encoded = String::with_capacity(value.len());
  for byte in value.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      encoded.push(byte as char);
    } else {
      encoded.push('%');
      encoded.push(HEX[(byte >> 4) as usize] as char);
      encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
  }
  encoded
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn url_encoded_pem_is_canonical_and_sensitive() {
    let certificate = capture_forwarded_client_certificate(&[CertificateDer::from(vec![0xff])])
      .expect("a leaf certificate should be captured");
    let value = certificate
      .encode(ClientCertificateForwardingFormat::UrlEncodedPem)
      .expect("bounded leaf should encode");

    assert_eq!(
      value.to_str().unwrap(),
      "-----BEGIN%20CERTIFICATE-----%0A%2Fw%3D%3D%0A-----END%20CERTIFICATE-----%0A"
    );
    assert!(value.is_sensitive());
  }

  #[test]
  fn rfc9440_is_padded_base64_inside_colons() {
    let certificate = capture_forwarded_client_certificate(&[CertificateDer::from(vec![0xff])])
      .expect("a leaf certificate should be captured");
    let value = certificate
      .encode(ClientCertificateForwardingFormat::Rfc9440)
      .expect("bounded leaf should encode");

    assert_eq!(value.to_str().unwrap(), ":/w==:");
    assert!(value.is_sensitive());
    assert_eq!(
      certificate.fingerprint(),
      Ok("a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89")
    );
  }

  #[test]
  fn debug_never_exposes_certificate_or_fingerprint_material() {
    let certificate = capture_forwarded_client_certificate(&[CertificateDer::from(vec![0xff])])
      .expect("a leaf certificate should be captured");

    assert_eq!(
      format!("{certificate:?}"),
      "ForwardedClientCertificate { redacted }"
    );
  }

  #[test]
  fn oversized_leaf_is_not_absent() {
    let boundary = capture_forwarded_client_certificate(&[CertificateDer::from(
      vec![0; MAX_FORWARDED_CLIENT_CERTIFICATE_DER_BYTES],
    )])
    .expect("the exact capture bound is retained");
    assert!(boundary.fingerprint().is_ok());
    let certificate = capture_forwarded_client_certificate(&[CertificateDer::from(vec![
      0_u8;
      MAX_FORWARDED_CLIENT_CERTIFICATE_DER_BYTES
        + 1
    ])])
    .expect("an oversized leaf remains present as a sentinel");

    assert_eq!(
      certificate.fingerprint(),
      Err(ForwardedClientCertificateCaptureError::Oversized)
    );
    assert_eq!(
      certificate.encode(ClientCertificateForwardingFormat::Rfc9440),
      Err(ForwardedClientCertificateCaptureError::Oversized)
    );
  }
}
