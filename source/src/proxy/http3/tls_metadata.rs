//! QUIC handshake metadata owned by the HTTP/3 transport boundary.

use crate::waf::WafTlsMetadata;

const QUIC_TLS_FINGERPRINT_SCHEME: &str = "quinn-rustls-quic-v2";

pub(super) fn downstream_quic_tls_metadata(
  connection: &h3_quinn::quinn::Connection,
) -> WafTlsMetadata {
  let handshake_data = connection.handshake_data().and_then(|data| {
    data
      .downcast::<h3_quinn::quinn::crypto::rustls::HandshakeData>()
      .ok()
  });
  let (alpn, sni) = handshake_data
    .map(|data| {
      (
        data
          .protocol
          .as_ref()
          .map(|value| String::from_utf8_lossy(value).into_owned()),
        data.server_name.clone(),
      )
    })
    .unwrap_or_default();
  let version = Some("TLSv1_3".to_string());
  // Quinn's stable rustls handshake data exposes ALPN and SNI for QUIC, but not the
  // negotiated cipher suite or key-exchange group. Keep explicit empty payload
  // slots so future metadata additions can move the QUIC scheme forward cleanly.
  let fingerprint = Some(quic_tls_fingerprint(QuicTlsFingerprintInput {
    version: version.as_deref(),
    cipher_suite: None,
    key_exchange_group: None,
    data_integrity_group: None,
    sni: sni.as_deref(),
    alpn: alpn.as_deref(),
  }));

  WafTlsMetadata {
    enabled: true,
    version,
    cipher_suite: None,
    sni,
    alpn,
    fingerprint,
    fingerprint_scheme: Some(QUIC_TLS_FINGERPRINT_SCHEME.to_string()),
    client_certificate: None,
  }
}

#[derive(Debug, Clone, Copy)]
struct QuicTlsFingerprintInput<'a> {
  version: Option<&'a str>,
  cipher_suite: Option<&'a str>,
  key_exchange_group: Option<&'a str>,
  data_integrity_group: Option<&'a str>,
  sni: Option<&'a str>,
  alpn: Option<&'a str>,
}

fn quic_tls_fingerprint(input: QuicTlsFingerprintInput<'_>) -> String {
  let payload = quic_tls_fingerprint_payload(input);
  hex_encode(&crate::crypto::sha256(payload.as_bytes()))
}

fn quic_tls_fingerprint_payload(input: QuicTlsFingerprintInput<'_>) -> String {
  format!(
    "{QUIC_TLS_FINGERPRINT_SCHEME}\nselected_version={}\nselected_cipher_suite={}\nselected_key_exchange_group={}\nselected_data_integrity_group={}\nsni={}\nalpn={}\nmetadata_source=quinn-rustls-handshake-data",
    input.version.unwrap_or_default(),
    input.cipher_suite.unwrap_or_default(),
    input.key_exchange_group.unwrap_or_default(),
    input.data_integrity_group.unwrap_or_default(),
    input.sni.unwrap_or_default(),
    input.alpn.unwrap_or_default()
  )
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn quic_tls_fingerprint_payload_uses_exposed_quic_scheme() {
    let payload = quic_tls_fingerprint_payload(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("example.com"),
      alpn: Some("h3"),
    });

    assert!(payload.starts_with("quinn-rustls-quic-v2\n"));
    assert!(payload.contains("selected_version=TLSv1_3"));
    assert!(payload.contains("selected_cipher_suite="));
    assert!(payload.contains("selected_key_exchange_group="));
    assert!(payload.contains("selected_data_integrity_group="));
    assert!(payload.contains("sni=example.com"));
    assert!(payload.contains("alpn=h3"));
    assert!(payload.contains("metadata_source=quinn-rustls-handshake-data"));
  }

  #[test]
  fn quic_tls_fingerprint_changes_when_exposed_handshake_metadata_changes() {
    let base = quic_tls_fingerprint(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("example.com"),
      alpn: Some("h3"),
    });
    let changed_sni = quic_tls_fingerprint(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("alt.example.com"),
      alpn: Some("h3"),
    });
    let changed_alpn = quic_tls_fingerprint(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("example.com"),
      alpn: Some("h3-29"),
    });

    assert_eq!(base.len(), 64);
    assert_ne!(base, changed_sni);
    assert_ne!(base, changed_alpn);
  }
}
