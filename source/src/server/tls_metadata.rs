//! TLS and QUIC metadata plus privacy-preserving client fingerprints.

use super::*;

pub(super) struct ClientHelloFingerprintMetadata {
  pub(super) cipher_suites: String,
  pub(super) key_exchange_groups: String,
  pub(super) signature_schemes: String,
  pub(super) data_integrity_groups: String,
}

pub(super) fn client_hello_fingerprint_metadata(
  client_hello: rustls::server::ClientHello<'_>,
) -> ClientHelloFingerprintMetadata {
  let cipher_suites = client_hello
    .cipher_suites()
    .iter()
    .map(|suite| format!("{suite:?}"))
    .collect::<Vec<_>>();
  let key_exchange_groups = client_hello
    .named_groups()
    .unwrap_or_default()
    .iter()
    .map(|group| format!("{group:?}"))
    .collect::<Vec<_>>();
  let signature_schemes = client_hello
    .signature_schemes()
    .iter()
    .map(|scheme| format!("{scheme:?}"))
    .collect::<Vec<_>>();
  let data_integrity_groups = unique_nonempty(
    cipher_suites
      .iter()
      .filter_map(|suite| cipher_suite_data_integrity_group(suite))
      .map(str::to_string),
  );

  ClientHelloFingerprintMetadata {
    cipher_suites: cipher_suites.join(","),
    key_exchange_groups: key_exchange_groups.join(","),
    signature_schemes: signature_schemes.join(","),
    data_integrity_groups: data_integrity_groups.join(","),
  }
}

pub(super) fn downstream_tls_metadata(
  connection: &rustls::ServerConnection,
  client_hello: &ClientHelloFingerprintMetadata,
) -> WafTlsMetadata {
  let version = connection
    .protocol_version()
    .map(|version| format!("{version:?}"));
  let cipher_suite = connection
    .negotiated_cipher_suite()
    .map(|suite| format!("{:?}", suite.suite()));
  let key_exchange_group = connection
    .negotiated_key_exchange_group()
    .map(|group| format!("{:?}", group.name()));
  let data_integrity_group = connection
    .negotiated_cipher_suite()
    .map(|suite| negotiated_cipher_suite_data_integrity_group(suite).to_string());
  let sni = connection.server_name().map(str::to_string);
  let alpn = connection
    .alpn_protocol()
    .map(|proto| String::from_utf8_lossy(proto).into_owned());
  let fingerprint = Some(tls_fingerprint(
    client_hello,
    version.as_deref(),
    cipher_suite.as_deref(),
    key_exchange_group.as_deref(),
    data_integrity_group.as_deref(),
    sni.as_deref(),
    alpn.as_deref(),
  ));

  WafTlsMetadata {
    enabled: true,
    version,
    cipher_suite,
    sni,
    alpn,
    fingerprint,
    fingerprint_scheme: Some(TCP_TLS_FINGERPRINT_SCHEME.to_string()),
    client_certificate: crate::tls::client_certificate_metadata(
      connection.peer_certificates().unwrap_or_default(),
    ),
  }
}

pub(super) fn tls_fingerprint(
  client_hello: &ClientHelloFingerprintMetadata,
  version: Option<&str>,
  cipher_suite: Option<&str>,
  key_exchange_group: Option<&str>,
  data_integrity_group: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  let payload = tls_fingerprint_payload(
    client_hello,
    version,
    cipher_suite,
    key_exchange_group,
    data_integrity_group,
    sni,
    alpn,
  );
  hex_encode(&crate::crypto::sha256(payload.as_bytes()))
}

pub(super) fn tls_fingerprint_payload(
  client_hello: &ClientHelloFingerprintMetadata,
  version: Option<&str>,
  cipher_suite: Option<&str>,
  key_exchange_group: Option<&str>,
  data_integrity_group: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  format!(
    "{TCP_TLS_FINGERPRINT_SCHEME}\nclient_hello_cipher_suites={}\nclient_hello_key_exchange_groups={}\nclient_hello_signature_schemes={}\nclient_hello_data_integrity_groups={}\nselected_version={}\nselected_cipher_suite={}\nselected_key_exchange_group={}\nselected_data_integrity_group={}\nsni={}\nalpn={}",
    client_hello.cipher_suites,
    client_hello.key_exchange_groups,
    client_hello.signature_schemes,
    client_hello.data_integrity_groups,
    version.unwrap_or_default(),
    cipher_suite.unwrap_or_default(),
    key_exchange_group.unwrap_or_default(),
    data_integrity_group.unwrap_or_default(),
    sni.unwrap_or_default(),
    alpn.unwrap_or_default()
  )
}

#[derive(Debug, Clone, Copy)]
pub(super) struct QuicTlsFingerprintInput<'a> {
  pub(super) version: Option<&'a str>,
  pub(super) cipher_suite: Option<&'a str>,
  pub(super) key_exchange_group: Option<&'a str>,
  pub(super) data_integrity_group: Option<&'a str>,
  pub(super) sni: Option<&'a str>,
  pub(super) alpn: Option<&'a str>,
}

pub(super) fn quic_tls_fingerprint(input: QuicTlsFingerprintInput<'_>) -> String {
  let payload = quic_tls_fingerprint_payload(input);
  hex_encode(&crate::crypto::sha256(payload.as_bytes()))
}

pub(super) fn quic_tls_fingerprint_payload(input: QuicTlsFingerprintInput<'_>) -> String {
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

pub(super) fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

pub(super) fn negotiated_cipher_suite_data_integrity_group(
  suite: rustls::SupportedCipherSuite,
) -> &'static str {
  match suite {
    rustls::SupportedCipherSuite::Tls12(suite) => {
      hash_algorithm_name(format!("{:?}", suite.common.hash_provider.algorithm()).as_str())
    }
    rustls::SupportedCipherSuite::Tls13(suite) => {
      hash_algorithm_name(format!("{:?}", suite.common.hash_provider.algorithm()).as_str())
    }
  }
}

pub(super) fn cipher_suite_data_integrity_group(cipher_suite: &str) -> Option<&'static str> {
  if cipher_suite.ends_with("_SHA512") {
    Some("SHA512")
  } else if cipher_suite.ends_with("_SHA384") {
    Some("SHA384")
  } else if cipher_suite.ends_with("_SHA256") {
    Some("SHA256")
  } else if cipher_suite.ends_with("_SHA") {
    Some("SHA")
  } else if cipher_suite.ends_with("_MD5") {
    Some("MD5")
  } else {
    None
  }
}

pub(super) fn hash_algorithm_name(name: &str) -> &'static str {
  match name {
    "SHA512" => "SHA512",
    "SHA384" => "SHA384",
    "SHA256" => "SHA256",
    "SHA1" => "SHA",
    "MD5" => "MD5",
    _ => "unknown",
  }
}

pub(super) fn unique_nonempty(values: impl IntoIterator<Item = String>) -> Vec<String> {
  let mut unique = Vec::new();
  for value in values {
    if !value.is_empty() && !unique.contains(&value) {
      unique.push(value);
    }
  }
  unique
}
