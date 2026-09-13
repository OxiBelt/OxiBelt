use std::sync::Arc;

use crate::config::{ProxyProtocolTlsConfig, ProxyProtocolTlsSource, ProxyProtocolVersion};
use crate::proxy_protocol::{ProxyProtocolMetadata, ProxyProtocolSslMetadata};

use super::tls::{ConnectionTlsEvidence, PreparedTlsHeader};

fn policy(source: ProxyProtocolTlsSource) -> ProxyProtocolTlsConfig {
  ProxyProtocolTlsConfig {
    source,
    client_certificate: false,
  }
}

fn metadata(
  source: &str,
  destination: &str,
  ssl: Option<ProxyProtocolSslMetadata>,
) -> Arc<ProxyProtocolMetadata> {
  Arc::new(ProxyProtocolMetadata {
    version: ProxyProtocolVersion::V2,
    source: source.parse().expect("source socket"),
    destination: Some(destination.parse().expect("destination socket")),
    ssl: ssl.map(Arc::new),
  })
}

fn unverified_ssl() -> ProxyProtocolSslMetadata {
  ProxyProtocolSslMetadata {
    client: 0,
    verify: 23,
    version: Some("TLSv1.3".to_string()),
    ..ProxyProtocolSslMetadata::default()
  }
}

#[test]
fn received_evidence_preserves_unverified_flags_and_writes_exact_v2_length() {
  let received = metadata(
    "192.0.2.10:40000",
    "198.51.100.20:443",
    Some(unverified_ssl()),
  );
  let prepared = PreparedTlsHeader::prepare(
    &policy(ProxyProtocolTlsSource::ReceivedProxy),
    &ConnectionTlsEvidence {
      received: Some(received),
      ..ConnectionTlsEvidence::default()
    },
    "192.0.2.10:51234".parse().unwrap(),
  )
  .expect("received evidence is emitted unchanged");
  let bytes = prepared.bytes();
  assert_eq!(
    u16::from_be_bytes([bytes[14], bytes[15]]) as usize,
    bytes.len() - 16
  );
  assert_eq!(&bytes[28..31], &[0x20, 0, 15]);
  assert_eq!(bytes[31], 0);
  assert_eq!(&bytes[32..36], &23u32.to_be_bytes());
  assert!(!prepared.certificate_identity);
}

#[test]
fn selected_source_never_falls_back_between_local_and_received() {
  let received = metadata(
    "192.0.2.10:40000",
    "198.51.100.20:443",
    Some(unverified_ssl()),
  );
  let evidence = ConnectionTlsEvidence {
    local: Some(metadata(
      "192.0.2.11:40000",
      "198.51.100.20:443",
      Some(ProxyProtocolSslMetadata {
        client: 1,
        verify: 1,
        version: Some("TLSv1.2".to_string()),
        ..ProxyProtocolSslMetadata::default()
      }),
    )),
    received: Some(received),
    ..ConnectionTlsEvidence::default()
  };
  assert!(
    PreparedTlsHeader::prepare(
      &policy(ProxyProtocolTlsSource::ReceivedProxy),
      &evidence,
      "192.0.2.10:51234".parse().unwrap(),
    )
    .is_ok()
  );
  assert!(
    PreparedTlsHeader::prepare(
      &policy(ProxyProtocolTlsSource::LocalTls),
      &evidence,
      "192.0.2.10:51234".parse().unwrap(),
    )
    .is_err()
  );
}

#[test]
fn missing_ssl_and_effective_client_mismatch_fail_closed() {
  let no_ssl = metadata("192.0.2.10:40000", "198.51.100.20:443", None);
  let evidence = ConnectionTlsEvidence {
    received: Some(no_ssl),
    ..ConnectionTlsEvidence::default()
  };
  assert!(
    PreparedTlsHeader::prepare(
      &policy(ProxyProtocolTlsSource::ReceivedProxy),
      &evidence,
      "192.0.2.10:51234".parse().unwrap(),
    )
    .is_err()
  );

  let mismatch = ConnectionTlsEvidence {
    received: Some(metadata(
      "192.0.2.10:40000",
      "198.51.100.20:443",
      Some(unverified_ssl()),
    )),
    ..ConnectionTlsEvidence::default()
  };
  assert!(
    PreparedTlsHeader::prepare(
      &policy(ProxyProtocolTlsSource::ReceivedProxy),
      &mismatch,
      "192.0.2.11:51234".parse().unwrap(),
    )
    .is_err()
  );
}

#[test]
fn local_capture_failure_is_distinct_from_missing_received_evidence() {
  let evidence = ConnectionTlsEvidence {
    local_capture_failed: true,
    ..ConnectionTlsEvidence::default()
  };
  let error = PreparedTlsHeader::prepare(
    &policy(ProxyProtocolTlsSource::LocalTls),
    &evidence,
    "192.0.2.10:51234".parse().unwrap(),
  )
  .expect_err("failed local capture must not become received evidence");
  assert!(
    error
      .to_string()
      .contains("local TLS metadata capture failed")
  );
}

#[test]
fn oversized_ssl_payload_is_rejected_before_header_emission() {
  let ssl = ProxyProtocolSslMetadata {
    client: 1,
    verify: 1,
    version: Some("x".repeat(u16::MAX as usize)),
    ..ProxyProtocolSslMetadata::default()
  };
  let evidence = ConnectionTlsEvidence {
    received: Some(metadata("192.0.2.10:40000", "198.51.100.20:443", Some(ssl))),
    ..ConnectionTlsEvidence::default()
  };
  assert!(
    PreparedTlsHeader::prepare(
      &policy(ProxyProtocolTlsSource::ReceivedProxy),
      &evidence,
      "192.0.2.10:51234".parse().unwrap(),
    )
    .is_err()
  );
}
