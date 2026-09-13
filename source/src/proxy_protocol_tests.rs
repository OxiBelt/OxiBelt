//! Socket-level regressions for trusted PROXY v2 TLS metadata intake.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::*;

type ParseResult = anyhow::Result<(TcpStream, SocketAddr, Option<Arc<ProxyProtocolMetadata>>)>;

#[tokio::test]
async fn fragmented_any_v2_header_retains_ssl_metadata() {
  let source: SocketAddr = "198.51.100.10:4242".parse().unwrap();
  let destination: SocketAddr = "192.0.2.10:443".parse().unwrap();
  let header = v2_header(
    0x21,
    0x11,
    ipv4_payload(
      source,
      destination,
      &[ssl_tlv(1, 0, &[(PP2_SUBTYPE_SSL_VERSION, b"TLSv1.3")])],
    ),
  );
  let (mut client, parser) =
    open_parser(proxy_config(ProxyProtocolVersion::Any, true), 1_000).await;
  client.write_all(&header[..5]).await.unwrap();
  tokio::time::sleep(Duration::from_millis(10)).await;
  client.write_all(&header[5..]).await.unwrap();

  let (_stream, accepted_source, metadata) = parser.await.unwrap().unwrap();
  assert_eq!(accepted_source, source);
  let metadata = metadata.expect("TLS-TLV intake should retain v2 metadata");
  assert_eq!(metadata.version, ProxyProtocolVersion::V2);
  assert_eq!(metadata.source, source);
  assert_eq!(metadata.destination, Some(destination));
  assert_eq!(
    metadata
      .ssl
      .as_deref()
      .and_then(|ssl| ssl.version.as_deref()),
    Some("TLSv1.3")
  );
}

#[tokio::test]
async fn any_v1_header_keeps_version_without_tls_assertion() {
  let (mut client, parser) =
    open_parser(proxy_config(ProxyProtocolVersion::Any, true), 1_000).await;
  client
    .write_all(b"PROXY TCP4 198.51.100.13 192.0.2.13 4242 443\r\n")
    .await
    .unwrap();
  let (_stream, source, metadata) = parser.await.unwrap().unwrap();
  assert_eq!(source, "198.51.100.13:4242".parse().unwrap());
  let metadata = metadata.expect("TLS-TLV-enabled any intake should retain v1 provenance");
  assert_eq!(metadata.version, ProxyProtocolVersion::V1);
  assert_eq!(metadata.destination, None);
  assert!(metadata.ssl.is_none());
}

#[tokio::test]
async fn slow_partial_tls_tlv_header_times_out_as_one_bounded_read() {
  let header = v2_header(
    0x21,
    0x11,
    ipv4_payload(
      "198.51.100.11:4242".parse().unwrap(),
      "192.0.2.11:443".parse().unwrap(),
      &[],
    ),
  );
  let (mut client, parser) = open_parser(proxy_config(ProxyProtocolVersion::V2, true), 40).await;
  client.write_all(&header[..8]).await.unwrap();
  let error = parser
    .await
    .unwrap()
    .expect_err("partial header must time out");
  assert!(
    error
      .to_string()
      .contains("PROXY protocol header timed out"),
    "unexpected timeout error: {error:#}"
  );
}

#[tokio::test]
async fn malformed_ssl_tlv_framing_text_and_der_are_rejected_from_the_socket() {
  let source: SocketAddr = "198.51.100.12:4242".parse().unwrap();
  let destination: SocketAddr = "192.0.2.12:443".parse().unwrap();
  let outer = ssl_tlv(1, 0, &[]);
  let cases = [
    ipv4_payload(source, destination, &[outer.clone(), outer]),
    ipv4_payload(source, destination, &[ssl_tlv_raw(1, 0, &[0xee, 0, 2, 0])]),
    ipv4_payload(
      source,
      destination,
      &[ssl_tlv(1, 0, &[(PP2_SUBTYPE_SSL_VERSION, &[0xff])])],
    ),
    ipv4_payload(
      source,
      destination,
      &[ssl_tlv(1, 0, &[(PP2_SUBTYPE_SSL_VERSION, b"TLS\0v1.3")])],
    ),
    ipv4_payload(
      source,
      destination,
      &[ssl_tlv(1, 0, &[(PP2_SUBTYPE_SSL_VERSION, b"TLS\nv1.3")])],
    ),
    ipv4_payload(
      source,
      destination,
      &[ssl_tlv(
        1,
        0,
        &[(PP2_SUBTYPE_SSL_CERT, b"not-a-der-certificate")],
      )],
    ),
  ];
  for payload in cases {
    assert_socket_rejects(v2_header(0x21, 0x11, payload)).await;
  }
}

#[test]
fn oversized_certificate_material_is_rejected_before_der_parsing() {
  // A nested v2 TLV is u16-sized, so a wire-representable certificate cannot
  // exceed 65535 bytes. Exercise the independent defensive bound directly.
  let error = ProxyProtocolCertificate::from_der(&vec![0; MAX_CERTIFICATE_DER_BYTES + 1])
    .expect_err("oversized certificate material must fail");
  assert!(error.to_string().contains("between 1 and"));
}

#[tokio::test]
async fn ipv6_metadata_is_preserved_and_local_unspec_frames_remain_rejected() {
  let source_ip: Ipv6Addr = "2001:db8:1::10".parse().unwrap();
  let destination_ip: Ipv6Addr = "2001:db8:2::20".parse().unwrap();
  let source = SocketAddr::new(source_ip.into(), 4242);
  let destination = SocketAddr::new(destination_ip.into(), 443);
  let mut payload = Vec::new();
  payload.extend_from_slice(&source_ip.octets());
  payload.extend_from_slice(&destination_ip.octets());
  payload.extend_from_slice(&source.port().to_be_bytes());
  payload.extend_from_slice(&destination.port().to_be_bytes());
  payload.extend_from_slice(&ssl_tlv(1, 0, &[]));
  let (mut client, parser) = open_parser(proxy_config(ProxyProtocolVersion::V2, true), 1_000).await;
  client
    .write_all(&v2_header(0x21, 0x21, payload))
    .await
    .unwrap();
  let (_stream, accepted_source, metadata) = parser.await.unwrap().unwrap();
  assert_eq!(accepted_source, source);
  let metadata = metadata.unwrap();
  assert_eq!(metadata.source, source);
  assert_eq!(metadata.destination, Some(destination));

  // Existing contract: only PROXY/TCP4/TCP6 can yield a resolved source.
  assert_socket_rejects(v2_header(0x20, 0x00, Vec::new())).await;
  assert_socket_rejects(v2_header(0x21, 0x01, Vec::new())).await;
}

fn proxy_config(version: ProxyProtocolVersion, tls_tlvs: bool) -> ProxyProtocolConfig {
  ProxyProtocolConfig {
    enabled: true,
    version,
    trusted_sources: vec!["127.0.0.1/32".to_string()],
    tls_tlvs,
  }
}

async fn open_parser(
  config: ProxyProtocolConfig,
  timeout_ms: u64,
) -> (TcpStream, JoinHandle<ParseResult>) {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let client = TcpStream::connect(address).await.unwrap();
  let (stream, peer) = listener.accept().await.unwrap();
  let parser = tokio::spawn(async move {
    accept_proxy_header_with_metadata(stream, peer, &config, Duration::from_millis(timeout_ms))
      .await
  });
  (client, parser)
}

async fn assert_socket_rejects(header: Vec<u8>) {
  let (mut client, parser) = open_parser(proxy_config(ProxyProtocolVersion::V2, true), 1_000).await;
  client.write_all(&header).await.unwrap();
  assert!(
    parser.await.unwrap().is_err(),
    "malformed frame must be rejected"
  );
}

fn v2_header(version_command: u8, family_transport: u8, payload: Vec<u8>) -> Vec<u8> {
  let length = u16::try_from(payload.len()).expect("fixture payload should fit");
  let mut header = Vec::with_capacity(16 + payload.len());
  header.extend_from_slice(V2_SIGNATURE);
  header.extend_from_slice(&[version_command, family_transport]);
  header.extend_from_slice(&length.to_be_bytes());
  header.extend_from_slice(&payload);
  header
}

fn ipv4_payload(source: SocketAddr, destination: SocketAddr, tlvs: &[Vec<u8>]) -> Vec<u8> {
  let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
    panic!("IPv4 fixture requires IPv4 addresses");
  };
  let mut payload = Vec::new();
  payload.extend_from_slice(&source.ip().octets());
  payload.extend_from_slice(&destination.ip().octets());
  payload.extend_from_slice(&source.port().to_be_bytes());
  payload.extend_from_slice(&destination.port().to_be_bytes());
  for tlv in tlvs {
    payload.extend_from_slice(tlv);
  }
  payload
}

fn ssl_tlv(client: u8, verify: u32, nested: &[(u8, &[u8])]) -> Vec<u8> {
  let mut value = vec![client];
  value.extend_from_slice(&verify.to_be_bytes());
  for (kind, nested_value) in nested {
    append_tlv(&mut value, *kind, nested_value);
  }
  outer_tlv(PP2_TYPE_SSL, &value)
}

fn ssl_tlv_raw(client: u8, verify: u32, nested: &[u8]) -> Vec<u8> {
  let mut value = vec![client];
  value.extend_from_slice(&verify.to_be_bytes());
  value.extend_from_slice(nested);
  outer_tlv(PP2_TYPE_SSL, &value)
}

fn outer_tlv(kind: u8, value: &[u8]) -> Vec<u8> {
  let mut output = Vec::new();
  append_tlv(&mut output, kind, value);
  output
}

fn append_tlv(output: &mut Vec<u8>, kind: u8, value: &[u8]) {
  let length = u16::try_from(value.len()).expect("fixture TLV should fit");
  output.push(kind);
  output.extend_from_slice(&length.to_be_bytes());
  output.extend_from_slice(value);
}
