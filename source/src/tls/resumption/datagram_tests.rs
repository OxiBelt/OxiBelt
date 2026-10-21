//! Exercise the real resumption registry across a QUIC DATAGRAM limit change.

use std::sync::Arc;
use std::time::Duration;

use h3_quinn::quinn::{self, Connection, Endpoint};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::*;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

const NAME: &str = "datagram-resumption.test";
const TIMEOUT: Duration = Duration::from_secs(5);

fn key(limit: Option<u64>, mode: TlsServerResumptionMode) -> TlsServerResumptionKey {
  TlsServerResumptionKey {
    scope: "downstream-quic",
    mode,
    server_identity: NAME.to_string(),
    client_auth_identity: "none".to_string(),
    quic_datagram_frame_size: limit,
    alpn_family: "h3",
    tls_provider: TlsCryptoProvider::default(),
    enable_secp256r1mlkem768: false,
  }
}

fn server_config(
  certs: &[CertificateDer<'static>],
  private_key: &PrivateKeyDer<'static>,
  state: &TlsResumptionState,
  limit: Option<u64>,
) -> quinn::ServerConfig {
  let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
    rustls::crypto::aws_lc_rs::default_provider(),
  ))
  .with_protocol_versions(&[&rustls::version::TLS13])
  .unwrap()
  .with_no_client_auth()
  .with_single_cert(certs.to_vec(), private_key.clone_key())
  .unwrap();
  tls.alpn_protocols = vec![b"h3".to_vec()];
  tls.max_early_data_size = u32::MAX;
  let resumption = TlsServerResumptionConfig::default();
  configure_server_resumption(
    &mut tls,
    &resumption,
    key(limit, resumption.mode),
    Some(state),
  )
  .unwrap();
  let mut config = quinn::ServerConfig::with_crypto(Arc::new(
    quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
  ));
  let mut transport = quinn::TransportConfig::default();
  transport.datagram_max_frame_size(limit.map(|limit| quinn::VarInt::from_u64(limit).unwrap()));
  config.transport_config(Arc::new(transport));
  config
}

async fn exchange_ticket(client: &Connection, server: &Connection) {
  tokio::time::timeout(TIMEOUT, async {
    let mut sent = server.open_uni().await.unwrap();
    sent.write_all(b"ticket barrier").await.unwrap();
    sent.finish().unwrap();
    let mut received = client.accept_uni().await.unwrap();
    assert_eq!(received.read_to_end(32).await.unwrap(), b"ticket barrier");
  })
  .await
  .unwrap();
}

#[tokio::test]
async fn old_datagram_limit_ticket_rejects_early_data_but_same_limit_still_accepts_it() {
  let temp = common::TempDir::new("datagram-ticket-transition");
  let (root_path, root_key) = common::create_self_signed_cert(temp.path(), "datagram-test-ca");
  let (cert_path, key_path) =
    common::create_ca_signed_server_cert(temp.path(), NAME, &root_path, &root_key);
  let certs = CertificateDer::pem_file_iter(cert_path)
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let private_key = PrivateKeyDer::from_pem_file(key_path).unwrap();
  let state = TlsResumptionState::default();
  // None is the pre-change cache key and the legacy advertised limit of 65535.
  let server = Endpoint::server(
    server_config(&certs, &private_key, &state, None),
    "127.0.0.1:0".parse().unwrap(),
  )
  .unwrap();
  let address = server.local_addr().unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots
    .add(CertificateDer::from_pem_file(root_path).unwrap())
    .unwrap();
  let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
    rustls::crypto::aws_lc_rs::default_provider(),
  ))
  .with_protocol_versions(&[&rustls::version::TLS13])
  .unwrap()
  .with_root_certificates(roots)
  .with_no_client_auth();
  tls.alpn_protocols = vec![b"h3".to_vec()];
  tls.enable_early_data = true;
  let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
  client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
  )));
  let (first_client, first_server) = tokio::time::timeout(TIMEOUT, async {
    tokio::join!(client.connect(address, NAME).unwrap(), async {
      server.accept().await.unwrap().await
    })
  })
  .await
  .unwrap();
  let (first_client, first_server) = (first_client.unwrap(), first_server.unwrap());
  exchange_ticket(&first_client, &first_server).await;
  first_client.close(0u32.into(), b"initial complete");
  first_server.close(0u32.into(), b"initial complete");

  for (round, should_accept) in [(0, false), (1, true)] {
    // Rebuild from the same real registry, as a configuration reload does.
    server.set_server_config(Some(server_config(
      &certs,
      &private_key,
      &state,
      Some(1144),
    )));
    let (connection, accepted) = client
      .connect(address, NAME)
      .unwrap()
      .into_0rtt()
      .expect("the client must actually offer a remembered ticket");
    // The old ticket permits this payload; its complete frame exceeds 1144.
    let early = if should_accept {
      vec![round; 32]
    } else {
      vec![round; 1143]
    };
    connection.send_datagram(early.clone().into()).unwrap();
    let (accepted, peer) = tokio::time::timeout(TIMEOUT, async {
      tokio::join!(accepted, async {
        server.accept().await.unwrap().await.unwrap()
      })
    })
    .await
    .unwrap();
    assert_eq!(accepted, should_accept);
    assert_eq!(connection.max_datagram_size(), Some(1144 - 9));
    if should_accept {
      assert_eq!(
        tokio::time::timeout(TIMEOUT, peer.read_datagram())
          .await
          .unwrap()
          .unwrap(),
        early
      );
    } else {
      assert!(
        tokio::time::timeout(Duration::from_millis(50), peer.read_datagram())
          .await
          .is_err(),
        "old-limit early data must not reach the new application"
      );
      connection
        .send_datagram(bytes::Bytes::from_static(b"after handshake"))
        .unwrap();
      assert_eq!(
        tokio::time::timeout(TIMEOUT, peer.read_datagram())
          .await
          .unwrap()
          .unwrap(),
        b"after handshake"[..]
      );
    }
    exchange_ticket(&connection, &peer).await;
    connection.close(0u32.into(), b"round complete");
    peer.close(0u32.into(), b"round complete");
  }
  client.close(0u32.into(), b"test complete");
  server.close(0u32.into(), b"test complete");
}

#[test]
fn changed_frame_limit_isolates_stateless_tickets_while_unchanged_context_reuses_keys() {
  let state = TlsResumptionState::default();
  let resumption = TlsServerResumptionConfig {
    mode: TlsServerResumptionMode::Stateless,
    ..TlsServerResumptionConfig::default()
  };
  let runtime = |limit| {
    let TlsServerResumptionRuntime::Stateless(ticketer) = state
      .server_resumption_runtime(key(limit, resumption.mode), &resumption)
      .unwrap()
    else {
      panic!("expected stateless ticket producer")
    };
    ticketer
  };
  let legacy = runtime(None);
  let current = runtime(Some(1144));
  let same = runtime(Some(1144));
  assert!(Arc::ptr_eq(&current, &same));
  let ticket = legacy.encrypt(b"legacy transport parameters").unwrap();
  assert!(current.decrypt(&ticket).is_none());
  let ticket = current.encrypt(b"current transport parameters").unwrap();
  assert_eq!(
    same.decrypt(&ticket).unwrap(),
    b"current transport parameters"
  );
}
