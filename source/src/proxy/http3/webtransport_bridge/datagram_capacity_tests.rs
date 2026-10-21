//! Real HTTP/3 CONNECT admission, including rejected-upstream cleanup.

use std::sync::Arc;
use std::time::Duration;

use h3_quinn::quinn::{self, Endpoint};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;

use crate::config::{Config, UpstreamEchConfig};
use crate::lifecycle::ConnectionDrain;
use crate::state::AppSnapshot;

use super::upstream_adapter::datagram_fixture;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

const NAME: &str = "localhost";
const TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn h3_datagram_capacity_is_checked_before_accept_and_failed_sessions_release_permits() {
  for (peer_cap, send_queue, succeeds, stale_snapshot, h2_ingress) in [
    (Some(1100), 1 << 20, false, false, false),
    (Some(1100), 1 << 20, true, false, true),
    (Some(1100), 1 << 20, false, true, false),
    (None, 1 << 20, false, false, false),
    (Some(65535), 64, false, false, false),
    (Some(65535), 1 << 20, true, false, false),
  ] {
    let temp = common::TempDir::new("webtransport-capacity-admission");
    let (root_path, root_key) = common::create_self_signed_cert(temp.path(), "datagram-test-ca");
    let (cert_path, key_path) =
      common::create_ca_signed_server_cert(temp.path(), NAME, &root_path, &root_key);
    let certs = CertificateDer::pem_file_iter(&cert_path)
      .unwrap()
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let private_key = PrivateKeyDer::from_pem_file(&key_path).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
      rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, private_key)
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut upstream_config = quinn::ServerConfig::with_crypto(Arc::new(
      quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(peer_cap.map(|_| 1 << 20));
    transport.datagram_max_frame_size(peer_cap.map(quinn::VarInt::from_u32));
    upstream_config.transport_config(Arc::new(transport));
    let upstream_endpoint =
      Endpoint::server(upstream_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let upstream_address = upstream_endpoint.local_addr().unwrap();
    let backend_endpoint = upstream_endpoint.clone();
    let backend = tokio::spawn(async move {
      let conn = backend_endpoint.accept().await.unwrap().await.unwrap();
      if peer_cap.is_none() {
        // The upstream adapter rejects absent QUIC DATAGRAM support before
        // exchanging WebTransport SETTINGS or opening a session at all.
        let error = tokio::time::timeout(TIMEOUT, conn.closed()).await.unwrap();
        assert!(
          matches!(error,
          quinn::ConnectionError::ApplicationClosed(ref close)
            if close.error_code.into_inner() == 0),
          "disabled-DATAGRAM upstream must close before session establishment: {error:?}"
        );
        return;
      }
      let session = datagram_fixture::Session::accept(conn).await
        .unwrap_or_else(|error| panic!("upstream SETTINGS peer_cap={peer_cap:?} send_queue={send_queue} stale_snapshot={stale_snapshot} h2={h2_ingress}: {error:?}"));
      if succeeds {
        let bytes = session.read_datagram().await.unwrap();
        session.send_datagram(bytes).unwrap();
      }
      tokio::time::timeout(TIMEOUT, session.closed())
        .await
        .expect("the rejected or finished upstream session must close");
    });
    let mut raw = common::minimal_config_toml(&cert_path, &key_path)
      .replace("http3 = false", "http3 = true")
      .replace("max_http_version = \"h2\"", "max_http_version = \"h3\"")
      .replace(
        "https://app.internal.example",
        &format!("https://localhost:{}", upstream_address.port()),
      );
    raw.push_str("\n[quic.socket]\nworkers = 1\nreuse_port = true\n");
    let mut config: Config = toml::from_str(&raw).unwrap();
    config.proxy.trusted_ca_certs = vec![root_path.clone()];
    config.quic.upstream.transport.datagram_send_buffer_bytes = send_queue;
    config.limits.max_webtransport_sessions_per_ip = Some(1);
    config.validate().unwrap();
    let downstream_config =
      crate::tls::build_quic_server_config(&config.tls, &config.quic, None).unwrap();
    let downstream = Endpoint::server(downstream_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let downstream_address = downstream.local_addr().unwrap();
    if stale_snapshot {
      // Reproduce a reload boundary: the Initial used the old 1144-byte
      // transport, while routing sees a newer snapshot with a smaller queue.
      // Using the new snapshot's cap would incorrectly admit the 1100-byte peer.
      config
        .quic
        .downstream
        .transport
        .datagram_receive_buffer_bytes = 128;
    }
    let snapshot = Arc::new(AppSnapshot::new(config).await.unwrap());
    if h2_ingress {
      // H2 capsules do not make the H3 downstream frame-size promise. A small
      // H3 upstream can therefore still accept this direction and carry data.
      h2_to_h3_echo(snapshot).await;
      tokio::time::timeout(TIMEOUT, backend)
        .await
        .unwrap()
        .unwrap();
      downstream.close(0u32.into(), b"test complete");
      upstream_endpoint.close(0u32.into(), b"test complete");
      continue;
    }
    let (shutdown_tx, shutdown) = watch::channel(false);
    let (_plane_tx, plane) = watch::channel(false);
    let (_drain_tx, drain) = watch::channel(false);
    let downstream_endpoint = downstream.clone();
    let state = snapshot.clone();
    let proxy = tokio::spawn(async move {
      let conn = downstream_endpoint.accept().await.unwrap().await.unwrap();
      crate::proxy::http3::handle_downstream_connection(
        conn,
        downstream_address,
        state,
        shutdown,
        plane.clone(),
        ConnectionDrain::new(drain, plane, Duration::ZERO),
      )
      .await
    });
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(
      crate::tls::build_upstream_quic_client_config(
        std::slice::from_ref(&root_path),
        &UpstreamEchConfig::default(),
        &snapshot.config.quic,
      )
      .unwrap(),
    );
    let conn = client
      .connect(downstream_address, NAME)
      .unwrap()
      .await
      .unwrap();
    assert_eq!(
      conn.max_receive_datagram_frame_size().unwrap().into_inner(),
      65_535,
      "the client keeps its independent incoming limit"
    );
    let result = tokio::time::timeout(
      TIMEOUT,
      datagram_fixture::Session::connect(
        conn,
        url::Url::parse("https://example.com/session").unwrap(),
      ),
    )
    .await
    .unwrap();
    let mut retained_session = None;
    if succeeds {
      let session = result.expect("a sufficiently capable upstream must receive downstream 200");
      let payload = bytes::Bytes::from(vec![42; session.max_datagram_size()]);
      session.send_datagram(payload.clone()).unwrap();
      assert_eq!(
        tokio::time::timeout(TIMEOUT, session.read_datagram())
          .await
          .unwrap()
          .unwrap(),
        payload
      );
      // Keep the client's critical streams alive until controlled server
      // shutdown, rather than testing the vendor client's close sequencing.
      retained_session = Some(session);
    } else {
      assert!(
        matches!(
          result,
          Err(ref error) if datagram_fixture::is_bad_gateway(error)
        ),
        "an incompatible upstream must produce 502 before 200: peer_cap={peer_cap:?} send_queue={send_queue} stale_snapshot={stale_snapshot}: {result:?}"
      );
      let permit =
        super::acquire_webtransport_session_permits("127.0.0.1".parse().unwrap(), None, &snapshot)
          .await
          .expect("failed CONNECT must release its only per-IP session permit");
      drop(permit);
    }
    shutdown_tx.send_replace(true);
    tokio::time::timeout(TIMEOUT, backend)
      .await
      .unwrap()
      .unwrap();
    let result = tokio::time::timeout(TIMEOUT, proxy).await.unwrap().unwrap();
    if let Err(error) = result {
      // On a non-200 result the vendor client consumes and drops its SETTINGS
      // driver. The server can observe that critical-stream FIN before QUIC's
      // close packet. Accept only that typed rejection-fixture teardown, after
      // the exact 502, upstream close, and released-permit assertions above.
      assert!(!succeeds, "successful session teardown failed: {error:#}");
      assert!(
        matches!(error.downcast_ref::<h3::error::ConnectionError>(),
        Some(h3::error::ConnectionError::Local {
          error: h3::error::LocalError::Application {
            code: h3::error::Code::H3_CLOSED_CRITICAL_STREAM, reason, ..
          }, ..
        }) if reason == "control stream was closed"),
        "unexpected rejected-client teardown: peer_cap={peer_cap:?} send_queue={send_queue} stale_snapshot={stale_snapshot}: {error:#}"
      );
    }
    drop(retained_session);
    client.close(0u32.into(), b"test complete");
    downstream.close(0u32.into(), b"test complete");
    upstream_endpoint.close(0u32.into(), b"test complete");
  }
}

async fn h2_to_h3_echo(snapshot: Arc<AppSnapshot>) {
  use bytes::Bytes;
  use http_body_util::Empty;
  use hyper_util::rt::{TokioExecutor, TokioIo};

  let (client_io, server_io) = tokio::io::duplex(65_536);
  let (_drain_tx, drain) = watch::channel(false);
  let (_lifecycle_tx, lifecycle) = watch::channel(false);
  let session_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let service_state = snapshot.clone();
  let service = hyper::service::service_fn(move |request| {
    let state = service_state.clone();
    let drain = ConnectionDrain::new(drain.clone(), lifecycle.clone(), Duration::ZERO);
    let sessions = session_count.clone();
    async move {
      Ok::<_, std::convert::Infallible>(
        crate::proxy::webtransport_h2::ingress::handle_request(
          request,
          "127.0.0.1:12345".parse().unwrap(),
          None,
          crate::waf::WafTransportMetadataInput::default(),
          Arc::new(crate::waf::WafTlsMetadata::default()),
          None,
          state,
          true,
          drain,
          sessions,
        )
        .await,
      )
    }
  });
  let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
  builder
    .enable_connect_protocol()
    .webtransport_settings(crate::proxy::webtransport_h2::ingress::server_settings());
  let server_task = tokio::spawn(async move {
    let _ = builder
      .serve_connection(TokioIo::new(server_io), service)
      .await;
  });
  let (mut sender, driver) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
    .handshake::<_, Empty<Bytes>>(TokioIo::new(client_io))
    .await
    .unwrap();
  let client_task = tokio::spawn(async move {
    let _ = driver.await;
  });
  let request = http::Request::builder()
    .method("CONNECT")
    .uri("https://example.com/session")
    .body(Empty::<Bytes>::new())
    .unwrap();
  let (response, carrier) =
    tokio::time::timeout(TIMEOUT, sender.send_webtransport_request(request))
      .await
      .unwrap()
      .unwrap();
  assert_eq!(
    response.status(),
    http::StatusCode::OK,
    "H2 ingress must not inherit the H3 downstream capacity admission rule"
  );
  let (session, actor) = crate::webtransport::Session::start(
    carrier,
    crate::webtransport::SessionOptions::proxy(
      snapshot.config.proxy.http2.webtransport,
      crate::webtransport::Role::Client,
    ),
    crate::webtransport::Budget::new(),
  )
  .unwrap();
  let payload = Bytes::from_static(b"H2 to small H3 upstream");
  session.send_datagram(payload.clone()).unwrap();
  assert_eq!(
    tokio::time::timeout(TIMEOUT, session.read_datagram())
      .await
      .unwrap()
      .unwrap(),
    payload
  );
  session.close(0, b"test complete");
  tokio::time::timeout(TIMEOUT, actor)
    .await
    .unwrap()
    .unwrap()
    .unwrap();
  client_task.abort();
  server_task.abort();
}
