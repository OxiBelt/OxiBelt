use super::*;
use oxibelt::config::{AdminTlsCertificateConfig, AdminTlsConfig};

fn client_config(ca: &Path, only_hybrid: bool) -> rustls::ClientConfig {
  let mut provider = tls::aws_lc_provider_with_secp256r1mlkem768(true);
  if only_hybrid {
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768];
  }
  let mut roots = rustls::RootCertStore::empty();
  roots.add(first_certificate_der(ca).into()).unwrap();
  rustls::ClientConfig::builder_with_provider(Arc::new(provider))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth()
}

fn handshake(
  server: Arc<rustls::ServerConfig>,
  client: rustls::ClientConfig,
) -> anyhow::Result<rustls::HandshakeKind> {
  let mut server = ServerConnection::new(server)?;
  let mut client = ClientConnection::new(Arc::new(client), "pq.example.test".try_into()?)?;
  for _ in 0..8 {
    let mut bytes = Vec::new();
    while client.wants_write() {
      client.write_tls(&mut bytes)?;
    }
    if !bytes.is_empty() {
      server.read_tls(&mut bytes.as_slice())?;
      server.process_new_packets()?;
    }
    bytes.clear();
    while server.wants_write() {
      server.write_tls(&mut bytes)?;
    }
    if !bytes.is_empty() {
      client.read_tls(&mut bytes.as_slice())?;
      client.process_new_packets()?;
    }
    if !client.is_handshaking() && !server.is_handshaking() {
      assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1MLKEM768
      );
      assert_eq!(
        server.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1MLKEM768
      );
      return Ok(client.handshake_kind().unwrap());
    }
  }
  anyhow::bail!("handshake did not complete")
}

#[test]
fn secp256r1mlkem768_downstream_turn_and_admin_require_opt_in() {
  let dir = common::TempDir::new("pq-surfaces");
  let (ca, ca_key) = common::create_self_signed_cert(dir.path(), "pq-ca");
  let (cert, key) =
    common::create_ca_signed_server_cert(dir.path(), "pq.example.test", &ca, &ca_key);
  let mut config = downstream_tls_config(cert.clone(), key.clone(), TlsClientAuthConfig::default());
  let listeners = ListenerConfig {
    https_bind: "127.0.0.1:8443".parse().unwrap(),
    https_binds: vec![],
    http_bind: None,
    http_binds: vec![],
    http_mode: Default::default(),
    http1: true,
    http2: true,
    http3: false,
    proxy_protocol: Default::default(),
    http_proxy_protocol: Default::default(),
  };
  let turn = TurnListenerTlsConfig::default();
  let mut admin = AdminTlsConfig {
    enabled: true,
    certificates: vec![AdminTlsCertificateConfig {
      server_names: vec!["pq.example.test".into()],
      cert_chain: cert,
      private_key: key,
      default: true,
    }],
    ..Default::default()
  };
  for enabled in [false, true] {
    if enabled {
      config.tls13.key_exchange_groups = vec![TlsKeyExchangeGroup::Secp256r1MlKem768];
      config.key_exchange_groups = config.tls13.key_exchange_groups.clone();
    }
    admin.enable_secp256r1mlkem768 = enabled;
    for server in [
      tls::build_server_config(&config, &listeners).unwrap(),
      tls::build_turn_server_config(&turn, &config).unwrap(),
      tls::build_admin_server_config(&admin).unwrap(),
    ] {
      let result = handshake(server, client_config(&ca, true));
      assert_eq!(result.is_ok(), enabled, "enabled={enabled}: {result:?}");
    }
  }
  assert_eq!(
    handshake(
      tls::build_server_config(&config, &listeners).unwrap(),
      client_config(&ca, false)
    )
    .unwrap(),
    rustls::HandshakeKind::FullWithHelloRetryRequest
  );
}

#[tokio::test]
async fn secp256r1mlkem768_quic_requires_opt_in() {
  let dir = common::TempDir::new("pq-quic");
  let (ca, ca_key) = common::create_self_signed_cert(dir.path(), "pq-ca");
  let (cert, key) =
    common::create_ca_signed_server_cert(dir.path(), "pq.example.test", &ca, &ca_key);
  let mut config = downstream_tls_config(cert.clone(), key.clone(), TlsClientAuthConfig::default());
  let mut admin = AdminTlsConfig {
    enabled: true,
    certificates: vec![AdminTlsCertificateConfig {
      server_names: vec!["pq.example.test".into()],
      cert_chain: cert,
      private_key: key,
      default: true,
    }],
    ..Default::default()
  };
  for enabled in [false, true] {
    if enabled {
      config.tls13.key_exchange_groups = vec![TlsKeyExchangeGroup::Secp256r1MlKem768];
    }
    admin.enable_secp256r1mlkem768 = enabled;
    for server in [
      tls::build_quic_server_config(&config, &QuicConfig::default(), None).unwrap(),
      tls::build_admin_quic_server_config_with_resumption(
        &admin,
        &QuicConfig::default(),
        None,
        None,
      )
      .unwrap(),
    ] {
      let server = Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
      let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
      let mut tls = client_config(&ca, true);
      tls.alpn_protocols = vec![b"h3".to_vec()];
      let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
      client.set_default_client_config(h3_quinn::quinn::ClientConfig::new(Arc::new(crypto)));
      let accept = async { server.accept().await.unwrap().await };
      let connect = client
        .connect(server.local_addr().unwrap(), "pq.example.test")
        .unwrap();
      let (accepted, connected) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(accept, connect)
      })
      .await
      .unwrap();
      assert_eq!(accepted.is_ok(), enabled);
      assert_eq!(connected.is_ok(), enabled);
      // The client offers only 0x11eb, so a completed authenticated QUIC handshake proves selection.
      client.close(0u32.into(), b"done");
      server.close(0u32.into(), b"done");
    }
  }
}
