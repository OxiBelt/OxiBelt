use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use h3_quinn::quinn::{Connection, Endpoint};
use rustls::client::{
  ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
  Tls13ClientSessionValue,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, HandshakeKind, NamedGroup, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use super::*;
use crate::cache::CacheStats;
use crate::config::{Config, MetricsConfig, QuicZeroRttMode, TlsServerResumptionMode, TlsVersion};
use crate::tls::{
  DownstreamTlsServerConfig, TlsResumptionState, TlsServerSessionStorageStats,
  build_downstream_quic_server_config_with_resumption_and_ocsp,
  build_downstream_tls_server_config_with_resumption_and_ocsp,
};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

const SERVER_NAME: &str = "ct-resumption.test";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SENTINEL: &[u8] = b"ct-resumption-sentinel";

#[test]
fn version_rollback_is_numeric_not_lexical() {
  assert!(parse_version("89.30").unwrap() > parse_version("89.9").unwrap());
  assert!(parse_version("89").is_err());
  assert!(parse_version("89.beta").is_err());
}

#[test]
fn cache_base64_is_canonical_and_bounded() {
  let encoded = base64::engine::general_purpose::STANDARD.encode(b"list");
  assert_eq!(decode_cache_base64(&encoded, 4).unwrap(), b"list");
  assert!(decode_cache_base64(&encoded, 3).is_err());
}

#[test]
fn resolver_chain_binding_covers_every_certificate() {
  let evaluated = vec![
    CertificateDer::from(vec![1, 2, 3]),
    CertificateDer::from(vec![4, 5, 6]),
  ];
  assert!(certificate_chain_matches(&evaluated, &evaluated));
  assert!(!certificate_chain_matches(
    &[CertificateDer::from(vec![1, 2, 3])],
    &evaluated
  ));
  assert!(!certificate_chain_matches(
    &[
      CertificateDer::from(vec![1, 2, 3]),
      CertificateDer::from(vec![4, 5, 7]),
    ],
    &evaluated
  ));
}

#[tokio::test]
async fn tcp_resumption_rechecks_live_ct_gate_for_supported_versions_and_stores() {
  for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
    for mode in [
      TlsServerResumptionMode::Stateful,
      TlsServerResumptionMode::Stateless,
    ] {
      assert_tcp_resumption_rechecks_gate(version, mode).await;
    }
  }
}

#[tokio::test]
async fn tcp_tls13_early_data_is_not_delivered_after_ct_gate_closes() {
  let mut fixture = TestFixture::new(
    TlsVersion::Tls13,
    TlsServerResumptionMode::Stateful,
    QuicZeroRttMode::Off,
  );
  let state = TlsResumptionState::default();
  let server_config = fixture.tcp_server_config(&state, SENTINEL.len() as u32);
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("TCP listener should bind");
  let address = listener.local_addr().expect("TCP address should resolve");
  let session_store = Arc::new(RecordingClientSessionStore::new());
  let client_config = Arc::new(fixture.client_config(
    &[&rustls::version::TLS13],
    session_store.clone(),
    true,
    None,
  ));

  let (client, server) =
    tcp_connect_pair(&listener, &server_config, address, client_config.clone())
      .await
      .expect("initial TCP TLS handshake should complete");
  assert_full_handshake(client.get_ref().1.handshake_kind());
  tcp_roundtrip_and_close(client, server, b'F').await;

  let delivered = Arc::new(AtomicUsize::new(0));
  let (kind, early_data_accepted) = tcp_early_data_attempt(
    &listener,
    &server_config,
    address,
    client_config.clone(),
    delivered.clone(),
  )
  .await
  .expect("resumed TCP early-data handshake should complete");
  assert_eq!(kind, Some(HandshakeKind::Resumed));
  assert!(
    early_data_accepted,
    "server should accept configured TLS 1.3 early data"
  );
  assert_eq!(delivered.load(Ordering::Acquire), SENTINEL.len());
  assert!(session_store.tls13_ticket_hit_count() >= 1);

  fixture.close_ct_gate();
  let before = delivered.load(Ordering::Acquire);
  let resume_hits_before = session_store.tls13_ticket_hit_count();
  let result = tcp_early_data_attempt(
    &listener,
    &server_config,
    address,
    client_config,
    delivered.clone(),
  )
  .await;
  assert!(
    session_store.tls13_ticket_hit_count() > resume_hits_before,
    "rejected TCP early-data attempt should consume a valid session ticket"
  );
  assert!(
    result.is_err(),
    "closed CT gate must reject resumed early data"
  );
  assert_eq!(
    delivered.load(Ordering::Acquire),
    before,
    "rejected early data must not reach the application"
  );
  fixture.assert_one_ct_reject();
}

#[tokio::test]
async fn quic_resumption_rechecks_live_ct_gate_with_and_without_zero_rtt() {
  for (mode, zero_rtt) in [
    (TlsServerResumptionMode::Stateful, QuicZeroRttMode::Off),
    (TlsServerResumptionMode::Stateless, QuicZeroRttMode::Off),
    (
      TlsServerResumptionMode::Stateful,
      QuicZeroRttMode::SafeMethods,
    ),
  ] {
    assert_quic_resumption_rechecks_gate(mode, zero_rtt).await;
  }
}

async fn assert_tcp_resumption_rechecks_gate(version: TlsVersion, mode: TlsServerResumptionMode) {
  let mut fixture = TestFixture::new(version, mode, QuicZeroRttMode::Off);
  let state = TlsResumptionState::default();
  let server_config = fixture.tcp_server_config(&state, 0);
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("TCP listener should bind");
  let address = listener.local_addr().expect("TCP address should resolve");
  let versions = match version {
    TlsVersion::Tls12 => &[&rustls::version::TLS12][..],
    TlsVersion::Tls13 => &[&rustls::version::TLS13][..],
  };
  let session_store = Arc::new(RecordingClientSessionStore::new());
  let client_config = Arc::new(fixture.client_config(versions, session_store.clone(), false, None));

  let (client, server) =
    tcp_connect_pair(&listener, &server_config, address, client_config.clone())
      .await
      .expect("initial TCP TLS handshake should complete");
  assert_full_handshake(client.get_ref().1.handshake_kind());
  tcp_roundtrip_and_close(client, server, b'1').await;

  let (mut resumed_client, mut resumed_server) =
    tcp_connect_pair(&listener, &server_config, address, client_config.clone())
      .await
      .expect("resumed TCP TLS handshake should complete");
  assert_eq!(
    resumed_client.get_ref().1.handshake_kind(),
    Some(HandshakeKind::Resumed),
    "{version:?} {mode:?} should resume"
  );
  assert!(session_store.resume_hit_count(version) >= 1);

  fixture.close_ct_gate();
  if version == TlsVersion::Tls13 && mode == TlsServerResumptionMode::Stateful {
    tcp_roundtrip(&mut resumed_client, &mut resumed_server, b'E').await;
  }
  close_tcp_pair(resumed_client, resumed_server).await;

  let resume_hits_before = session_store.resume_hit_count(version);
  let result = tcp_connect_pair(&listener, &server_config, address, client_config).await;
  assert!(
    session_store.resume_hit_count(version) > resume_hits_before,
    "rejected {version:?} {mode:?} attempt should retrieve valid resumption state"
  );
  assert!(
    result.is_err(),
    "closed CT gate must reject {version:?} {mode:?} resumption"
  );
  fixture.assert_one_ct_reject();
}

async fn assert_quic_resumption_rechecks_gate(
  mode: TlsServerResumptionMode,
  zero_rtt: QuicZeroRttMode,
) {
  let mut fixture = TestFixture::new(TlsVersion::Tls13, mode, zero_rtt);
  let state = TlsResumptionState::default();
  let server_config = fixture.quic_server_config(&state);
  let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
    .expect("QUIC server endpoint should bind");
  let address = server_endpoint
    .local_addr()
    .expect("QUIC server address should resolve");
  let session_store = Arc::new(RecordingClientSessionStore::new());
  let mut client_endpoint =
    Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("QUIC client endpoint should bind");
  client_endpoint.set_default_client_config(fixture.quic_client_config(session_store.clone()));

  let (client, server) = quic_connect(&client_endpoint, &server_endpoint, address)
    .await
    .expect("initial QUIC handshake should complete");
  quic_roundtrip(&client, &server, b'1').await;
  client.close(0u32.into(), b"initial complete");
  server.close(0u32.into(), b"initial complete");

  let (resumed_client, resumed_server, accepted_early_data) = quic_resume(
    &client_endpoint,
    &server_endpoint,
    address,
    zero_rtt == QuicZeroRttMode::SafeMethods,
  )
  .await
  .expect("resumed QUIC handshake should complete");
  assert!(session_store.tls13_ticket_hit_count() >= 1);
  assert_eq!(
    accepted_early_data,
    zero_rtt == QuicZeroRttMode::SafeMethods,
    "QUIC early-data acceptance should follow zero_rtt policy"
  );

  fixture.close_ct_gate();
  if mode == TlsServerResumptionMode::Stateful && zero_rtt == QuicZeroRttMode::Off {
    quic_roundtrip(&resumed_client, &resumed_server, b'E').await;
  }
  resumed_client.close(0u32.into(), b"resumed complete");
  resumed_server.close(0u32.into(), b"resumed complete");

  let delivered = Arc::new(AtomicUsize::new(0));
  let resume_hits_before = session_store.tls13_ticket_hit_count();
  let result = quic_rejected_resume(
    &client_endpoint,
    &server_endpoint,
    address,
    zero_rtt == QuicZeroRttMode::SafeMethods,
    delivered.clone(),
  )
  .await;
  assert!(
    session_store.tls13_ticket_hit_count() > resume_hits_before,
    "rejected QUIC attempt should consume a valid session ticket"
  );
  assert!(
    result.is_err(),
    "closed CT gate must reject QUIC resumption"
  );
  assert_eq!(
    delivered.load(Ordering::Acquire),
    0,
    "rejected QUIC early data must not reach the application"
  );
  fixture.assert_one_ct_reject();

  client_endpoint.close(0u32.into(), b"test complete");
  server_endpoint.close(0u32.into(), b"test complete");
}

struct TestFixture {
  _temp_dir: common::TempDir,
  config: Config,
  runtime: DownstreamCtRuntime,
  gate: Arc<AtomicBool>,
  metrics: Arc<Metrics>,
  root_cert: std::path::PathBuf,
}

impl TestFixture {
  fn new(version: TlsVersion, mode: TlsServerResumptionMode, zero_rtt: QuicZeroRttMode) -> Self {
    let temp_dir = common::TempDir::new("ct-resumption");
    let (root_cert, root_key) = common::create_self_signed_cert(temp_dir.path(), "ct-test-ca");
    let (leaf_cert, private_key) =
      common::create_ca_signed_server_cert(temp_dir.path(), SERVER_NAME, &root_cert, &root_key);
    let cert_chain = temp_dir.path().join("ct-resumption-chain.pem");
    let mut chain = std::fs::read(&leaf_cert).expect("leaf certificate should read");
    chain.extend(std::fs::read(&root_cert).expect("root certificate should read"));
    std::fs::write(&cert_chain, chain).expect("certificate chain should write");
    let mut config: Config =
      toml::from_str(&common::minimal_config_toml(&cert_chain, &private_key))
        .expect("test configuration should parse");
    config.tls.min_version = version;
    config.tls.max_version = version;
    config.tls.ct.mode = DownstreamCtMode::Enforce;
    config.tls.resumption.mode = mode;
    config.quic.zero_rtt = zero_rtt;

    let contexts = certificate_contexts(&config.tls).expect("certificate contexts should load");
    let partitions = certificate_partitions(&config.tls, &contexts);
    let gates = Arc::new(build_gates(&contexts));
    let gate = gates
      .get(&contexts[0].identity)
      .expect("default CT gate should exist")
      .clone();
    let metrics = Metrics::new();
    let mut status = disabled_status(&config.tls, &contexts);
    status.enabled = true;
    let runtime = DownstreamCtRuntime {
      inner: Arc::new(RuntimeInner {
        status: Arc::new(Mutex::new(status)),
        gates,
        certificate_bindings: Arc::new(build_certificate_bindings(&contexts)),
        list_stale_at: Arc::new(AtomicU64::new(u64::MAX)),
        partitions,
        worker: Mutex::new(None),
        metrics: metrics.clone(),
      }),
    };
    Self {
      _temp_dir: temp_dir,
      config,
      runtime,
      gate,
      metrics,
      root_cert,
    }
  }

  fn tcp_server_config(
    &self,
    state: &TlsResumptionState,
    max_early_data_size: u32,
  ) -> DownstreamTlsServerConfig {
    build_downstream_tls_server_config_with_resumption_and_ocsp(
      &self.config.crypto,
      &self.config.tls,
      &self.config.listeners,
      &self.config.routes,
      max_early_data_size,
      Some(state),
      None,
      None,
      Some(&self.runtime),
    )
    .expect("TCP TLS server config should build")
  }

  fn quic_server_config(&self, state: &TlsResumptionState) -> h3_quinn::quinn::ServerConfig {
    build_downstream_quic_server_config_with_resumption_and_ocsp(
      &self.config.crypto,
      &self.config.tls,
      &self.config.quic,
      None,
      &self.config.routes,
      Some(state),
      None,
      None,
      Some(&self.runtime),
    )
    .expect("QUIC TLS server config should build")
    .default_config()
  }

  fn client_config(
    &self,
    versions: &[&'static rustls::SupportedProtocolVersion],
    store: Arc<RecordingClientSessionStore>,
    enable_early_data: bool,
    alpn: Option<&[u8]>,
  ) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(&self.root_cert)
      .expect("root certificate should open")
      .collect::<Result<Vec<_>, _>>()
      .expect("root certificate should parse");
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1, "test root should be trusted");
    let mut config =
      ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(versions)
        .expect("client TLS versions should configure")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::store(store);
    config.enable_early_data = enable_early_data;
    if let Some(alpn) = alpn {
      config.alpn_protocols = vec![alpn.to_vec()];
    }
    config
  }

  fn quic_client_config(
    &self,
    store: Arc<RecordingClientSessionStore>,
  ) -> h3_quinn::quinn::ClientConfig {
    let client = self.client_config(&[&rustls::version::TLS13], store, true, Some(b"h3"));
    let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from(client)
      .expect("QUIC client TLS config should build");
    h3_quinn::quinn::ClientConfig::new(Arc::new(crypto))
  }

  fn close_ct_gate(&mut self) {
    self.gate.store(true, Ordering::Release);
  }

  fn assert_one_ct_reject(&self) {
    let output = self.metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );
    assert!(
      output.contains("oxibelt_tls_ct_handshake_rejects_total 1\n"),
      "CT rejection metric should record exactly one denied handshake"
    );
  }
}

#[derive(Debug)]
struct RecordingClientSessionStore {
  inner: ClientSessionMemoryCache,
  tls12_hits: AtomicUsize,
  tls13_ticket_hits: AtomicUsize,
}

impl RecordingClientSessionStore {
  fn new() -> Self {
    Self {
      inner: ClientSessionMemoryCache::new(32),
      tls12_hits: AtomicUsize::new(0),
      tls13_ticket_hits: AtomicUsize::new(0),
    }
  }

  fn resume_hit_count(&self, version: TlsVersion) -> usize {
    match version {
      TlsVersion::Tls12 => self.tls12_hits.load(Ordering::Acquire),
      TlsVersion::Tls13 => self.tls13_ticket_hit_count(),
    }
  }

  fn tls13_ticket_hit_count(&self) -> usize {
    self.tls13_ticket_hits.load(Ordering::Acquire)
  }
}

impl ClientSessionStore for RecordingClientSessionStore {
  fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
    self.inner.set_kx_hint(server_name, group);
  }

  fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
    self.inner.kx_hint(server_name)
  }

  fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
    self.inner.set_tls12_session(server_name, value);
  }

  fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
    let session = self.inner.tls12_session(server_name);
    if session.is_some() {
      self.tls12_hits.fetch_add(1, Ordering::AcqRel);
    }
    session
  }

  fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
    self.inner.remove_tls12_session(server_name);
  }

  fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
    self.inner.insert_tls13_ticket(server_name, value);
  }

  fn take_tls13_ticket(
    &self,
    server_name: &ServerName<'static>,
  ) -> Option<Tls13ClientSessionValue> {
    let ticket = self.inner.take_tls13_ticket(server_name);
    if ticket.is_some() {
      self.tls13_ticket_hits.fetch_add(1, Ordering::AcqRel);
    }
    ticket
  }
}

async fn tcp_connect_pair(
  listener: &TcpListener,
  server_config: &DownstreamTlsServerConfig,
  address: std::net::SocketAddr,
  client_config: Arc<ClientConfig>,
) -> Result<(ClientTlsStream<TcpStream>, ServerTlsStream<TcpStream>), String> {
  let server = async {
    let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
      .await
      .map_err(|error| error.to_string())?;
    let selected = server_config.select(&start.client_hello());
    start
      .into_stream(selected)
      .await
      .map_err(|error| error.to_string())
  };
  let client = async {
    let stream = TcpStream::connect(address)
      .await
      .map_err(|error| error.to_string())?;
    TlsConnector::from(client_config)
      .connect(test_server_name(), stream)
      .await
      .map_err(|error| error.to_string())
  };
  let (client, server) = tokio::time::timeout(IO_TIMEOUT, async { tokio::join!(client, server) })
    .await
    .map_err(|_| "TCP handshake timed out".to_string())?;
  Ok((client?, server?))
}

async fn tcp_roundtrip(
  client: &mut ClientTlsStream<TcpStream>,
  server: &mut ServerTlsStream<TcpStream>,
  byte: u8,
) {
  tokio::time::timeout(IO_TIMEOUT, async {
    client
      .write_all(&[byte])
      .await
      .expect("TCP client should write");
    client.flush().await.expect("TCP client should flush");
    let mut received = [0u8; 1];
    server
      .read_exact(&mut received)
      .await
      .expect("TCP server should read");
    assert_eq!(received, [byte]);
    server
      .write_all(&received)
      .await
      .expect("TCP server should write");
    server.flush().await.expect("TCP server should flush");
    client
      .read_exact(&mut received)
      .await
      .expect("TCP client should read");
    assert_eq!(received, [byte]);
  })
  .await
  .expect("TCP roundtrip should not time out");
}

async fn tcp_roundtrip_and_close(
  mut client: ClientTlsStream<TcpStream>,
  mut server: ServerTlsStream<TcpStream>,
  byte: u8,
) {
  tcp_roundtrip(&mut client, &mut server, byte).await;
  close_tcp_pair(client, server).await;
}

async fn close_tcp_pair(
  mut client: ClientTlsStream<TcpStream>,
  mut server: ServerTlsStream<TcpStream>,
) {
  tokio::time::timeout(IO_TIMEOUT, async {
    server
      .shutdown()
      .await
      .expect("TCP server should shut down");
    let mut trailing = Vec::new();
    client
      .read_to_end(&mut trailing)
      .await
      .expect("TCP client should process close and tickets");
  })
  .await
  .expect("TCP shutdown should not time out");
}

async fn tcp_early_data_attempt(
  listener: &TcpListener,
  server_config: &DownstreamTlsServerConfig,
  address: std::net::SocketAddr,
  client_config: Arc<ClientConfig>,
  delivered: Arc<AtomicUsize>,
) -> Result<(Option<HandshakeKind>, bool), String> {
  let server = async {
    let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
      .await
      .map_err(|error| error.to_string())?;
    let selected = server_config.select(&start.client_hello());
    let mut stream = start
      .into_stream(selected)
      .await
      .map_err(|error| error.to_string())?;
    let mut received = Vec::new();
    if let Some(mut early_data) = stream.get_mut().1.early_data() {
      early_data
        .read_to_end(&mut received)
        .map_err(|error| error.to_string())?;
    }
    if received.is_empty() {
      stream
        .read_to_end(&mut received)
        .await
        .map_err(|error| error.to_string())?;
    }
    delivered.fetch_add(received.len(), Ordering::AcqRel);
    stream.shutdown().await.map_err(|error| error.to_string())?;
    Ok::<_, String>(received)
  };
  let client = async {
    let stream = TcpStream::connect(address)
      .await
      .map_err(|error| error.to_string())?;
    let mut stream = TlsConnector::from(client_config)
      .early_data(true)
      .connect(test_server_name(), stream)
      .await
      .map_err(|error| error.to_string())?;
    stream
      .write_all(SENTINEL)
      .await
      .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;
    stream.shutdown().await.map_err(|error| error.to_string())?;
    let mut trailing = Vec::new();
    stream
      .read_to_end(&mut trailing)
      .await
      .map_err(|error| error.to_string())?;
    Ok::<_, String>((
      stream.get_ref().1.handshake_kind(),
      stream.get_ref().1.is_early_data_accepted(),
    ))
  };
  let (client, server) = tokio::time::timeout(IO_TIMEOUT, async { tokio::join!(client, server) })
    .await
    .map_err(|_| "TCP early-data attempt timed out".to_string())?;
  let client = client?;
  let received = server?;
  if received != SENTINEL {
    return Err("TCP application received unexpected data".to_string());
  }
  Ok(client)
}

mod quic;
use quic::*;

fn assert_full_handshake(kind: Option<HandshakeKind>) {
  assert!(
    matches!(
      kind,
      Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
    ),
    "initial connection should use a full handshake, got {kind:?}"
  );
}

fn test_server_name() -> ServerName<'static> {
  ServerName::try_from(SERVER_NAME.to_string()).expect("test server name should be valid")
}
