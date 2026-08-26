use std::sync::Arc;

use anyhow::{Context, anyhow};
use h3_quinn::quinn::ClientConfig as QuinnClientConfig;
use h3_quinn::quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode, Resumption};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::EchConfigListBytes;

use crate::config::{
  CryptoConfig, OutboundTlsRevocationConfig, QuicConfig, UpstreamEchConfig, UpstreamEchMode,
  UpstreamTlsResumptionConfig, UpstreamTlsSubjectAltName, UpstreamTlsTrust,
};

use super::certificate_io::read_existing_file;
use super::client_roots::{load_upstream_root_store_with_trust, load_webpki_root_store};
use super::outbound_revocation::OutboundRevocationRuntime;
use super::resumption::{
  TlsResumptionState, upstream_client_config_key, upstream_client_resumption,
};

/// Builds the upstream TCP TLS client configuration used by proxy clients.
pub fn build_upstream_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
) -> anyhow::Result<ClientConfig> {
  let crypto = CryptoConfig::default();
  build_upstream_client_config_with_crypto_and_resumption(
    &crypto,
    extra_root_certificates,
    ech,
    &UpstreamTlsResumptionConfig::default(),
    None,
    "default",
  )
}

pub(crate) fn build_webpki_client_config_with_crypto(
  crypto: &CryptoConfig,
) -> anyhow::Result<ClientConfig> {
  let provider = Arc::new(super::provider::crypto_provider(crypto)?);
  let roots = load_webpki_root_store();
  let builder = ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()
    .context("failed to configure WebPKI TLS versions")?;
  let mut client_config = builder.with_root_certificates(roots).with_no_client_auth();
  client_config.resumption = upstream_client_resumption(&UpstreamTlsResumptionConfig::default());
  Ok(client_config)
}

pub fn build_upstream_client_config_with_resumption(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
) -> anyhow::Result<ClientConfig> {
  let crypto = CryptoConfig::default();
  build_upstream_client_config_with_crypto_and_resumption(
    &crypto,
    extra_root_certificates,
    ech,
    resumption,
    state,
    upstream_name,
  )
}

pub(crate) fn build_upstream_client_config_with_crypto_resumption_and_revocation(
  crypto: &CryptoConfig,
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<ClientConfig> {
  build_upstream_client_config_with_trust(
    crypto,
    extra_root_certificates,
    UpstreamTlsTrust::Inherit,
    &[],
    ech,
    resumption,
    state,
    upstream_name,
    revocation,
  )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_upstream_client_config_with_trust(
  crypto: &CryptoConfig,
  extra_root_certificates: &[std::path::PathBuf],
  trust: UpstreamTlsTrust,
  subject_alt_names: &[UpstreamTlsSubjectAltName],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<ClientConfig> {
  let key = upstream_client_config_key(
    "tcp",
    crypto.tls_provider,
    upstream_name,
    extra_root_certificates,
    trust,
    subject_alt_names,
    ech,
    resumption,
  )?;
  let revocation_enabled = revocation
    .as_ref()
    .is_some_and(|(_, policy)| policy.enabled());
  if let Some(state) = state
    && !revocation_enabled
  {
    return state.upstream_client_config(key, || {
      build_uncached_upstream_client_config(
        crypto,
        extra_root_certificates,
        trust,
        subject_alt_names,
        ech,
        resumption,
        false,
        None,
      )
    });
  }
  build_uncached_upstream_client_config(
    crypto,
    extra_root_certificates,
    trust,
    subject_alt_names,
    ech,
    resumption,
    false,
    revocation,
  )
}

#[allow(clippy::too_many_arguments)]
fn build_uncached_upstream_client_config(
  crypto: &CryptoConfig,
  extra_root_certificates: &[std::path::PathBuf],
  trust: UpstreamTlsTrust,
  subject_alt_names: &[UpstreamTlsSubjectAltName],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  quic_only: bool,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<ClientConfig> {
  let provider = Arc::new(super::provider::crypto_provider(crypto)?);
  let roots = Arc::new(load_upstream_root_store_with_trust(
    extra_root_certificates,
    trust,
  )?);
  let revocation_enabled = revocation
    .as_ref()
    .is_some_and(|(_, policy)| policy.enabled());

  let builder = ClientConfig::builder_with_provider(provider.clone());
  let builder = match upstream_ech_mode(ech)? {
    Some(mode) => builder
      .with_ech(mode)
      .context("failed to configure upstream TLS 1.3 ECH")?,
    None if quic_only => builder
      .with_protocol_versions(&[&rustls::version::TLS13])
      .context("failed to configure upstream QUIC TLS versions")?,
    None => builder
      .with_safe_default_protocol_versions()
      .context("failed to configure upstream TLS versions")?,
  };

  let mut client_config = if !subject_alt_names.is_empty() || revocation.is_some() {
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
      .build()
      .context("failed to build upstream WebPKI verifier")?;
    let verifier =
      super::upstream_san::explicit_subject_alt_name_verifier(verifier, subject_alt_names)?;
    let verifier = if let Some((runtime, policy)) = revocation {
      runtime.verifier(verifier, policy)
    } else {
      verifier
    };
    builder
      .dangerous()
      .with_custom_certificate_verifier(verifier)
      .with_no_client_auth()
  } else {
    builder.with_root_certificates(roots).with_no_client_auth()
  };
  client_config.resumption = effective_upstream_client_resumption(resumption, revocation_enabled);

  Ok(client_config)
}

fn effective_upstream_client_resumption(
  resumption: &UpstreamTlsResumptionConfig,
  revocation_enabled: bool,
) -> Resumption {
  if revocation_enabled {
    Resumption::disabled()
  } else {
    upstream_client_resumption(resumption)
  }
}

pub fn build_upstream_quic_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
) -> anyhow::Result<QuinnClientConfig> {
  let crypto = CryptoConfig::default();
  build_upstream_quic_client_config_with_crypto_and_resumption(
    &crypto,
    extra_root_certificates,
    ech,
    quic,
    &UpstreamTlsResumptionConfig::default(),
    None,
    "default",
  )
}

pub(crate) fn build_upstream_client_config_with_crypto_and_resumption(
  crypto: &CryptoConfig,
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
) -> anyhow::Result<ClientConfig> {
  build_upstream_client_config_with_crypto_resumption_and_revocation(
    crypto,
    extra_root_certificates,
    ech,
    resumption,
    state,
    upstream_name,
    None,
  )
}

pub fn build_upstream_quic_client_config_with_resumption(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
) -> anyhow::Result<QuinnClientConfig> {
  let crypto = CryptoConfig::default();
  build_upstream_quic_client_config_with_crypto_and_resumption(
    &crypto,
    extra_root_certificates,
    ech,
    quic,
    resumption,
    state,
    upstream_name,
  )
}

pub(crate) fn build_upstream_quic_client_config_with_crypto_and_resumption(
  crypto: &CryptoConfig,
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
) -> anyhow::Result<QuinnClientConfig> {
  build_upstream_quic_client_config_with_crypto_resumption_and_revocation(
    crypto,
    extra_root_certificates,
    ech,
    quic,
    resumption,
    state,
    upstream_name,
    None,
  )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_upstream_quic_client_config_with_crypto_resumption_and_revocation(
  crypto: &CryptoConfig,
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<QuinnClientConfig> {
  build_upstream_quic_client_config_with_trust(
    crypto,
    extra_root_certificates,
    UpstreamTlsTrust::Inherit,
    &[],
    ech,
    quic,
    resumption,
    state,
    upstream_name,
    revocation,
  )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_upstream_quic_client_config_with_trust(
  crypto: &CryptoConfig,
  extra_root_certificates: &[std::path::PathBuf],
  trust: UpstreamTlsTrust,
  subject_alt_names: &[UpstreamTlsSubjectAltName],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<QuinnClientConfig> {
  let key = upstream_client_config_key(
    "quic",
    crypto.tls_provider,
    upstream_name,
    extra_root_certificates,
    trust,
    subject_alt_names,
    ech,
    resumption,
  )?;
  let revocation_enabled = revocation
    .as_ref()
    .is_some_and(|(_, policy)| policy.enabled());
  let mut client_config = if let Some(state) = state
    && !revocation_enabled
  {
    state.upstream_client_config(key, || {
      build_uncached_upstream_client_config(
        crypto,
        extra_root_certificates,
        trust,
        subject_alt_names,
        ech,
        resumption,
        true,
        None,
      )
    })?
  } else {
    build_uncached_upstream_client_config(
      crypto,
      extra_root_certificates,
      trust,
      subject_alt_names,
      ech,
      resumption,
      true,
      revocation,
    )?
  };
  client_config.alpn_protocols = vec![b"h3".to_vec()];

  let quic_crypto =
    QuicClientConfig::try_from(client_config).context("failed to build QUIC client TLS config")?;
  let mut quic_config = QuinnClientConfig::new(Arc::new(quic_crypto));
  quic_config.transport_config(crate::quic::transport_config(
    &quic.upstream.transport,
    "quic.upstream.transport",
  )?);
  Ok(quic_config)
}

fn upstream_ech_mode(ech: &UpstreamEchConfig) -> anyhow::Result<Option<EchMode>> {
  match ech.mode {
    UpstreamEchMode::Disabled => Ok(None),
    UpstreamEchMode::Grease => Ok(Some(EchMode::Grease(build_ech_grease_config()?))),
    UpstreamEchMode::ConfigList => Ok(Some(EchMode::Enable(load_ech_config(ech)?))),
  }
}

fn build_ech_grease_config() -> anyhow::Result<EchGreaseConfig> {
  let suite = default_ech_hpke_suites()
    .first()
    .copied()
    .ok_or_else(|| anyhow!("aws-lc-rs provider does not expose HPKE suites for ECH"))?;
  let (public_key, _private_key) = suite
    .generate_key_pair()
    .context("failed to generate ECH GREASE placeholder key")?;

  Ok(EchGreaseConfig::new(suite, public_key))
}

fn load_ech_config(ech: &UpstreamEchConfig) -> anyhow::Result<EchConfig> {
  let path = ech
    .config_list_file
    .as_ref()
    .ok_or_else(|| anyhow!("upstream ECH config_list_file must be configured"))?;
  let bytes = read_existing_file("upstream ECH config list file", path)?;

  EchConfig::new(EchConfigListBytes::from(bytes), default_ech_hpke_suites()).with_context(|| {
    format!(
      "failed to parse upstream ECH config list from {}",
      path.display()
    )
  })
}

fn default_ech_hpke_suites() -> &'static [&'static dyn Hpke] {
  rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
}

#[cfg(test)]
mod tests {
  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  use std::ffi::OsStr;
  use std::fs;
  use std::path::{Path, PathBuf};
  use std::process::{Command, Stdio};
  use std::time::Duration;

  use crate::config::{
    Config, ListenerConfig, OcspConfig, ProxyProtocolConfig, Tls12CipherSuite,
    Tls12NegotiationConfig, Tls13CipherSuite, Tls13NegotiationConfig, TlsClientAuthConfig,
    TlsConfig, TlsKeyExchangeGroup, TlsRemoteSignerConfig, TlsVersion, UpstreamEchConfig,
    UpstreamTlsConfig, UpstreamTlsResumptionConfig, UpstreamTlsSubjectAltName,
  };
  use crate::metrics::Metrics;
  use rustls::HandshakeKind;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::{TcpListener, TcpStream};
  use tokio_rustls::{TlsAcceptor, TlsConnector};

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn upstream_revocation_disables_tls_resumption() {
    let temp_dir = common::TempDir::new("upstream-revocation-resumption");
    let server_name = "upstream-revocation-resumption.test";
    let (ca_cert_path, ca_key_path) =
      common::create_self_signed_cert(temp_dir.path(), "upstream-revocation-ca");
    let (server_cert_path, server_key_path) =
      create_ocsp_aia_server_cert(temp_dir.path(), server_name, &ca_cert_path, &ca_key_path);
    let chain_path = write_certificate_chain(temp_dir.path(), &server_cert_path, &ca_cert_path);
    let server_tls = test_tls_config(chain_path.clone(), server_key_path.clone());

    let resuming_client = build_upstream_client_config_with_resumption(
      std::slice::from_ref(&ca_cert_path),
      &UpstreamEchConfig::default(),
      &UpstreamTlsResumptionConfig::default(),
      None,
      "resumption-control",
    )
    .expect("non-revocation upstream client config should build");
    let (_, second_kind, first_tickets) =
      run_two_handshakes(&server_tls, resuming_client, server_name).await;
    assert!(
      first_tickets > 0,
      "control handshake should receive TLS 1.3 tickets"
    );
    assert_eq!(
      second_kind,
      Some(HandshakeKind::Resumed),
      "non-revocation upstream client should preserve configured TLS resumption"
    );

    let revocation_config = upstream_revocation_config(&chain_path, &server_key_path);
    let revocation = OutboundRevocationRuntime::new(&revocation_config, Metrics::new())
      .await
      .expect("outbound revocation runtime should build");
    let crypto = CryptoConfig::default();
    let revocation_client = build_upstream_client_config_with_crypto_resumption_and_revocation(
      &crypto,
      std::slice::from_ref(&ca_cert_path),
      &UpstreamEchConfig::default(),
      &UpstreamTlsResumptionConfig::default(),
      None,
      "revocation",
      Some((&revocation, revocation.default_policy())),
    )
    .expect("revocation-aware upstream client config should build");
    let (_, second_kind, _) = run_two_handshakes(&server_tls, revocation_client, server_name).await;
    assert!(
      matches!(
        second_kind,
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
      ),
      "revocation-aware upstream client must force a fresh certificate verification"
    );
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn explicit_subject_alt_names_separate_sni_from_certificate_identity() {
    let temp_dir = common::TempDir::new("upstream-explicit-san");
    let certificate_dns_name = "certificate.example.test";
    let certificate_uri = "spiffe://example.test/ns/backend/sa/service";
    let sni_name = "sni.example.test";
    let (ca_cert_path, ca_key_path) =
      common::create_self_signed_cert(temp_dir.path(), "upstream-explicit-san-ca");
    let (server_cert_path, server_key_path) = create_subject_alt_name_server_cert(
      temp_dir.path(),
      certificate_dns_name,
      certificate_uri,
      &ca_cert_path,
      &ca_key_path,
    );
    let chain_path = write_certificate_chain(temp_dir.path(), &server_cert_path, &ca_cert_path);
    let server_tls = test_tls_config(chain_path, server_key_path);
    let client = |subject_alt_names: Vec<UpstreamTlsSubjectAltName>, roots: &[PathBuf]| {
      let policy = UpstreamTlsConfig {
        subject_alt_names,
        ..UpstreamTlsConfig::default()
      };
      build_upstream_client_config_with_trust(
        &CryptoConfig::default(),
        roots,
        UpstreamTlsTrust::Inherit,
        &policy.subject_alt_names,
        &policy.ech,
        &policy.resumption,
        None,
        "explicit-san-test",
        None,
      )
      .expect("upstream TLS client should build")
    };

    assert!(
      run_one_handshake(
        &server_tls,
        client(
          vec![UpstreamTlsSubjectAltName::Dns(
            certificate_dns_name.to_string()
          )],
          std::slice::from_ref(&ca_cert_path),
        ),
        sni_name,
      )
      .await,
      "an explicit DNS SAN should authenticate independently of SNI"
    );
    assert!(
      run_one_handshake(
        &server_tls,
        client(
          vec![UpstreamTlsSubjectAltName::Uri(certificate_uri.to_string())],
          std::slice::from_ref(&ca_cert_path),
        ),
        sni_name,
      )
      .await,
      "an exact URI SAN should authenticate after chain validation"
    );
    assert!(
      !run_one_handshake(
        &server_tls,
        client(
          vec![UpstreamTlsSubjectAltName::Uri(
            "spiffe://example.test/ns/backend/sa/other".to_string()
          )],
          std::slice::from_ref(&ca_cert_path),
        ),
        certificate_dns_name,
      )
      .await,
      "a matching SNI must not authenticate when an explicit SAN list mismatches"
    );
    assert!(
      !run_one_handshake(
        &server_tls,
        client(
          vec![UpstreamTlsSubjectAltName::Uri(
            "spiffe://EXAMPLE.test/ns/backend/sa/service".to_string()
          )],
          std::slice::from_ref(&ca_cert_path),
        ),
        certificate_dns_name,
      )
      .await,
      "URI SAN authentication must preserve exact case instead of normalizing identities"
    );

    let wildcard_dir = temp_dir.path().join("wildcard");
    fs::create_dir(&wildcard_dir).expect("wildcard certificate directory should be created");
    let (wildcard_cert_path, wildcard_key_path) = create_subject_alt_name_server_cert(
      &wildcard_dir,
      "*.example.test",
      certificate_uri,
      &ca_cert_path,
      &ca_key_path,
    );
    let wildcard_chain_path =
      write_certificate_chain(&wildcard_dir, &wildcard_cert_path, &ca_cert_path);
    let wildcard_server_tls = test_tls_config(wildcard_chain_path, wildcard_key_path);
    assert!(
      !run_one_handshake(
        &wildcard_server_tls,
        client(
          vec![UpstreamTlsSubjectAltName::Dns(
            "backend.example.test".to_string()
          )],
          std::slice::from_ref(&ca_cert_path),
        ),
        "backend.example.test",
      )
      .await,
      "a certificate wildcard must not satisfy an explicitly configured exact DNS SAN"
    );

    let (untrusted_ca_path, _untrusted_ca_key_path) =
      common::create_self_signed_cert(temp_dir.path(), "upstream-explicit-san-untrusted-ca");
    assert!(
      !run_one_handshake(
        &server_tls,
        client(
          vec![UpstreamTlsSubjectAltName::Uri(certificate_uri.to_string())],
          std::slice::from_ref(&untrusted_ca_path),
        ),
        sni_name,
      )
      .await,
      "a matching URI SAN must not bypass certificate-chain validation"
    );
  }

  async fn run_one_handshake(
    server_tls: &TlsConfig,
    client_config: ClientConfig,
    server_name: &str,
  ) -> bool {
    let server_config = crate::tls::build_server_config(server_tls, &test_listeners())
      .expect("server TLS config should build");
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("test TLS listener should bind");
    let addr = listener
      .local_addr()
      .expect("listener address should exist");
    let acceptor = TlsAcceptor::from(server_config);
    let server = tokio::spawn(async move {
      let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
      acceptor
        .accept(stream)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
    });

    let stream = TcpStream::connect(addr)
      .await
      .expect("client should connect");
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
      .expect("test server name should be valid");
    let client_result = tokio::time::timeout(
      Duration::from_secs(5),
      TlsConnector::from(Arc::new(client_config)).connect(server_name, stream),
    )
    .await
    .expect("client TLS handshake should not time out");
    let succeeded = client_result.is_ok();
    drop(client_result);

    let server_result = tokio::time::timeout(Duration::from_secs(5), server)
      .await
      .expect("server TLS handshake should not time out")
      .expect("server task should finish");
    if succeeded {
      server_result.expect("server TLS handshake should complete when the client accepted it");
    }
    succeeded
  }

  async fn run_two_handshakes(
    server_tls: &TlsConfig,
    client_config: ClientConfig,
    server_name: &str,
  ) -> (Option<HandshakeKind>, Option<HandshakeKind>, u32) {
    let server_config = crate::tls::build_server_config(server_tls, &test_listeners())
      .expect("server TLS config should build");
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("test TLS listener should bind");
    let addr = listener
      .local_addr()
      .expect("listener address should exist");
    let acceptor = TlsAcceptor::from(server_config);
    let server = tokio::spawn(async move {
      for _ in 0..2 {
        let (stream, _) = listener.accept().await.expect("server should accept");
        let mut stream = acceptor
          .accept(stream)
          .await
          .expect("server TLS handshake should complete");
        let mut byte = [0u8; 1];
        stream
          .read_exact(&mut byte)
          .await
          .expect("server should read client byte");
        stream
          .write_all(&byte)
          .await
          .expect("server should write response byte");
        stream
          .shutdown()
          .await
          .expect("server TLS shutdown should complete");
      }
    });

    let client_config = Arc::new(client_config);
    let (first_kind, first_tickets) = connect_once(addr, client_config.clone(), server_name).await;
    let (second_kind, _) = connect_once(addr, client_config, server_name).await;
    server.await.expect("server task should finish");
    (first_kind, second_kind, first_tickets)
  }

  async fn connect_once(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    server_name: &str,
  ) -> (Option<HandshakeKind>, u32) {
    let stream = TcpStream::connect(addr)
      .await
      .expect("client should connect");
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
      .expect("test server name should be valid");
    let mut stream = TlsConnector::from(client_config)
      .connect(server_name, stream)
      .await
      .expect("client TLS handshake should complete");
    let kind = stream.get_ref().1.handshake_kind();
    stream
      .write_all(&[42])
      .await
      .expect("client should write request byte");
    stream
      .flush()
      .await
      .expect("client should flush request byte");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
      .await
      .expect("client read should not time out")
      .expect("client should read response");
    assert_eq!(response, vec![42]);
    (kind, stream.get_ref().1.tls13_tickets_received())
  }

  fn upstream_revocation_config(cert_path: &Path, key_path: &Path) -> Config {
    let raw = common::minimal_config_toml(cert_path, key_path)
      + r#"

[proxy.upstream_revocation.ocsp]
mode = "live_fetch"
failure_policy = "degraded_allow"
request_timeout_ms = 1
"#;
    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  fn test_tls_config(cert_path: PathBuf, key_path: PathBuf) -> TlsConfig {
    TlsConfig {
      server_names: Vec::new(),
      cert_chain: cert_path,
      private_key: Some(key_path),
      remote_signer: TlsRemoteSignerConfig::default(),
      require_sni: false,
      reject_unknown_sni: false,
      ssl_early_data: None,
      certificates: Vec::new(),
      min_version: TlsVersion::Tls13,
      max_version: TlsVersion::Tls13,
      tls12: Tls12NegotiationConfig {
        groups: vec![
          Tls12CipherSuite::EcdheEcdsaAes256GcmSha384,
          Tls12CipherSuite::EcdheEcdsaAes128GcmSha256,
          Tls12CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
          Tls12CipherSuite::EcdheRsaAes256GcmSha384,
          Tls12CipherSuite::EcdheRsaAes128GcmSha256,
          Tls12CipherSuite::EcdheRsaChacha20Poly1305Sha256,
        ],
        key_exchange_groups: vec![
          TlsKeyExchangeGroup::X25519,
          TlsKeyExchangeGroup::Secp256r1,
          TlsKeyExchangeGroup::Secp384r1,
        ],
      },
      tls13: Tls13NegotiationConfig {
        key_exchange_groups: vec![
          TlsKeyExchangeGroup::X25519MlKem768,
          TlsKeyExchangeGroup::X25519,
          TlsKeyExchangeGroup::Secp256r1,
        ],
        ciphers: vec![
          Tls13CipherSuite::Aes256GcmSha384,
          Tls13CipherSuite::Aes128GcmSha256,
          Tls13CipherSuite::Chacha20Poly1305Sha256,
        ],
      },
      key_exchange_groups: vec![
        TlsKeyExchangeGroup::X25519MlKem768,
        TlsKeyExchangeGroup::X25519,
        TlsKeyExchangeGroup::Secp256r1,
      ],
      session_tickets: true,
      session_ticket_rotation_seconds: 86_400,
      resumption: Default::default(),
      client_auth: TlsClientAuthConfig::default(),
      ocsp: OcspConfig::default(),
      crlite: crate::config::CrliteConfig::default(),
      ct: crate::config::DownstreamCtConfig::default(),
    }
  }

  fn test_listeners() -> ListenerConfig {
    ListenerConfig {
      https_bind: "127.0.0.1:8443".parse().unwrap(),
      https_binds: vec!["127.0.0.1:8443".parse().unwrap()],
      http_bind: None,
      http_binds: Vec::new(),
      http_mode: Default::default(),
      http1: true,
      http2: false,
      http3: false,
      proxy_protocol: ProxyProtocolConfig::default(),
    }
  }

  fn create_ocsp_aia_server_cert(
    dir: &Path,
    common_name: &str,
    ca_cert_path: &Path,
    ca_key_path: &Path,
  ) -> (PathBuf, PathBuf) {
    let key_path = dir.join("ocsp-aia-server.key");
    let cert_path = dir.join("ocsp-aia-server.pem");
    let csr_path = dir.join("ocsp-aia-server.csr");
    let config_path = dir.join("ocsp-aia-server.cnf");
    fs::write(
      &config_path,
      format!(
        "[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = req_ext\nprompt = no\n\n[req_distinguished_name]\nCN = {common_name}\n\n[req_ext]\nsubjectAltName = @alt_names\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\nauthorityInfoAccess = OCSP;URI:http://127.0.0.1:9/ocsp\n\n[alt_names]\nDNS.1 = {common_name}\n"
      ),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", config_path.display()));

    run_command(
      "openssl",
      &[
        OsStr::new("req"),
        OsStr::new("-newkey"),
        OsStr::new("rsa:2048"),
        OsStr::new("-sha256"),
        OsStr::new("-nodes"),
        OsStr::new("-config"),
        config_path.as_os_str(),
        OsStr::new("-keyout"),
        key_path.as_os_str(),
        OsStr::new("-out"),
        csr_path.as_os_str(),
      ],
    );
    run_command(
      "openssl",
      &[
        OsStr::new("x509"),
        OsStr::new("-req"),
        OsStr::new("-in"),
        csr_path.as_os_str(),
        OsStr::new("-CA"),
        ca_cert_path.as_os_str(),
        OsStr::new("-CAkey"),
        ca_key_path.as_os_str(),
        OsStr::new("-CAcreateserial"),
        OsStr::new("-days"),
        OsStr::new("1"),
        OsStr::new("-sha256"),
        OsStr::new("-extfile"),
        config_path.as_os_str(),
        OsStr::new("-extensions"),
        OsStr::new("req_ext"),
        OsStr::new("-out"),
        cert_path.as_os_str(),
      ],
    );
    (cert_path, key_path)
  }

  fn create_subject_alt_name_server_cert(
    dir: &Path,
    dns_name: &str,
    uri: &str,
    ca_cert_path: &Path,
    ca_key_path: &Path,
  ) -> (PathBuf, PathBuf) {
    let key_path = dir.join("explicit-san-server.key");
    let cert_path = dir.join("explicit-san-server.pem");
    let csr_path = dir.join("explicit-san-server.csr");
    let config_path = dir.join("explicit-san-server.cnf");
    fs::write(
      &config_path,
      format!(
        "[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = req_ext\nprompt = no\n\n[req_distinguished_name]\nCN = {dns_name}\n\n[req_ext]\nsubjectAltName = @alt_names\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n\n[alt_names]\nDNS.1 = {dns_name}\nURI.1 = {uri}\n"
      ),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", config_path.display()));

    run_command(
      "openssl",
      &[
        OsStr::new("req"),
        OsStr::new("-newkey"),
        OsStr::new("rsa:2048"),
        OsStr::new("-sha256"),
        OsStr::new("-nodes"),
        OsStr::new("-config"),
        config_path.as_os_str(),
        OsStr::new("-keyout"),
        key_path.as_os_str(),
        OsStr::new("-out"),
        csr_path.as_os_str(),
      ],
    );
    run_command(
      "openssl",
      &[
        OsStr::new("x509"),
        OsStr::new("-req"),
        OsStr::new("-in"),
        csr_path.as_os_str(),
        OsStr::new("-CA"),
        ca_cert_path.as_os_str(),
        OsStr::new("-CAkey"),
        ca_key_path.as_os_str(),
        OsStr::new("-CAcreateserial"),
        OsStr::new("-days"),
        OsStr::new("1"),
        OsStr::new("-sha256"),
        OsStr::new("-extfile"),
        config_path.as_os_str(),
        OsStr::new("-extensions"),
        OsStr::new("req_ext"),
        OsStr::new("-out"),
        cert_path.as_os_str(),
      ],
    );
    (cert_path, key_path)
  }

  fn write_certificate_chain(dir: &Path, leaf_path: &Path, issuer_path: &Path) -> PathBuf {
    let chain_path = dir.join("ocsp-aia-server-chain.pem");
    let mut chain = fs::read(leaf_path)
      .unwrap_or_else(|error| panic!("failed to read {}: {error}", leaf_path.display()));
    chain.extend(
      fs::read(issuer_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", issuer_path.display())),
    );
    fs::write(&chain_path, chain)
      .unwrap_or_else(|error| panic!("failed to write {}: {error}", chain_path.display()));
    chain_path
  }

  fn run_command(command: &str, args: &[impl AsRef<OsStr>]) {
    let status = Command::new(command)
      .args(args.iter().map(AsRef::as_ref))
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .status()
      .unwrap_or_else(|error| panic!("failed to spawn {command}: {error}"));
    assert!(status.success(), "{command} failed with status {status}");
  }
}
