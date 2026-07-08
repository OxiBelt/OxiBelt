//! TLS configuration builders for downstream, upstream, admin, TURN, and QUIC transports.
//! Certificate loading and resumption keys stay scoped to the transport that uses them.

use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use h3_quinn::quinn::ServerConfig as QuinnServerConfig;
use h3_quinn::quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::{RootCertStore, ServerConfig, sign::CertifiedKey};

use self::certificate_io::{end_entity_cert, load_certs, load_private_key};
use self::negotiation::{
  downstream_crypto_provider_for_policy, downstream_crypto_provider_for_tls12,
  downstream_crypto_provider_for_tls13,
};
use crate::config::{
  AdminTlsConfig, CryptoConfig, QuicConfig, QuicZeroRttMode, TlsClientAuthConfig,
  TlsClientAuthMode, TlsConfig, TlsKeyExchangeGroup, TlsNegotiationPolicy, TlsVersion,
  TurnListenerTlsConfig,
};

mod admin_quic;
mod cert_metadata;
mod certificate_io;
mod certificate_partition;
mod client_auth;
mod client_roots;
mod crlite;
mod crlite_managed;
mod crlite_runtime;
mod downstream_tcp;
mod negotiation;
mod ocsp;
mod outbound_revocation;
mod provider;
mod resumption;
mod server_policy;
mod upstream_client;
pub(crate) use cert_metadata::{
  ParsedCertificateMetadata, client_certificate_metadata, parse_certificate_metadata,
};

pub(crate) use admin_quic::build_admin_quic_server_config_with_crypto_and_resumption;
pub use admin_quic::build_admin_quic_server_config_with_resumption;
pub(crate) use crlite_runtime::CrliteRuntime;
pub use crlite_runtime::CrliteRuntimeStatus;
use downstream_tcp::{
  DownstreamTcpTlsBuild, build_downstream_tcp_server_config_for_tls12,
  build_downstream_tcp_server_config_for_tls13,
};
pub use downstream_tcp::{build_server_config, build_server_config_with_resumption};
pub use ocsp::OcspRuntimeStatus;
pub(crate) use ocsp::OcspStapleRuntime;
pub(crate) use outbound_revocation::OutboundRevocationRuntime;
pub use outbound_revocation::OutboundRevocationRuntimeStatus;
pub use resumption::{TlsResumptionState, TlsServerSessionStorageStats};
use resumption::{
  TlsServerResumptionKey, certificate_identity, client_auth_identity, configure_server_resumption,
};
pub use server_policy::{
  DownstreamQuicServerConfig, DownstreamTlsServerConfig, TurnTlsServerConfig,
};
pub(crate) use server_policy::{
  build_downstream_quic_server_config_with_resumption_and_ocsp,
  build_downstream_tls_server_config_with_resumption_and_ocsp,
  build_turn_tls_server_config_with_resumption,
};
pub use upstream_client::{
  build_upstream_client_config, build_upstream_client_config_with_resumption,
  build_upstream_quic_client_config, build_upstream_quic_client_config_with_resumption,
};
pub(crate) use upstream_client::{
  build_upstream_client_config_with_crypto_resumption_and_revocation,
  build_upstream_quic_client_config_with_crypto_resumption_and_revocation,
  build_webpki_client_config_with_crypto,
};

pub fn install_default_provider() -> anyhow::Result<()> {
  let provider = provider::default_crypto_provider();
  let _ = provider.install_default();
  Ok(())
}

pub fn install_configured_provider(config: &crate::config::CryptoConfig) -> anyhow::Result<()> {
  let provider = provider::crypto_provider(config)?;
  let _ = provider.install_default();
  Ok(())
}

pub(crate) fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
  provider::default_crypto_provider()
}

fn quic_initial_tls13_aes128_gcm_sha256_suite(
  crypto: &CryptoConfig,
) -> anyhow::Result<rustls::quic::Suite> {
  let provider = provider::crypto_provider(crypto)?;
  provider
    .cipher_suites
    .iter()
    .find_map(|suite| match suite.suite() {
      rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => {
        suite.tls13().and_then(|tls13| tls13.quic_suite())
      }
      _ => None,
    })
    .ok_or_else(|| {
      anyhow!(
        "failed to find QUIC Initial TLS_AES_128_GCM_SHA256 suite in selected rustls crypto provider"
      )
    })
}

/// Builds the downstream QUIC server configuration used by HTTP/3 listeners.
pub fn build_quic_server_config(
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
) -> anyhow::Result<QuinnServerConfig> {
  let crypto = CryptoConfig::default();
  build_quic_server_config_with_crypto_and_resumption(
    &crypto,
    tls,
    quic,
    quic_host_key_base_dir,
    None,
  )
}

pub fn build_quic_server_config_with_resumption(
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<QuinnServerConfig> {
  let crypto = CryptoConfig::default();
  build_quic_server_config_with_crypto_and_resumption(
    &crypto,
    tls,
    quic,
    quic_host_key_base_dir,
    resumption_state,
  )
}

pub(crate) fn build_quic_server_config_with_crypto_and_resumption(
  crypto: &CryptoConfig,
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<QuinnServerConfig> {
  build_quic_server_config_with_crypto_resumption_and_ocsp(
    crypto,
    tls,
    quic,
    quic_host_key_base_dir,
    resumption_state,
    None,
    None,
  )
}

pub(crate) fn build_quic_server_config_with_crypto_resumption_and_ocsp(
  crypto: &CryptoConfig,
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<QuinnServerConfig> {
  build_downstream_quic_server_config_for_tls13(
    tls,
    quic,
    quic_host_key_base_dir,
    crypto,
    &tls.tls13.key_exchange_groups,
    &tls.tls13.ciphers,
    None,
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_downstream_quic_server_config_for_tls13(
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  crypto: &CryptoConfig,
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[crate::config::Tls13CipherSuite],
  certificate_partition_identity: Option<&str>,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<QuinnServerConfig> {
  let provider = Arc::new(downstream_crypto_provider_for_tls13(
    crypto,
    key_exchange_groups,
    ciphers,
  )?);
  let (server_identity, mut cert_resolver) = ocsp::downstream_cert_resolver_for_identity(
    tls,
    &provider,
    ocsp_runtime,
    certificate_partition_identity,
  )?;
  if let Some(runtime) = crlite_runtime {
    cert_resolver = runtime.wrap_resolver(cert_resolver);
  }
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("failed to configure QUIC TLS versions")?;
  let mut server_config = match downstream_client_cert_verifier(&tls.client_auth, provider)? {
    Some(verifier) => builder.with_client_cert_verifier(verifier),
    None => builder.with_no_client_auth(),
  }
  .with_cert_resolver(cert_resolver);
  if quic.zero_rtt == QuicZeroRttMode::SafeMethods {
    server_config.max_early_data_size = u32::MAX;
  }
  configure_server_resumption(
    &mut server_config,
    &tls.resumption,
    TlsServerResumptionKey {
      scope: "downstream-quic",
      mode: tls.resumption.mode,
      server_identity,
      client_auth_identity: client_auth_identity(&tls.client_auth)?,
      alpn_family: "h3",
      tls_provider: crypto.tls_provider,
    },
    resumption_state,
  )?;
  server_config.alpn_protocols = vec![b"h3".to_vec()];

  let initial_suite = quic_initial_tls13_aes128_gcm_sha256_suite(crypto)
    .context("failed to build QUIC Initial cipher suite")?;
  let quic_crypto = QuicServerConfig::with_initial(Arc::new(server_config), initial_suite)
    .context("failed to build QUIC server TLS config")?;
  let mut quic_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
  crate::quic::apply_server_config(quic, quic_host_key_base_dir, &mut quic_config)?;
  Ok(quic_config)
}

/// Builds the TCP TLS server configuration for the admin listener.
pub fn build_admin_server_config(tls: &AdminTlsConfig) -> anyhow::Result<Arc<ServerConfig>> {
  let crypto = CryptoConfig::default();
  build_admin_server_config_with_crypto_and_resumption(&crypto, tls, None)
}

/// Builds the admin TCP TLS server configuration with optional shared resumption storage.
pub fn build_admin_server_config_with_resumption(
  tls: &AdminTlsConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let crypto = CryptoConfig::default();
  build_admin_server_config_with_crypto_and_resumption(&crypto, tls, resumption_state)
}

pub(crate) fn build_admin_server_config_with_crypto_and_resumption(
  crypto: &CryptoConfig,
  tls: &AdminTlsConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let provider = Arc::new(provider::crypto_provider(crypto)?);
  let mut certificates = Vec::new();
  let mut default = None;
  let mut identity_certs = Vec::new();
  for (index, certificate) in tls.certificates.iter().enumerate() {
    let certs = load_certs(&certificate.cert_chain)?;
    identity_certs.extend(certs.iter().cloned());
    let key = load_private_key(&certificate.private_key)?;
    let certified_key = CertifiedKey::from_der(certs, key, &provider)
      .context("failed to create admin rustls certified key")?;
    let certified_key = Arc::new(certified_key);
    if certificate.default || (tls.certificates.len() == 1 && index == 0) {
      default = Some(certified_key.clone());
    }
    certificates.push(AdminCertificate {
      server_names: certificate
        .server_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect(),
      certified_key,
    });
  }

  let resolver = AdminCertResolver {
    certificates,
    default,
    require_sni: tls.require_sni,
    reject_unknown_sni: tls.reject_unknown_sni,
  };
  let versions = tls_protocol_versions(tls.min_version, tls.max_version);
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&versions)
    .context("failed to configure admin TLS versions")?;
  let mut server_config = match downstream_client_cert_verifier(&tls.client_auth, provider)? {
    Some(verifier) => builder.with_client_cert_verifier(verifier),
    None => builder.with_no_client_auth(),
  }
  .with_cert_resolver(Arc::new(resolver));
  configure_server_resumption(
    &mut server_config,
    &tls.resumption,
    TlsServerResumptionKey {
      scope: "admin-tcp",
      mode: tls.resumption.mode,
      server_identity: certificate_identity(&identity_certs),
      client_auth_identity: client_auth_identity(&tls.client_auth)?,
      alpn_family: "admin-http1",
      tls_provider: crypto.tls_provider,
    },
    resumption_state,
  )?;
  server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
  Ok(Arc::new(server_config))
}

pub fn build_turn_server_config(
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
) -> anyhow::Result<Arc<ServerConfig>> {
  let crypto = CryptoConfig::default();
  build_turn_server_config_with_crypto_and_resumption(&crypto, listener_tls, default_tls, None)
}

pub fn build_turn_server_config_with_resumption(
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let crypto = CryptoConfig::default();
  build_turn_server_config_with_crypto_and_resumption(
    &crypto,
    listener_tls,
    default_tls,
    resumption_state,
  )
}

pub(crate) fn build_turn_server_config_with_crypto_and_resumption(
  crypto: &CryptoConfig,
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  build_turn_server_config_for_policy(
    listener_tls,
    default_tls,
    crypto,
    &default_tls.negotiation_policy(),
    &tls_protocol_versions(default_tls.min_version, default_tls.max_version),
    resumption_state,
  )
}

pub(super) fn build_turn_server_config_for_policy(
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  crypto: &CryptoConfig,
  policy: &TlsNegotiationPolicy,
  versions: &[&'static rustls::SupportedProtocolVersion],
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  build_turn_server_config_with_provider(
    listener_tls,
    default_tls,
    downstream_crypto_provider_for_policy(crypto, policy)?,
    crypto,
    versions,
    resumption_state,
  )
}

pub(super) fn build_turn_server_config_for_tls13(
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  crypto: &CryptoConfig,
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[crate::config::Tls13CipherSuite],
  versions: &[&'static rustls::SupportedProtocolVersion],
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  build_turn_server_config_with_provider(
    listener_tls,
    default_tls,
    downstream_crypto_provider_for_tls13(crypto, key_exchange_groups, ciphers)?,
    crypto,
    versions,
    resumption_state,
  )
}

pub(super) fn build_turn_server_config_for_tls12(
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  crypto: &CryptoConfig,
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[crate::config::Tls12CipherSuite],
  versions: &[&'static rustls::SupportedProtocolVersion],
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  build_turn_server_config_with_provider(
    listener_tls,
    default_tls,
    downstream_crypto_provider_for_tls12(crypto, key_exchange_groups, ciphers)?,
    crypto,
    versions,
    resumption_state,
  )
}

fn build_turn_server_config_with_provider(
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  provider: rustls::crypto::CryptoProvider,
  crypto: &CryptoConfig,
  versions: &[&'static rustls::SupportedProtocolVersion],
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let provider = Arc::new(provider);
  let cert_chain = listener_tls
    .cert_chain
    .as_ref()
    .unwrap_or(&default_tls.cert_chain);
  let private_key = listener_tls.private_key.as_ref();
  let certified_key = load_turn_certified_key(
    cert_chain,
    private_key,
    listener_tls,
    default_tls,
    &provider,
  )
  .context("failed to create TURN rustls certified key")?;
  let server_identity = certificate_identity(&certified_key.cert);
  let cert_resolver = rustls::sign::SingleCertAndKey::from(certified_key);
  let builder = ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(versions)
    .context("failed to configure TURN TLS versions")?;
  let mut server_config = builder
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(cert_resolver));
  let resumption = listener_tls
    .resumption
    .as_ref()
    .unwrap_or(&default_tls.resumption);
  configure_server_resumption(
    &mut server_config,
    resumption,
    TlsServerResumptionKey {
      scope: "turn-tls",
      mode: resumption.mode,
      server_identity,
      client_auth_identity: "client-auth:off".to_string(),
      alpn_family: "turn",
      tls_provider: crypto.tls_provider,
    },
    resumption_state,
  )?;
  server_config.alpn_protocols = Vec::new();
  Ok(Arc::new(server_config))
}

fn load_downstream_certified_key(
  tls: &TlsConfig,
  provider: &rustls::crypto::CryptoProvider,
) -> anyhow::Result<CertifiedKey> {
  load_downstream_certified_key_for_material(
    tls,
    &tls.cert_chain,
    tls.private_key.as_ref(),
    tls
      .remote_signer
      .enabled
      .then_some(&tls.remote_signer.key_id),
    provider,
  )
}

pub(super) fn load_downstream_certificate_certified_key(
  tls: &TlsConfig,
  certificate: &crate::config::TlsCertificateConfig,
  provider: &rustls::crypto::CryptoProvider,
) -> anyhow::Result<CertifiedKey> {
  load_downstream_certified_key_for_material(
    tls,
    &certificate.cert_chain,
    certificate.private_key.as_ref(),
    certificate.remote_signer_key_id.as_ref(),
    provider,
  )
}

fn load_downstream_certified_key_for_material(
  tls: &TlsConfig,
  cert_chain: &std::path::Path,
  private_key: Option<&std::path::PathBuf>,
  remote_signer_key_id: Option<&String>,
  provider: &rustls::crypto::CryptoProvider,
) -> anyhow::Result<CertifiedKey> {
  let certs = load_certs(cert_chain)?;
  if tls.remote_signer.enabled {
    let key_id = remote_signer_key_id
      .ok_or_else(|| anyhow!("remote signer key id is required for downstream TLS certificate"))?;
    let signing_key = crate::remote_signer::RemoteSigningKey::connect(
      &tls.remote_signer,
      key_id,
      end_entity_cert(&certs)?,
    )?;
    let certified_key = CertifiedKey::new(certs, signing_key);
    match certified_key.keys_match() {
      Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
        Ok(certified_key)
      }
      Err(error) => Err(error).context("remote signer key does not match certificate"),
    }
  } else {
    let private_key = private_key
      .ok_or_else(|| anyhow!("tls.private_key is required unless remote signing is enabled"))?;
    let key = load_private_key(private_key)?;
    CertifiedKey::from_der(certs, key, provider).context("failed to load local TLS private key")
  }
}

fn load_turn_certified_key(
  cert_chain: &std::path::Path,
  private_key: Option<&std::path::PathBuf>,
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  provider: &rustls::crypto::CryptoProvider,
) -> anyhow::Result<CertifiedKey> {
  let certs = load_certs(cert_chain)?;
  if let Some(private_key) = private_key {
    let key = load_private_key(private_key)?;
    return CertifiedKey::from_der(certs, key, provider)
      .context("failed to load local TURN TLS private key");
  }
  if let Some(key_id) = &listener_tls.remote_signer_key_id {
    return load_remote_turn_certified_key(certs, default_tls, key_id);
  }
  if default_tls.remote_signer.enabled {
    load_remote_turn_certified_key(certs, default_tls, &default_tls.remote_signer.key_id)
  } else {
    let private_key = default_tls
      .private_key
      .as_ref()
      .ok_or_else(|| anyhow!("tls.private_key is required for TURN TLS"))?;
    let key = load_private_key(private_key)?;
    CertifiedKey::from_der(certs, key, provider)
      .context("failed to load default local TURN TLS private key")
  }
}

fn load_remote_turn_certified_key(
  certs: Vec<CertificateDer<'static>>,
  default_tls: &TlsConfig,
  key_id: &str,
) -> anyhow::Result<CertifiedKey> {
  let signing_key = crate::remote_signer::RemoteSigningKey::connect(
    &default_tls.remote_signer,
    key_id,
    end_entity_cert(&certs)?,
  )?;
  let certified_key = CertifiedKey::new(certs, signing_key);
  match certified_key.keys_match() {
    Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
      Ok(certified_key)
    }
    Err(error) => Err(error).context("remote TURN signer key does not match certificate"),
  }
}

#[derive(Debug)]
struct AdminCertificate {
  server_names: Vec<String>,
  certified_key: Arc<CertifiedKey>,
}

#[derive(Debug)]
struct AdminCertResolver {
  certificates: Vec<AdminCertificate>,
  default: Option<Arc<CertifiedKey>>,
  require_sni: bool,
  reject_unknown_sni: bool,
}

impl rustls::server::ResolvesServerCert for AdminCertResolver {
  fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    let Some(server_name) = client_hello.server_name() else {
      return (!self.require_sni).then(|| self.default.clone()).flatten();
    };
    if let Some(certificate) =
      select_admin_certificate_by_names(&self.certificates, server_name, |certificate| {
        &certificate.server_names
      })
    {
      return Some(certificate.certified_key.clone());
    }
    if self.reject_unknown_sni {
      None
    } else {
      self.default.clone()
    }
  }
}

fn select_admin_certificate_by_names<'a, T>(
  certificates: &'a [T],
  server_name: &str,
  names: impl Fn(&'a T) -> &'a [String] + Copy,
) -> Option<&'a T> {
  for certificate in certificates {
    if names(certificate)
      .iter()
      .any(|pattern| !pattern.starts_with("*.") && pattern.eq_ignore_ascii_case(server_name))
    {
      return Some(certificate);
    }
  }
  certificates.iter().find(|&certificate| {
    names(certificate)
      .iter()
      .any(|pattern| pattern.starts_with("*.") && sni_matches(pattern, server_name))
  })
}

pub(super) fn sni_matches(pattern: &str, server_name: &str) -> bool {
  if let Some(suffix) = pattern.strip_prefix("*.") {
    let Some(prefix_len) = server_name.len().checked_sub(suffix.len() + 1) else {
      return false;
    };
    if server_name.as_bytes().get(prefix_len) != Some(&b'.') {
      return false;
    }
    let Some(prefix) = server_name.get(..prefix_len) else {
      return false;
    };
    let Some(server_suffix) = server_name.get(prefix_len + 1..) else {
      return false;
    };
    if !server_suffix.eq_ignore_ascii_case(suffix) {
      return false;
    }
    return !prefix.is_empty() && !prefix.contains('.');
  }
  pattern.eq_ignore_ascii_case(server_name)
}

fn load_client_auth_root_store(paths: &[std::path::PathBuf]) -> anyhow::Result<RootCertStore> {
  let mut roots = RootCertStore::empty();
  for path in paths {
    let certs = load_certs(path)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
      bail!(
        "no parsable downstream client auth root certificates found in {}",
        path.display()
      );
    }
  }
  Ok(roots)
}

fn downstream_client_cert_verifier(
  client_auth: &TlsClientAuthConfig,
  provider: Arc<rustls::crypto::CryptoProvider>,
) -> anyhow::Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>> {
  match client_auth.mode {
    TlsClientAuthMode::Off => Ok(None),
    TlsClientAuthMode::Optional | TlsClientAuthMode::Require => {
      let roots = load_client_auth_root_store(&client_auth.ca_certs)?;
      let mut verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
      if client_auth.mode == TlsClientAuthMode::Optional {
        verifier = verifier.allow_unauthenticated();
      }
      verifier
        .build()
        .context("failed to build downstream client certificate verifier")
        .map(|verifier| {
          Some(self::client_auth::enforce_verify_depth(
            verifier,
            client_auth.verify_depth,
          ))
        })
    }
  }
}

fn tls_protocol_versions(
  min_version: TlsVersion,
  max_version: TlsVersion,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
  match (min_version, max_version) {
    (TlsVersion::Tls12, TlsVersion::Tls12) => vec![&rustls::version::TLS12],
    (TlsVersion::Tls12, TlsVersion::Tls13) => {
      vec![&rustls::version::TLS13, &rustls::version::TLS12]
    }
    (TlsVersion::Tls13, TlsVersion::Tls13) => vec![&rustls::version::TLS13],
    (TlsVersion::Tls13, TlsVersion::Tls12) => vec![&rustls::version::TLS13],
  }
}

#[cfg(test)]
mod tests {
  use super::{select_admin_certificate_by_names, sni_matches};

  #[test]
  fn sni_matches_without_lowercase_allocation() {
    assert!(sni_matches("admin.example.test", "Admin.Example.Test"));
    assert!(sni_matches("*.example.test", "Admin.Example.Test"));
    assert!(!sni_matches("*.example.test", "deep.admin.example.test"));
    assert!(!sni_matches("*.example.test", "example.test"));
  }

  #[test]
  fn admin_certificate_selection_prefers_exact_name_before_wildcard() {
    let certificates = vec![
      vec!["*.example.test".to_string()],
      vec!["admin.example.test".to_string()],
    ];

    let selected =
      select_admin_certificate_by_names(&certificates, "Admin.Example.Test", Vec::as_slice)
        .expect("admin certificate should match");

    assert_eq!(selected, &certificates[1]);
  }
}
