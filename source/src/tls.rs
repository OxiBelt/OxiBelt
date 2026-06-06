//! TLS configuration builders for downstream, upstream, admin, TURN, and QUIC transports.
//! Certificate loading and resumption keys stay scoped to the transport that uses them.

use std::fs;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use h3_quinn::quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use h3_quinn::quinn::{ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, sign::CertifiedKey};

use crate::config::{
  AdminTlsConfig, ListenerConfig, OcspMode, QuicConfig, QuicZeroRttMode, TlsClientAuthConfig,
  TlsClientAuthMode, TlsConfig, TlsKeyExchangeGroup, TlsVersion, TurnListenerTlsConfig,
  UpstreamEchConfig, UpstreamEchMode, UpstreamTlsResumptionConfig, canonicalize_existing_file,
};

mod admin_quic;
mod cert_metadata;
mod client_auth;
mod crlite;
mod crlite_managed;
mod crlite_runtime;
mod ocsp;
mod resumption;
pub(crate) use cert_metadata::client_certificate_metadata;

pub use admin_quic::build_admin_quic_server_config_with_resumption;
pub(crate) use crlite_runtime::CrliteRuntime;
pub use crlite_runtime::CrliteRuntimeStatus;
pub use ocsp::OcspRuntimeStatus;
pub(crate) use ocsp::OcspStapleRuntime;
pub use resumption::{TlsResumptionState, TlsServerSessionStorageStats};
use resumption::{
  TlsServerResumptionKey, certificate_identity, client_auth_identity, configure_server_resumption,
  upstream_client_config_key, upstream_client_resumption,
};

pub fn install_default_provider() -> anyhow::Result<()> {
  let provider = rustls::crypto::aws_lc_rs::default_provider();
  let _ = provider.install_default();
  Ok(())
}

fn downstream_crypto_provider(tls: &TlsConfig) -> rustls::crypto::CryptoProvider {
  let mut provider = rustls::crypto::aws_lc_rs::default_provider();
  provider.kx_groups = tls
    .key_exchange_groups
    .iter()
    .copied()
    .map(supported_key_exchange_group)
    .collect();
  provider
}

fn supported_key_exchange_group(
  group: TlsKeyExchangeGroup,
) -> &'static dyn rustls::crypto::SupportedKxGroup {
  match group {
    TlsKeyExchangeGroup::X25519MlKem768 => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
    TlsKeyExchangeGroup::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
    TlsKeyExchangeGroup::Secp256r1 => rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    TlsKeyExchangeGroup::Secp384r1 => rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
  }
}

/// Builds the shared downstream TCP TLS server configuration for HTTP/1 and HTTP/2.
pub fn build_server_config(
  tls: &TlsConfig,
  listeners: &ListenerConfig,
) -> anyhow::Result<Arc<ServerConfig>> {
  build_server_config_with_resumption(tls, listeners, None)
}

/// Builds the downstream TCP TLS server configuration with optional shared resumption storage.
pub fn build_server_config_with_resumption(
  tls: &TlsConfig,
  listeners: &ListenerConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  build_server_config_with_resumption_and_ocsp(tls, listeners, resumption_state, None, None)
}

pub(crate) fn build_server_config_with_resumption_and_ocsp(
  tls: &TlsConfig,
  listeners: &ListenerConfig,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let provider = Arc::new(downstream_crypto_provider(tls));
  let (server_identity, mut cert_resolver) =
    ocsp::downstream_cert_resolver(tls, &provider, ocsp_runtime)?;
  if let Some(runtime) = crlite_runtime {
    cert_resolver = runtime.wrap_resolver(cert_resolver);
  }
  let versions = tls_protocol_versions(tls.min_version, tls.max_version);
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&versions)
    .context("failed to configure TLS versions")?;
  let mut server_config = match downstream_client_cert_verifier(&tls.client_auth, provider)? {
    Some(verifier) => builder.with_client_cert_verifier(verifier),
    None => builder.with_no_client_auth(),
  }
  .with_cert_resolver(cert_resolver);
  configure_server_resumption(
    &mut server_config,
    &tls.resumption,
    TlsServerResumptionKey {
      scope: "downstream-tcp",
      mode: tls.resumption.mode,
      server_identity,
      client_auth_identity: client_auth_identity(&tls.client_auth)?,
      alpn_family: "http1-http2",
    },
    resumption_state,
  )?;

  let mut alpn = Vec::new();
  if listeners.http2 {
    alpn.push(b"h2".to_vec());
  }
  if listeners.http1 {
    alpn.push(b"http/1.1".to_vec());
  }
  server_config.alpn_protocols = alpn;

  Ok(Arc::new(server_config))
}

/// Builds the downstream QUIC server configuration used by HTTP/3 listeners.
pub fn build_quic_server_config(
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
) -> anyhow::Result<QuinnServerConfig> {
  build_quic_server_config_with_resumption(tls, quic, quic_host_key_base_dir, None)
}

pub fn build_quic_server_config_with_resumption(
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<QuinnServerConfig> {
  build_quic_server_config_with_resumption_and_ocsp(
    tls,
    quic,
    quic_host_key_base_dir,
    resumption_state,
    None,
    None,
  )
}

pub(crate) fn build_quic_server_config_with_resumption_and_ocsp(
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<QuinnServerConfig> {
  let provider = Arc::new(downstream_crypto_provider(tls));
  let (server_identity, mut cert_resolver) =
    ocsp::downstream_cert_resolver(tls, &provider, ocsp_runtime)?;
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
    },
    resumption_state,
  )?;
  server_config.alpn_protocols = vec![b"h3".to_vec()];

  let quic_crypto =
    QuicServerConfig::try_from(server_config).context("failed to build QUIC server TLS config")?;
  let mut quic_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
  crate::quic::apply_server_config(quic, quic_host_key_base_dir, &mut quic_config)?;
  Ok(quic_config)
}

/// Builds the TCP TLS server configuration for the admin listener.
pub fn build_admin_server_config(tls: &AdminTlsConfig) -> anyhow::Result<Arc<ServerConfig>> {
  build_admin_server_config_with_resumption(tls, None)
}

/// Builds the admin TCP TLS server configuration with optional shared resumption storage.
pub fn build_admin_server_config_with_resumption(
  tls: &AdminTlsConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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
  build_turn_server_config_with_resumption(listener_tls, default_tls, None)
}

pub fn build_turn_server_config_with_resumption(
  listener_tls: &TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let provider = Arc::new(downstream_crypto_provider(default_tls));
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
  let versions = tls_protocol_versions(default_tls.min_version, default_tls.max_version);
  let builder = ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&versions)
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
  let certs = load_certs(&tls.cert_chain)?;
  if tls.remote_signer.enabled {
    let signing_key = crate::remote_signer::RemoteSigningKey::connect(
      &tls.remote_signer,
      &tls.remote_signer.key_id,
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
    let private_key = tls
      .private_key
      .as_ref()
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

fn end_entity_cert<'a>(
  certs: &'a [CertificateDer<'static>],
) -> anyhow::Result<&'a CertificateDer<'static>> {
  certs
    .first()
    .ok_or_else(|| anyhow!("certificate chain must include an end-entity certificate"))
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
    let Some(server_name) = client_hello.server_name().map(str::to_ascii_lowercase) else {
      return (!self.require_sni).then(|| self.default.clone()).flatten();
    };
    for certificate in &self.certificates {
      if certificate
        .server_names
        .iter()
        .any(|pattern| admin_sni_matches(pattern, &server_name))
      {
        return Some(certificate.certified_key.clone());
      }
    }
    if self.reject_unknown_sni {
      None
    } else {
      self.default.clone()
    }
  }
}

fn admin_sni_matches(pattern: &str, server_name: &str) -> bool {
  if let Some(suffix) = pattern.strip_prefix("*.") {
    let suffix = format!(".{suffix}");
    let Some(prefix) = server_name.strip_suffix(&suffix) else {
      return false;
    };
    return !prefix.is_empty() && !prefix.contains('.');
  }
  pattern == server_name
}

/// Builds the upstream TCP TLS client configuration used by proxy clients.
pub fn build_upstream_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
) -> anyhow::Result<ClientConfig> {
  build_upstream_client_config_with_resumption(
    extra_root_certificates,
    ech,
    &UpstreamTlsResumptionConfig::default(),
    None,
    "default",
  )
}

pub fn build_upstream_client_config_with_resumption(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
) -> anyhow::Result<ClientConfig> {
  let key = upstream_client_config_key(
    "tcp",
    upstream_name,
    extra_root_certificates,
    ech,
    resumption,
  )?;
  if let Some(state) = state {
    return state.upstream_client_config(key, || {
      build_uncached_upstream_client_config(extra_root_certificates, ech, resumption, false)
    });
  }
  build_uncached_upstream_client_config(extra_root_certificates, ech, resumption, false)
}

fn build_uncached_upstream_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  quic_only: bool,
) -> anyhow::Result<ClientConfig> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let roots = load_upstream_root_store(extra_root_certificates)?;

  let builder = ClientConfig::builder_with_provider(provider);
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

  let mut client_config = builder.with_root_certificates(roots).with_no_client_auth();
  client_config.resumption = upstream_client_resumption(resumption);

  Ok(client_config)
}

pub fn build_upstream_quic_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
) -> anyhow::Result<QuinnClientConfig> {
  build_upstream_quic_client_config_with_resumption(
    extra_root_certificates,
    ech,
    quic,
    &UpstreamTlsResumptionConfig::default(),
    None,
    "default",
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
  let key = upstream_client_config_key(
    "quic",
    upstream_name,
    extra_root_certificates,
    ech,
    resumption,
  )?;
  let mut client_config = if let Some(state) = state {
    state.upstream_client_config(key, || {
      build_uncached_upstream_client_config(extra_root_certificates, ech, resumption, true)
    })?
  } else {
    build_uncached_upstream_client_config(extra_root_certificates, ech, resumption, true)?
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

pub(super) fn load_certs(path: &std::path::Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let bytes = read_existing_file("certificate file", path)?;
  let mut cursor = bytes.as_slice();
  rustls_pemfile::certs(&mut cursor)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

fn load_private_key(path: &std::path::Path) -> anyhow::Result<PrivateKeyDer<'static>> {
  let bytes = read_existing_file("private key file", path)?;
  let mut cursor = bytes.as_slice();
  rustls_pemfile::private_key(&mut cursor)
    .with_context(|| format!("failed to parse private key from {}", path.display()))?
    .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

fn load_ocsp_response(tls: &TlsConfig) -> anyhow::Result<Option<Vec<u8>>> {
  match tls.ocsp.mode {
    OcspMode::Disabled => Ok(None),
    OcspMode::StaticFile => {
      let path = tls
        .ocsp
        .response_file
        .as_ref()
        .ok_or_else(|| anyhow!("OCSP response file must be configured"))?;
      let bytes = read_existing_file("OCSP response file", path)?;
      Ok(Some(bytes))
    }
    OcspMode::LiveFetch => Ok(None),
  }
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

pub(super) fn read_existing_file(
  field_name: &str,
  path: &std::path::Path,
) -> anyhow::Result<Vec<u8>> {
  let canonical_path = canonicalize_existing_file(field_name, path)?;
  let canonical_parent = path
    .parent()
    .unwrap_or_else(|| std::path::Path::new("."))
    .canonicalize()
    .with_context(|| {
      format!(
        "failed to resolve {field_name} parent for {}",
        path.display()
      )
    })?;

  if !canonical_path.starts_with(&canonical_parent) {
    bail!("{field_name} must stay within its configured directory");
  }

  fs::read(&canonical_path).with_context(|| format!("failed to read {}", canonical_path.display()))
}

pub(crate) fn load_upstream_root_store(
  extra_root_certificates: &[std::path::PathBuf],
) -> anyhow::Result<RootCertStore> {
  let mut roots = RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

  for path in extra_root_certificates {
    let certs = load_certs(path)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
      bail!(
        "no parsable upstream root certificates found in {}",
        path.display()
      );
    }
  }

  Ok(roots)
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
