use std::sync::Arc;

use anyhow::{Context, anyhow};
use h3_quinn::quinn::ClientConfig as QuinnClientConfig;
use h3_quinn::quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::EchConfigListBytes;

use crate::config::{
  OutboundTlsRevocationConfig, QuicConfig, UpstreamEchConfig, UpstreamEchMode,
  UpstreamTlsResumptionConfig,
};

use super::client_roots::{load_upstream_root_store, load_webpki_root_store};
use super::outbound_revocation::OutboundRevocationRuntime;
use super::read_existing_file;
use super::resumption::{
  TlsResumptionState, upstream_client_config_key, upstream_client_resumption,
};

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

pub(crate) fn build_webpki_client_config() -> anyhow::Result<ClientConfig> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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
  build_upstream_client_config_with_resumption_and_revocation(
    extra_root_certificates,
    ech,
    resumption,
    state,
    upstream_name,
    None,
  )
}

pub(crate) fn build_upstream_client_config_with_resumption_and_revocation(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<ClientConfig> {
  let key = upstream_client_config_key(
    "tcp",
    upstream_name,
    extra_root_certificates,
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
      build_uncached_upstream_client_config(extra_root_certificates, ech, resumption, false, None)
    });
  }
  build_uncached_upstream_client_config(extra_root_certificates, ech, resumption, false, revocation)
}

fn build_uncached_upstream_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  resumption: &UpstreamTlsResumptionConfig,
  quic_only: bool,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<ClientConfig> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let roots = Arc::new(load_upstream_root_store(extra_root_certificates)?);

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

  let mut client_config = if let Some((runtime, policy)) = revocation {
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
      .build()
      .context("failed to build upstream WebPKI verifier")?;
    builder
      .dangerous()
      .with_custom_certificate_verifier(runtime.verifier(verifier, policy))
      .with_no_client_auth()
  } else {
    builder.with_root_certificates(roots).with_no_client_auth()
  };
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
  build_upstream_quic_client_config_with_resumption_and_revocation(
    extra_root_certificates,
    ech,
    quic,
    resumption,
    state,
    upstream_name,
    None,
  )
}

pub(crate) fn build_upstream_quic_client_config_with_resumption_and_revocation(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
  resumption: &UpstreamTlsResumptionConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<QuinnClientConfig> {
  let key = upstream_client_config_key(
    "quic",
    upstream_name,
    extra_root_certificates,
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
      build_uncached_upstream_client_config(extra_root_certificates, ech, resumption, true, None)
    })?
  } else {
    build_uncached_upstream_client_config(
      extra_root_certificates,
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
