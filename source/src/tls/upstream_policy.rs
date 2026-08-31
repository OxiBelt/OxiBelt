//! Per-upstream TLS trust composition.
//! Policy roots stay separate from transport construction so exclusive trust cannot inherit roots.

use std::sync::Arc;

use h3_quinn::quinn::ClientConfig as QuinnClientConfig;
use rustls::ClientConfig;

use crate::config::{
  CryptoConfig, OutboundTlsRevocationConfig, QuicConfig, UpstreamTlsConfig, UpstreamTlsTrust,
};

use super::outbound_revocation::OutboundRevocationRuntime;
use super::resumption::TlsResumptionState;
use super::upstream_client::{
  build_upstream_client_config_with_trust, build_upstream_quic_client_config_with_trust,
};

pub(crate) fn build_upstream_client_config_with_policy(
  crypto: &CryptoConfig,
  inherited_root_certificates: &[std::path::PathBuf],
  tls: &UpstreamTlsConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<ClientConfig> {
  let root_certificates = effective_policy_roots(inherited_root_certificates, tls);
  build_upstream_client_config_with_trust(
    crypto,
    &root_certificates,
    tls.trust,
    &tls.subject_alt_names,
    tls.client_identity.as_ref(),
    &tls.ech,
    &tls.resumption,
    state,
    upstream_name,
    revocation,
  )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_upstream_quic_client_config_with_policy(
  crypto: &CryptoConfig,
  inherited_root_certificates: &[std::path::PathBuf],
  tls: &UpstreamTlsConfig,
  quic: &QuicConfig,
  state: Option<&TlsResumptionState>,
  upstream_name: &str,
  revocation: Option<(&OutboundRevocationRuntime, Arc<OutboundTlsRevocationConfig>)>,
) -> anyhow::Result<QuinnClientConfig> {
  let root_certificates = effective_policy_roots(inherited_root_certificates, tls);
  build_upstream_quic_client_config_with_trust(
    crypto,
    &root_certificates,
    tls.trust,
    &tls.subject_alt_names,
    tls.client_identity.as_ref(),
    &tls.ech,
    quic,
    &tls.resumption,
    state,
    upstream_name,
    revocation,
  )
}

fn effective_policy_roots(
  inherited_root_certificates: &[std::path::PathBuf],
  tls: &UpstreamTlsConfig,
) -> Vec<std::path::PathBuf> {
  match tls.trust {
    UpstreamTlsTrust::Inherit => inherited_root_certificates
      .iter()
      .chain(&tls.trusted_ca_certs)
      .cloned()
      .collect(),
    UpstreamTlsTrust::System => Vec::new(),
    UpstreamTlsTrust::Exclusive => tls.trusted_ca_certs.clone(),
  }
}
