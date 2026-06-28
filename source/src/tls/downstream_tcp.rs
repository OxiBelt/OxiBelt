//! Downstream TCP TLS server builders for HTTP/1 and HTTP/2 listeners.

use std::sync::Arc;

use anyhow::Context;
use rustls::ServerConfig;

use crate::config::{ListenerConfig, TlsConfig, TlsKeyExchangeGroup, TlsNegotiationPolicy};

use super::negotiation::{
  downstream_crypto_provider_for_policy, downstream_crypto_provider_for_tls12,
  downstream_crypto_provider_for_tls13,
};
use super::resumption::{
  TlsServerResumptionKey, client_auth_identity, configure_server_resumption,
};
use super::{
  CrliteRuntime, OcspStapleRuntime, TlsResumptionState, downstream_client_cert_verifier, ocsp,
  tls_protocol_versions,
};

#[derive(Clone)]
pub(super) struct DownstreamTcpTlsBuild<'a> {
  tls: &'a TlsConfig,
  listeners: &'a ListenerConfig,
  max_early_data_size: u32,
  resumption_state: Option<&'a TlsResumptionState>,
  ocsp_runtime: Option<&'a OcspStapleRuntime>,
  crlite_runtime: Option<&'a CrliteRuntime>,
  certificate_partition_identity: Option<String>,
}

impl<'a> DownstreamTcpTlsBuild<'a> {
  pub(super) fn new(
    tls: &'a TlsConfig,
    listeners: &'a ListenerConfig,
    max_early_data_size: u32,
    resumption_state: Option<&'a TlsResumptionState>,
    ocsp_runtime: Option<&'a OcspStapleRuntime>,
    crlite_runtime: Option<&'a CrliteRuntime>,
  ) -> Self {
    Self {
      tls,
      listeners,
      max_early_data_size,
      resumption_state,
      ocsp_runtime,
      crlite_runtime,
      certificate_partition_identity: None,
    }
  }

  pub(super) fn with_max_early_data_size(self, max_early_data_size: u32) -> Self {
    Self {
      max_early_data_size,
      ..self
    }
  }

  pub(super) fn with_certificate_partition_identity(
    self,
    certificate_partition_identity: Option<String>,
  ) -> Self {
    Self {
      certificate_partition_identity,
      ..self
    }
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
  build_server_config_with_resumption_and_ocsp(tls, listeners, 0, resumption_state, None, None)
}

pub(crate) fn build_server_config_with_resumption_and_ocsp(
  tls: &TlsConfig,
  listeners: &ListenerConfig,
  max_early_data_size: u32,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<Arc<ServerConfig>> {
  let build = DownstreamTcpTlsBuild::new(
    tls,
    listeners,
    max_early_data_size,
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  );
  build_downstream_tcp_server_config_for_policy(
    build,
    &tls.negotiation_policy(),
    &tls_protocol_versions(tls.min_version, tls.max_version),
  )
}

pub(super) fn build_downstream_tcp_server_config_for_policy(
  build: DownstreamTcpTlsBuild<'_>,
  policy: &TlsNegotiationPolicy,
  versions: &[&'static rustls::SupportedProtocolVersion],
) -> anyhow::Result<Arc<ServerConfig>> {
  build_downstream_tcp_server_config_with_provider(
    build,
    downstream_crypto_provider_for_policy(policy),
    versions,
  )
}

pub(super) fn build_downstream_tcp_server_config_for_tls13(
  build: DownstreamTcpTlsBuild<'_>,
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[crate::config::Tls13CipherSuite],
  versions: &[&'static rustls::SupportedProtocolVersion],
) -> anyhow::Result<Arc<ServerConfig>> {
  build_downstream_tcp_server_config_with_provider(
    build,
    downstream_crypto_provider_for_tls13(key_exchange_groups, ciphers),
    versions,
  )
}

pub(super) fn build_downstream_tcp_server_config_for_tls12(
  build: DownstreamTcpTlsBuild<'_>,
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[crate::config::Tls12CipherSuite],
  versions: &[&'static rustls::SupportedProtocolVersion],
) -> anyhow::Result<Arc<ServerConfig>> {
  build_downstream_tcp_server_config_with_provider(
    build,
    downstream_crypto_provider_for_tls12(key_exchange_groups, ciphers),
    versions,
  )
}

fn build_downstream_tcp_server_config_with_provider(
  build: DownstreamTcpTlsBuild<'_>,
  provider: rustls::crypto::CryptoProvider,
  versions: &[&'static rustls::SupportedProtocolVersion],
) -> anyhow::Result<Arc<ServerConfig>> {
  let provider = Arc::new(provider);
  let (server_identity, mut cert_resolver) = ocsp::downstream_cert_resolver_for_identity(
    build.tls,
    &provider,
    build.ocsp_runtime,
    build.certificate_partition_identity.as_deref(),
  )?;
  if let Some(runtime) = build.crlite_runtime {
    cert_resolver = runtime.wrap_resolver(cert_resolver);
  }
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(versions)
    .context("failed to configure TLS versions")?;
  let mut server_config =
    match downstream_client_cert_verifier(&build.tls.client_auth, provider)? {
      Some(verifier) => builder.with_client_cert_verifier(verifier),
      None => builder.with_no_client_auth(),
    }
    .with_cert_resolver(cert_resolver);
  server_config.max_early_data_size = build.max_early_data_size;
  configure_server_resumption(
    &mut server_config,
    &build.tls.resumption,
    TlsServerResumptionKey {
      scope: "downstream-tcp",
      mode: build.tls.resumption.mode,
      server_identity,
      client_auth_identity: client_auth_identity(&build.tls.client_auth)?,
      alpn_family: "http1-http2",
    },
    build.resumption_state,
  )?;

  let mut alpn = Vec::new();
  if build.listeners.http2 {
    alpn.push(b"h2".to_vec());
  }
  if build.listeners.http1 {
    alpn.push(b"http/1.1".to_vec());
  }
  server_config.alpn_protocols = alpn;

  Ok(Arc::new(server_config))
}
