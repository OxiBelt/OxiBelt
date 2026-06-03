use std::sync::Arc;

use anyhow::Context;

use crate::config::Config;
use crate::state::AppSnapshot;

pub(super) async fn build_downstream_tls_reload_configs(
  config: &Config,
  active: &AppSnapshot,
) -> anyhow::Result<(
  crate::tls::OcspStapleRuntime,
  Arc<rustls::ServerConfig>,
  Option<h3_quinn::quinn::ServerConfig>,
)> {
  let ocsp_staple =
    crate::tls::OcspStapleRuntime::new(&config.tls, &active.control_http, active.metrics.clone())
      .await
      .context("failed to build OCSP staple runtime")?;
  let tls_server_config = crate::tls::build_server_config_with_resumption_and_ocsp(
    &config.tls,
    &config.listeners,
    Some(&active.tls_resumption),
    Some(&ocsp_staple),
  )
  .context("failed to rebuild downstream TLS config")?;
  let quic_server_config = if config.listeners.http3 {
    Some(
      crate::tls::build_quic_server_config_with_resumption_and_ocsp(
        &config.tls,
        &config.quic,
        config.source_paths.cert_dir.as_deref(),
        Some(&active.tls_resumption),
        Some(&ocsp_staple),
      )
      .context("failed to rebuild QUIC TLS config")?,
    )
  } else {
    None
  };
  Ok((ocsp_staple, tls_server_config, quic_server_config))
}
