use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct TlsRuntimeSnapshot {
  pub downstream_cert_chain_configured: bool,
  pub downstream_private_key_configured: bool,
  pub crlite_mode: String,
  pub crlite_filter_file_configured: bool,
  pub crlite: crate::tls::CrliteRuntimeStatus,
  pub ocsp_mode: String,
  pub ocsp_response_file_configured: bool,
  pub ocsp: crate::tls::OcspRuntimeStatus,
  pub quic_host_key_configured: bool,
  pub remote_signer_enabled: bool,
  pub admin_tls_configured: bool,
}
