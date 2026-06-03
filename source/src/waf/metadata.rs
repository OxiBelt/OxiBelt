//! Transport and protocol metadata consumed by WAF rules.
//! Metadata is descriptive and should not mutate the underlying request.

#[derive(Debug, Clone, Default)]
pub struct WafTlsMetadata {
  pub enabled: bool,
  pub version: Option<String>,
  pub cipher_suite: Option<String>,
  pub sni: Option<String>,
  pub alpn: Option<String>,
  pub fingerprint: Option<String>,
  pub fingerprint_scheme: Option<String>,
  pub client_certificate: Option<WafClientCertificateMetadata>,
}

#[derive(Debug, Clone, Default)]
pub struct WafClientCertificateMetadata {
  pub fingerprint_sha256: String,
  pub subject_common_names: Vec<String>,
  pub san_dns_names: Vec<String>,
  pub san_ip_addresses: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum WafProtocol {
  Http,
  Websocket,
  Webrtc,
  Webtransport,
}

impl WafProtocol {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Websocket => "websocket",
      Self::Webrtc => "webrtc",
      Self::Webtransport => "webtransport",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafTransportNetwork {
  Tcp,
  Udp,
}

impl WafTransportNetwork {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Tcp => "tcp",
      Self::Udp => "udp",
    }
  }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WafTransportMetadataInput<'a> {
  pub tcp_mss: Option<u32>,
  pub tcp_rtt_ms: Option<u64>,
  pub udp_datagram_size: Option<usize>,
  pub udp_connection_id: Option<&'a str>,
}
