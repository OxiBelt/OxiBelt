//! Explicit selection of connection-owned TLS evidence for a TCP backend.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, bail};

use crate::config::{ProxyProtocolTlsConfig, ProxyProtocolTlsSource};
use crate::proxy_protocol::{ProxyProtocolMetadata, encode_ssl_tlv};

/// Local and trusted-forwarded evidence deliberately have distinct provenance.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionTlsEvidence {
  pub(crate) local: Option<Arc<ProxyProtocolMetadata>>,
  pub(crate) received: Option<Arc<ProxyProtocolMetadata>>,
  pub(crate) local_capture_failed: bool,
}

#[derive(Clone)]
pub(crate) struct PreparedTlsHeader {
  bytes: Arc<[u8]>,
  pub(crate) cache_identity: crate::cache::CacheProxyProtocolIdentity,
  pub(crate) certificate_identity: bool,
}

impl std::fmt::Debug for PreparedTlsHeader {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("PreparedTlsHeader { redacted }")
  }
}

impl PreparedTlsHeader {
  pub(crate) fn prepare(
    config: &ProxyProtocolTlsConfig,
    evidence: &ConnectionTlsEvidence,
    effective_client: SocketAddr,
  ) -> anyhow::Result<Self> {
    let (metadata, source) = match config.source {
      ProxyProtocolTlsSource::LocalTls => {
        if evidence.local_capture_failed {
          bail!("local TLS metadata capture failed");
        }
        (evidence.local.as_deref(), "local_tls")
      }
      ProxyProtocolTlsSource::ReceivedProxy => (evidence.received.as_deref(), "received_proxy"),
    };
    let metadata = metadata.context("selected PROXY TLS metadata source is unavailable")?;
    if metadata.source.ip() != effective_client.ip() {
      bail!("PROXY TLS metadata source does not match effective client identity");
    }
    let destination = metadata
      .destination
      .context("original TLS destination is unavailable")?;
    if metadata.source.is_ipv4() != destination.is_ipv4()
      || metadata.source.ip().is_unspecified()
      || destination.ip().is_unspecified()
    {
      bail!("original TLS address pair is not representable");
    }
    let ssl = metadata
      .ssl
      .as_deref()
      .context("selected PROXY SSL assertion is unavailable")?;
    let tlv = encode_ssl_tlv(ssl, config.client_certificate)?;
    let mut bytes = super::v2_header(metadata.source, destination);
    let payload_len = bytes
      .len()
      .checked_sub(16)
      .and_then(|len| len.checked_add(tlv.len()))
      .and_then(|len| u16::try_from(len).ok())
      .context("PROXY TLS header exceeds the wire size limit")?;
    bytes[14..16].copy_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&tlv);
    let policy_identity = format!("{source}:client_certificate={}", config.client_certificate);
    let cache_identity = crate::cache::CacheProxyProtocolIdentity::new(&policy_identity, &bytes);
    Ok(Self {
      bytes: bytes.into(),
      cache_identity,
      certificate_identity: ssl.client & 0x06 != 0
        || ssl.common_name.is_some()
        || (config.client_certificate && ssl.certificate.is_some()),
    })
  }

  pub(crate) fn bytes(&self) -> &[u8] {
    &self.bytes
  }
}

pub(crate) fn local_capture_needed(config: &crate::config::Config) -> bool {
  config.upstreams.iter().any(|upstream| {
    upstream
      .proxy_protocol_tls
      .as_ref()
      .is_some_and(|policy| policy.source == ProxyProtocolTlsSource::LocalTls)
  })
}

pub(crate) fn local_certificate_capture_needed(config: &crate::config::Config) -> bool {
  config.upstreams.iter().any(|upstream| {
    upstream.proxy_protocol_tls.as_ref().is_some_and(|policy| {
      policy.source == ProxyProtocolTlsSource::LocalTls && policy.client_certificate
    })
  })
}
