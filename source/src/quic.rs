use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use h3_quinn::quinn::crypto::{AeadKey, CryptoError, HandshakeTokenKey, HmacKey};
use h3_quinn::quinn::{
  Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt,
};
use ring::{aead, hkdf, hmac};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::{QuicConfig, QuicSocketConfig};

const QUIC_HOST_KEY_BYTES: usize = 64;
const QUIC_HOST_KEY_RESET_LABEL: &[u8] = b"oxibelt quic stateless reset v1";
const QUIC_HOST_KEY_TOKEN_LABEL: &[u8] = b"oxibelt quic retry token v1";

pub fn transport_config(config: &QuicConfig) -> anyhow::Result<Arc<TransportConfig>> {
  let mut transport = TransportConfig::default();
  transport.max_concurrent_bidi_streams(
    VarInt::try_from(config.transport.max_concurrent_bidi_streams)
      .context("quic.transport.max_concurrent_bidi_streams is too large")?,
  );
  transport.max_concurrent_uni_streams(
    VarInt::try_from(config.transport.max_concurrent_uni_streams)
      .context("quic.transport.max_concurrent_uni_streams is too large")?,
  );
  let idle_timeout: IdleTimeout = Duration::from_millis(config.transport.idle_timeout_ms)
    .try_into()
    .context("quic.transport.idle_timeout_ms is too large")?;
  transport.max_idle_timeout(Some(idle_timeout));
  transport.datagram_receive_buffer_size(Some(config.transport.datagram_receive_buffer_bytes));
  transport.datagram_send_buffer_size(config.transport.datagram_send_buffer_bytes);
  transport.enable_segmentation_offload(config.transport.gso);
  Ok(Arc::new(transport))
}

pub fn endpoint_config(config: &QuicConfig) -> anyhow::Result<EndpointConfig> {
  let reset_key = quic_host_key(config)?
    .map(|key| Arc::new(ResetHmacKey::new(key.reset_key)) as Arc<dyn HmacKey>);
  let mut endpoint = match reset_key {
    Some(key) => EndpointConfig::new(key),
    None => EndpointConfig::default(),
  };
  endpoint
    .max_udp_payload_size(config.transport.max_udp_payload_size)
    .context("invalid quic.transport.max_udp_payload_size")?;
  Ok(endpoint)
}

pub fn apply_server_config(
  config: &QuicConfig,
  server_config: &mut ServerConfig,
) -> anyhow::Result<()> {
  if let Some(key) = quic_host_key(config)? {
    server_config.token_key(Arc::new(RetryTokenKey::new(key.token_key)));
  }
  server_config.transport_config(transport_config(config)?);
  Ok(())
}

pub fn bind_server_endpoint(
  bind: SocketAddr,
  server_config: ServerConfig,
  config: &QuicConfig,
) -> anyhow::Result<Endpoint> {
  let socket = bind_udp_socket(bind, &config.socket)?;
  Endpoint::new(
    endpoint_config(config)?,
    Some(server_config),
    socket,
    Arc::new(TokioRuntime),
  )
  .with_context(|| format!("failed to bind downstream HTTP/3 listener to {bind}"))
}

pub fn bind_client_endpoint(
  remote_addr: SocketAddr,
  config: &QuicConfig,
) -> anyhow::Result<Endpoint> {
  let socket = bind_udp_socket(client_bind_addr(remote_addr), &config.socket)?;
  Endpoint::new(
    endpoint_config(config)?,
    None,
    socket,
    Arc::new(TokioRuntime),
  )
  .context("failed to create upstream QUIC endpoint")
}

pub fn client_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
  match remote_addr.ip() {
    IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
  }
}

pub fn load_host_key(path: &Path) -> anyhow::Result<[u8; QUIC_HOST_KEY_BYTES]> {
  let raw = std::fs::read_to_string(path)
    .with_context(|| format!("failed to read QUIC host key file {}", path.display()))?;
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .with_context(|| {
      format!(
        "failed to decode base64 QUIC host key from {}",
        path.display()
      )
    })?;
  if decoded.len() != QUIC_HOST_KEY_BYTES {
    bail!("quic.host_key_file must contain base64 for exactly {QUIC_HOST_KEY_BYTES} random bytes");
  }
  let mut key = [0u8; QUIC_HOST_KEY_BYTES];
  key.copy_from_slice(&decoded);
  Ok(key)
}

fn bind_udp_socket(bind: SocketAddr, config: &QuicSocketConfig) -> anyhow::Result<UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))
    .with_context(|| format!("failed to create UDP socket for {bind}"))?;
  if config.receive_buffer_bytes > 0 {
    socket
      .set_recv_buffer_size(config.receive_buffer_bytes)
      .context("failed to set QUIC UDP receive buffer size")?;
  }
  if config.send_buffer_bytes > 0 {
    socket
      .set_send_buffer_size(config.send_buffer_bytes)
      .context("failed to set QUIC UDP send buffer size")?;
  }
  socket
    .bind(&SockAddr::from(bind))
    .with_context(|| format!("failed to bind QUIC UDP socket to {bind}"))?;
  socket
    .set_nonblocking(true)
    .context("failed to set QUIC UDP socket nonblocking")?;
  Ok(socket.into())
}

#[derive(Clone, Copy)]
struct DerivedHostKey {
  reset_key: [u8; 32],
  token_key: [u8; 32],
}

fn quic_host_key(config: &QuicConfig) -> anyhow::Result<Option<DerivedHostKey>> {
  let Some(path) = &config.host_key_file else {
    return Ok(None);
  };
  let key = load_host_key(path)?;
  Ok(Some(DerivedHostKey {
    reset_key: derive_host_key(&key, QUIC_HOST_KEY_RESET_LABEL)?,
    token_key: derive_host_key(&key, QUIC_HOST_KEY_TOKEN_LABEL)?,
  }))
}

fn derive_host_key(host_key: &[u8; QUIC_HOST_KEY_BYTES], label: &[u8]) -> anyhow::Result<[u8; 32]> {
  let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, label);
  let prk = salt.extract(host_key);
  let okm = prk
    .expand(&[b"oxibelt"], hkdf::HKDF_SHA256)
    .map_err(|_| anyhow::anyhow!("failed to derive QUIC host key material"))?;
  let mut out = [0u8; 32];
  okm
    .fill(&mut out)
    .map_err(|_| anyhow::anyhow!("failed to fill QUIC host key material"))?;
  Ok(out)
}

struct ResetHmacKey {
  key: hmac::Key,
}

impl ResetHmacKey {
  fn new(key: [u8; 32]) -> Self {
    Self {
      key: hmac::Key::new(hmac::HMAC_SHA256, &key),
    }
  }
}

impl HmacKey for ResetHmacKey {
  fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
    signature_out.copy_from_slice(hmac::sign(&self.key, data).as_ref());
  }

  fn signature_len(&self) -> usize {
    32
  }

  fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    hmac::verify(&self.key, data, signature).map_err(|_| CryptoError)
  }
}

struct RetryTokenKey {
  prk: hkdf::Prk,
}

impl RetryTokenKey {
  fn new(key: [u8; 32]) -> Self {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"oxibelt quic token aead");
    Self {
      prk: salt.extract(&key),
    }
  }
}

impl HandshakeTokenKey for RetryTokenKey {
  fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn AeadKey> {
    let info = [random_bytes];
    let okm = self
      .prk
      .expand(&info, hkdf::HKDF_SHA256)
      .expect("HKDF-SHA256 accepts 32 byte output");
    let mut key_buffer = [0u8; 32];
    okm
      .fill(&mut key_buffer)
      .expect("HKDF output buffer length is valid");
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_buffer)
      .expect("AES-256-GCM accepts 32 byte keys");
    Box::new(RetryAeadKey(aead::LessSafeKey::new(key)))
  }
}

struct RetryAeadKey(aead::LessSafeKey);

impl AeadKey for RetryAeadKey {
  fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
    let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
    self
      .0
      .seal_in_place_append_tag(nonce, aead::Aad::from(additional_data), data)
      .map_err(|_| CryptoError)
  }

  fn open<'a>(
    &self,
    data: &'a mut [u8],
    additional_data: &[u8],
  ) -> Result<&'a mut [u8], CryptoError> {
    let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
    self
      .0
      .open_in_place(nonce, aead::Aad::from(additional_data), data)
      .map_err(|_| CryptoError)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn load_host_key_accepts_exactly_64_base64_bytes() {
    let dir = std::env::temp_dir().join(format!("oxibelt-quic-host-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("key.b64");
    let bytes = [7u8; QUIC_HOST_KEY_BYTES];
    std::fs::write(
      &path,
      base64::engine::general_purpose::STANDARD.encode(bytes),
    )
    .unwrap();

    assert_eq!(load_host_key(&path).unwrap(), bytes);
    let _ = std::fs::remove_dir_all(dir);
  }

  #[test]
  fn load_host_key_rejects_wrong_length() {
    let dir = std::env::temp_dir().join(format!(
      "oxibelt-quic-host-key-short-{}",
      std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("key.b64");
    std::fs::write(
      &path,
      base64::engine::general_purpose::STANDARD.encode([1u8; 63]),
    )
    .unwrap();

    let error = load_host_key(&path).unwrap_err();
    assert!(error.to_string().contains("exactly 64"));
    let _ = std::fs::remove_dir_all(dir);
  }
}
