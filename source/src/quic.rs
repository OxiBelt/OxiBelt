//! QUIC endpoint construction and transport defaults for HTTP/3-facing sockets.
//! Host keys and retry policy stay explicit because they affect replay and amplification boundaries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use anyhow::{Context, bail};
use base64::Engine;
use h3_quinn::quinn::crypto::{AeadKey, CryptoError, HandshakeTokenKey, HmacKey};
use h3_quinn::quinn::{
  Endpoint, EndpointConfig, IdleTimeout, MtuDiscoveryConfig, ServerConfig, TokioRuntime,
  TransportConfig, VarInt,
};
use hkdf::Hkdf;
use sha2::Sha256;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::{
  QuicConfig, QuicSocketConfig, QuicTransportConfig, canonicalize_existing_file,
};

pub(crate) mod h3;

const QUIC_HOST_KEY_BYTES: usize = 64;
const QUIC_HOST_KEY_RESET_LABEL: &[u8] = b"oxibelt quic stateless reset v1";
const QUIC_HOST_KEY_TOKEN_LABEL: &[u8] = b"oxibelt quic retry token v1";
const QUIC_RETRY_TOKEN_AEAD_LABEL: &[u8] = b"oxibelt quic token aead";
const QUIC_RETRY_TOKEN_NONCE: [u8; 12] = [0u8; 12];

pub fn transport_config(
  config: &QuicTransportConfig,
  path: &'static str,
) -> anyhow::Result<Arc<TransportConfig>> {
  let mut transport = TransportConfig::default();
  transport.max_concurrent_bidi_streams(
    VarInt::try_from(config.max_concurrent_bidi_streams)
      .with_context(|| format!("{path}.max_concurrent_bidi_streams is too large"))?,
  );
  transport.max_concurrent_uni_streams(
    VarInt::try_from(config.max_concurrent_uni_streams)
      .with_context(|| format!("{path}.max_concurrent_uni_streams is too large"))?,
  );
  let idle_timeout: IdleTimeout = Duration::from_millis(config.idle_timeout_ms)
    .try_into()
    .with_context(|| format!("{path}.idle_timeout_ms is too large"))?;
  transport.max_idle_timeout(Some(idle_timeout));
  let keep_alive_interval = (config.keep_alive_interval_ms > 0)
    .then(|| Duration::from_millis(config.keep_alive_interval_ms));
  transport.keep_alive_interval(keep_alive_interval);
  transport.stream_receive_window(
    VarInt::try_from(config.stream_receive_window_bytes)
      .with_context(|| format!("{path}.stream_receive_window_bytes is too large"))?,
  );
  transport.receive_window(
    VarInt::try_from(config.receive_window_bytes)
      .with_context(|| format!("{path}.receive_window_bytes is too large"))?,
  );
  transport.send_window(config.send_window_bytes);
  transport.send_fairness(config.send_fairness);
  transport.datagram_receive_buffer_size(Some(config.datagram_receive_buffer_bytes));
  transport.datagram_send_buffer_size(config.datagram_send_buffer_bytes);
  transport.enable_segmentation_offload(config.gso);
  transport.initial_mtu(config.initial_mtu);
  transport.min_mtu(config.min_mtu);
  let mtu_discovery_config = if config.mtu_discovery.enabled {
    let mut mtu = MtuDiscoveryConfig::default();
    mtu.upper_bound(config.mtu_discovery.upper_bound);
    mtu.interval(Duration::from_millis(config.mtu_discovery.interval_ms));
    mtu.black_hole_cooldown(Duration::from_millis(
      config.mtu_discovery.black_hole_cooldown_ms,
    ));
    mtu.minimum_change(config.mtu_discovery.minimum_change);
    Some(mtu)
  } else {
    None
  };
  transport.mtu_discovery_config(mtu_discovery_config);
  Ok(Arc::new(transport))
}

pub fn endpoint_config(
  config: &QuicConfig,
  transport_config: &QuicTransportConfig,
  transport_path: &'static str,
  host_key_base_dir: Option<&Path>,
) -> anyhow::Result<EndpointConfig> {
  let reset_key = quic_host_key(config, host_key_base_dir)?
    .map(|key| Arc::new(ResetHmacKey::new(key.reset_key)) as Arc<dyn HmacKey>);
  let mut endpoint = match reset_key {
    Some(key) => EndpointConfig::new(key),
    None => EndpointConfig::default(),
  };
  endpoint
    .max_udp_payload_size(transport_config.max_udp_payload_size)
    .with_context(|| format!("invalid {transport_path}.max_udp_payload_size"))?;
  Ok(endpoint)
}

pub fn apply_server_config(
  config: &QuicConfig,
  host_key_base_dir: Option<&Path>,
  server_config: &mut ServerConfig,
) -> anyhow::Result<()> {
  if let Some(key) = quic_host_key(config, host_key_base_dir)? {
    server_config.token_key(Arc::new(RetryTokenKey::new(key.token_key)));
  }
  server_config.transport_config(transport_config(
    &config.downstream.transport,
    "quic.downstream.transport",
  )?);
  Ok(())
}

pub fn bind_server_endpoint(
  bind: SocketAddr,
  server_config: ServerConfig,
  config: &QuicConfig,
  host_key_base_dir: Option<&Path>,
) -> anyhow::Result<Endpoint> {
  bind_server_endpoint_with_worker_index(bind, server_config, config, host_key_base_dir, 0)
}

pub fn bind_server_endpoints(
  bind: SocketAddr,
  server_config: ServerConfig,
  config: &QuicConfig,
  host_key_base_dir: Option<&Path>,
) -> anyhow::Result<Vec<Endpoint>> {
  let mut endpoints = Vec::with_capacity(config.socket.workers);
  let first = bind_server_endpoint(bind, server_config.clone(), config, host_key_base_dir)?;
  let assigned = first
    .local_addr()
    .context("failed to read downstream HTTP/3 listener address")?;
  endpoints.push(first);

  if config.socket.workers == 1 {
    return Ok(endpoints);
  }

  let worker_bind = SocketAddr::new(bind.ip(), assigned.port());
  for worker_index in 1..config.socket.workers {
    endpoints.push(bind_server_endpoint_with_worker_index(
      worker_bind,
      server_config.clone(),
      config,
      host_key_base_dir,
      worker_index,
    )?);
  }
  Ok(endpoints)
}

fn bind_server_endpoint_with_worker_index(
  bind: SocketAddr,
  server_config: ServerConfig,
  config: &QuicConfig,
  host_key_base_dir: Option<&Path>,
  worker_index: usize,
) -> anyhow::Result<Endpoint> {
  let socket = bind_udp_socket_with_worker_index(bind, &config.socket, worker_index)?;
  Endpoint::new(
    endpoint_config(
      config,
      &config.downstream.transport,
      "quic.downstream.transport",
      host_key_base_dir,
    )?,
    Some(server_config),
    socket,
    Arc::new(TokioRuntime),
  )
  .with_context(|| format!("failed to bind downstream HTTP/3 listener to {bind}"))
}

pub fn bind_client_endpoint(
  remote_addr: SocketAddr,
  config: &QuicConfig,
  host_key_base_dir: Option<&Path>,
) -> anyhow::Result<Endpoint> {
  let socket = bind_udp_socket(client_bind_addr(remote_addr), &config.socket)?;
  Endpoint::new(
    endpoint_config(
      config,
      &config.upstream.transport,
      "quic.upstream.transport",
      host_key_base_dir,
    )?,
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

pub fn load_host_key(base_dir: &Path, path: &Path) -> anyhow::Result<[u8; QUIC_HOST_KEY_BYTES]> {
  let canonical_base_dir = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve QUIC host key base directory {}",
      base_dir.display()
    )
  })?;
  let canonical_path = canonicalize_existing_file("quic.host_key_file", path)?;
  if !canonical_path.starts_with(&canonical_base_dir) {
    bail!("quic.host_key_file must stay within the configured certificate directory");
  }

  let raw = std::fs::read_to_string(&canonical_path).with_context(|| {
    format!(
      "failed to read QUIC host key file {}",
      canonical_path.display()
    )
  })?;
  let encoded: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(encoded.as_bytes())
    .with_context(|| {
      format!(
        "failed to decode base64 QUIC host key from {}",
        canonical_path.display()
      )
    })?;
  if decoded.len() != QUIC_HOST_KEY_BYTES {
    bail!("quic.host_key_file must contain base64 for exactly {QUIC_HOST_KEY_BYTES} random bytes");
  }
  let mut key = [0u8; QUIC_HOST_KEY_BYTES];
  key.copy_from_slice(&decoded);
  Ok(key)
}

pub(crate) fn bind_udp_socket(
  bind: SocketAddr,
  config: &QuicSocketConfig,
) -> anyhow::Result<UdpSocket> {
  bind_udp_socket_with_worker_index(bind, config, 0)
}

fn bind_udp_socket_with_worker_index(
  bind: SocketAddr,
  config: &QuicSocketConfig,
  worker_index: usize,
) -> anyhow::Result<UdpSocket> {
  if let Some(socket) = crate::netport_switcher::bind_udp_socket(
    bind,
    crate::netport_switcher::SwitcherUdpOptions::quic(config),
    "downstream HTTP/3",
    worker_index,
  )? {
    return Ok(socket);
  }
  let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))
    .with_context(|| format!("failed to create UDP socket for {bind}"))?;
  if bind.is_ipv6() {
    socket
      .set_only_v6(true)
      .with_context(|| format!("failed to set UDP IPV6_V6ONLY for {bind}"))?;
  }
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
  if config.reuse_port {
    socket
      .set_reuse_port(true)
      .context("failed to set QUIC UDP SO_REUSEPORT")?;
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

fn quic_host_key(
  config: &QuicConfig,
  host_key_base_dir: Option<&Path>,
) -> anyhow::Result<Option<DerivedHostKey>> {
  let Some(path) = &config.host_key_file else {
    return Ok(None);
  };
  let base_dir = host_key_base_dir.ok_or_else(|| {
    anyhow::anyhow!("quic.host_key_file requires a configured certificate directory")
  })?;
  let key = load_host_key(base_dir, path)?;
  Ok(Some(DerivedHostKey {
    reset_key: derive_host_key(&key, QUIC_HOST_KEY_RESET_LABEL)?,
    token_key: derive_host_key(&key, QUIC_HOST_KEY_TOKEN_LABEL)?,
  }))
}

fn derive_host_key(host_key: &[u8; QUIC_HOST_KEY_BYTES], label: &[u8]) -> anyhow::Result<[u8; 32]> {
  let mut out = [0u8; 32];
  Hkdf::<Sha256>::new(Some(label), host_key)
    .expand(b"oxibelt", &mut out)
    .map_err(|_| anyhow::anyhow!("failed to fill QUIC host key material"))?;
  Ok(out)
}

struct ResetHmacKey {
  key: [u8; 32],
}

impl ResetHmacKey {
  fn new(key: [u8; 32]) -> Self {
    Self { key }
  }
}

impl HmacKey for ResetHmacKey {
  fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
    signature_out.copy_from_slice(&crate::crypto::hmac_sha256(&self.key, data));
  }

  fn signature_len(&self) -> usize {
    32
  }

  fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    crate::crypto::verify_hmac_sha256(&self.key, data, signature)
      .then_some(())
      .ok_or(CryptoError)
  }
}

struct RetryTokenKey {
  key: [u8; 32],
}

impl RetryTokenKey {
  fn new(key: [u8; 32]) -> Self {
    Self { key }
  }
}

impl HandshakeTokenKey for RetryTokenKey {
  fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn AeadKey> {
    let mut key_buffer = [0u8; 32];
    Hkdf::<Sha256>::new(Some(QUIC_RETRY_TOKEN_AEAD_LABEL), &self.key)
      .expand(random_bytes, &mut key_buffer)
      .expect("HKDF output buffer length is valid");
    Box::new(RetryAeadKey(
      Aes256Gcm::new_from_slice(&key_buffer).expect("AES-256-GCM accepts 32 byte keys"),
    ))
  }
}

struct RetryAeadKey(Aes256Gcm);

impl AeadKey for RetryAeadKey {
  fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
    let nonce = Nonce::from_slice(&QUIC_RETRY_TOKEN_NONCE);
    self
      .0
      .encrypt_in_place(nonce, additional_data, data)
      .map_err(|_| CryptoError)
  }

  fn open<'a>(
    &self,
    data: &'a mut [u8],
    additional_data: &[u8],
  ) -> Result<&'a mut [u8], CryptoError> {
    if data.len() < 16 {
      return Err(CryptoError);
    }
    let tag_start = data.len() - 16;
    let (ciphertext, tag) = data.split_at_mut(tag_start);
    let nonce = Nonce::from_slice(&QUIC_RETRY_TOKEN_NONCE);
    let tag = Tag::from_slice(tag);
    self
      .0
      .decrypt_in_place_detached(nonce, additional_data, ciphertext, tag)
      .map_err(|_| CryptoError)?;
    Ok(ciphertext)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{QuicMtuDiscoveryConfig, QuicTransportConfig};

  #[test]
  fn reset_hmac_key_signs_and_verifies() {
    let key = ResetHmacKey::new([7; 32]);
    let data = b"stateless reset material";
    let mut signature = vec![0u8; key.signature_len()];

    key.sign(data, &mut signature);

    assert!(key.verify(data, &signature).is_ok());
    assert!(key.verify(b"tampered", &signature).is_err());
    signature[0] ^= 0xff;
    assert!(key.verify(data, &signature).is_err());
  }

  #[test]
  fn retry_token_key_seals_and_opens_with_additional_data() {
    let key = RetryTokenKey::new([9; 32]);
    let aead = key.aead_from_hkdf(b"retry random");
    let additional_data = b"client address";
    let mut token = b"opaque retry token".to_vec();

    assert!(aead.seal(&mut token, additional_data).is_ok());
    assert_ne!(token, b"opaque retry token");

    let opened = match aead.open(&mut token, additional_data) {
      Ok(opened) => opened,
      Err(_) => panic!("retry token should decrypt with matching additional data"),
    };
    assert_eq!(opened, b"opaque retry token");
  }

  #[test]
  fn retry_token_key_rejects_wrong_additional_data() {
    let key = RetryTokenKey::new([9; 32]);
    let aead = key.aead_from_hkdf(b"retry random");
    let mut token = b"opaque retry token".to_vec();

    assert!(aead.seal(&mut token, b"client address").is_ok());

    assert!(aead.open(&mut token, b"other client").is_err());
  }

  #[test]
  fn transport_config_maps_keep_alive_and_window_settings() {
    let config = QuicTransportConfig {
      keep_alive_interval_ms: 25,
      stream_receive_window_bytes: 2048,
      receive_window_bytes: 4096,
      send_window_bytes: 8192,
      send_fairness: false,
      ..QuicTransportConfig::default()
    };

    let transport = transport_config(&config, "test.transport").expect("transport config");
    let debug = format!("{transport:?}");

    assert!(
      debug.contains("stream_receive_window: 2048"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("receive_window: 4096"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("send_window: 8192"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("send_fairness: false"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("keep_alive_interval: Some(25ms)"),
      "unexpected debug output: {debug}"
    );
  }

  #[test]
  fn transport_config_disables_keep_alive_and_mtu_discovery_when_configured() {
    let config = QuicTransportConfig {
      keep_alive_interval_ms: 0,
      mtu_discovery: QuicMtuDiscoveryConfig {
        enabled: false,
        ..QuicMtuDiscoveryConfig::default()
      },
      ..QuicTransportConfig::default()
    };

    let transport = transport_config(&config, "test.transport").expect("transport config");
    let debug = format!("{transport:?}");

    assert!(
      debug.contains("receive_window: 8388608"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("keep_alive_interval: None"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("mtu_discovery_config: None"),
      "unexpected debug output: {debug}"
    );
  }

  #[test]
  fn transport_config_maps_mtu_discovery_settings() {
    let config = QuicTransportConfig {
      initial_mtu: 1300,
      min_mtu: 1200,
      mtu_discovery: QuicMtuDiscoveryConfig {
        enabled: true,
        upper_bound: 1500,
        interval_ms: 700_000,
        black_hole_cooldown_ms: 80_000,
        minimum_change: 40,
      },
      ..QuicTransportConfig::default()
    };

    let transport = transport_config(&config, "test.transport").expect("transport config");
    let debug = format!("{transport:?}");

    assert!(
      debug.contains("initial_mtu: 1300"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("min_mtu: 1200"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("upper_bound: 1500"),
      "unexpected debug output: {debug}"
    );
    assert!(
      debug.contains("minimum_change: 40"),
      "unexpected debug output: {debug}"
    );
  }
}
