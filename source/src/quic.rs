use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use h3_quinn::quinn::crypto::{AeadKey, CryptoError, HandshakeTokenKey, HmacKey};
use h3_quinn::quinn::{
  Endpoint, EndpointConfig, IdleTimeout, MtuDiscoveryConfig, ServerConfig, TokioRuntime,
  TransportConfig, VarInt,
};
use ring::{aead, hkdf, hmac};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::{
  QuicConfig, QuicSocketConfig, QuicTransportConfig, canonicalize_existing_file,
};

pub(crate) mod h3;

const QUIC_HOST_KEY_BYTES: usize = 64;
const QUIC_HOST_KEY_RESET_LABEL: &[u8] = b"oxibelt quic stateless reset v1";
const QUIC_HOST_KEY_TOKEN_LABEL: &[u8] = b"oxibelt quic retry token v1";

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
  let socket = bind_udp_socket(bind, &config.socket)?;
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
  for _ in 1..config.socket.workers {
    endpoints.push(bind_server_endpoint(
      worker_bind,
      server_config.clone(),
      config,
      host_key_base_dir,
    )?);
  }
  Ok(endpoints)
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
  use crate::config::{QuicMtuDiscoveryConfig, QuicTransportConfig};

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
