//! Remote certificate signing client and local protocol server support.
//! Signing keys are delegated over a narrow socket protocol instead of being copied into proxy code.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};
use tokio::net::{UnixListener, UnixStream as TokioUnixStream};
use tokio::sync::{Semaphore, TryAcquireError};
use tracing::{info, warn};

use crate::config::TlsRemoteSignerConfig;
use pool::RemoteSignerConnectionPool;
use protocol::{
  RemoteSignerRequest, RemoteSignerResponse, SignContext, read_async_frame_with_timeout,
  read_sync_frame, write_async_frame_with_timeout, write_sync_frame,
};

mod keys;
mod pool;
mod protocol;
#[cfg(test)]
mod tests;
mod token;

use keys::{PREFERRED_SIGNATURE_SCHEMES, ServerKey, load_server_keys};
use token::{RemoteSignerTokenProvider, request_token_is_valid, token_to_wire};

pub const DEFAULT_REMOTE_SIGNER_MAX_CONNECTIONS: usize = 256;
pub const DEFAULT_REMOTE_SIGNER_IO_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_REMOTE_SIGNER_TOKEN_RELOAD_INTERVAL_MS: u64 = 1_000;
const TLS13_SERVER_CERT_VERIFY_CONTEXT: &[u8; 34] = b"TLS 1.3, server CertificateVerify\x00";

#[derive(Clone)]
pub struct RemoteSigningKey {
  client: RemoteSignerClient,
  key_id: String,
  public_key: Vec<u8>,
  algorithm: SignatureAlgorithm,
  schemes: Vec<SignatureScheme>,
}

impl RemoteSigningKey {
  pub fn connect(
    config: &TlsRemoteSignerConfig,
    key_id: &str,
    certificate: &CertificateDer<'_>,
  ) -> anyhow::Result<Arc<dyn SigningKey>> {
    let client = RemoteSignerClient::from_config(config)?;
    let description = client.describe_key(key_id)?;
    let certificate_spki = certificate_spki(certificate)
      .context("failed to parse configured TLS certificate public key")?;
    if description.public_key != certificate_spki {
      bail!("remote signer key {key_id} does not match configured TLS certificate public key");
    }
    if description.schemes.is_empty() {
      bail!("remote signer key {key_id} did not report any supported TLS signature schemes");
    }
    Ok(Arc::new(Self {
      client,
      key_id: key_id.to_string(),
      public_key: description.public_key,
      algorithm: description.algorithm,
      schemes: description.schemes,
    }))
  }
}

impl SigningKey for RemoteSigningKey {
  fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
    self
      .schemes
      .iter()
      .copied()
      .find(|scheme| offered.contains(scheme))
      .map(|scheme| {
        Box::new(RemoteSigner {
          client: self.client.clone(),
          key_id: self.key_id.clone(),
          scheme,
        }) as Box<dyn Signer>
      })
  }

  fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
    Some(SubjectPublicKeyInfoDer::from(self.public_key.clone()))
  }

  fn algorithm(&self) -> SignatureAlgorithm {
    self.algorithm
  }
}

impl fmt::Debug for RemoteSigningKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RemoteSigningKey")
      .field("key_id", &self.key_id)
      .field("algorithm", &self.algorithm)
      .field("schemes", &self.schemes)
      .finish()
  }
}

#[derive(Clone)]
struct RemoteSignerClient {
  socket_path: PathBuf,
  token_provider: RemoteSignerTokenProvider,
  connect_timeout: Duration,
  sign_timeout: Duration,
  pool: Arc<RemoteSignerConnectionPool>,
  #[cfg(test)]
  connect_override: Option<Arc<dyn Fn() -> anyhow::Result<UnixStream> + Send + Sync>>,
  allow_tls12_unstructured_signing: bool,
}

impl RemoteSignerClient {
  fn from_config(config: &TlsRemoteSignerConfig) -> anyhow::Result<Self> {
    Ok(Self {
      socket_path: config.socket_path.clone(),
      token_provider: RemoteSignerTokenProvider::from_sources(
        config.token_file.clone(),
        &config.token_env,
        Duration::from_millis(config.token_reload_interval_ms),
      )?,
      connect_timeout: Duration::from_millis(config.connect_timeout_ms),
      sign_timeout: Duration::from_millis(config.sign_timeout_ms),
      pool: Arc::new(RemoteSignerConnectionPool::new(
        config.pool_max_idle_connections,
      )),
      #[cfg(test)]
      connect_override: None,
      allow_tls12_unstructured_signing: config.allow_tls12_unstructured_signing,
    })
  }

  fn describe_key(&self, key_id: &str) -> anyhow::Result<RemoteKeyDescription> {
    match self.request_authenticated(|token| RemoteSignerRequest::DescribeKey {
      token: token_to_wire(&token),
      key_id: key_id.to_string(),
    })? {
      RemoteSignerResponse::DescribeKey {
        public_key,
        algorithm,
        schemes,
      } => Ok(RemoteKeyDescription {
        public_key: decode_base64("remote signer public_key", &public_key)?,
        algorithm: parse_signature_algorithm(&algorithm)?,
        schemes: parse_signature_schemes(&schemes),
      }),
      RemoteSignerResponse::Error { code, message } => {
        bail!("remote signer describe_key failed: {code}: {message}")
      }
      _ => bail!("remote signer returned unexpected describe_key response"),
    }
  }

  fn sign(
    &self,
    key_id: &str,
    scheme: SignatureScheme,
    message: &[u8],
  ) -> Result<Vec<u8>, RustlsError> {
    let context = if is_tls13_server_certificate_verify_message(message) {
      SignContext::Tls13ServerCertificateVerify
    } else if self.allow_tls12_unstructured_signing {
      SignContext::Tls12Unstructured
    } else {
      return Err(RustlsError::General(
        "remote signer refused non-TLS 1.3 server CertificateVerify signing input".to_string(),
      ));
    };

    let response = self.request_authenticated(|token| RemoteSignerRequest::Sign {
      token: token_to_wire(&token),
      key_id: key_id.to_string(),
      scheme: u16::from(scheme),
      context,
      message: base64::engine::general_purpose::STANDARD.encode(message),
    });
    match response {
      Ok(RemoteSignerResponse::Sign { signature }) => {
        decode_base64("remote signer signature", &signature)
          .map_err(|error| RustlsError::General(error.to_string()))
      }
      Ok(RemoteSignerResponse::Error { code, message }) => Err(RustlsError::General(format!(
        "remote signer sign failed: {code}: {message}"
      ))),
      Ok(_) => Err(RustlsError::General(
        "remote signer returned unexpected sign response".to_string(),
      )),
      Err(error) => Err(RustlsError::General(format!(
        "remote signer request failed: {error}"
      ))),
    }
  }

  fn request_authenticated<F>(&self, make_request: F) -> anyhow::Result<RemoteSignerResponse>
  where
    F: Fn([u8; 32]) -> RemoteSignerRequest,
  {
    self.request_authenticated_with_transport(make_request, |stream, request| {
      self.request_on_stream(stream, request)
    })
  }

  fn request_authenticated_with_transport<F, T>(
    &self,
    make_request: F,
    mut transport: T,
  ) -> anyhow::Result<RemoteSignerResponse>
  where
    F: Fn([u8; 32]) -> RemoteSignerRequest,
    T: FnMut(&mut UnixStream, &RemoteSignerRequest) -> anyhow::Result<RemoteSignerResponse>,
  {
    let response = self.request_with_transport(
      make_request(self.token_provider.current_token()),
      &mut transport,
    )?;
    if !is_unauthorized_response(&response) || !self.token_provider.reloadable() {
      return Ok(response);
    }

    self.token_provider.force_refresh();
    self.request_with_transport(
      make_request(self.token_provider.current_token()),
      &mut transport,
    )
  }

  fn request_with_transport<F>(
    &self,
    request: RemoteSignerRequest,
    mut transport: F,
  ) -> anyhow::Result<RemoteSignerResponse>
  where
    F: FnMut(&mut UnixStream, &RemoteSignerRequest) -> anyhow::Result<RemoteSignerResponse>,
  {
    if let Some(mut stream) = self.pool.take(self.sign_timeout) {
      match transport(&mut stream, &request) {
        Ok(response) => {
          self.pool.put(stream);
          return Ok(response);
        }
        Err(error) => {
          tracing::debug!(
            error = %error,
            socket_path = %self.socket_path.display(),
            "discarding stale remote signer pooled connection"
          );
        }
      }
    }

    let mut stream = self.connect()?;
    let response = transport(&mut stream, &request)?;
    self.pool.put(stream);
    Ok(response)
  }

  fn connect(&self) -> anyhow::Result<UnixStream> {
    #[cfg(test)]
    if let Some(connect) = &self.connect_override {
      return connect();
    }
    connect_with_timeout(self.socket_path.clone(), self.connect_timeout)
      .with_context(|| format!("failed to connect to {}", self.socket_path.display()))
  }

  fn request_on_stream(
    &self,
    stream: &mut UnixStream,
    request: &RemoteSignerRequest,
  ) -> anyhow::Result<RemoteSignerResponse> {
    #[cfg(test)]
    let set_timeouts = self.connect_override.is_none();
    #[cfg(not(test))]
    let set_timeouts = true;
    if set_timeouts {
      stream
        .set_read_timeout(Some(self.sign_timeout))
        .context("failed to set remote signer read timeout")?;
      stream
        .set_write_timeout(Some(self.sign_timeout))
        .context("failed to set remote signer write timeout")?;
    }
    write_sync_frame(stream, request)?;
    read_sync_frame(stream)
  }
}

#[derive(Debug)]
struct RemoteSigner {
  client: RemoteSignerClient,
  key_id: String,
  scheme: SignatureScheme,
}

impl Signer for RemoteSigner {
  fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
    self.client.sign(&self.key_id, self.scheme, message)
  }

  fn scheme(&self) -> SignatureScheme {
    self.scheme
  }
}

impl fmt::Debug for RemoteSignerClient {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RemoteSignerClient")
      .field("socket_path", &self.socket_path)
      .field("token_source", &self.token_provider.source_label())
      .field("connect_timeout", &self.connect_timeout)
      .field("sign_timeout", &self.sign_timeout)
      .field("pool_max_idle_connections", &self.pool.max_idle)
      .field(
        "allow_tls12_unstructured_signing",
        &self.allow_tls12_unstructured_signing,
      )
      .finish()
  }
}

#[derive(Debug, Clone)]
pub struct SignerServerConfig {
  pub socket_path: PathBuf,
  pub socket_mode: u32,
  pub keys: Vec<(String, PathBuf)>,
  pub token_env: String,
  pub token_file: Option<PathBuf>,
  pub token_reload_interval: Duration,
  pub max_connections: usize,
  pub io_timeout: Duration,
  pub allow_peer_uids: Vec<u32>,
  pub allow_peer_gids: Vec<u32>,
  pub allow_tls12_unstructured_signing: bool,
}

pub async fn serve(config: SignerServerConfig) -> anyhow::Result<()> {
  if config.max_connections == 0 {
    bail!("remote signer max_connections must be greater than 0");
  }
  if config.io_timeout.is_zero() {
    bail!("remote signer io_timeout must be greater than 0");
  }
  if config.token_reload_interval.is_zero() {
    bail!("remote signer token_reload_interval must be greater than 0");
  }
  validate_socket_mode(config.socket_mode)?;
  if config.allow_peer_uids.is_empty() && config.allow_peer_gids.is_empty() {
    warn!(
      "remote signer peer UID/GID allowlists are empty; local peers with socket access are allowed"
    );
  }

  let token_provider = RemoteSignerTokenProvider::from_sources(
    config.token_file,
    &config.token_env,
    config.token_reload_interval,
  )?;
  let keys = Arc::new(load_server_keys(&config.keys)?);
  let listener = bind_listener(&config.socket_path, config.socket_mode)?;
  let max_connections = config.max_connections;
  let io_timeout = config.io_timeout;
  let allow_tls12_unstructured_signing = config.allow_tls12_unstructured_signing;
  info!(
    socket_path = %config.socket_path.display(),
    token_source = %token_provider.source_label(),
    keys = keys.len(),
    max_connections,
    io_timeout_ms = io_timeout.as_millis(),
    "remote TLS private-key signer listening"
  );

  let allow_peer_uids = Arc::new(config.allow_peer_uids);
  let allow_peer_gids = Arc::new(config.allow_peer_gids);
  let connection_permits = Arc::new(Semaphore::new(max_connections));
  loop {
    let (stream, _) = listener.accept().await?;
    let permit = match connection_permits.clone().try_acquire_owned() {
      Ok(permit) => permit,
      Err(TryAcquireError::NoPermits) => {
        warn!("remote signer connection limit reached; closing accepted connection");
        continue;
      }
      Err(TryAcquireError::Closed) => bail!("remote signer connection limiter closed"),
    };
    let keys = keys.clone();
    let token_provider = token_provider.clone();
    let allow_peer_uids = allow_peer_uids.clone();
    let allow_peer_gids = allow_peer_gids.clone();
    tokio::spawn(async move {
      let _permit = permit;
      if let Err(error) = handle_connection(
        stream,
        keys,
        token_provider,
        allow_peer_uids,
        allow_peer_gids,
        io_timeout,
        allow_tls12_unstructured_signing,
      )
      .await
      {
        warn!("remote signer connection failed: {error}");
      }
    });
  }
}

async fn handle_connection(
  mut stream: TokioUnixStream,
  keys: Arc<HashMap<String, ServerKey>>,
  token_provider: RemoteSignerTokenProvider,
  allow_peer_uids: Arc<Vec<u32>>,
  allow_peer_gids: Arc<Vec<u32>>,
  io_timeout: Duration,
  allow_tls12_unstructured_signing: bool,
) -> anyhow::Result<()> {
  if !peer_is_allowed(&stream, &allow_peer_uids, &allow_peer_gids)? {
    write_async_frame_with_timeout(
      &mut stream,
      &RemoteSignerResponse::Error {
        code: "forbidden_peer".to_string(),
        message: "peer credentials are not allowed".to_string(),
      },
      io_timeout,
    )
    .await?;
    return Ok(());
  }

  loop {
    let request: RemoteSignerRequest =
      match read_async_frame_with_timeout(&mut stream, io_timeout).await {
        Ok(request) => request,
        Err(error) if remote_signer_peer_closed(&error) => return Ok(()),
        Err(error) => return Err(error),
      };
    let response = process_request(
      request,
      &keys,
      &token_provider,
      allow_tls12_unstructured_signing,
    );
    match write_async_frame_with_timeout(&mut stream, &response, io_timeout).await {
      Ok(()) => {}
      Err(error) if remote_signer_peer_closed(&error) => return Ok(()),
      Err(error) => return Err(error),
    }
  }
}

fn remote_signer_peer_closed(error: &anyhow::Error) -> bool {
  error.chain().any(|cause| {
    cause.downcast_ref::<io::Error>().is_some_and(|error| {
      matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
          | io::ErrorKind::ConnectionReset
          | io::ErrorKind::BrokenPipe
          | io::ErrorKind::NotConnected
      )
    })
  })
}

fn process_request(
  request: RemoteSignerRequest,
  keys: &HashMap<String, ServerKey>,
  token_provider: &RemoteSignerTokenProvider,
  allow_tls12_unstructured_signing: bool,
) -> RemoteSignerResponse {
  let token = token_provider.current_token();
  if !request_token_is_valid(request.token(), &token) {
    return RemoteSignerResponse::Error {
      code: "unauthorized".to_string(),
      message: "invalid signer token".to_string(),
    };
  }

  match request {
    RemoteSignerRequest::DescribeKey { key_id, .. } => match keys.get(&key_id) {
      Some(key) => RemoteSignerResponse::DescribeKey {
        public_key: base64::engine::general_purpose::STANDARD.encode(&key.public_key),
        algorithm: signature_algorithm_name(key.algorithm).to_string(),
        schemes: key.schemes.iter().copied().map(u16::from).collect(),
      },
      None => RemoteSignerResponse::Error {
        code: "unknown_key".to_string(),
        message: "unknown key id".to_string(),
      },
    },
    RemoteSignerRequest::Sign {
      key_id,
      scheme,
      context,
      message,
      ..
    } => {
      let Some(key) = keys.get(&key_id) else {
        return RemoteSignerResponse::Error {
          code: "unknown_key".to_string(),
          message: "unknown key id".to_string(),
        };
      };
      let Ok(message) = decode_base64("signing message", &message) else {
        return RemoteSignerResponse::Error {
          code: "invalid_request".to_string(),
          message: "signing message must be base64".to_string(),
        };
      };
      match context {
        SignContext::Tls13ServerCertificateVerify => {
          if !is_tls13_server_certificate_verify_message(&message) {
            return RemoteSignerResponse::Error {
              code: "invalid_tls13_message".to_string(),
              message: "message is not a TLS 1.3 server CertificateVerify input".to_string(),
            };
          }
        }
        SignContext::Tls12Unstructured => {
          if !allow_tls12_unstructured_signing {
            return RemoteSignerResponse::Error {
              code: "tls12_disabled".to_string(),
              message: "TLS 1.2 unstructured signing is disabled".to_string(),
            };
          }
        }
      }
      let scheme = SignatureScheme::from(scheme);
      let Some(signer) = key.key.choose_scheme(&[scheme]) else {
        return RemoteSignerResponse::Error {
          code: "unsupported_scheme".to_string(),
          message: "key does not support requested signature scheme".to_string(),
        };
      };
      match signer.sign(&message) {
        Ok(signature) => RemoteSignerResponse::Sign {
          signature: base64::engine::general_purpose::STANDARD.encode(signature),
        },
        Err(error) => RemoteSignerResponse::Error {
          code: "signing_failed".to_string(),
          message: error.to_string(),
        },
      }
    }
  }
}

fn bind_listener(path: &Path, mode: u32) -> anyhow::Result<UnixListener> {
  validate_socket_mode(mode)?;
  if let Some(parent) = path.parent()
    && !parent.as_os_str().is_empty()
  {
    std::fs::create_dir_all(parent)
      .with_context(|| format!("failed to create socket directory {}", parent.display()))?;
  }
  match std::fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_socket() => {
      std::fs::remove_file(path)
        .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
    }
    Ok(_) => bail!("{} exists and is not a Unix socket", path.display()),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
    Err(error) => {
      return Err(error)
        .with_context(|| format!("failed to inspect socket path {}", path.display()));
    }
  }
  let listener = UnixListener::bind(path)
    .with_context(|| format!("failed to bind Unix socket {}", path.display()))?;
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    .with_context(|| format!("failed to set permissions on {}", path.display()))?;
  Ok(listener)
}

fn validate_socket_mode(mode: u32) -> anyhow::Result<()> {
  if !matches!(mode, 0o600 | 0o660) {
    bail!("remote signer socket mode must be 0600 or 0660");
  }
  Ok(())
}

fn peer_is_allowed(
  stream: &TokioUnixStream,
  allow_peer_uids: &[u32],
  allow_peer_gids: &[u32],
) -> anyhow::Result<bool> {
  if allow_peer_uids.is_empty() && allow_peer_gids.is_empty() {
    return Ok(true);
  }
  let credentials = stream
    .peer_cred()
    .context("failed to read peer credentials")?;
  Ok(peer_credentials_are_allowed(
    credentials.uid(),
    credentials.gid(),
    allow_peer_uids,
    allow_peer_gids,
  ))
}

fn peer_credentials_are_allowed(
  uid: u32,
  gid: u32,
  allow_peer_uids: &[u32],
  allow_peer_gids: &[u32],
) -> bool {
  allow_peer_uids.contains(&uid) || allow_peer_gids.contains(&gid)
}

fn certificate_spki(certificate: &CertificateDer<'_>) -> anyhow::Result<Vec<u8>> {
  let cert = webpki::EndEntityCert::try_from(certificate)
    .map_err(|error| anyhow!("failed to parse certificate: {error}"))?;
  Ok(cert.subject_public_key_info().as_ref().to_vec())
}

fn is_tls13_server_certificate_verify_message(message: &[u8]) -> bool {
  let prefix_len = 64 + TLS13_SERVER_CERT_VERIFY_CONTEXT.len();
  if message.len() <= prefix_len {
    return false;
  }
  let hash_len = message.len() - prefix_len;
  matches!(hash_len, 32 | 48 | 64)
    && message[..64].iter().all(|byte| *byte == b' ')
    && &message[64..prefix_len] == TLS13_SERVER_CERT_VERIFY_CONTEXT
}

fn connect_with_timeout(path: PathBuf, timeout: Duration) -> anyhow::Result<UnixStream> {
  let (tx, rx) = std::sync::mpsc::channel();
  std::thread::spawn(move || {
    let _ = tx.send(UnixStream::connect(path));
  });
  match rx.recv_timeout(timeout) {
    Ok(Ok(stream)) => Ok(stream),
    Ok(Err(error)) => Err(error.into()),
    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow!("connect timed out")),
    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
      Err(anyhow!("connect worker exited before returning a result"))
    }
  }
}

fn is_unauthorized_response(response: &RemoteSignerResponse) -> bool {
  matches!(
    response,
    RemoteSignerResponse::Error { code, .. } if code == "unauthorized"
  )
}

fn decode_base64(field: &str, value: &str) -> anyhow::Result<Vec<u8>> {
  base64::engine::general_purpose::STANDARD
    .decode(value)
    .with_context(|| format!("{field} must contain base64"))
}

fn parse_signature_schemes(values: &[u16]) -> Vec<SignatureScheme> {
  PREFERRED_SIGNATURE_SCHEMES
    .iter()
    .copied()
    .filter(|scheme| values.contains(&u16::from(*scheme)))
    .collect()
}

fn parse_signature_algorithm(value: &str) -> anyhow::Result<SignatureAlgorithm> {
  match value {
    "rsa" => Ok(SignatureAlgorithm::RSA),
    "ecdsa" => Ok(SignatureAlgorithm::ECDSA),
    "ed25519" => Ok(SignatureAlgorithm::ED25519),
    "ed448" => Ok(SignatureAlgorithm::ED448),
    _ => bail!("unsupported remote signer key algorithm {value}"),
  }
}

fn signature_algorithm_name(algorithm: SignatureAlgorithm) -> &'static str {
  match algorithm {
    SignatureAlgorithm::RSA => "rsa",
    SignatureAlgorithm::ECDSA => "ecdsa",
    SignatureAlgorithm::ED25519 => "ed25519",
    SignatureAlgorithm::ED448 => "ed448",
    _ => "unknown",
  }
}

#[derive(Debug)]
struct RemoteKeyDescription {
  public_key: Vec<u8>,
  algorithm: SignatureAlgorithm,
  schemes: Vec<SignatureScheme>,
}
