use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Instant;

use anyhow::Context;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::config::{CryptoConfig, ProxyHttp2Config, UpstreamConfig};
use crate::proxy::http::body::ProxyBody;
use crate::tls::{OutboundRevocationRuntime, TlsResumptionState};
use crate::upstream_resolution::{
  CandidateAttemptError, CandidateRaceError, CandidateSchedulerConfig, ResolutionPolicy,
  race_happy_eyeballs_candidates,
};

pub(super) type DirectH2Driver =
  Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send + 'static>>;

pub(super) struct DirectH2Connected {
  pub(super) sender: SendRequest<ProxyBody>,
  pub(super) peer_max_streams: Arc<AtomicUsize>,
  pub(super) driver: DirectH2Driver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectH2ConnectErrorClass {
  TcpConnect,
  TlsHandshake,
  H2Handshake,
}

pub(super) struct DirectH2ConnectFailure {
  pub(super) class: DirectH2ConnectErrorClass,
  pub(super) error: anyhow::Error,
}

#[derive(Clone)]
pub(super) struct DirectH2Origin {
  pub(super) scheme: &'static str,
  pub(super) host: String,
  pub(super) port: u16,
}

impl DirectH2Origin {
  pub(super) fn from_url(origin: &Url) -> Option<Self> {
    let scheme = match origin.scheme() {
      "http" => "http",
      "https" => "https",
      _ => return None,
    };
    Some(Self {
      scheme,
      host: origin.host_str()?.to_owned(),
      port: origin.port_or_known_default()?,
    })
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_direct_h2(
  origin: &DirectH2Origin,
  tls_server_name: Option<&str>,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  http2_config: &ProxyHttp2Config,
  deadline: Instant,
  capacity_changed: Arc<Notify>,
  resolution_policy: ResolutionPolicy,
  scheduler_policy: CandidateSchedulerConfig,
  svcb_enabled: bool,
  allowed_svcb_ports: &[u16],
) -> Result<DirectH2Connected, DirectH2ConnectFailure> {
  let tokio_deadline = tokio::time::Instant::from_std(deadline);
  let mut updates = crate::upstream_resolution::resolve_http_candidate_updates(
    &origin.host,
    origin.port,
    &format!("direct-h2:{}:{}", origin.host, origin.port),
    resolution_policy,
    crate::upstream_resolution::HttpTransportProtocol::H2,
    tls_config.is_some(),
    svcb_enabled,
    allowed_svcb_ports,
    tokio_deadline,
  )
  .map_err(|error| DirectH2ConnectFailure {
    class: DirectH2ConnectErrorClass::TcpConnect,
    error,
  })?;
  let server_name = tls_server_name.unwrap_or(origin.host.as_str()).to_owned();
  race_happy_eyeballs_candidates(
    &mut updates,
    scheduler_policy,
    tokio_deadline,
    |candidate, _| {
      let tls_config = tls_config.clone();
      let server_name = server_name.clone();
      let capacity_changed = capacity_changed.clone();
      async move {
        let address = candidate.into_value();
        let stream = tokio::time::timeout_at(tokio_deadline, TcpStream::connect(address))
          .await
          .map_err(|_| {
            CandidateAttemptError::Endpoint(DirectH2ConnectFailure {
              class: DirectH2ConnectErrorClass::TcpConnect,
              error: anyhow::anyhow!("direct H2 upstream candidate {address} timed out"),
            })
          })?
          .with_context(|| format!("failed to connect direct H2 upstream candidate {address}"))
          .map_err(|error| {
            CandidateAttemptError::Endpoint(DirectH2ConnectFailure {
              class: DirectH2ConnectErrorClass::TcpConnect,
              error,
            })
          })?;
        stream.set_nodelay(true).map_err(|error| {
          CandidateAttemptError::Endpoint(DirectH2ConnectFailure {
            class: DirectH2ConnectErrorClass::TcpConnect,
            error: anyhow::Error::new(error)
              .context("failed to enable TCP_NODELAY for direct H2 upstream"),
          })
        })?;
        let connected = match tls_config {
          Some(tls_config) => {
            connect_tls_h2_until(
              tls_config,
              server_name,
              stream,
              http2_config,
              deadline,
              capacity_changed,
            )
            .await
          }
          None => h2_handshake_until_with_capacity_notify(
            stream,
            http2_config,
            deadline,
            capacity_changed,
          )
          .await
          .map_err(|error| DirectH2ConnectFailure {
            class: DirectH2ConnectErrorClass::H2Handshake,
            error,
          }),
        };
        connected.map_err(CandidateAttemptError::Endpoint)
      }
    },
  )
  .await
  .map_err(map_candidate_race_error)
}

fn map_candidate_race_error(
  error: CandidateRaceError<DirectH2ConnectFailure>,
) -> DirectH2ConnectFailure {
  match error {
    CandidateRaceError::Exhausted {
      admission_error: Some(error),
      ..
    }
    | CandidateRaceError::Exhausted {
      last_endpoint_error: Some(error),
      admission_error: None,
    } => error,
    CandidateRaceError::Deadline => DirectH2ConnectFailure {
      class: DirectH2ConnectErrorClass::TcpConnect,
      error: anyhow::anyhow!("direct H2 upstream connection deadline elapsed"),
    },
    CandidateRaceError::NoCandidates
    | CandidateRaceError::Exhausted {
      last_endpoint_error: None,
      admission_error: None,
    } => DirectH2ConnectFailure {
      class: DirectH2ConnectErrorClass::TcpConnect,
      error: anyhow::anyhow!("direct H2 upstream resolver returned no usable candidates"),
    },
  }
}

#[cfg(test)]
pub(super) async fn h2_handshake_until<I>(
  io: I,
  http2_config: &ProxyHttp2Config,
  deadline: Instant,
) -> anyhow::Result<DirectH2Connected>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  h2_handshake_until_with_capacity_notify(io, http2_config, deadline, Arc::new(Notify::new())).await
}

async fn h2_handshake_until_with_capacity_notify<I>(
  io: I,
  http2_config: &ProxyHttp2Config,
  deadline: Instant,
  capacity_changed: Arc<Notify>,
) -> anyhow::Result<DirectH2Connected>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  tokio::time::timeout_at(
    deadline.into(),
    h2_handshake_with_capacity_notify(io, http2_config, capacity_changed),
  )
  .await
  .context("direct H2 upstream HTTP/2 handshake timed out")?
}

#[cfg(test)]
pub(super) async fn h2_handshake<I>(
  io: I,
  http2_config: &ProxyHttp2Config,
) -> anyhow::Result<DirectH2Connected>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  h2_handshake_with_capacity_notify(io, http2_config, Arc::new(Notify::new())).await
}

async fn h2_handshake_with_capacity_notify<I>(
  io: I,
  http2_config: &ProxyHttp2Config,
  capacity_changed: Arc<Notify>,
) -> anyhow::Result<DirectH2Connected>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
  crate::h2_tuning::apply_client_conn_defaults(&mut builder, http2_config);
  let (sender, connection) = builder
    .handshake(TokioIo::new(io))
    .await
    .context("failed to establish direct HTTP/2 upstream connection")?;
  let peer_max_streams = Arc::new(AtomicUsize::new(connection.current_max_send_streams()));
  let driver_peer_max_streams = peer_max_streams.clone();
  let mut connection = Box::pin(connection);
  let driver = Box::pin(std::future::poll_fn(move |cx| {
    let result = connection.as_mut().poll(cx);
    let current = connection.as_ref().get_ref().current_max_send_streams();
    if driver_peer_max_streams.swap(current, Ordering::AcqRel) != current {
      capacity_changed.notify_waiters();
    }
    match result {
      Poll::Ready(result) => Poll::Ready(result),
      Poll::Pending => Poll::Pending,
    }
  }));
  Ok(DirectH2Connected {
    sender,
    peer_max_streams,
    driver,
  })
}

pub(super) fn build_h2_tls_config(
  upstream: &UpstreamConfig,
  extra_root_certs: &[PathBuf],
  crypto: &CryptoConfig,
  tls_resumption: &TlsResumptionState,
  outbound_revocation: &OutboundRevocationRuntime,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
  let root_certs;
  let extra_root_certs = if upstream.extra_trusted_ca_certs.is_empty() {
    extra_root_certs
  } else {
    root_certs = extra_root_certs
      .iter()
      .chain(upstream.extra_trusted_ca_certs.iter())
      .cloned()
      .collect::<Vec<PathBuf>>();
    &root_certs
  };
  let revocation_policy = outbound_revocation.policy_for_upstream(upstream);
  let mut tls_config = crate::tls::build_upstream_client_config_with_policy(
    crypto,
    extra_root_certs,
    &upstream.tls,
    Some(tls_resumption),
    &upstream.name,
    Some((outbound_revocation, revocation_policy)),
  )?;
  tls_config.alpn_protocols = vec![b"h2".to_vec()];
  Ok(Arc::new(tls_config))
}

async fn connect_tls_h2_until(
  tls_config: Arc<rustls::ClientConfig>,
  server_name: String,
  stream: TcpStream,
  http2_config: &ProxyHttp2Config,
  deadline: Instant,
  capacity_changed: Arc<Notify>,
) -> Result<DirectH2Connected, DirectH2ConnectFailure> {
  let server_name = rustls::pki_types::ServerName::try_from(server_name).map_err(|error| {
    DirectH2ConnectFailure {
      class: DirectH2ConnectErrorClass::TlsHandshake,
      error: anyhow::anyhow!("invalid upstream TLS server name: {error}"),
    }
  })?;
  let tls = tokio::time::timeout_at(
    deadline.into(),
    TlsConnector::from(tls_config).connect(server_name, stream),
  )
  .await
  .map_err(|_| DirectH2ConnectFailure {
    class: DirectH2ConnectErrorClass::TlsHandshake,
    error: anyhow::anyhow!("direct H2 upstream TLS handshake timed out"),
  })?
  .context("direct H2 upstream TLS handshake failed")
  .map_err(|error| DirectH2ConnectFailure {
    class: DirectH2ConnectErrorClass::TlsHandshake,
    error,
  })?;
  if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
    return Err(DirectH2ConnectFailure {
      class: DirectH2ConnectErrorClass::TlsHandshake,
      error: anyhow::anyhow!("direct H2 upstream did not negotiate the h2 ALPN protocol"),
    });
  }
  h2_handshake_until_with_capacity_notify(tls, http2_config, deadline, capacity_changed)
    .await
    .map_err(|error| DirectH2ConnectFailure {
      class: DirectH2ConnectErrorClass::H2Handshake,
      error,
    })
}
