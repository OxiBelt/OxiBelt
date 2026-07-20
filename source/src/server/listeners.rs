//! TCP and HTTP/3 accept loops.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_tcp(
  listener: TcpListener,
  kind: TcpListenerKind,
  state: AppHandle,
  mut quiesce: watch::Receiver<bool>,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  accept_error_backoff: Duration,
  connections: TaskRegistry,
  long_connection_close_delay: Duration,
) -> anyhow::Result<()> {
  let bind = listener
    .local_addr()
    .context("failed to read TCP listener address")?;
  info!(bind = %bind, ?kind, worker = worker_index, "downstream TCP listener started");

  loop {
    tokio::select! {
        biased;
        changed = quiesce.changed() => {
            if changed.is_err() || *quiesce.borrow() {
              info!(bind = %bind, worker = worker_index, "downstream TCP listener quiesced");
              return Ok(());
            }
        }
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(bind = %bind, worker = worker_index, "downstream TCP listener stopped");
            }
            return Ok(());
        }
        accepted = listener.accept() => {
            let (stream, peer_addr) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, worker = worker_index, "failed to accept downstream connection");
                    tokio::time::sleep(accept_error_backoff).await;
                    continue;
                }
            };
            crate::tcp_socket::enable_tcp_nodelay(&stream, peer_addr, "downstream listener");

            let connection_state = state.connection_snapshot();
            let connection_shutdown = shutdown.clone();
            let connection_snapshot = connection_state.snapshot;
            let data_plane_drain = connection_state.data_plane_drain;
            let overload_connection = match connection_snapshot.overload.try_admit_connection() {
              Ok(lease) => lease,
              Err(_) => continue,
            };
            let connection_drain = ConnectionDrain::with_data_plane(
              connection_shutdown.clone(),
              connection_snapshot.lifecycle.subscribe(),
              data_plane_drain.clone(),
              long_connection_close_delay,
            );
            connections.spawn(async move {
                let _overload_connection = overload_connection;
                let result = match kind {
                  TcpListenerKind::Https => handle_connection(
                    stream,
                    peer_addr,
                    bind,
                    connection_snapshot,
                    connection_shutdown,
                    data_plane_drain,
                    connection_drain,
                  ).await,
                  TcpListenerKind::PlainHttp => plain_http::handle_connection(
                    stream,
                    peer_addr,
                    connection_snapshot,
                    connection_shutdown,
                    data_plane_drain,
                    connection_drain,
                  ).await,
                };
                if let Err(error) = result {
                    connection_errors::log_tcp(peer_addr, &error);
                }
            });
        }
    }
  }
}

pub(super) fn bind_http3_listener(
  bind: SocketAddr,
  snapshot: &AppSnapshot,
) -> anyhow::Result<BoundHttp3Listener> {
  let server_config = snapshot
    .quic_server_config
    .clone()
    .ok_or_else(|| anyhow::anyhow!("HTTP/3 listener is enabled without QUIC server config"))?;
  let (endpoints, sni_forward_quic) =
    crate::sni_forward::quic::bind_sni_or_plain_server_endpoints(bind, server_config, snapshot)?;
  Ok(BoundHttp3Listener {
    bind,
    socket: snapshot.config.quic.socket.clone(),
    transport: snapshot.config.quic.downstream.transport.clone(),
    endpoints,
    sni_forward_quic,
  })
}

pub(super) async fn serve_http3(
  endpoint: h3_quinn::quinn::Endpoint,
  state: AppHandle,
  mut quiesce: watch::Receiver<bool>,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  connections: TaskRegistry,
  long_connection_close_delay: Duration,
) -> anyhow::Result<()> {
  let bind = endpoint
    .local_addr()
    .context("failed to read HTTP/3 listener address")?;
  let mut shutting_down = *shutdown.borrow();
  let mut quiescing = *quiesce.borrow() || shutting_down;
  info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener started");

  loop {
    tokio::select! {
        biased;
        changed = quiesce.changed() => {
            if changed.is_err() || *quiesce.borrow() {
              if !quiescing {
                info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener quiesced");
              }
              quiescing = true;
            }
        }
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener stopped");
            }
            quiescing = true;
            shutting_down = true;
        }
        _ = connections.wait_idle(), if shutting_down => {
            // `Endpoint::close` is safe only after every accepted connection has
            // finished. It then prevents a final race from re-queuing an Initial
            // after this worker stops consuming `endpoint.accept()`.
            endpoint.close(0u32.into(), b"listener drained");
            return Ok(());
        }
        connecting = endpoint.accept() => {
            let Some(connecting) = connecting else {
                return Ok(());
            };
            if quiescing {
                // The endpoint driver continues receiving QUIC Initial packets while
                // established connections drain. Consume every queued Incoming so an
                // unauthenticated peer cannot accumulate Quinn's pending-handshake
                // buffer during pre-drain, but retain already accepted connections.
                connecting.ignore();
                continue;
            }
            let connection_state = state.connection_snapshot();
            let connection_snapshot = connection_state.snapshot;
            let data_plane_drain = connection_state.data_plane_drain;
            if connection_snapshot.config.quic.retry && !connecting.remote_address_validated() && connecting.may_retry() {
                if let Err(error) = connecting.retry() {
                    connection_snapshot.metrics.record_quic_retry("error");
                    warn!(error = %error, "failed to send QUIC Retry packet");
                } else {
                    connection_snapshot.metrics.record_quic_retry("sent");
                }
                continue;
            }
            let overload_connection = match connection_snapshot.overload.try_admit_connection() {
                Ok(lease) => lease,
                Err(_) => {
                    connecting.refuse();
                    continue;
                }
            };
            let connection_shutdown = shutdown.clone();
            let connection_drain = ConnectionDrain::with_data_plane(
              connection_shutdown.clone(),
              connection_snapshot.lifecycle.subscribe(),
              data_plane_drain.clone(),
              long_connection_close_delay,
            );
            let peer_addr = connecting.remote_address();
            connections.spawn(async move {
                let _overload_connection = overload_connection;
                match connecting.await {
                    Ok(connection) => {
                        if let Err(error) = http3::handle_downstream_connection(
                          connection,
                          connection_snapshot,
                          connection_shutdown,
                          data_plane_drain,
                          connection_drain,
                        ).await {
                            connection_errors::log_http3(peer_addr, &error);
                        }
                    }
                    Err(error) => {
                        warn!(error = %error, "failed to accept downstream HTTP/3 connection");
                    }
                }
            });
        }
    }
  }
}
