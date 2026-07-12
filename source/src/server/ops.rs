use std::convert::Infallible;

use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::warn;

use crate::overload::ControlPlane;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::rollout_identity;

#[derive(Clone, Copy)]
pub(super) enum OpsKind {
  Metrics,
  Health,
}

impl OpsKind {
  const fn control_plane(self) -> ControlPlane {
    match self {
      Self::Metrics => ControlPlane::Metrics,
      Self::Health => ControlPlane::Health,
    }
  }
}

pub(super) async fn serve_ops_listener(
  listener: TcpListener,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  kind: OpsKind,
) -> anyhow::Result<()> {
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          return Ok(());
        }
      }
      accepted = listener.accept() => {
        let (stream, peer_addr) = match accepted {
          Ok(value) => value,
          Err(error) => {
            warn!(error = %error, "failed to accept ops connection");
            continue;
          }
        };
        crate::tcp_socket::enable_tcp_nodelay(&stream, peer_addr, "ops listener");
        let state = state.clone();
        let plane = kind.control_plane();
        let Some(control_connection) = state
          .snapshot()
          .overload
          .try_admit_control_connection(plane)
        else {
          continue;
        };
        tokio::spawn(async move {
          let _control_connection = control_connection;
          let service = service_fn(move |request: hyper::Request<Incoming>| {
            let state = state.clone();
            async move {
              let Some(_control_request) = state
                .snapshot()
                .overload
                .try_admit_control_request(plane)
              else {
                return Ok::<_, Infallible>(text_response(
                  StatusCode::SERVICE_UNAVAILABLE,
                  "control capacity exhausted",
                ));
              };
              Ok::<_, Infallible>(ops_response(request, state, kind))
            }
          });
          if let Err(error) = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
          {
            warn!(peer = %peer_addr, error = %error, "ops connection failed");
          }
        });
      }
    }
  }
}

fn ops_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  kind: OpsKind,
) -> Response<ProxyBody> {
  match kind {
    OpsKind::Metrics => {
      let snapshot = state.snapshot();
      let mut body = snapshot.metrics.prometheus(
        &snapshot.config.metrics,
        snapshot.cache.stats(),
        snapshot.tls_resumption.server_session_storage_stats(),
      );
      snapshot.overload.append_prometheus(&mut body);
      snapshot.circuit_breakers.append_prometheus(&mut body);
      text_response(StatusCode::OK, &body)
    }
    OpsKind::Health => {
      let snapshot = state.snapshot();
      let path = request.uri().path();
      rollout_identity::health_response(snapshot.as_ref(), path)
        .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"))
    }
  }
}
