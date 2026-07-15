use std::convert::Infallible;

use ::http::{Response, StatusCode};
use anyhow::Context;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::lifecycle::TaskRegistry;
use crate::overload::ControlPlane;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::runtime_health::{
  PROCESS_GENERATION, RuntimeTaskKind, RuntimeTaskPolicy, spawn_supervised_task,
};
use crate::state::AppHandle;

use super::rollout_identity;

#[derive(Clone, Copy)]
pub(super) enum OpsKind {
  Metrics,
  Health,
}

pub(super) struct OpsTasks {
  shutdown: Vec<watch::Sender<bool>>,
  tasks: Vec<JoinHandle<()>>,
}

impl OpsTasks {
  pub(super) async fn start(
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> anyhow::Result<Self> {
    let snapshot = state.snapshot();
    let runtime_health = snapshot.runtime_health.clone();
    let mut shutdown = Vec::new();
    let mut tasks = Vec::new();
    if snapshot.config.metrics.enabled {
      let listener = TcpListener::bind(snapshot.config.metrics.bind)
        .await
        .with_context(|| {
          format!(
            "failed to bind metrics listener to {}",
            snapshot.config.metrics.bind
          )
        })?;
      let (tx, rx) = watch::channel(false);
      shutdown.push(tx);
      let mut initial_listener = Some(listener);
      let task_state = state.clone();
      let bind = snapshot.config.metrics.bind;
      tasks.push(spawn_supervised_task(
        runtime_health.clone(),
        PROCESS_GENERATION,
        RuntimeTaskKind::MetricsListener,
        RuntimeTaskPolicy::RestartableOptional,
        rx,
        error_tx.clone(),
        move |shutdown| {
          let listener = initial_listener.take();
          let task_state = task_state.clone();
          async move {
            let listener = match listener {
              Some(listener) => listener,
              None => TcpListener::bind(bind)
                .await
                .with_context(|| format!("failed to rebind metrics listener to {bind}"))?,
            };
            serve_ops_listener(listener, task_state, shutdown, OpsKind::Metrics)
              .await
              .context("metrics listener failed")
          }
        },
      ));
    }
    if snapshot.config.health.enabled {
      let listener = TcpListener::bind(snapshot.config.health.bind)
        .await
        .with_context(|| {
          format!(
            "failed to bind health listener to {}",
            snapshot.config.health.bind
          )
        })?;
      let (tx, rx) = watch::channel(false);
      shutdown.push(tx);
      let mut initial_listener = Some(listener);
      let task_state = state.clone();
      tasks.push(spawn_supervised_task(
        runtime_health.clone(),
        PROCESS_GENERATION,
        RuntimeTaskKind::HealthListener,
        RuntimeTaskPolicy::Fatal,
        rx,
        error_tx.clone(),
        move |shutdown| {
          let listener = initial_listener.take();
          let task_state = task_state.clone();
          async move {
            let Some(listener) = listener else {
              anyhow::bail!("health listener restart was requested for a fatal task");
            };
            serve_ops_listener(listener, task_state, shutdown, OpsKind::Health)
              .await
              .context("health listener failed")
          }
        },
      ));
    }
    let active_pool_health = snapshot.config.upstream_pools.iter().any(|pool| {
      pool.health_check.enabled && pool.health_check.mode == crate::config::HealthCheckMode::Active
    });
    let overload_enabled = snapshot.config.overload.enabled;
    let discovery_enabled = snapshot
      .config
      .upstream_pools
      .iter()
      .any(|pool| !pool.discovery.is_empty());
    let (tx, rx) = watch::channel(false);
    shutdown.push(tx);
    let task_state = state.clone();
    tasks.push(spawn_supervised_task(
      runtime_health.clone(),
      PROCESS_GENERATION,
      RuntimeTaskKind::PoolHealth,
      if active_pool_health {
        RuntimeTaskPolicy::RestartableCritical
      } else {
        RuntimeTaskPolicy::RestartableOptional
      },
      rx,
      error_tx.clone(),
      move |shutdown| {
        let task_state = task_state.clone();
        async move {
          crate::pool_health::run_pool_health_checks(task_state, shutdown).await;
          Ok(())
        }
      },
    ));
    let (tx, rx) = watch::channel(false);
    shutdown.push(tx);
    let task_state = state.clone();
    tasks.push(spawn_supervised_task(
      runtime_health.clone(),
      PROCESS_GENERATION,
      RuntimeTaskKind::OverloadSampler,
      if overload_enabled {
        RuntimeTaskPolicy::RestartableCritical
      } else {
        RuntimeTaskPolicy::RestartableOptional
      },
      rx,
      error_tx.clone(),
      move |shutdown| {
        let task_state = task_state.clone();
        async move {
          crate::overload::run_sampler(task_state, shutdown).await;
          Ok(())
        }
      },
    ));
    let (tx, rx) = watch::channel(false);
    shutdown.push(tx);
    let task_state = state;
    tasks.push(spawn_supervised_task(
      runtime_health,
      PROCESS_GENERATION,
      RuntimeTaskKind::UpstreamDiscovery,
      if discovery_enabled {
        RuntimeTaskPolicy::RestartableCritical
      } else {
        RuntimeTaskPolicy::RestartableOptional
      },
      rx,
      error_tx,
      move |shutdown| {
        let task_state = task_state.clone();
        async move {
          crate::upstream_discovery::run_dynamic_upstream_discovery(task_state, shutdown).await;
          Ok(())
        }
      },
    ));
    Ok(Self { shutdown, tasks })
  }
}

impl Drop for OpsTasks {
  fn drop(&mut self) {
    for tx in &self.shutdown {
      let _ = tx.send(true);
    }
    for task in &self.tasks {
      task.abort();
    }
  }
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
  let connections = TaskRegistry::new(
    RuntimeTaskKind::OpsConnection,
    state.snapshot().runtime_health.clone(),
  );
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        connections.abort_all();
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
        connections.spawn(async move {
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
      snapshot.runtime_health.append_prometheus(&mut body);
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
