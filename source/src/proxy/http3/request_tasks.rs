//! Per-connection HTTP/3 request task lifecycle and admission limits.

use std::sync::Arc;

use ::http::{Request, Response, StatusCode};
use anyhow::Context;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::{H3DownstreamRequestContext, H3RequestStream, handle_h3_request};
use crate::config::Config;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;

pub(super) struct RequestAdmission {
  accepted: usize,
  limit: usize,
}

impl RequestAdmission {
  pub(super) fn new(config: &Config) -> Self {
    Self::with_limit(request_limit_from_config(config))
  }

  pub(super) fn try_admit(&mut self) -> bool {
    if self.accepted >= self.limit {
      return false;
    }
    self.accepted += 1;
    true
  }

  #[cfg(test)]
  fn accepted(&self) -> usize {
    self.accepted
  }

  fn with_limit(limit: usize) -> Self {
    Self {
      accepted: 0,
      limit: limit.max(1),
    }
  }
}

pub(super) struct RequestTaskSet {
  permits: Arc<Semaphore>,
  tasks: JoinSet<()>,
}

impl RequestTaskSet {
  pub(super) fn new(config: &Config) -> Self {
    Self::with_active_limit(active_limit_from_config(config))
  }

  pub(super) fn acquire_permit(
    &self,
  ) -> impl std::future::Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send + 'static
  {
    let permits = self.permits.clone();
    async move { permits.acquire_owned().await }
  }

  pub(super) fn try_acquire_permit(&self) -> Option<OwnedSemaphorePermit> {
    match self.permits.clone().try_acquire_owned() {
      Ok(permit) => Some(permit),
      Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => None,
    }
  }

  pub(super) fn spawn(
    &mut self,
    request: Request<()>,
    stream: H3RequestStream,
    context: H3DownstreamRequestContext,
    permit: OwnedSemaphorePermit,
  ) {
    self.spawn_task(handle(request, stream, context, permit));
  }

  pub(super) fn is_empty(&self) -> bool {
    self.tasks.is_empty()
  }

  pub(super) async fn join_next(&mut self) {
    let completed = self.tasks.join_next().await;
    log_result(completed);
  }

  pub(super) fn reap_completed(&mut self) {
    while let Some(completed) = self.tasks.try_join_next() {
      log_result(Some(completed));
    }
  }

  pub(super) async fn wait_all(&mut self) {
    while !self.tasks.is_empty() {
      self.join_next().await;
    }
  }

  pub(super) async fn abort_all(&mut self) {
    self.tasks.abort_all();
    self.wait_all().await;
  }

  fn with_active_limit(limit: usize) -> Self {
    Self {
      permits: Arc::new(Semaphore::new(limit.max(1))),
      tasks: JoinSet::new(),
    }
  }

  fn spawn_task<F>(&mut self, future: F)
  where
    F: std::future::Future<Output = ()> + Send + 'static,
  {
    self.tasks.spawn(future);
  }
}

pub(super) async fn acquire_permit_or_stop(
  request_tasks: &mut RequestTaskSet,
  shutdown: &mut tokio::sync::watch::Receiver<bool>,
  data_plane_drain: &mut tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<Option<OwnedSemaphorePermit>> {
  let permit = request_tasks.acquire_permit();
  tokio::pin!(permit);

  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          request_tasks.abort_all().await;
          return Ok(None);
        }
        continue;
      }
      changed = data_plane_drain.changed() => {
        if changed.is_ok() && *data_plane_drain.borrow() {
          request_tasks.abort_all().await;
          return Ok(None);
        }
        continue;
      }
      _ = request_tasks.join_next(), if !request_tasks.is_empty() => {
        continue;
      }
      acquired = &mut permit => {
        return acquired
          .map(Some)
          .context("HTTP/3 request task limiter closed");
      }
    }
  }
}

pub(super) fn too_many_requests_response() -> Response<ProxyBody> {
  text_response(
    StatusCode::TOO_MANY_REQUESTS,
    "too many requests on this connection",
  )
}

async fn handle(
  request: Request<()>,
  stream: H3RequestStream,
  context: H3DownstreamRequestContext,
  _permit: OwnedSemaphorePermit,
) {
  let peer_addr = context.peer_addr;
  let _request_guard = context
    .state
    .runtime_introspection_guard(RuntimeCounter::Http3Request);
  match handle_h3_request(request, stream, context).await {
    Ok(status) => {
      debug!(peer = %peer_addr, %status, "handled downstream HTTP/3 request");
    }
    Err(error) => {
      warn!(peer = %peer_addr, error = %error, "downstream HTTP/3 request failed");
    }
  }
}

fn log_result(completed: Option<Result<(), tokio::task::JoinError>>) {
  if let Some(Err(error)) = completed {
    warn!(error = %error, "downstream HTTP/3 request task failed");
  }
}

fn active_limit_from_config(config: &Config) -> usize {
  active_limit_from_values(
    config.quic.downstream.transport.max_concurrent_bidi_streams,
    config.limits.max_requests_per_connection,
  )
}

fn active_limit_from_values(
  max_concurrent_bidi_streams: u64,
  max_requests_per_connection: usize,
) -> usize {
  let configured_streams = usize::try_from(max_concurrent_bidi_streams)
    .unwrap_or(usize::MAX)
    .max(1);
  configured_streams.min(max_requests_per_connection.max(1))
}

fn request_limit_from_config(config: &Config) -> usize {
  config.limits.max_requests_per_connection.max(1)
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use tokio::sync::oneshot;

  use super::*;

  #[test]
  fn active_limit_uses_lower_configured_bound() {
    assert_eq!(active_limit_from_values(64, 32), 32);
    assert_eq!(active_limit_from_values(64, 256), 64);
  }

  #[test]
  fn active_limit_never_returns_zero() {
    assert_eq!(active_limit_from_values(0, 0), 1);
  }

  #[test]
  fn request_admission_rejects_after_limit() {
    let mut admission = RequestAdmission::with_limit(2);

    assert!(admission.try_admit());
    assert!(admission.try_admit());
    assert!(!admission.try_admit());
    assert_eq!(admission.accepted(), 2);
  }

  #[tokio::test]
  async fn completed_task_releases_active_permit() {
    let mut tasks = RequestTaskSet::with_active_limit(1);
    let first = tasks
      .acquire_permit()
      .await
      .expect("first permit should be available");
    let second = tasks.acquire_permit();
    tokio::pin!(second);

    assert!(
      tokio::time::timeout(Duration::from_millis(10), &mut second)
        .await
        .is_err(),
      "second permit should wait while the first request is active"
    );

    tasks.spawn_task(async move {
      drop(first);
    });
    tasks.join_next().await;

    let second = tokio::time::timeout(Duration::from_secs(1), second)
      .await
      .expect("second permit should become available")
      .expect("semaphore should remain open");
    drop(second);
  }

  #[test]
  fn try_acquire_permit_observes_saturation() {
    let tasks = RequestTaskSet::with_active_limit(1);
    let first = tasks
      .try_acquire_permit()
      .expect("first permit should be available immediately");

    assert!(
      tasks.try_acquire_permit().is_none(),
      "second immediate acquire should observe saturation"
    );

    drop(first);
    assert!(
      tasks.try_acquire_permit().is_some(),
      "released permit should become immediately available"
    );
  }

  #[tokio::test]
  async fn reap_completed_drains_ready_tasks_without_waiting() {
    let mut tasks = RequestTaskSet::with_active_limit(2);

    tasks.spawn_task(async {});
    tokio::task::yield_now().await;
    tasks.reap_completed();

    assert!(tasks.is_empty());
  }

  #[tokio::test]
  async fn wait_all_reaps_completed_tasks() {
    let mut tasks = RequestTaskSet::with_active_limit(2);

    tasks.spawn_task(async {});
    tasks.spawn_task(async {});
    tasks.wait_all().await;

    assert!(tasks.is_empty());
  }

  #[tokio::test]
  async fn abort_all_reaps_tracked_tasks() {
    let mut tasks = RequestTaskSet::with_active_limit(1);
    let (started_tx, started_rx) = oneshot::channel();
    let (_release_tx, release_rx) = oneshot::channel::<()>();

    tasks.spawn_task(async move {
      let _ = started_tx.send(());
      let _ = release_rx.await;
    });
    started_rx.await.expect("task should start");

    tasks.abort_all().await;

    assert!(tasks.is_empty());
  }
}
