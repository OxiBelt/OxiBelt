//! Public lifecycle control for owned and caller-runtime server drivers.
//!
//! The handle side does not contain a Tokio `JoinHandle`. This lets an owned runtime keep and
//! await its driver on a dedicated thread while callers observe the same bounded final result.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use tokio::sync::{Notify, mpsc, watch};

use crate::application::StartupReport;
use crate::runtime::topology::RuntimeTopologySnapshot;

const CONTROL_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum BoundListenerKind {
  Https,
  Http,
  Http3,
  Admin,
  AdminHttp3,
  Metrics,
  Health,
  Stream,
  Turn,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum BoundListenerTransport {
  Tcp,
  Udp,
  Quic,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundListener {
  pub kind: BoundListenerKind,
  pub transport: BoundListenerTransport,
  pub address: SocketAddr,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServerReadiness {
  Starting,
  Ready,
  NotReady,
  Draining,
  Stopped,
  Failed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReadinessReason {
  Startup,
  Listening,
  Overloaded,
  ConfigRevisionUnavailable,
  AdminAuthorityUnavailable,
  RuntimeUnhealthy,
  PreDrainRequested,
  ShutdownRequested,
  ShutdownComplete,
  RuntimeFailed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ReadinessSnapshot {
  pub state: ServerReadiness,
  pub reason: ReadinessReason,
}

impl ReadinessSnapshot {
  pub const fn starting() -> Self {
    Self {
      state: ServerReadiness::Starting,
      reason: ReadinessReason::Startup,
    }
  }

  pub const fn ready() -> Self {
    Self {
      state: ServerReadiness::Ready,
      reason: ReadinessReason::Listening,
    }
  }

  pub const fn is_ready(self) -> bool {
    matches!(self.state, ServerReadiness::Ready)
  }

  const fn terminal(self) -> bool {
    matches!(
      self.state,
      ServerReadiness::Stopped | ServerReadiness::Failed
    )
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ShutdownOutcome {
  Graceful,
  Forced,
  Cancelled,
  Failed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ShutdownReason {
  CallerRequested,
  ProcessSignal,
  ImmediateCancellation,
  DeadlineExpired,
  RuntimeFailure,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ShutdownResult {
  pub outcome: ShutdownOutcome,
  pub reason: ShutdownReason,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ControlCommand {
  PreDrain,
  Reload,
  Graceful { deadline: Instant },
}

pub(crate) struct ImmediateCancellation {
  requested: AtomicBool,
  notify: Notify,
}

impl ImmediateCancellation {
  fn new() -> Self {
    Self {
      requested: AtomicBool::new(false),
      notify: Notify::new(),
    }
  }

  fn request(&self) {
    self.requested.store(true, Ordering::Release);
    self.notify.notify_waiters();
  }

  pub(crate) async fn cancelled(&self) {
    loop {
      let notified = self.notify.notified();
      if self.requested.load(Ordering::Acquire) {
        return;
      }
      notified.await;
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SignalMode {
  Process,
  CallerManaged,
}

pub(crate) struct PreparedServer {
  pub(crate) handle: ServerHandle,
  driver: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
}

impl PreparedServer {
  pub(crate) fn new(
    handle: ServerHandle,
    driver: impl Future<Output = ()> + Send + 'static,
  ) -> Self {
    Self {
      handle,
      driver: Box::pin(driver),
    }
  }

  pub(crate) fn spawn(self) -> ServerHandle {
    let Self { handle, driver } = self;
    tokio::spawn(driver);
    handle
  }

  pub(crate) fn with_startup_report(mut self, report: StartupReport) -> Self {
    self.handle.startup_report = Some(Arc::new(report));
    self
  }

  pub(crate) fn into_parts(
    self,
  ) -> (
    ServerHandle,
    Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
  ) {
    (self.handle, self.driver)
  }
}

/// A cloneable observer/control capability which does not keep the server alive.
#[derive(Clone)]
pub struct ServerControl {
  command_tx: mpsc::WeakSender<ControlCommand>,
  cancellation: Weak<ImmediateCancellation>,
  readiness_rx: watch::Receiver<ReadinessSnapshot>,
}

impl fmt::Debug for ServerControl {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ServerControl")
      .field("readiness", &*self.readiness_rx.borrow())
      .finish_non_exhaustive()
  }
}

impl ServerControl {
  pub fn readiness(&self) -> ReadinessSnapshot {
    *self.readiness_rx.borrow()
  }

  pub fn subscribe_readiness(&self) -> watch::Receiver<ReadinessSnapshot> {
    self.readiness_rx.clone()
  }

  pub async fn pre_drain(&self) -> Result<(), ServerControlClosed> {
    self.send(ControlCommand::PreDrain).await
  }

  pub async fn reload(&self) -> Result<(), ServerControlClosed> {
    self.send(ControlCommand::Reload).await
  }

  pub async fn shutdown(&self, deadline: Instant) -> Result<(), ServerControlClosed> {
    self.send(ControlCommand::Graceful { deadline }).await
  }

  pub fn cancel(&self) -> Result<(), ServerControlClosed> {
    let cancellation = self.cancellation.upgrade().ok_or(ServerControlClosed)?;
    cancellation.request();
    Ok(())
  }

  async fn send(&self, command: ControlCommand) -> Result<(), ServerControlClosed> {
    let sender = self.command_tx.upgrade().ok_or(ServerControlClosed)?;
    sender.send(command).await.map_err(|_| ServerControlClosed)
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ServerControlClosed;

impl fmt::Display for ServerControlClosed {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("server lifecycle control is closed")
  }
}

impl std::error::Error for ServerControlClosed {}

/// Unique owner for a running OxiBelt server.
///
/// Dropping the handle requests immediate cancellation. Await [`Self::shutdown`] or [`Self::wait`]
/// when the caller needs proof that the lifecycle driver joined all owned tasks.
#[must_use = "dropping the server handle requests immediate cancellation"]
pub struct ServerHandle {
  command_tx: mpsc::Sender<ControlCommand>,
  cancellation: Arc<ImmediateCancellation>,
  readiness_rx: watch::Receiver<ReadinessSnapshot>,
  final_rx: watch::Receiver<Option<ShutdownResult>>,
  runtime_topology: Arc<RuntimeTopologySnapshot>,
  bound_listeners: Arc<[BoundListener]>,
  startup_report: Option<Arc<StartupReport>>,
  owned_runtime_done: Option<watch::Receiver<bool>>,
}

impl fmt::Debug for ServerHandle {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ServerHandle")
      .field("readiness", &self.readiness())
      .field("bound_listeners", &self.bound_listeners)
      .finish_non_exhaustive()
  }
}

impl ServerHandle {
  pub fn readiness(&self) -> ReadinessSnapshot {
    *self.readiness_rx.borrow()
  }

  pub fn subscribe_readiness(&self) -> watch::Receiver<ReadinessSnapshot> {
    self.readiness_rx.clone()
  }

  pub async fn wait_ready(
    &mut self,
    deadline: Instant,
  ) -> Result<ReadinessSnapshot, WaitReadyError> {
    loop {
      let readiness = self.readiness();
      if readiness.is_ready() {
        return Ok(readiness);
      }
      if readiness.terminal() {
        return Err(WaitReadyError::Terminated(readiness));
      }
      if tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        self.readiness_rx.changed(),
      )
      .await
      .map_err(|_| WaitReadyError::DeadlineExpired)?
      .is_err()
      {
        return Err(WaitReadyError::Closed);
      }
    }
  }

  pub fn runtime_topology(&self) -> &RuntimeTopologySnapshot {
    &self.runtime_topology
  }

  pub fn startup_report(&self) -> Option<&StartupReport> {
    self.startup_report.as_deref()
  }

  pub fn bound_listeners(&self) -> &[BoundListener] {
    &self.bound_listeners
  }

  pub(crate) fn with_owned_runtime_completion(mut self, completion: watch::Receiver<bool>) -> Self {
    self.owned_runtime_done = Some(completion);
    self
  }

  pub fn control(&self) -> ServerControl {
    ServerControl {
      command_tx: self.command_tx.downgrade(),
      cancellation: Arc::downgrade(&self.cancellation),
      readiness_rx: self.readiness_rx.clone(),
    }
  }

  pub fn cancel(&self) -> Result<(), ServerControlClosed> {
    self.control().cancel()
  }

  pub async fn shutdown(mut self, deadline: Instant) -> anyhow::Result<ShutdownResult> {
    self
      .command_tx
      .send(ControlCommand::Graceful { deadline })
      .await
      .map_err(|_| anyhow::anyhow!(ServerControlClosed))?;
    self.wait_inner().await
  }

  pub async fn wait(mut self) -> anyhow::Result<ShutdownResult> {
    self.wait_inner().await
  }

  async fn wait_inner(&mut self) -> anyhow::Result<ShutdownResult> {
    let result = loop {
      if let Some(result) = *self.final_rx.borrow() {
        break result;
      }
      if self.final_rx.changed().await.is_err() {
        anyhow::bail!("server lifecycle driver closed without a final result");
      }
    };
    if let Some(completion) = &mut self.owned_runtime_done {
      while !*completion.borrow() {
        if completion.changed().await.is_err() {
          anyhow::bail!("owned runtime thread closed without joined completion");
        }
      }
    }
    Ok(result)
  }
}

impl Drop for ServerHandle {
  fn drop(&mut self) {
    self.cancellation.request();
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WaitReadyError {
  DeadlineExpired,
  Terminated(ReadinessSnapshot),
  Closed,
}

impl fmt::Display for WaitReadyError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DeadlineExpired => formatter.write_str("server readiness deadline expired"),
      Self::Terminated(readiness) => {
        write!(
          formatter,
          "server terminated before readiness: {readiness:?}"
        )
      }
      Self::Closed => formatter.write_str("server readiness channel closed"),
    }
  }
}

impl std::error::Error for WaitReadyError {}

pub(crate) struct ServerLifecycle {
  pub(crate) command_rx: mpsc::Receiver<ControlCommand>,
  pub(crate) cancellation: Arc<ImmediateCancellation>,
  readiness_tx: watch::Sender<ReadinessSnapshot>,
  final_tx: watch::Sender<Option<ShutdownResult>>,
}

impl ServerLifecycle {
  pub(crate) fn new(
    runtime_topology: RuntimeTopologySnapshot,
    mut bound_listeners: Vec<BoundListener>,
  ) -> (ServerHandle, Self) {
    bound_listeners.sort_unstable();
    bound_listeners.dedup();
    let (command_tx, command_rx) = mpsc::channel(CONTROL_CAPACITY);
    let cancellation = Arc::new(ImmediateCancellation::new());
    let (readiness_tx, readiness_rx) = watch::channel(ReadinessSnapshot::starting());
    let (final_tx, final_rx) = watch::channel(None);
    (
      ServerHandle {
        command_tx,
        cancellation: cancellation.clone(),
        readiness_rx,
        final_rx,
        runtime_topology: Arc::new(runtime_topology),
        bound_listeners: Arc::from(bound_listeners),
        startup_report: None,
        owned_runtime_done: None,
      },
      Self {
        command_rx,
        cancellation,
        readiness_tx,
        final_tx,
      },
    )
  }

  pub(crate) fn publish(&self, readiness: ReadinessSnapshot) {
    self.readiness_tx.send_replace(readiness);
  }

  pub(crate) fn publish_final(&self, result: ShutdownResult) {
    let readiness = match result.outcome {
      ShutdownOutcome::Failed => ReadinessSnapshot {
        state: ServerReadiness::Failed,
        reason: ReadinessReason::RuntimeFailed,
      },
      _ => ReadinessSnapshot {
        state: ServerReadiness::Stopped,
        reason: ReadinessReason::ShutdownComplete,
      },
    };
    self.publish(readiness);
    self.final_tx.send_replace(Some(result));
  }
}

pub(crate) fn readiness_for_snapshot(snapshot: &crate::state::AppSnapshot) -> ReadinessSnapshot {
  if snapshot.lifecycle.reason() == "overload"
    && snapshot.config.overload.actions.hard.fail_readiness
  {
    return ReadinessSnapshot {
      state: ServerReadiness::NotReady,
      reason: ReadinessReason::Overloaded,
    };
  }
  if snapshot.lifecycle.is_draining() {
    return ReadinessSnapshot {
      state: ServerReadiness::Draining,
      reason: ReadinessReason::PreDrainRequested,
    };
  }
  if !snapshot.config.rollout.is_ready() {
    return ReadinessSnapshot {
      state: ServerReadiness::NotReady,
      reason: ReadinessReason::ConfigRevisionUnavailable,
    };
  }
  #[cfg(feature = "admin-runtime")]
  if !snapshot.admin_mutations.cluster_rollout_ready() {
    return ReadinessSnapshot {
      state: ServerReadiness::NotReady,
      reason: ReadinessReason::AdminAuthorityUnavailable,
    };
  }
  if !snapshot.runtime_health.is_ready() {
    return ReadinessSnapshot {
      state: ServerReadiness::NotReady,
      reason: ReadinessReason::RuntimeUnhealthy,
    };
  }
  if !snapshot.certificate_transparency.is_ready() {
    return ReadinessSnapshot {
      state: ServerReadiness::NotReady,
      reason: ReadinessReason::RuntimeUnhealthy,
    };
  }
  ReadinessSnapshot::ready()
}

impl Drop for ServerLifecycle {
  fn drop(&mut self) {
    if self.final_tx.borrow().is_none() {
      self.publish_final(ShutdownResult {
        outcome: ShutdownOutcome::Failed,
        reason: ShutdownReason::RuntimeFailure,
      });
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn weak_control_does_not_keep_server_alive() {
    let (handle, lifecycle) = ServerLifecycle::new(RuntimeTopologySnapshot::external(), Vec::new());
    let control = handle.control();
    drop(handle);
    drop(lifecycle);
    assert_eq!(control.cancel(), Err(ServerControlClosed));
  }

  #[tokio::test]
  async fn final_result_is_observable_without_a_tokio_join_handle() {
    let (handle, lifecycle) = ServerLifecycle::new(RuntimeTopologySnapshot::external(), Vec::new());
    lifecycle.publish(ReadinessSnapshot::ready());
    lifecycle.publish_final(ShutdownResult {
      outcome: ShutdownOutcome::Graceful,
      reason: ShutdownReason::CallerRequested,
    });
    assert_eq!(
      handle
        .wait()
        .await
        .expect("final result should be published"),
      ShutdownResult {
        outcome: ShutdownOutcome::Graceful,
        reason: ShutdownReason::CallerRequested,
      }
    );
  }

  #[tokio::test]
  async fn graceful_shutdown_uses_the_caller_deadline_and_returns_final_result() {
    let (handle, mut lifecycle) =
      ServerLifecycle::new(RuntimeTopologySnapshot::external(), Vec::new());
    let deadline = Instant::now() + std::time::Duration::from_secs(1);
    let driver = tokio::spawn(async move {
      assert!(matches!(
        lifecycle.command_rx.recv().await,
        Some(ControlCommand::Graceful { deadline: observed }) if observed == deadline
      ));
      lifecycle.publish_final(ShutdownResult {
        outcome: ShutdownOutcome::Graceful,
        reason: ShutdownReason::CallerRequested,
      });
    });

    assert_eq!(
      handle
        .shutdown(deadline)
        .await
        .expect("graceful result should be observable"),
      ShutdownResult {
        outcome: ShutdownOutcome::Graceful,
        reason: ShutdownReason::CallerRequested,
      }
    );
    driver.await.expect("lifecycle driver should join");
  }

  #[tokio::test]
  async fn immediate_cancellation_is_observable_and_does_not_detach_the_driver() {
    let (handle, lifecycle) = ServerLifecycle::new(RuntimeTopologySnapshot::external(), Vec::new());
    let driver = tokio::spawn(async move {
      lifecycle.cancellation.cancelled().await;
      lifecycle.publish_final(ShutdownResult {
        outcome: ShutdownOutcome::Cancelled,
        reason: ShutdownReason::ImmediateCancellation,
      });
    });

    handle.cancel().expect("cancellation should be admitted");
    assert_eq!(
      handle
        .wait()
        .await
        .expect("cancel result should be observable"),
      ShutdownResult {
        outcome: ShutdownOutcome::Cancelled,
        reason: ShutdownReason::ImmediateCancellation,
      }
    );
    driver.await.expect("lifecycle driver should join");
  }

  #[tokio::test]
  async fn immediate_cancellation_cannot_be_crowded_out_by_control_commands() {
    let (handle, lifecycle) = ServerLifecycle::new(RuntimeTopologySnapshot::external(), Vec::new());
    for _ in 0..CONTROL_CAPACITY {
      handle
        .command_tx
        .try_send(ControlCommand::PreDrain)
        .expect("control queue should accept its declared capacity");
    }
    handle
      .control()
      .cancel()
      .expect("cancellation should not use bounded command capacity");
    tokio::time::timeout(
      std::time::Duration::from_secs(1),
      lifecycle.cancellation.cancelled(),
    )
    .await
    .expect("cancellation should publish immediately");
  }

  #[tokio::test]
  async fn lifecycle_instances_can_complete_sequentially() {
    for _ in 0..2 {
      let (handle, lifecycle) =
        ServerLifecycle::new(RuntimeTopologySnapshot::external(), Vec::new());
      lifecycle.publish_final(ShutdownResult {
        outcome: ShutdownOutcome::Graceful,
        reason: ShutdownReason::CallerRequested,
      });
      assert_eq!(
        handle
          .wait()
          .await
          .expect("sequential result should publish")
          .outcome,
        ShutdownOutcome::Graceful
      );
    }
  }

  #[tokio::test]
  async fn owned_handle_waits_for_runtime_thread_completion_after_driver_final() {
    let (handle, lifecycle) = ServerLifecycle::new(RuntimeTopologySnapshot::external(), Vec::new());
    let (runtime_done_tx, runtime_done_rx) = watch::channel(false);
    let handle = handle.with_owned_runtime_completion(runtime_done_rx);
    lifecycle.publish_final(ShutdownResult {
      outcome: ShutdownOutcome::Graceful,
      reason: ShutdownReason::CallerRequested,
    });
    let waiter = tokio::spawn(handle.wait());
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    runtime_done_tx.send_replace(true);
    assert_eq!(
      waiter
        .await
        .expect("wait task should join")
        .expect("runtime completion should publish")
        .outcome,
      ShutdownOutcome::Graceful
    );
  }

  #[test]
  fn bound_listener_inventory_is_sorted_and_deduplicated() {
    let address = "127.0.0.1:8080"
      .parse()
      .expect("test listener address should parse");
    let listener = BoundListener {
      kind: BoundListenerKind::Http,
      transport: BoundListenerTransport::Tcp,
      address,
    };
    let (handle, _lifecycle) = ServerLifecycle::new(
      RuntimeTopologySnapshot::external(),
      vec![listener, listener],
    );
    assert_eq!(handle.bound_listeners(), &[listener]);
  }
}
