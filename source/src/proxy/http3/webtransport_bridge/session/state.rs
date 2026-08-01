//! Shared state for a single WebTransport bridge session.
//! State transitions are centralized so task shutdown and admin visibility agree.

use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinHandle;

use super::super::super::H3RequestStream;
use super::super::super::upstream_connection::WebTransportConnectionGuard;
use super::connection_limits::WebTransportSessionPermits;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::stream_waf::StreamWafRequestContext;
use crate::runtime_introspection::RuntimeCounterGuard;
use crate::state::AppSnapshot;
use crate::telemetry::{TelemetryStart, TraceContext};
#[cfg(feature = "admin-runtime")]
use crate::webtransport_admin::WebTransportSessionGuard;

pub(in crate::proxy::http3::webtransport_bridge) struct ActiveWebTransportSession {
  pub(super) upstream: Arc<web_transport_quinn::Session>,
  pub(super) _upstream_connection_guard: WebTransportConnectionGuard,
  pub(super) connect_stream: H3RequestStream,
  #[cfg(feature = "admin-runtime")]
  pub(super) admin_guard: WebTransportSessionGuard,
  pub(super) _connection_permits: WebTransportSessionPermits,
  pub(super) _introspection_guard: RuntimeCounterGuard,
  pub(super) stream_waf_state: Option<Arc<AppSnapshot>>,
  pub(super) metrics_state: Arc<AppSnapshot>,
  pub(super) stream_waf: Option<StreamWafRequestContext>,
  pub(super) timeouts: EffectiveTimeouts,
  pub(super) route_name: String,
  pub(super) upstream_name: String,
  pub(super) trace_context: Option<TraceContext>,
  pub(super) started_at: TelemetryStart,
  pub(in crate::proxy::http3::webtransport_bridge) last_activity: Instant,
  pub(super) tasks: Vec<JoinHandle<()>>,
}

impl ActiveWebTransportSession {
  pub(in crate::proxy::http3::webtransport_bridge) fn webtransport_idle(
    &self,
  ) -> std::time::Duration {
    self.timeouts.webtransport_idle
  }

  pub(in crate::proxy::http3::webtransport_bridge) fn record_activity(&mut self) {
    self.last_activity = Instant::now();
    #[cfg(feature = "admin-runtime")]
    self
      .metrics_state
      .webtransport_admin
      .record_activity(self.admin_guard.id());
    self.reap_finished_tasks();
  }

  pub(in crate::proxy::http3::webtransport_bridge) fn reap_finished_tasks(&mut self) {
    self.tasks.retain(|task| !task.is_finished());
  }
}
