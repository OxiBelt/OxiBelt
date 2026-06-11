//! Low-overhead runtime counters surfaced through authorized diagnostics.
//! Counters are observational only and must not influence proxy decisions.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::diagnostics::{RuntimeSnapshot, build_runtime_snapshot};
use crate::state::AppSnapshot;

const RUNTIME_INTROSPECTION_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Default)]
pub struct RuntimeIntrospectionState {
  downstream_https_tcp_connections: AtomicUsize,
  plain_http_connections: AtomicUsize,
  http1_connections: AtomicUsize,
  http1_requests: AtomicUsize,
  http2_connections: AtomicUsize,
  http2_streams: AtomicUsize,
  http3_connections: AtomicUsize,
  http3_requests: AtomicUsize,
  websocket_tunnels: AtomicUsize,
  webtransport_sessions: AtomicUsize,
  stream_listener_connections: AtomicUsize,
  stream_listener_udp_flows: AtomicUsize,
  turn_tcp_connections: AtomicUsize,
  turn_tls_connections: AtomicUsize,
}

impl RuntimeIntrospectionState {
  pub fn new() -> Arc<Self> {
    Arc::new(Self::default())
  }

  pub fn guard(self: &Arc<Self>, counter: RuntimeIntrospectionCounter) -> RuntimeCounterGuard {
    self.increment(counter);
    RuntimeCounterGuard {
      state: self.clone(),
      counter,
    }
  }

  pub fn connections(&self) -> RuntimeConnectionSnapshot {
    RuntimeConnectionSnapshot {
      downstream: DownstreamConnectionSnapshot {
        https_tcp_active: self.load(RuntimeIntrospectionCounter::DownstreamHttpsTcpConnection),
        plain_http_active: self.load(RuntimeIntrospectionCounter::PlainHttpConnection),
      },
      http: HttpConnectionSnapshot {
        http1_connections_active: self.load(RuntimeIntrospectionCounter::Http1Connection),
        http1_requests_active: self.load(RuntimeIntrospectionCounter::Http1Request),
        http2_connections_active: self.load(RuntimeIntrospectionCounter::Http2Connection),
        http2_streams_active: self.load(RuntimeIntrospectionCounter::Http2Stream),
        http3_connections_active: self.load(RuntimeIntrospectionCounter::Http3Connection),
        http3_requests_active: self.load(RuntimeIntrospectionCounter::Http3Request),
      },
      tunnels: TunnelConnectionSnapshot {
        websocket_active: self.load(RuntimeIntrospectionCounter::WebSocketTunnel),
        webtransport_sessions_active: self.load(RuntimeIntrospectionCounter::WebTransportSession),
      },
      streams: StreamConnectionSnapshot {
        stream_listener_connections_active: self
          .load(RuntimeIntrospectionCounter::StreamListenerConnection),
        stream_listener_udp_flows_active: self
          .load(RuntimeIntrospectionCounter::StreamListenerUdpFlow),
      },
      turn: TurnConnectionSnapshot {
        tcp_connections_active: self.load(RuntimeIntrospectionCounter::TurnTcpConnection),
        tls_connections_active: self.load(RuntimeIntrospectionCounter::TurnTlsConnection),
      },
    }
  }

  fn increment(&self, counter: RuntimeIntrospectionCounter) {
    self.counter(counter).fetch_add(1, Ordering::Relaxed);
  }

  fn decrement(&self, counter: RuntimeIntrospectionCounter) {
    let previous = self.counter(counter).fetch_sub(1, Ordering::Relaxed);
    debug_assert!(
      previous > 0,
      "runtime introspection counter decremented below zero"
    );
    if previous == 0 {
      self.counter(counter).fetch_add(1, Ordering::Relaxed);
    }
  }

  fn load(&self, counter: RuntimeIntrospectionCounter) -> usize {
    self.counter(counter).load(Ordering::Relaxed)
  }

  fn counter(&self, counter: RuntimeIntrospectionCounter) -> &AtomicUsize {
    match counter {
      RuntimeIntrospectionCounter::DownstreamHttpsTcpConnection => {
        &self.downstream_https_tcp_connections
      }
      RuntimeIntrospectionCounter::PlainHttpConnection => &self.plain_http_connections,
      RuntimeIntrospectionCounter::Http1Connection => &self.http1_connections,
      RuntimeIntrospectionCounter::Http1Request => &self.http1_requests,
      RuntimeIntrospectionCounter::Http2Connection => &self.http2_connections,
      RuntimeIntrospectionCounter::Http2Stream => &self.http2_streams,
      RuntimeIntrospectionCounter::Http3Connection => &self.http3_connections,
      RuntimeIntrospectionCounter::Http3Request => &self.http3_requests,
      RuntimeIntrospectionCounter::WebSocketTunnel => &self.websocket_tunnels,
      RuntimeIntrospectionCounter::WebTransportSession => &self.webtransport_sessions,
      RuntimeIntrospectionCounter::StreamListenerConnection => &self.stream_listener_connections,
      RuntimeIntrospectionCounter::StreamListenerUdpFlow => &self.stream_listener_udp_flows,
      RuntimeIntrospectionCounter::TurnTcpConnection => &self.turn_tcp_connections,
      RuntimeIntrospectionCounter::TurnTlsConnection => &self.turn_tls_connections,
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub enum RuntimeIntrospectionCounter {
  DownstreamHttpsTcpConnection,
  PlainHttpConnection,
  Http1Connection,
  Http1Request,
  Http2Connection,
  Http2Stream,
  Http3Connection,
  Http3Request,
  WebSocketTunnel,
  WebTransportSession,
  StreamListenerConnection,
  StreamListenerUdpFlow,
  TurnTcpConnection,
  TurnTlsConnection,
}

pub struct RuntimeCounterGuard {
  state: Arc<RuntimeIntrospectionState>,
  counter: RuntimeIntrospectionCounter,
}

impl Drop for RuntimeCounterGuard {
  fn drop(&mut self) {
    self.state.decrement(self.counter);
  }
}

#[derive(Debug, Serialize)]
pub struct RuntimeIntrospection {
  pub metadata: RuntimeIntrospectionMetadata,
  pub runtime: RuntimeSnapshot,
  pub connections: RuntimeConnectionSnapshot,
}

#[derive(Debug, Serialize)]
pub struct RuntimeIntrospectionMetadata {
  pub format_version: u32,
  pub generated_at_unix_ms: u64,
  pub package_version: &'static str,
  pub redacted: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeConnectionSnapshot {
  pub downstream: DownstreamConnectionSnapshot,
  pub http: HttpConnectionSnapshot,
  pub tunnels: TunnelConnectionSnapshot,
  pub streams: StreamConnectionSnapshot,
  pub turn: TurnConnectionSnapshot,
}

#[derive(Debug, Serialize)]
pub struct DownstreamConnectionSnapshot {
  pub https_tcp_active: usize,
  pub plain_http_active: usize,
}

#[derive(Debug, Serialize)]
pub struct HttpConnectionSnapshot {
  pub http1_connections_active: usize,
  pub http1_requests_active: usize,
  pub http2_connections_active: usize,
  pub http2_streams_active: usize,
  pub http3_connections_active: usize,
  pub http3_requests_active: usize,
}

#[derive(Debug, Serialize)]
pub struct TunnelConnectionSnapshot {
  pub websocket_active: usize,
  pub webtransport_sessions_active: usize,
}

#[derive(Debug, Serialize)]
pub struct StreamConnectionSnapshot {
  pub stream_listener_connections_active: usize,
  pub stream_listener_udp_flows_active: usize,
}

#[derive(Debug, Serialize)]
pub struct TurnConnectionSnapshot {
  pub tcp_connections_active: usize,
  pub tls_connections_active: usize,
}

pub fn build_runtime_introspection(snapshot: &AppSnapshot) -> RuntimeIntrospection {
  RuntimeIntrospection {
    metadata: RuntimeIntrospectionMetadata {
      format_version: RUNTIME_INTROSPECTION_FORMAT_VERSION,
      generated_at_unix_ms: now_unix_ms(),
      package_version: env!("CARGO_PKG_VERSION"),
      redacted: true,
    },
    runtime: build_runtime_snapshot(snapshot),
    connections: snapshot.runtime_introspection.connections(),
  }
}

fn now_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn guards_increment_and_decrement_active_counters() {
    let state = RuntimeIntrospectionState::new();
    {
      let _guard = state.guard(RuntimeIntrospectionCounter::Http2Stream);
      assert_eq!(state.connections().http.http2_streams_active, 1);
    }

    assert_eq!(state.connections().http.http2_streams_active, 0);
  }

  #[test]
  fn serialized_connections_include_grouped_fields() {
    let state = RuntimeIntrospectionState::new();
    let _https = state.guard(RuntimeIntrospectionCounter::DownstreamHttpsTcpConnection);
    let _webtransport = state.guard(RuntimeIntrospectionCounter::WebTransportSession);
    let value = serde_json::to_value(state.connections()).expect("connections should serialize");

    assert_eq!(value["downstream"]["https_tcp_active"], 1);
    assert_eq!(value["tunnels"]["webtransport_sessions_active"], 1);
    assert_eq!(value["http"]["http1_connections_active"], 0);
  }
}
