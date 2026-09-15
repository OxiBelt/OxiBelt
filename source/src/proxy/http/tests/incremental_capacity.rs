//! Public HTTP admission responses for RFC 10036 requests.

use super::*;
use crate::circuit_breakers::{AdmissionLease, AdmissionRejection, AdmissionRejectionReason};
use crate::config::{CapacitySetting, Config, HttpVersion, RouteHeaderValueConfig};
use http::Version;
use hyper::body::{Frame, SizeHint};
use pretty_assertions::assert_eq;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// A request rejected during admission must never poll its upload body.
struct UnpolledBody;

impl Body for UnpolledBody {
  type Data = bytes::Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    panic!("capacity rejection must not poll the upload")
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

#[derive(Clone, Copy)]
enum Scope {
  Global,
  Route,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reason {
  ActiveLimit,
  QueueFull,
  QueueTimeout,
}

impl Reason {
  const fn admission_reason(self) -> AdmissionRejectionReason {
    match self {
      Self::ActiveLimit => AdmissionRejectionReason::ActiveLimit,
      Self::QueueFull => AdmissionRejectionReason::QueueFull,
      Self::QueueTimeout => AdmissionRejectionReason::QueueTimeout,
    }
  }
}

async fn snapshot(scope: Scope, reason: Reason) -> (Arc<AppSnapshot>, common::TempDir) {
  snapshot_with_status_policy(scope, reason, false, Some(false)).await
}

async fn snapshot_with_status_policy(
  scope: Scope,
  reason: Reason,
  global_proxy_status: bool,
  route_proxy_status: Option<bool>,
) -> (Arc<AppSnapshot>, common::TempDir) {
  let temp = common::TempDir::new("incremental-capacity");
  let (cert, key) = common::create_self_signed_cert(temp.path(), "incremental-capacity");
  let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert, &key)).unwrap();
  // 1,001 ms proves the public response uses a ceiling, not truncation.
  config.circuit_breakers.capacity_retry_after_ms = 1_001;
  // The protocol signal is mandatory even where both applicable knobs disable it.
  config.proxy.status_headers.proxy_status = global_proxy_status;
  config.routes[0].status_headers.proxy_status = route_proxy_status;
  // The public handler enters global admission through the priority layer.
  // Keep that path for ActiveLimit, but exercise QueueFull and QueueTimeout
  // through the ordinary bounded queue so their typed reasons are observable.
  if matches!(scope, Scope::Global) && !matches!(reason, Reason::ActiveLimit) {
    config.circuit_breakers.priority.enabled = false;
  }

  // Keep the other admission scope out of the way so the selected scope is
  // the one that supplies the typed rejection.
  match scope {
    Scope::Global => {
      config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
      config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(2);
      config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(2);
      config
        .circuit_breakers
        .route_defaults
        .pending_queue_timeout_ms = 3_000;
    }
    Scope::Route => {
      config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(2);
      config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(2);
      config.circuit_breakers.global.pending_queue_timeout_ms = 3_000;
      config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(1);
    }
  }
  let (active, pending, timeout) = match reason {
    Reason::ActiveLimit => (1, 0, 3_000),
    // QueueFull needs a positive queue occupied by a real pending waiter.
    Reason::QueueFull => (1, 1, 3_000),
    Reason::QueueTimeout => (1, 1, 10),
  };
  match scope {
    Scope::Global => {
      config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(pending);
      config.circuit_breakers.global.pending_queue_timeout_ms = timeout;
      config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(active);
    }
    Scope::Route => {
      config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(pending);
      config
        .circuit_breakers
        .route_defaults
        .pending_queue_timeout_ms = timeout;
      config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(active);
    }
  }
  config.validate().unwrap();
  (Arc::new(AppSnapshot::new(config).await.unwrap()), temp)
}

async fn late_exchange_snapshot(
  upstream_version: HttpVersion,
) -> (Arc<AppSnapshot>, common::TempDir) {
  let temp = common::TempDir::new("incremental-capacity-late-exchange");
  let (cert, key) =
    common::create_self_signed_cert(temp.path(), "incremental-capacity-late-exchange");
  let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert, &key)).unwrap();
  config.circuit_breakers.capacity_retry_after_ms = 1_001;
  config.proxy.status_headers.proxy_status = false;
  config.routes[0].status_headers.proxy_status = Some(false);
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(2);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(0);
  config.routes[0]
    .actions
    .request_headers
    .set
    .push(RouteHeaderValueConfig {
      name: "incremental".into(),
      value: "?1".into(),
    });
  config.routes[0].upstream_http_version = Some(upstream_version);
  config.upstreams[0].max_http_version = upstream_version;
  config.upstreams[0].origin = "https://127.0.0.1:9".parse().unwrap();
  config.validate().unwrap();
  (Arc::new(AppSnapshot::new(config).await.unwrap()), temp)
}

async fn send<B>(
  state: Arc<AppSnapshot>,
  version: Version,
  incremental: &[&str],
  body: B,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes, Error = body::BoxError> + Send + Sync + Unpin + 'static,
{
  let mut request = Request::builder()
    .method("POST")
    .uri("/upload")
    .version(version)
    .header("host", "example.com")
    .body(body)
    .unwrap();
  for value in incremental {
    request
      .headers_mut()
      .append("incremental", value.parse().unwrap());
  }
  tokio::time::timeout(
    Duration::from_secs(3),
    handle_inner(
      request,
      "203.0.113.10:49152".parse().unwrap(),
      None,
      WafTransportMetadataInput::default(),
      Arc::new(WafTlsMetadata::default()),
      None,
      None,
      state,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      true,
      "http",
      test_drain(),
    ),
  )
  .await
  .expect("admission response headers should complete")
}

async fn hold(scope: Scope, state: &Arc<AppSnapshot>) -> AdmissionLease {
  let route = state
    .route_table
    .resolve("example.com", "/upload", &state.upstreams)
    .unwrap();
  match scope {
    Scope::Global => state
      .circuit_breakers
      .admit_global_request(None)
      .await
      .unwrap(),
    Scope::Route => state
      .circuit_breakers
      .admit_route_scope_request(&route.route.name, None)
      .await
      .unwrap(),
  }
}

type PendingAdmission =
  Pin<Box<dyn Future<Output = Result<AdmissionLease, AdmissionRejection>> + Send>>;

struct CapacityPressure {
  // Keeping this future alive keeps its bounded queue slot occupied. Drop it
  // before the lease so the queue's cancellation cleanup is exercised too.
  waiter: Option<PendingAdmission>,
  lease: AdmissionLease,
}

impl CapacityPressure {
  fn release(mut self) {
    drop(self.waiter.take());
    drop(self.lease);
  }
}

async fn prepare(scope: Scope, reason: Reason, state: &Arc<AppSnapshot>) -> CapacityPressure {
  let lease = hold(scope, state).await;
  let waiter = if reason == Reason::QueueFull {
    let route = state
      .route_table
      .resolve("example.com", "/upload", &state.upstreams)
      .unwrap()
      .route
      .name
      .clone();
    let runtime = state.circuit_breakers.clone();
    let mut waiter: PendingAdmission = match scope {
      Scope::Global => Box::pin(async move { runtime.admit_global_request(None).await }),
      Scope::Route => {
        Box::pin(async move { runtime.admit_route_scope_request(&route, None).await })
      }
    };
    let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(
      matches!(waiter.as_mut().poll(&mut context), Poll::Pending),
      "the positive queue slot must be occupied before the public request starts"
    );
    Some(waiter)
  } else {
    None
  };
  CapacityPressure { lease, waiter }
}

async fn assert_capacity_releases(scope: Scope, state: &Arc<AppSnapshot>) {
  let released = tokio::time::timeout(Duration::from_secs(1), hold(scope, state))
    .await
    .expect("released admission capacity should not wait");
  drop(released);
}

fn assert_capacity_response(
  response: &Response<ProxyBody>,
  version: Version,
  reason: Reason,
  marked: bool,
) {
  assert_eq!(
    response
      .extensions()
      .get::<AdmissionRejection>()
      .map(|value| value.reason),
    Some(reason.admission_reason()),
    "the public response must retain the actual typed admission reason"
  );
  assert_eq!(
    response.status(),
    if marked {
      StatusCode::TOO_MANY_REQUESTS
    } else {
      StatusCode::SERVICE_UNAVAILABLE
    }
  );
  assert_eq!(response.headers().get("retry-after").unwrap(), "2");
  assert_eq!(
    response
      .headers()
      .get("cache-control")
      .map(|v| v.as_bytes()),
    marked.then_some(b"no-store".as_slice())
  );
  assert_eq!(
    response.headers().get("proxy-status").map(|v| v.as_bytes()),
    marked.then_some(b"oxibelt; error=connection_limit_reached".as_slice())
  );
  assert_eq!(
    response.headers().get("connection").map(|v| v.as_bytes()),
    (marked && matches!(version, Version::HTTP_10 | Version::HTTP_11))
      .then_some(b"close".as_slice())
  );
}

#[tokio::test]
async fn public_handler_adapts_each_actual_capacity_reason_at_global_and_route_scope() {
  for scope in [Scope::Global, Scope::Route] {
    for reason in [Reason::ActiveLimit, Reason::QueueFull, Reason::QueueTimeout] {
      for marked in [false, true] {
        let (state, _temp) = snapshot(scope, reason).await;
        let pressure = prepare(scope, reason, &state).await;
        let response = send(
          state.clone(),
          Version::HTTP_11,
          if marked { &["?1"] } else { &[] },
          UnpolledBody,
        )
        .await;
        assert_capacity_response(&response, Version::HTTP_11, reason, marked);
        drop(response);
        pressure.release();
        assert_capacity_releases(scope, &state).await;
      }
    }
  }
}

#[tokio::test]
async fn only_a_single_valid_true_incremental_item_activates_capacity_adaptation() {
  for values in [&["?0"][..], &["not-structured"][..], &["?1", "?0"][..]] {
    let (state, _temp) = snapshot(Scope::Global, Reason::ActiveLimit).await;
    let pressure = prepare(Scope::Global, Reason::ActiveLimit, &state).await;
    let response = send(state.clone(), Version::HTTP_11, values, UnpolledBody).await;
    assert_capacity_response(&response, Version::HTTP_11, Reason::ActiveLimit, false);
    drop(response);
    pressure.release();
    assert_capacity_releases(Scope::Global, &state).await;
  }
}

#[tokio::test]
async fn capacity_proxy_status_is_mandatory_for_inherited_and_route_disabled_policy() {
  for (global_proxy_status, route_proxy_status) in [(false, None), (true, Some(false))] {
    let (state, _temp) = snapshot_with_status_policy(
      Scope::Route,
      Reason::ActiveLimit,
      global_proxy_status,
      route_proxy_status,
    )
    .await;
    let pressure = prepare(Scope::Route, Reason::ActiveLimit, &state).await;
    let response = send(state.clone(), Version::HTTP_11, &["?1"], UnpolledBody).await;
    assert_capacity_response(&response, Version::HTTP_11, Reason::ActiveLimit, true);
    drop(response);
    pressure.release();
    assert_capacity_releases(Scope::Route, &state).await;
  }
}

#[tokio::test]
async fn route_added_incremental_adapts_late_upstream_admission_and_preserves_downstream_version() {
  for upstream_version in [HttpVersion::H2, HttpVersion::H3] {
    for downstream_version in [
      Version::HTTP_10,
      Version::HTTP_11,
      Version::HTTP_2,
      Version::HTTP_3,
    ] {
      let (state, _temp) = late_exchange_snapshot(upstream_version).await;
      let route = state
        .route_table
        .resolve("example.com", "/upload", &state.upstreams)
        .unwrap()
        .route
        .name
        .clone();
      let upstream_lease = state
        .circuit_breakers
        .admit_upstream_attempt(&route, None, None)
        .await
        .expect("the held upstream admission should occupy the route scope");
      let response = send(state.clone(), downstream_version, &[], UnpolledBody).await;
      assert_capacity_response(&response, downstream_version, Reason::ActiveLimit, true);
      assert_eq!(
        response.version(),
        downstream_version,
        "late exchange adaptation must retain the downstream protocol version"
      );
      drop(response);
      drop(upstream_lease);
      let released = tokio::time::timeout(
        Duration::from_secs(1),
        state
          .circuit_breakers
          .admit_upstream_attempt(&route, None, None),
      )
      .await
      .expect("released upstream admission should not wait")
      .expect("released upstream admission should be available");
      drop(released);
    }
  }
}

#[tokio::test]
async fn marked_capacity_rejections_keep_downstream_version_and_close_all_http1_uploads() {
  for version in [
    Version::HTTP_10,
    Version::HTTP_11,
    Version::HTTP_2,
    Version::HTTP_3,
  ] {
    let (state, _temp) = snapshot(Scope::Global, Reason::ActiveLimit).await;
    let pressure = prepare(Scope::Global, Reason::ActiveLimit, &state).await;
    let response = send(state.clone(), version, &["?1"], UnpolledBody).await;
    assert_capacity_response(&response, version, Reason::ActiveLimit, true);
    drop(response);

    // Empty requests are also eligible for an admission rejection and must
    // receive the same HTTP/1 connection-close signal.
    let empty = send(state.clone(), version, &["?1"], empty_test_body()).await;
    assert_capacity_response(&empty, version, Reason::ActiveLimit, true);
    drop(empty);
    pressure.release();
    assert_capacity_releases(Scope::Global, &state).await;
  }
}
