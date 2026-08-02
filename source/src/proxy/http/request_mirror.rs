//! Best-effort route request mirroring.
//! Mirrors are fire-and-forget and never affect the primary response path.

use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::{HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tracing::warn;

use crate::config::{HttpVersion, ProxyProtocolEgressMode, RouteConfig, UpstreamConfig};
use crate::state::AppSnapshot;

use super::EffectiveTimeouts;
use super::body::ProxyBody;
use super::retry::send_one_shot_with_state;
use super::route_action_runtime;
use super::route_actions::{self, RouteActionRenderContext};
use super::upstream::select_pool_upstream;
use super::version::{select_upstream_http_version, upstream_request_version};

const MAX_IN_FLIGHT_MIRROR_BODY_BYTES: usize = 64 * 1024 * 1024;
static REQUEST_MIRROR_BODY_BUDGET: LazyLock<Arc<Semaphore>> =
  LazyLock::new(|| Arc::new(Semaphore::new(MAX_IN_FLIGHT_MIRROR_BODY_BYTES)));

pub(super) fn spawn_request_mirrors(
  state: Arc<AppSnapshot>,
  route: &RouteConfig,
  outbound: &mut Request<ProxyBody>,
  request_uri: &http::Uri,
  client_addr: std::net::SocketAddr,
  host: &str,
  downstream_scheme: &str,
) {
  if state.overload.request_mirroring_disabled() {
    state.metrics.record_request_mirror_skip();
    return;
  }
  let body_size_hint = outbound.body().size_hint();
  let body_is_known_empty = body_size_hint.exact() == Some(0);
  let content_length = outbound
    .headers()
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<usize>().ok());
  let request_body_limit =
    usize::try_from(route.effective_max_request_body_bytes(&state.config.limits))
      .unwrap_or(usize::MAX);
  let mut pending = Vec::new();
  let mut capture_subscriptions = Vec::new();

  for mirror in route_action_runtime::enabled_mirrors(route) {
    if mirror.max_body_bytes == 0 && !matches!(*outbound.method(), Method::GET | Method::HEAD) {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    if !route_action_runtime::mirror_sample_allows(mirror, &route.name, request_uri) {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    let effective_body_limit = mirror.max_body_bytes.min(request_body_limit);
    if mirror.max_body_bytes > 0
      && content_length.is_some_and(|length| length > effective_body_limit)
    {
      state.metrics.record_request_mirror_skip();
      continue;
    }
    let body_receiver = if mirror.max_body_bytes > 0 && !body_is_known_empty {
      let (sender, receiver) = oneshot::channel();
      capture_subscriptions.push(MirrorCaptureSubscription {
        limit: effective_body_limit,
        sender: Some(sender),
      });
      Some(receiver)
    } else {
      None
    };
    pending.push(PendingMirror {
      pool_name: mirror.upstream_pool.clone(),
      request: empty_request_from(outbound),
      body_receiver,
    });
  }

  if !capture_subscriptions.is_empty() {
    let max_capture_bytes = capture_subscriptions
      .iter()
      .map(|subscription| subscription.limit)
      .max()
      .unwrap_or(0);
    if let Some(permit) = reserve_mirror_body_budget(&REQUEST_MIRROR_BODY_BUDGET, max_capture_bytes)
    {
      let body = std::mem::replace(outbound.body_mut(), full_body(Bytes::new()));
      *outbound.body_mut() =
        MirrorCaptureBody::new(body, capture_subscriptions, Some(Arc::new(permit))).boxed();
    }
  }

  for pending_mirror in pending {
    let mirror_state = state.clone();
    let route = route.clone();
    let route_name = route.name.clone();
    let hash_key = format!("{host}{request_uri}");
    let downstream_scheme = downstream_scheme.to_string();
    let downstream_host = host.to_string();
    let downstream_uri = request_uri.clone();
    tokio::spawn(async move {
      let PendingMirror {
        pool_name,
        mut request,
        body_receiver,
      } = pending_mirror;
      if let Some(body_receiver) = body_receiver {
        let Ok(Some(body)) = body_receiver.await else {
          mirror_state.metrics.record_request_mirror_skip();
          return;
        };
        let _body_budget = body.budget;
        set_mirror_body(&mut request, body.bytes);
      } else {
        set_mirror_body(&mut request, Bytes::new());
      }
      let selected = match select_pool_upstream(
        mirror_state.as_ref(),
        &pool_name,
        client_addr,
        &hash_key,
        None,
        None,
      )
      .await
      {
        Ok(selected) => selected,
        Err(error) => {
          mirror_state.metrics.record_request_mirror_error();
          warn!(route = %route_name, pool = %pool_name, error = ?error, "failed to select request mirror upstream");
          return;
        }
      };
      let upstream = selected.upstream.clone();
      let _selection = selected.into_pool_selection();
      let upstream_version = mirror_upstream_version(&mirror_state, &route, &upstream);
      if upstream_version == HttpVersion::H3
        || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
      {
        mirror_state.metrics.record_request_mirror_skip();
        return;
      }
      let Some(upstream_uri) = mirror_state.upstream_uri_parts.get(&upstream.name) else {
        mirror_state.metrics.record_request_mirror_error();
        warn!(route = %route_name, upstream = %upstream.name, "missing request mirror upstream URI parts");
        return;
      };
      let target_uri = match route_actions::build_upstream_uri(
        upstream_uri,
        &route,
        RouteActionRenderContext {
          route_prefix: route.effective_path_prefix(),
          path_captures: &[],
          downstream_scheme: &downstream_scheme,
          downstream_host: &downstream_host,
          downstream_uri: &downstream_uri,
        },
      ) {
        Ok(uri) => uri,
        Err(error) => {
          mirror_state.metrics.record_request_mirror_error();
          warn!(route = %route_name, upstream = %upstream.name, error = %error, "failed to build request mirror URI");
          return;
        }
      };
      *request.uri_mut() = target_uri;
      *request.version_mut() = upstream_request_version(upstream_version);
      let timeouts = EffectiveTimeouts::new(&mirror_state.config, &route, &upstream);
      let Some(client) = mirror_state.clients.for_upstream_version(
        &upstream.name,
        upstream.origin.scheme(),
        upstream_version,
      ) else {
        mirror_state.metrics.record_request_mirror_skip();
        return;
      };
      match send_one_shot_with_state(client, request, timeouts, mirror_state.as_ref(), None).await {
        Ok(_) => mirror_state.metrics.record_request_mirror_success(),
        Err(error) => {
          mirror_state.metrics.record_request_mirror_error();
          warn!(upstream = %upstream.name, error = %error, "request mirror dispatch failed");
        }
      }
    });
  }
}

struct PendingMirror {
  pool_name: String,
  request: Request<ProxyBody>,
  body_receiver: Option<oneshot::Receiver<Option<CapturedMirrorBody>>>,
}

struct MirrorCaptureSubscription {
  limit: usize,
  sender: Option<oneshot::Sender<Option<CapturedMirrorBody>>>,
}

struct CapturedMirrorBody {
  bytes: Bytes,
  budget: Option<Arc<OwnedSemaphorePermit>>,
}

struct MirrorCaptureBody {
  inner: ProxyBody,
  captured: BytesMut,
  max_capture_bytes: usize,
  oversized: bool,
  subscriptions: Vec<MirrorCaptureSubscription>,
  budget: Option<Arc<OwnedSemaphorePermit>>,
}

impl MirrorCaptureBody {
  fn new(
    inner: ProxyBody,
    subscriptions: Vec<MirrorCaptureSubscription>,
    budget: Option<Arc<OwnedSemaphorePermit>>,
  ) -> Self {
    let max_capture_bytes = subscriptions
      .iter()
      .map(|subscription| subscription.limit)
      .max()
      .unwrap_or(0);
    Self {
      inner,
      captured: BytesMut::new(),
      max_capture_bytes,
      oversized: false,
      subscriptions,
      budget,
    }
  }

  fn capture(&mut self, data: &Bytes) {
    if self.oversized {
      return;
    }
    let Some(total) = self.captured.len().checked_add(data.len()) else {
      self.oversized = true;
      self.captured.clear();
      return;
    };
    if total > self.max_capture_bytes {
      self.oversized = true;
      self.captured.clear();
      return;
    }
    self.captured.extend_from_slice(data);
  }

  fn finish_capture(&mut self) {
    let body = (!self.oversized).then(|| self.captured.split().freeze());
    for subscription in &mut self.subscriptions {
      let result = body
        .as_ref()
        .filter(|body| body.len() <= subscription.limit)
        .map(|body| CapturedMirrorBody {
          bytes: body.clone(),
          budget: self.budget.clone(),
        });
      if let Some(sender) = subscription.sender.take() {
        let _ = sender.send(result);
      }
    }
  }

  fn cancel_capture(&mut self) {
    self.captured.clear();
    for subscription in &mut self.subscriptions {
      if let Some(sender) = subscription.sender.take() {
        let _ = sender.send(None);
      }
    }
  }
}

fn reserve_mirror_body_budget(
  budget: &Arc<Semaphore>,
  bytes: usize,
) -> Option<OwnedSemaphorePermit> {
  let permits = u32::try_from(bytes).ok()?;
  budget.clone().try_acquire_many_owned(permits).ok()
}

impl Drop for MirrorCaptureBody {
  fn drop(&mut self) {
    self.cancel_capture();
  }
}

impl Body for MirrorCaptureBody {
  type Data = Bytes;
  type Error = super::body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.inner).poll_frame(context) {
      Poll::Ready(Some(Ok(frame))) => {
        if let Some(data) = frame.data_ref() {
          self.capture(data);
        }
        Poll::Ready(Some(Ok(frame)))
      }
      Poll::Ready(Some(Err(error))) => {
        self.cancel_capture();
        Poll::Ready(Some(Err(error)))
      }
      Poll::Ready(None) => {
        self.finish_capture();
        Poll::Ready(None)
      }
      Poll::Pending => Poll::Pending,
    }
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

fn mirror_upstream_version(
  state: &AppSnapshot,
  route: &RouteConfig,
  upstream: &UpstreamConfig,
) -> HttpVersion {
  route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      state.config.proxy.auto_upgrade.enabled,
      state.config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  })
}

#[allow(
  clippy::expect_used,
  reason = "all request builder inputs are cloned from an existing valid request"
)]
fn empty_request_from<B>(request: &Request<B>) -> Request<ProxyBody> {
  let mut builder = Request::builder()
    .method(request.method().clone())
    .uri(request.uri().clone())
    .version(request.version());
  *builder.headers_mut().expect("request builder headers") = request.headers().clone();
  builder
    .body(full_body(bytes::Bytes::new()))
    .expect("request clone builds")
}

fn set_mirror_body(request: &mut Request<ProxyBody>, body: Bytes) {
  request
    .headers_mut()
    .remove(http::header::TRANSFER_ENCODING);
  if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
    request
      .headers_mut()
      .insert(http::header::CONTENT_LENGTH, value);
  }
  *request.body_mut() = full_body(body);
}

fn full_body(bytes: bytes::Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> super::body::BoxError { match never {} })
    .boxed()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn subscription(
    limit: usize,
  ) -> (
    MirrorCaptureSubscription,
    oneshot::Receiver<Option<CapturedMirrorBody>>,
  ) {
    let (sender, receiver) = oneshot::channel();
    (
      MirrorCaptureSubscription {
        limit,
        sender: Some(sender),
      },
      receiver,
    )
  }

  #[tokio::test]
  async fn mirror_capture_replays_primary_and_honors_each_limit() {
    let (small, small_result) = subscription(3);
    let (large, large_result) = subscription(6);
    let body = MirrorCaptureBody::new(
      full_body(Bytes::from_static(b"abcdef")),
      vec![small, large],
      None,
    )
    .boxed();

    let primary = body
      .collect()
      .await
      .expect("primary mirror tee should remain readable")
      .to_bytes();
    assert_eq!(primary.as_ref(), b"abcdef");
    assert!(
      small_result
        .await
        .expect("small mirror result should be delivered")
        .is_none()
    );
    assert_eq!(
      large_result
        .await
        .expect("large mirror result should be delivered")
        .expect("body within large mirror limit")
        .bytes,
      Bytes::from_static(b"abcdef")
    );
  }

  #[tokio::test]
  async fn oversized_mirror_capture_skips_without_truncating_primary() {
    let (subscription, result) = subscription(4);
    let body = MirrorCaptureBody::new(
      full_body(Bytes::from_static(b"abcdef")),
      vec![subscription],
      None,
    )
    .boxed();

    let primary = body
      .collect()
      .await
      .expect("oversized mirror must not fail the primary body")
      .to_bytes();
    assert_eq!(primary.as_ref(), b"abcdef");
    assert!(
      result
        .await
        .expect("oversized mirror result should be delivered")
        .is_none()
    );
  }

  #[tokio::test]
  async fn unconsumed_primary_cancels_bodyful_mirror() {
    let (subscription, result) = subscription(8);
    let body = MirrorCaptureBody::new(
      full_body(Bytes::from_static(b"body")),
      vec![subscription],
      None,
    );
    drop(body);

    assert!(
      result
        .await
        .expect("canceled mirror result should be delivered")
        .is_none()
    );
  }

  #[tokio::test]
  async fn mirror_capture_holds_aggregate_budget_until_the_dispatched_body_drops() {
    let budget = Arc::new(Semaphore::new(6));
    let permit = reserve_mirror_body_budget(&budget, 6).expect("budget should admit one capture");
    assert!(reserve_mirror_body_budget(&budget, 1).is_none());
    let (subscription, result) = subscription(6);
    let body = MirrorCaptureBody::new(
      full_body(Bytes::from_static(b"abcdef")),
      vec![subscription],
      Some(Arc::new(permit)),
    )
    .boxed();

    body
      .collect()
      .await
      .expect("primary body should remain readable");
    let captured = result
      .await
      .expect("capture result should be delivered")
      .expect("capture should fit");
    assert_eq!(budget.available_permits(), 0);
    drop(captured);
    assert_eq!(budget.available_permits(), 6);
  }

  #[test]
  fn mirror_body_rewrites_framing_to_captured_length() {
    let mut request = Request::builder()
      .header(http::header::TRANSFER_ENCODING, "chunked")
      .body(full_body(Bytes::new()))
      .expect("request should build");

    set_mirror_body(&mut request, Bytes::from_static(b"abc"));

    assert!(
      request
        .headers()
        .get(http::header::TRANSFER_ENCODING)
        .is_none()
    );
    assert_eq!(request.headers()[http::header::CONTENT_LENGTH], "3");
  }
}
