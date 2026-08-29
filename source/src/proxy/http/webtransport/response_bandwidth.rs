//! Final response shaping for WebTransport setup and route-selected failures.

use std::sync::Arc;

use http::Response;

use crate::bandwidth::{BandwidthDirection, RouteBandwidthLimiter};

use super::super::body::{self, ProxyBody};

#[derive(Clone)]
struct WebTransportResponseBandwidth(Arc<RouteBandwidthLimiter>);

pub(super) fn with_webtransport_bandwidth_context(
  mut response: Response<ProxyBody>,
  bandwidth: Arc<RouteBandwidthLimiter>,
) -> Response<ProxyBody> {
  response
    .extensions_mut()
    .insert(WebTransportResponseBandwidth(bandwidth));
  response
}

pub(crate) fn shape_webtransport_response(
  response: Response<ProxyBody>,
  bandwidth: Option<Arc<RouteBandwidthLimiter>>,
  metrics: Arc<crate::metrics::Metrics>,
) -> Response<ProxyBody> {
  let (mut parts, response_body) = response.into_parts();
  let bandwidth = bandwidth.or_else(|| {
    parts
      .extensions
      .remove::<WebTransportResponseBandwidth>()
      .map(|bandwidth| bandwidth.0)
  });
  let Some(bandwidth) = bandwidth else {
    return Response::from_parts(parts, response_body);
  };
  let response_body = if let Some(inlined) = parts
    .extensions
    .remove::<body::InlinedKnownSmallResponseBody>()
  {
    let (data, trailers) = inlined.into_parts();
    body::materialized_known_small_body(data, trailers)
  } else {
    response_body
  };
  parts.extensions.remove::<body::KnownSmallResponseBody>();
  parts
    .extensions
    .remove::<body::CompiledKnownSmallNoopResponse>();
  Response::from_parts(
    parts,
    body::with_bandwidth(
      response_body,
      bandwidth,
      BandwidthDirection::Download,
      metrics,
      crate::metrics::BandwidthTrafficClass::Http,
      None,
    ),
  )
}

#[cfg(test)]
mod tests {
  use std::num::NonZeroU64;

  use bytes::Bytes;
  use http_body_util::BodyExt;
  use hyper::body::Frame;

  use super::*;
  use crate::bandwidth::{BandwidthPolicy, BandwidthRate};
  use crate::metrics::Metrics;

  #[tokio::test]
  async fn setup_response_materializes_inlined_known_small_body() {
    let placeholder = http_body_util::Empty::<Bytes>::new()
      .map_err(|never| -> body::BoxError { match never {} })
      .boxed();
    let mut response = Response::new(placeholder);
    response
      .extensions_mut()
      .insert(body::KnownSmallResponseBody);
    response
      .extensions_mut()
      .insert(body::CompiledKnownSmallNoopResponse);
    response
      .extensions_mut()
      .insert(body::InlinedKnownSmallResponseBody::new(
        Bytes::from_static(b"setup body"),
        None,
      ));

    let response = shape_webtransport_response(
      response,
      Some(RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED)),
      Metrics::new(),
    );

    assert!(
      response
        .extensions()
        .get::<body::KnownSmallResponseBody>()
        .is_none()
    );
    assert!(
      response
        .extensions()
        .get::<body::CompiledKnownSmallNoopResponse>()
        .is_none()
    );
    assert!(
      response
        .extensions()
        .get::<body::InlinedKnownSmallResponseBody>()
        .is_none()
    );
    let body = response
      .into_body()
      .collect()
      .await
      .expect("bandwidth-shaped setup response should collect")
      .to_bytes();
    assert_eq!(body.as_ref(), b"setup body");
  }

  #[tokio::test(start_paused = true)]
  async fn setup_response_observes_unlimited_to_limited_reload() {
    let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED);
    let (source_tx, source) = body::channel_body(1);
    let response =
      shape_webtransport_response(Response::new(source), Some(limiter.clone()), Metrics::new());
    let mut shaped = response.into_body();

    source_tx
      .send(Ok(Frame::data(Bytes::from_static(b"open"))))
      .await
      .unwrap();
    let open = shaped.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(open.as_ref(), b"open");

    let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(4).unwrap());
    limiter
      .update(BandwidthPolicy::new(BandwidthRate::Unlimited, rate))
      .unwrap();
    source_tx
      .send(Ok(Frame::data(Bytes::from_static(b"slow"))))
      .await
      .unwrap();
    let limited = shaped.frame();
    tokio::pin!(limited);
    assert!(futures_util::poll!(limited.as_mut()).is_pending());
    tokio::time::advance(std::time::Duration::from_millis(250)).await;
    let first = limited.await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(first.as_ref(), b"s");
  }
}
