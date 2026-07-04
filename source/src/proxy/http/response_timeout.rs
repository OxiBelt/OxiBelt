//! Downstream response timeout markers and body wrapping.

use std::time::Duration;

use http::Response;

use crate::waf::WafTransportNetwork;

use super::body::{self, BodyTimeoutKind, ProxyBody};

#[derive(Clone, Copy)]
pub(crate) struct DownstreamResponseSendTimeout(pub(crate) Duration);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DownstreamResponseTimeoutSelection {
  MarkedOnly,
  SkippedKnownSmall,
  BackpressureBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DownstreamResponseTimeoutSelected(pub(crate) DownstreamResponseTimeoutSelection);

pub(crate) fn downstream_response_send_timeout(response: &Response<ProxyBody>) -> Option<Duration> {
  response
    .extensions()
    .get::<DownstreamResponseSendTimeout>()
    .map(|timeout| timeout.0)
}

pub(crate) fn with_downstream_response_timeout(
  response: Response<ProxyBody>,
  timeout: Duration,
  transport_network: WafTransportNetwork,
) -> Response<ProxyBody> {
  if transport_network == WafTransportNetwork::Udp {
    return mark_downstream_response_timeout(response, timeout);
  }

  let (mut parts, body) = response.into_parts();
  if parts
    .extensions
    .get::<body::KnownSmallResponseBody>()
    .is_some()
  {
    parts.extensions.insert(DownstreamResponseTimeoutSelected(
      DownstreamResponseTimeoutSelection::SkippedKnownSmall,
    ));
    return Response::from_parts(parts, body);
  }
  parts
    .extensions
    .insert(DownstreamResponseSendTimeout(timeout));
  parts.extensions.insert(DownstreamResponseTimeoutSelected(
    DownstreamResponseTimeoutSelection::BackpressureBody,
  ));
  let body =
    body::with_backpressure_send_timeout(body, timeout, BodyTimeoutKind::DownstreamResponseSend);
  Response::from_parts(parts, body)
}

fn mark_downstream_response_timeout(
  response: Response<ProxyBody>,
  timeout: Duration,
) -> Response<ProxyBody> {
  let (mut parts, body) = response.into_parts();
  parts
    .extensions
    .insert(DownstreamResponseSendTimeout(timeout));
  parts.extensions.insert(DownstreamResponseTimeoutSelected(
    DownstreamResponseTimeoutSelection::MarkedOnly,
  ));
  Response::from_parts(parts, body)
}
