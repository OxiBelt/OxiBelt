use crate::metrics::fast_path::labels::FastPathTransportMissReason;

pub(super) fn direct_h1_transport_miss_reason(
  error: &anyhow::Error,
) -> FastPathTransportMissReason {
  match crate::upstream_failure::classify(error.as_ref()) {
    Some(
      crate::upstream_failure::UpstreamFailure::ConnectionTimeout
      | crate::upstream_failure::UpstreamFailure::ConnectionRefused,
    ) => FastPathTransportMissReason::ConnectError,
    Some(
      crate::upstream_failure::UpstreamFailure::HttpResponseTimeout
      | crate::upstream_failure::UpstreamFailure::ConnectionTerminated,
    ) => FastPathTransportMissReason::ResponseError,
    _ => FastPathTransportMissReason::SendError,
  }
}
