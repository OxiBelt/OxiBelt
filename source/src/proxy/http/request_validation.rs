//! Request framing, header, URI, and body-size validation.

use super::*;

pub(crate) fn validate_request_limits<B>(
  request: &Request<B>,
  limits: &crate::config::LimitsConfig,
) -> Result<(), (StatusCode, &'static str)> {
  if uri_wire_len(request.uri()) > limits.max_uri_bytes {
    return Err((StatusCode::URI_TOO_LONG, "request URI is too large"));
  }
  if request.headers().len() > limits.max_headers {
    return Err((
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
      "too many headers",
    ));
  }
  let mut total = 0usize;
  for (name, value) in request.headers() {
    if name.as_str().len() > limits.max_header_name_bytes {
      return Err((
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "header name is too large",
      ));
    }
    if value.as_bytes().len() > limits.max_header_value_bytes {
      return Err((
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "header value is too large",
      ));
    }
    total += name.as_str().len() + value.as_bytes().len();
  }
  if total > limits.max_total_header_bytes {
    return Err((
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
      "headers are too large",
    ));
  }
  match request_body_framing(request.headers()) {
    RequestBodyFraming::Ambiguous => {
      return Err((StatusCode::BAD_REQUEST, "ambiguous request body framing"));
    }
    RequestBodyFraming::InvalidContentLength => {
      return Err((StatusCode::BAD_REQUEST, "invalid request body framing"));
    }
    _ => {}
  }
  Ok(())
}

pub(crate) fn validate_request_body_size_limit<B>(
  request: &Request<B>,
  max_request_body_bytes: u64,
) -> Result<(), (StatusCode, &'static str)> {
  if positive_content_length(request.headers())
    .is_some_and(|length| length > max_request_body_bytes)
  {
    return Err((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"));
  }
  Ok(())
}

pub(super) fn uri_wire_len(uri: &http::Uri) -> usize {
  let mut len = 0usize;
  let has_scheme = uri.scheme_str().is_some();
  if let Some(scheme) = uri.scheme_str() {
    len += scheme.len() + 1;
  }
  if let Some(authority) = uri.authority() {
    if has_scheme {
      len += 2;
    }
    len += authority.as_str().len();
  }
  if let Some(path_and_query) = uri.path_and_query() {
    len += path_and_query.as_str().len();
  }
  len
}

pub(super) async fn reject_content_length_zero_data<B>(
  request: Request<B>,
  timeout: Duration,
  version: http::Version,
) -> Result<Request<Either<B, ProxyBody>>, Response<ProxyBody>>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + Unpin + 'static,
{
  if !h2_or_h3_content_length_zero_guard_required(version, request.headers()) {
    let (parts, body) = request.into_parts();
    return Ok(Request::from_parts(parts, Either::Left(body)));
  }

  let request = request.map(|body| body.map_err(Into::into).boxed());
  let (parts, body) = request.into_parts();
  let mut body = body::with_read_timeout(body, timeout, BodyTimeoutKind::DownstreamRequestRead);
  while let Some(frame) = body.frame().await {
    let frame = match frame {
      Ok(frame) => frame,
      Err(error) => {
        if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          return Err(text_response(
            StatusCode::REQUEST_TIMEOUT,
            "request body timed out",
          ));
        }
        warn!(error = %error, "failed to read Content-Length: 0 request body");
        return Err(text_response(
          StatusCode::BAD_REQUEST,
          "failed to read request body",
        ));
      }
    };
    if frame.data_ref().is_some_and(|data| !data.is_empty()) {
      return Err(text_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "request body is too large",
      ));
    }
  }

  let mut request = Request::from_parts(parts, Either::Right(full_body(bytes::Bytes::new())));
  request
    .extensions_mut()
    .insert(VerifiedContentLengthZeroBody);
  Ok(request)
}
