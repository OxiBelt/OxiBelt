use bytes::Bytes;
use http_body_util::combinators::BoxBody;

pub(super) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(super) type ProxyBody = BoxBody<Bytes, BoxError>;

pub(super) fn boxed_error(error: hyper::Error) -> BoxError {
  Box::new(error)
}
