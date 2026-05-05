use bytes::Bytes;
use http_body_util::combinators::BoxBody;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ProxyBody = BoxBody<Bytes, BoxError>;

pub(crate) fn boxed_error<E>(error: E) -> BoxError
where
  E: std::error::Error + Send + Sync + 'static,
{
  Box::new(error)
}
