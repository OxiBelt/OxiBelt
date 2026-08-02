#[cfg(test)]
use bytes::Bytes;
use http::Request;
#[cfg(test)]
use http_body_util::{BodyExt, Empty};

#[cfg(test)]
use crate::proxy::http::body::BoxError;
use crate::proxy::http::body::ProxyBody;

pub(super) struct PreparedDirectH2Request {
  pub(super) request: Request<ProxyBody>,
  fallback_version: http::Version,
}

impl PreparedDirectH2Request {
  pub(super) fn from_request(mut request: Request<ProxyBody>) -> anyhow::Result<Self> {
    if request.uri().scheme().is_none() || request.uri().authority().is_none() {
      anyhow::bail!("direct H2 request URI must be absolute-form");
    }
    let fallback_version = request.version();
    *request.version_mut() = http::Version::HTTP_2;
    Ok(Self {
      request,
      fallback_version,
    })
  }

  pub(super) fn into_parts(self) -> (Request<ProxyBody>, http::Version) {
    (self.request, self.fallback_version)
  }

  #[cfg(test)]
  pub(super) fn into_fallback_request(mut self) -> Request<ProxyBody> {
    *self.request.version_mut() = self.fallback_version;
    self.request
  }
}

pub(super) fn restore_fallback_version(
  mut request: Request<ProxyBody>,
  fallback_version: http::Version,
) -> Request<ProxyBody> {
  *request.version_mut() = fallback_version;
  request
}

#[cfg(test)]
pub(super) fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}
