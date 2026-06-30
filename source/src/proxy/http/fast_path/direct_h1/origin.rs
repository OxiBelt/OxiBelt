use http::HeaderValue;
use url::{Position, Url};

pub(super) struct DirectH1Origin {
  pub(super) host: String,
  pub(super) port: u16,
  pub(super) authority_header: HeaderValue,
}

impl DirectH1Origin {
  pub(super) fn from_url(origin: &Url) -> Option<Self> {
    if origin.scheme() != "http" {
      return None;
    }
    let host = origin.host_str()?.to_owned();
    let port = origin.port_or_known_default()?;
    let authority = match origin.port() {
      Some(_) => origin[Position::BeforeHost..Position::AfterPort].to_owned(),
      None => host.clone(),
    };
    let authority_header = HeaderValue::from_str(&authority).ok()?;
    Some(Self {
      host,
      port,
      authority_header,
    })
  }
}
