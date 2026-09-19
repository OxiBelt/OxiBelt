use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use hyper::body::{Body, Frame, SizeHint};
use sha2::{Digest as _, Sha256, Sha512};

use super::{
  Algorithm, BoxError, Field, ProxyBody, UNENCODED_DIGEST, digest_value, header_map_bytes,
};

pub(super) struct DigestBody {
  body: ProxyBody,
  fields: Vec<Field>,
  sha256: Option<Sha256>,
  sha512: Option<Sha512>,
  trailers: Option<HeaderMap>,
  saw_trailers: bool,
  clean_eof: bool,
  emitted: bool,
}

impl DigestBody {
  pub(super) fn new(body: ProxyBody, fields: Vec<Field>) -> Self {
    let sha256 = fields
      .iter()
      .any(|field| field.needs_downstream_hash(Algorithm::Sha256));
    let sha512 = fields
      .iter()
      .any(|field| field.needs_downstream_hash(Algorithm::Sha512));
    Self {
      body,
      fields,
      sha256: sha256.then(Sha256::new),
      sha512: sha512.then(Sha512::new),
      trailers: None,
      saw_trailers: false,
      clean_eof: false,
      emitted: false,
    }
  }

  fn value(&self, algorithm: Algorithm) -> Option<String> {
    match algorithm {
      Algorithm::Sha256 => Some(digest_value(
        algorithm,
        self.sha256.clone()?.finalize().as_slice(),
      )),
      Algorithm::Sha512 => Some(digest_value(
        algorithm,
        self.sha512.clone()?.finalize().as_slice(),
      )),
    }
  }

  fn final_trailers(&self) -> Option<HeaderMap> {
    let mut trailers = self.trailers.clone().unwrap_or_default();
    let mut generated = HeaderMap::new();
    for field in &self.fields {
      if trailers.contains_key(field.name()) {
        continue;
      }
      match field {
        Field::Unencoded {
          state: Some(state), ..
        } if !state.source().is_empty() => {
          for value in state.source() {
            trailers.append(HeaderName::from_static(UNENCODED_DIGEST), value);
          }
        }
        Field::Unencoded {
          algorithm: Some(algorithm),
          state: Some(state),
        } => {
          let Some(value) = state.digest(*algorithm) else {
            continue;
          };
          generated.append(
            HeaderName::from_static(UNENCODED_DIGEST),
            HeaderValue::from_str(&value).ok()?,
          );
        }
        Field::Unencoded {
          algorithm: Some(algorithm),
          state: None,
        } => {
          let value = self.value(*algorithm)?;
          generated.append(
            HeaderName::from_static(UNENCODED_DIGEST),
            HeaderValue::from_str(&value).ok()?,
          );
        }
        Field::Unencoded {
          algorithm: None, ..
        } => {}
        _ => {
          let algorithm = field.algorithm()?;
          let value = self.value(algorithm)?;
          generated.append(
            HeaderName::from_static(field.name()),
            HeaderValue::from_str(&value).ok()?,
          );
        }
      }
    }
    if header_map_bytes(&trailers).saturating_add(header_map_bytes(&generated))
      <= super::MAX_FIELD_BYTES
    {
      trailers.extend(generated);
    }
    (!trailers.is_empty()).then_some(trailers)
  }
}

impl Body for DigestBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    loop {
      if self.emitted {
        return Poll::Ready(None);
      }
      if self.clean_eof {
        self.emitted = true;
        return Poll::Ready(
          self
            .final_trailers()
            .map(|trailers| Ok(Frame::trailers(trailers))),
        );
      }
      match Pin::new(&mut self.body).poll_frame(cx) {
        Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
          Ok(data) => {
            if self.saw_trailers {
              self.emitted = true;
              return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                "body contains data after trailers",
              )))));
            }
            if let Some(hash) = &mut self.sha256 {
              hash.update(&data);
            }
            if let Some(hash) = &mut self.sha512 {
              hash.update(&data);
            }
            return Poll::Ready(Some(Ok(Frame::data(data))));
          }
          Err(frame) => match frame.into_trailers() {
            Ok(trailers) => {
              if self.saw_trailers {
                self.emitted = true;
                return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                  "body contains multiple trailer frames",
                )))));
              }
              self.saw_trailers = true;
              self.trailers = Some(trailers);
              continue;
            }
            Err(frame) => return Poll::Ready(Some(Ok(frame))),
          },
        },
        Poll::Ready(Some(Err(error))) => {
          self.emitted = true;
          return Poll::Ready(Some(Err(error)));
        }
        Poll::Ready(None) => {
          self.clean_eof = true;
          continue;
        }
        Poll::Pending => return Poll::Pending,
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    self.emitted
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}
