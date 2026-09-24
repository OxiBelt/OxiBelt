//! Bounded request Content-Digest validation with lossless frame replay.
// sfv visitor implementations constrain associated output/error types more
// tightly than the public visitor trait's return-position impl Trait bounds.
#![allow(refining_impl_trait_internal)]

use std::{
  collections::VecDeque,
  convert::Infallible,
  pin::Pin,
  task::{Context, Poll},
  time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Request};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use sfv::visitor::{DictionaryVisitor, EntryVisitor, Ignored, ItemVisitor, ParameterVisitor};
use sfv::{BareItemFromInput, KeyRef, Parser};
use sha2::{Digest, Sha256, Sha512};

use crate::proxy::http::body::{BoxError, ProxyBody};

const MAX_DIGEST_FIELD_BYTES: usize = 4096;
const MAX_DIGEST_MEMBERS: usize = 16;
const MAX_BODY_FRAMES: usize = 4096;
const INSPECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct DigestValues {
  sha256: Option<Vec<u8>>,
  sha512: Option<Vec<u8>>,
  members: usize,
  invalid: bool,
}

struct DigestEntry<'a> {
  name: String,
  out: &'a mut DigestValues,
}
struct DigestItem<'a> {
  name: String,
  out: &'a mut DigestValues,
}
struct DigestParams<'a> {
  name: String,
  value: Option<Vec<u8>>,
  out: &'a mut DigestValues,
}

impl<'de> DictionaryVisitor<'de> for DigestValues {
  type Out = Self;
  type Error = Infallible;
  fn entry(
    &mut self,
    key: &'de KeyRef,
  ) -> Result<impl EntryVisitor<'de, Error = Self::Error>, Self::Error> {
    self.members += 1;
    Ok(DigestEntry {
      name: key.as_str().to_owned(),
      out: self,
    })
  }
  fn finish(self) -> Result<Self, Self::Error> {
    Ok(self)
  }
}
impl<'de> EntryVisitor<'de> for DigestEntry<'_> {
  type Error = Infallible;
  fn item(self) -> Result<impl ItemVisitor<'de, Error = Self::Error>, Self::Error> {
    Ok(DigestItem {
      name: self.name,
      out: self.out,
    })
  }
  fn inner_list(
    self,
  ) -> Result<impl sfv::visitor::InnerListVisitor<'de, Error = Self::Error>, Self::Error> {
    self.out.invalid = true;
    Ok(Ignored)
  }
}
impl<'de> ItemVisitor<'de> for DigestItem<'_> {
  type Out = ();
  type Error = Infallible;
  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = (), Error = Self::Error>, Self::Error> {
    let value = if let BareItemFromInput::ByteSequence(value) = item {
      Some(value)
    } else {
      None
    };
    Ok(DigestParams {
      name: self.name,
      value,
      out: self.out,
    })
  }
}
impl<'de> ParameterVisitor<'de> for DigestParams<'_> {
  type Out = ();
  type Error = Infallible;
  fn parameter(
    &mut self,
    _key: &'de KeyRef,
    _value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    self.out.invalid = true;
    Ok(())
  }
  fn finish(self) -> Result<(), Self::Error> {
    let Some(value) = self.value else {
      self.out.invalid = true;
      return Ok(());
    };
    let duplicate = match self.name.as_str() {
      "sha-256" => self.out.sha256.replace(value).is_some(),
      "sha-512" => self.out.sha512.replace(value).is_some(),
      _ => false,
    };
    self.out.invalid |= duplicate;
    Ok(())
  }
}

fn expected(headers: &HeaderMap) -> Option<DigestValues> {
  let mut input = Vec::new();
  let mut found = false;
  for value in headers.get_all("content-digest") {
    if found {
      input.extend_from_slice(b", ");
    }
    found = true;
    input.extend_from_slice(value.as_bytes());
    if input.len() > MAX_DIGEST_FIELD_BYTES {
      return None;
    }
  }
  if !found {
    return None;
  }
  let parsed = Parser::new(&input)
    .with_version(sfv::Version::Rfc8941)
    .parse_dictionary_with_visitor(DigestValues::default())
    .ok()?;
  if parsed.invalid
    || parsed.members == 0
    || parsed.members > MAX_DIGEST_MEMBERS
    || parsed.sha256.as_ref().is_some_and(|v| v.len() != 32)
    || parsed.sha512.as_ref().is_some_and(|v| v.len() != 64)
    || parsed.sha256.is_none() && parsed.sha512.is_none()
  {
    return None;
  }
  Some(parsed)
}

struct ReplayBody<B> {
  queued: VecDeque<Result<Frame<Bytes>, BoxError>>,
  inner: Pin<Box<B>>,
}
impl<B> Body for ReplayBody<B>
where
  B: Body<Data = Bytes>,
  B::Error: Into<BoxError>,
{
  type Data = Bytes;
  type Error = BoxError;
  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    if let Some(frame) = self.queued.pop_front() {
      return Poll::Ready(Some(frame));
    }
    self
      .inner
      .as_mut()
      .poll_frame(cx)
      .map(|frame| frame.map(|result| result.map_err(Into::into)))
  }
  fn is_end_stream(&self) -> bool {
    self.queued.is_empty() && self.inner.is_end_stream()
  }
  fn size_hint(&self) -> SizeHint {
    SizeHint::default()
  }
}

/// Validate all supported digest members over the complete decoded body.
/// On a read error or over-bound body, verification is false and every consumed
/// frame (including trailers or the error) is replayed before the remaining body.
pub(crate) async fn inspect<B>(request: Request<B>, max_bytes: usize) -> (Request<ProxyBody>, bool)
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
  let expected = expected(request.headers());
  let (parts, body) = request.into_parts();
  let Some(expected) = expected else {
    return (
      Request::from_parts(
        parts,
        body.map_err(|error| -> BoxError { error.into() }).boxed(),
      ),
      false,
    );
  };
  let mut inner = Box::pin(body);
  let mut queued = VecDeque::new();
  let mut sha256 = Sha256::new();
  let mut sha512 = Sha512::new();
  let mut bytes = 0usize;
  let mut complete = false;
  let mut failed = false;
  let mut frames = 0usize;
  let deadline = tokio::time::Instant::now() + INSPECTION_TIMEOUT;
  loop {
    if frames == MAX_BODY_FRAMES {
      failed = true;
      break;
    }
    let frame = match tokio::time::timeout_at(deadline, inner.as_mut().frame()).await {
      Ok(frame) => frame,
      Err(_) => {
        failed = true;
        break;
      }
    };
    let Some(frame) = frame else {
      complete = true;
      break;
    };
    frames += 1;
    match frame {
      Ok(frame) => {
        if let Some(data) = frame.data_ref() {
          bytes = bytes.saturating_add(data.len());
          if bytes <= max_bytes {
            sha256.update(data);
            sha512.update(data);
          } else {
            failed = true;
            queued.push_back(Ok(frame));
            break;
          }
        }
        queued.push_back(Ok(frame));
      }
      Err(error) => {
        queued.push_back(Err(error.into()));
        failed = true;
        break;
      }
    }
  }
  let valid = complete
    && !failed
    && expected
      .sha256
      .as_ref()
      .is_none_or(|value| Sha256::finalize(sha256).as_slice() == value.as_slice())
    && expected
      .sha512
      .as_ref()
      .is_none_or(|value| Sha512::finalize(sha512).as_slice() == value.as_slice());
  let replay = ReplayBody { queued, inner }.boxed();
  (Request::from_parts(parts, replay), valid)
}

#[cfg(test)]
mod tests {
  use super::*;
  use futures_util::stream;
  use http_body_util::{Full, StreamBody};

  #[tokio::test]
  async fn matching_digest_replays_body() {
    let request = Request::builder()
      .header(
        "content-digest",
        "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:",
      )
      .body(Full::new(Bytes::from_static(b"hello")))
      .unwrap();
    let (request, valid) = inspect(request, 5).await;
    assert!(valid);
    assert_eq!(
      request.into_body().collect().await.unwrap().to_bytes(),
      Bytes::from_static(b"hello")
    );
  }

  #[tokio::test]
  async fn over_bound_is_false_and_replays_trailers() {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-end", "yes".parse().unwrap());
    let frames: Vec<Result<_, Infallible>> = vec![
      Ok(Frame::data(Bytes::from_static(b"hello"))),
      Ok(Frame::trailers(trailers)),
    ];
    let request = Request::builder()
      .header(
        "content-digest",
        "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:",
      )
      .body(StreamBody::new(stream::iter(frames)))
      .unwrap();
    let (request, valid) = inspect(request, 4).await;
    assert!(!valid);
    let collected = request.into_body().collect().await.unwrap();
    assert_eq!(collected.trailers().unwrap()["x-end"], "yes");
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"hello"));
  }
}
