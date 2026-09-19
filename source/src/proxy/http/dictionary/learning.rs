//! Bounded complete-body dictionary learning after policy evaluation.
use super::super::body::{BoxError, ProxyBody};
use crate::compression_dictionary::{
  fields::{self, UseAsDictionary},
  runtime::{DictionaryLearningReservation, DictionaryScope},
};
use crate::state::AppSnapshot;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::{
  future::Future,
  pin::Pin,
  sync::Mutex,
  task::{Context, Poll},
  time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(in crate::proxy::http) async fn attach(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  scope: &DictionaryScope,
  url: &url::Url,
) -> Response<ProxyBody> {
  let Some(profile) = state.compression_dictionary.profile(&scope.profile) else {
    return response;
  };
  if !profile.config.learn || response.status() != StatusCode::OK {
    return response;
  }
  let Some(fresh_until) = freshness(response.headers()) else {
    return response;
  };
  let Ok(Some(declaration)) = fields::parse_use_as_dictionary_header(response.headers(), url)
  else {
    return response;
  };
  if !declaration.is_supported() {
    return response;
  }
  let limit = profile.config.max_dictionary_bytes;
  if response
    .headers()
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok())
    .is_some_and(|size| size > limit)
  {
    return response;
  }
  let Ok(reservation) = state
    .compression_dictionary
    .begin_learning(&scope.profile, scope, limit)
    .await
  else {
    return response;
  };
  let (parts, body) = response.into_parts();
  Response::from_parts(
    parts,
    LearningBody {
      body,
      bytes: Vec::new(),
      limit,
      deadline: Instant::now()
        .checked_add(Duration::from_millis(profile.config.codec_timeout_ms))
        .unwrap_or_else(Instant::now),
      reservation: Some(reservation),
      declaration: Some(declaration),
      url: url.clone(),
      fresh_until,
      commit: Mutex::new(None),
      done: false,
    }
    .boxed(),
  )
}

pub(super) fn freshness(headers: &HeaderMap) -> Option<u64> {
  if headers.contains_key(http::header::SET_COOKIE)
    || headers.contains_key(http::header::TRAILER)
    || headers.contains_key(http::header::CONTENT_RANGE)
    || headers.contains_key(http::header::CONTENT_ENCODING)
  {
    return None;
  }
  let mut max_age = None;
  for value in headers.get_all(http::header::CACHE_CONTROL) {
    for directive in value.to_str().ok()?.split(',') {
      let (name, value) = directive
        .trim()
        .split_once('=')
        .map_or((directive.trim(), None), |(name, value)| {
          (name.trim(), Some(value.trim()))
        });
      if ["no-store", "private", "no-cache"]
        .iter()
        .any(|item| name.eq_ignore_ascii_case(item))
      {
        return None;
      }
      if name.eq_ignore_ascii_case("max-age") {
        if max_age.is_some() {
          return None;
        }
        max_age = Some(value?.trim_matches('"').parse::<u64>().ok()?);
      }
    }
  }
  let now = SystemTime::now();
  let date = httpdate::parse_http_date(headers.get(http::header::DATE)?.to_str().ok()?).ok()?;
  let age = headers
    .get(http::header::AGE)
    .map(|value| value.to_str().ok()?.parse::<u64>().ok())
    .unwrap_or(Some(0))?;
  let apparent_age = now
    .duration_since(date)
    .unwrap_or_default()
    .as_secs()
    .max(age);
  let remaining = max_age?.checked_sub(apparent_age)?;
  if remaining == 0 {
    return None;
  }
  u64::try_from(now.duration_since(UNIX_EPOCH).ok()?.as_millis())
    .ok()?
    .checked_add(remaining.checked_mul(1000)?)
}

type Commit = Pin<Box<dyn Future<Output = ()> + Send>>;
struct LearningBody {
  body: ProxyBody,
  bytes: Vec<u8>,
  limit: u64,
  deadline: Instant,
  reservation: Option<DictionaryLearningReservation>,
  declaration: Option<UseAsDictionary>,
  url: url::Url,
  fresh_until: u64,
  commit: Mutex<Option<Commit>>,
  done: bool,
}
impl Body for LearningBody {
  type Data = bytes::Bytes;
  type Error = BoxError;
  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.done {
      let Ok(mut commit) = self.commit.lock() else {
        return Poll::Ready(None);
      };
      if let Some(future) = commit.as_mut() {
        if future.as_mut().poll(cx).is_pending() {
          return Poll::Pending;
        }
        *commit = None;
      }
      return Poll::Ready(None);
    }
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Some(frame)) => {
        match &frame {
          Ok(frame) if self.reservation.is_some() => {
            if let Some(bytes) = frame.data_ref().filter(|bytes| {
              self.bytes.len().saturating_add(bytes.len()) as u64 <= self.limit
                && Instant::now() < self.deadline
            }) {
              self.bytes.extend_from_slice(bytes);
            } else {
              self.reservation = None;
              self.bytes = Vec::new();
            }
          }
          Err(_) => {
            self.reservation = None;
            self.bytes = Vec::new();
          }
          _ => {}
        }
        Poll::Ready(Some(frame))
      }
      Poll::Ready(None) => {
        self.done = true;
        if let (Some(reservation), Some(declaration)) =
          (self.reservation.take(), self.declaration.take())
        {
          let bytes = std::mem::take(&mut self.bytes);
          let url = self.url.clone();
          let until = self.fresh_until;
          let future: Commit = Box::pin(async move {
            let _ = reservation.commit(url, declaration, bytes, until).await;
          });
          if let Ok(mut slot) = self.commit.lock() {
            *slot = Some(future);
          }
        }
        self.poll_frame(cx)
      }
    }
  }
  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn learning_requires_explicit_fresh_public_response() {
    let mut headers = HeaderMap::new();
    headers.insert(
      http::header::DATE,
      http::HeaderValue::from_str(&httpdate::fmt_http_date(SystemTime::now())).unwrap(),
    );
    assert!(freshness(&headers).is_none());
    headers.insert(
      http::header::CACHE_CONTROL,
      http::HeaderValue::from_static("public, max-age=300"),
    );
    assert!(freshness(&headers).is_some());
    for value in [
      "private, max-age=300",
      "no-store, max-age=300",
      "no-cache, max-age=300",
      "max-age=300, max-age=600",
    ] {
      headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_str(value).unwrap(),
      );
      assert!(freshness(&headers).is_none(), "{value}");
    }
    headers.insert(
      http::header::CACHE_CONTROL,
      http::HeaderValue::from_static("max-age=300"),
    );
    headers.insert(http::header::AGE, http::HeaderValue::from_static("300"));
    assert!(freshness(&headers).is_none());
    headers.remove(http::header::AGE);
    headers.insert(
      http::header::SET_COOKIE,
      http::HeaderValue::from_static("session=private"),
    );
    assert!(freshness(&headers).is_none());
  }
}
