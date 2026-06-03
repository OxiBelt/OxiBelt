//! Response body tee for disk-backed streaming cache fills.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use crate::cache::{CacheFillGuard, CacheInsertContext, CacheStreamingInsert};
use crate::config::{Config, RouteConfig};
use crate::state::AppSnapshot;

use super::body::{BoxError, ProxyBody};
use super::cache_status::{
  self, CacheHeaderOutcome as CacheOutcome, CacheHeaderReason as CacheReason,
};

struct CacheStreamingBody {
  body: ProxyBody,
  insert: Option<CacheStreamingInsert>,
}

pub(super) fn cache_streaming_body(body: ProxyBody, insert: CacheStreamingInsert) -> ProxyBody {
  CacheStreamingBody {
    body,
    insert: Some(insert),
  }
  .boxed()
}

pub(super) fn exact_response_content_length(headers: &HeaderMap) -> Option<usize> {
  let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
  let value = values.next()?;
  if values.next().is_some() {
    return None;
  }
  value.to_str().ok()?.trim().parse().ok()
}

pub(super) fn response_collect_limit(config: &Config) -> usize {
  config
    .cache
    .max_size_bytes
    .min(config.proxy.buffering.max_memory_body_bytes)
}

pub(super) fn exact_body_size_hint_len(size_hint: &SizeHint) -> Option<usize> {
  let upper = size_hint.upper()?;
  (size_hint.lower() == upper).then(|| usize::try_from(upper).ok())?
}

#[allow(clippy::too_many_arguments)]
pub(super) fn maybe_stream_cache_response(
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
  route: Option<&RouteConfig>,
  parts: http::response::Parts,
  body: ProxyBody,
  prepared: Box<crate::cache::CachePreparedInsert>,
  expected_body_len: usize,
  cache_fill_guard: Option<CacheFillGuard>,
) -> Result<Response<ProxyBody>, Box<(http::response::Parts, ProxyBody)>> {
  let stream_started = Instant::now();
  match state
    .cache
    .begin_streaming_insert(*prepared, expected_body_len, cache_fill_guard)
  {
    crate::cache::CacheStreamingInsertDecision::Started(insert) => {
      record_fill_stage(state, route, "body_stream", "started", stream_started);
      Ok(streaming_response(state, route_cache, parts, body, insert))
    }
    crate::cache::CacheStreamingInsertDecision::Rejected(outcome) => {
      let reason = match outcome {
        crate::cache::CacheInsertOutcome::AdmissionWarming => {
          record_fill_stage(
            state,
            route,
            "local_store",
            "admission_warming",
            stream_started,
          );
          state.metrics.record_cache_admission_rejection();
          CacheReason::AdmissionWarming
        }
        crate::cache::CacheInsertOutcome::StoreFailed => {
          record_fill_stage(state, route, "local_store", "store_failed", stream_started);
          state.metrics.record_cache_fill_error();
          state.cache.note_fill_not_stored_reason(
            insert_ctx(route_cache, scheme, host, method, uri, request_headers),
            crate::cache::CacheFillSuppressionReason::StoreFailed,
          );
          CacheReason::StoreFailed
        }
        crate::cache::CacheInsertOutcome::Rejected => {
          record_fill_stage(state, route, "local_store", "rejected", stream_started);
          state.metrics.record_cache_admission_rejection();
          state.cache.note_fill_not_stored_reason(
            insert_ctx(route_cache, scheme, host, method, uri, request_headers),
            crate::cache::CacheFillSuppressionReason::AdmissionRejected,
          );
          CacheReason::AdmissionRejected
        }
        crate::cache::CacheInsertOutcome::NotCacheable => {
          record_fill_stage(state, route, "local_store", "not_cacheable", stream_started);
          state.cache.note_fill_not_stored(insert_ctx(
            route_cache,
            scheme,
            host,
            method,
            uri,
            request_headers,
          ));
          CacheReason::NotCacheable
        }
        crate::cache::CacheInsertOutcome::Stored => CacheReason::Stored,
      };
      Ok(streaming_rejection_response(
        state,
        route_cache,
        parts,
        body,
        reason,
      ))
    }
    crate::cache::CacheStreamingInsertDecision::NotEligible => Err(Box::new((parts, body))),
  }
}

impl Body for CacheStreamingBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let poll = Pin::new(&mut self.body).poll_frame(cx);
    let finished = matches!(&poll, Poll::Ready(None));
    match &poll {
      Poll::Ready(Some(Ok(frame))) => {
        if let Some(data) = frame.data_ref()
          && let Some(insert) = &mut self.insert
          && !insert.write_data(data.clone())
        {
          self.insert = None;
        }
      }
      Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
        if let Some(mut insert) = self.insert.take()
          && finished
        {
          insert.finish();
        }
      }
      Poll::Pending => {}
    }
    poll
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

fn streaming_response(
  state: &AppSnapshot,
  route_cache: Option<&str>,
  mut parts: http::response::Parts,
  body: ProxyBody,
  insert: CacheStreamingInsert,
) -> Response<ProxyBody> {
  strip_surrogate_control_if_needed(state, route_cache, &mut parts.headers);
  let mut response = Response::from_parts(parts, cache_streaming_body(body, insert));
  cache_status::apply(&mut response, CacheOutcome::Miss, CacheReason::Stored);
  response
}

fn streaming_rejection_response(
  state: &AppSnapshot,
  route_cache: Option<&str>,
  mut parts: http::response::Parts,
  body: ProxyBody,
  reason: CacheReason,
) -> Response<ProxyBody> {
  strip_surrogate_control_if_needed(state, route_cache, &mut parts.headers);
  let mut response = Response::from_parts(parts, body);
  cache_status::apply(&mut response, CacheOutcome::Miss, reason);
  response
}

fn strip_surrogate_control_if_needed(
  state: &AppSnapshot,
  route_cache: Option<&str>,
  headers: &mut HeaderMap,
) {
  if state.cache.strip_surrogate_control(route_cache) {
    headers.remove("surrogate-control");
  }
}

fn record_fill_stage(
  state: &AppSnapshot,
  route: Option<&RouteConfig>,
  stage: &str,
  outcome: &str,
  started: Instant,
) {
  if let Some(route) = route {
    super::record_route_cache_fill_stage(state, route, stage, outcome, started);
  }
}

fn insert_ctx<'a>(
  route_cache: Option<&'a str>,
  scheme: &'a str,
  host: &'a str,
  method: &'a Method,
  uri: &'a http::Uri,
  request_headers: &'a HeaderMap,
) -> CacheInsertContext<'a> {
  CacheInsertContext {
    policy_name: route_cache,
    scheme,
    host,
    method,
    uri,
    request_headers,
  }
}
