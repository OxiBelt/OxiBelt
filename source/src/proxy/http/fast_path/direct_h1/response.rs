use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::client::conn::http1::SendRequest;

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::DirectH1PoolEvent;
use crate::proxy::http::body::{BoxError, ProxyBody};

use super::{DirectH1Pool, DirectH1PutError};

pub(in crate::proxy::http::fast_path) struct DirectH1Response {
  pub(in crate::proxy::http::fast_path) response: Response<ProxyBody>,
  pub(super) lease: Option<DirectH1Lease>,
}

impl DirectH1Response {
  pub(in crate::proxy::http::fast_path) fn take_lease(&mut self) -> Option<DirectH1Lease> {
    self.lease.take()
  }
}

pub(in crate::proxy::http::fast_path) struct DirectH1Lease {
  pub(super) pool: Arc<DirectH1Pool>,
  pub(super) metrics: Arc<Metrics>,
  pub(super) sender: SendRequest<ProxyBody>,
  pub(super) diagnostic_metrics: bool,
  pub(super) reusable_by_headers: bool,
}

impl DirectH1Lease {
  pub(super) fn recycle_if_reusable(self, body_consumed: bool) {
    if body_consumed && self.reusable_by_headers {
      if let Err(error) = self.pool.put_sender(self.sender)
        && self.diagnostic_metrics
      {
        self
          .metrics
          .record_direct_h1_pool_event_id(DirectH1PoolEvent::Drop);
        match error {
          DirectH1PutError::Full => self
            .metrics
            .record_direct_h1_pool_event_id(DirectH1PoolEvent::DropFull),
          DirectH1PutError::Locked => self
            .metrics
            .record_direct_h1_pool_event_id(DirectH1PoolEvent::DropLocked),
        }
      }
    } else if self.diagnostic_metrics {
      self
        .metrics
        .record_direct_h1_pool_event_id(DirectH1PoolEvent::Drop);
    }
  }
}

pub(in crate::proxy::http::fast_path) fn recycle_response_body(
  body: ProxyBody,
  lease: DirectH1Lease,
  body_consumed: bool,
) -> ProxyBody {
  if body_consumed {
    lease.recycle_if_reusable(true);
    return body;
  }
  recycle_body_on_eof(body, lease)
}

fn recycle_body_on_eof(body: ProxyBody, lease: DirectH1Lease) -> ProxyBody {
  DirectH1RecycleBody {
    body,
    lease: Some(lease),
  }
  .boxed()
}

struct DirectH1RecycleBody {
  body: ProxyBody,
  lease: Option<DirectH1Lease>,
}

impl DirectH1RecycleBody {
  fn recycle(&mut self, body_consumed: bool) {
    if let Some(lease) = self.lease.take() {
      lease.recycle_if_reusable(body_consumed);
    }
  }
}

impl Body for DirectH1RecycleBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(None) => {
        self.recycle(true);
        Poll::Ready(None)
      }
      Poll::Ready(Some(Err(error))) => {
        self.recycle(false);
        Poll::Ready(Some(Err(error)))
      }
      poll => poll,
    }
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> hyper::body::SizeHint {
    self.body.size_hint()
  }
}

impl Drop for DirectH1RecycleBody {
  fn drop(&mut self) {
    self.recycle(false);
  }
}
