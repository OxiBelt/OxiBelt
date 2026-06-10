use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use super::super::body::{self, ProxyBody};

struct PollCountingBody {
  data: Option<Bytes>,
  poll_count: Arc<AtomicUsize>,
}

impl Body for PollCountingBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _context: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let this = self.get_mut();
    this.poll_count.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(this.data.take().map(|data| Ok(Frame::data(data))))
  }

  fn size_hint(&self) -> SizeHint {
    let mut hint = SizeHint::new();
    let len = self.data.as_ref().map(Bytes::len).unwrap_or(0);
    hint.set_exact(len as u64);
    hint
  }
}

pub(super) fn counted_body(bytes: Bytes, poll_count: Arc<AtomicUsize>) -> ProxyBody {
  PollCountingBody {
    data: Some(bytes),
    poll_count,
  }
  .boxed()
}
