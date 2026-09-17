//! Live informational-response relaying shared by HTTP/1.1, HTTP/2, and HTTP/3.

use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

use http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING, UPGRADE};
use http::{Extensions, HeaderMap, Response, StatusCode};
use tokio::sync::mpsc;

const MAX_RESPONSES: usize = hyper::ext::MAX_INFORMATIONAL_RESPONSES;
const MAX_HEADER_BYTES: usize = hyper::ext::MAX_INFORMATIONAL_HEADER_BYTES;
const UPLOAD_DRAFT_INTEROP_VERSION: &str = "upload-draft-interop-version";

/// Whether a request explicitly opts into draft-12 / interop-9 104 handling.
///
/// A duplicate, malformed, missing, or different Structured Fields integer is
/// deliberately not a candidate. The caller must retain the original request
/// headers through the upstream exchange and must never infer this from a
/// response alone.
pub(crate) fn candidate(headers: &HeaderMap) -> bool {
  super::managed_upload::compatible_interop(headers)
}

/// Immutable evidence that the original downstream request negotiated
/// interop-9. Header mutations later in the pipeline cannot create it.
#[derive(Clone, Copy, Debug)]
struct ClientInterop;

/// Capture transport and replay-relevant request facts before WAF or route
/// transformations can modify the headers. HTTP/3 has already installed its
/// emitter when this runs; HTTP/1.1 and HTTP/2 expose Hyper's sender directly.
pub(crate) fn latch_request<B>(request: &mut http::Request<B>) {
  let negotiated = candidate(request.headers());
  let resumable_header = [
    "upload-complete",
    "upload-offset",
    "upload-length",
    UPLOAD_DRAFT_INTEROP_VERSION,
  ]
  .into_iter()
  .any(|name| request.headers().contains_key(name));
  if negotiated {
    request.extensions_mut().insert(ClientInterop);
  }
  if resumable_header {
    request
      .extensions_mut()
      .insert(super::resumable::NoReplayRequest);
  }
  if request.extensions().get::<Emitter>().is_none()
    && let Some(sender) = request
      .extensions()
      .get::<hyper::ext::InformationalSender>()
      .cloned()
  {
    request.extensions_mut().insert(Emitter::Hyper(sender));
  }
}

/// Whether the immutable downstream negotiation latch is present.
pub(crate) fn negotiated(extensions: &Extensions) -> bool {
  extensions.get::<ClientInterop>().is_some()
}

/// Whether a received 104 advertises the same draft interop version.
pub(crate) fn compatible_104(headers: &HeaderMap) -> bool {
  candidate(headers)
}

#[derive(Clone)]
pub(crate) enum Emitter {
  Hyper(hyper::ext::InformationalSender),
  H3(H3Sender),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendError {
  MissingEmitter,
  InvalidStatus,
  ForbiddenHeader,
  HeaderTooLarge,
  Full,
  Closed,
}

impl From<hyper::ext::InformationalSendError> for SendError {
  fn from(error: hyper::ext::InformationalSendError) -> Self {
    match error {
      hyper::ext::InformationalSendError::InvalidStatus => Self::InvalidStatus,
      hyper::ext::InformationalSendError::ForbiddenHeader => Self::ForbiddenHeader,
      hyper::ext::InformationalSendError::HeaderTooLarge => Self::HeaderTooLarge,
      hyper::ext::InformationalSendError::Full => Self::Full,
      hyper::ext::InformationalSendError::Closed => Self::Closed,
    }
  }
}

/// Send a live informational response through the request's downstream transport.
///
/// The operation never waits for network I/O. Callers must abort the exchange
/// on an error so an upstream 104 is neither silently dropped nor reordered.
pub(crate) fn send(extensions: &Extensions, response: Response<()>) -> Result<(), SendError> {
  extensions
    .get::<Emitter>()
    .ok_or(SendError::MissingEmitter)
    .and_then(|emitter| send_via(emitter, response))
}

/// Send through a previously cloned request-local emitter.
///
/// Upstream HTTP/3 splits its request stream, so it retains this clone while
/// concurrently receiving upstream interim responses and sending the body.
pub(crate) fn send_via(emitter: &Emitter, response: Response<()>) -> Result<(), SendError> {
  match emitter {
    Emitter::Hyper(sender) => sender.try_send(response).map_err(Into::into),
    Emitter::H3(sender) => sender.try_send(response),
  }
}

/// Install the HTTP/3 half of the request-local informational bridge.
pub(crate) fn install_h3(extensions: &mut Extensions) -> H3Receiver {
  let state = Arc::new(H3QueueState {
    queued_header_bytes: AtomicUsize::new(0),
  });
  let (tx, rx) = mpsc::channel(MAX_RESPONSES);
  extensions.insert(Emitter::H3(H3Sender {
    tx,
    state: state.clone(),
  }));
  H3Receiver { rx, state }
}

#[derive(Clone)]
pub(crate) struct H3Sender {
  tx: mpsc::Sender<QueuedResponse>,
  state: Arc<H3QueueState>,
}

struct H3QueueState {
  queued_header_bytes: AtomicUsize,
}

struct QueuedResponse {
  response: Response<()>,
  header_bytes: usize,
}

pub(crate) struct H3Receiver {
  rx: mpsc::Receiver<QueuedResponse>,
  state: Arc<H3QueueState>,
}

impl H3Sender {
  fn try_send(&self, response: Response<()>) -> Result<(), SendError> {
    let header_bytes = validate_response(&response)?;
    if !self.reserve_header_bytes(header_bytes) {
      return Err(SendError::HeaderTooLarge);
    }
    match self.tx.try_send(QueuedResponse {
      response,
      header_bytes,
    }) {
      Ok(()) => Ok(()),
      Err(error) => {
        self.release_header_bytes(header_bytes);
        match error {
          mpsc::error::TrySendError::Full(_) => Err(SendError::Full),
          mpsc::error::TrySendError::Closed(_) => Err(SendError::Closed),
        }
      }
    }
  }

  fn reserve_header_bytes(&self, bytes: usize) -> bool {
    let mut current = self.state.queued_header_bytes.load(Ordering::Relaxed);
    loop {
      let Some(next) = current.checked_add(bytes) else {
        return false;
      };
      if next > MAX_HEADER_BYTES {
        return false;
      }
      match self.state.queued_header_bytes.compare_exchange_weak(
        current,
        next,
        Ordering::AcqRel,
        Ordering::Relaxed,
      ) {
        Ok(_) => return true,
        Err(observed) => current = observed,
      }
    }
  }

  fn release_header_bytes(&self, bytes: usize) {
    self
      .state
      .queued_header_bytes
      .fetch_sub(bytes, Ordering::AcqRel);
  }
}

impl H3Receiver {
  /// Drain a queued response without waiting. This is used immediately before
  /// the final downstream HTTP/3 response so a same-poll 104 is not lost.
  pub(crate) fn try_recv(&mut self) -> Option<Response<()>> {
    let queued = self.rx.try_recv().ok()?;
    self
      .state
      .queued_header_bytes
      .fetch_sub(queued.header_bytes, Ordering::AcqRel);
    Some(queued.response)
  }

  pub(crate) async fn recv(&mut self) -> Option<Response<()>> {
    let queued = self.rx.recv().await?;
    self
      .state
      .queued_header_bytes
      .fetch_sub(queued.header_bytes, Ordering::AcqRel);
    Some(queued.response)
  }
}

fn validate_response(response: &Response<()>) -> Result<usize, SendError> {
  if !response.status().is_informational() || response.status() == StatusCode::SWITCHING_PROTOCOLS {
    return Err(SendError::InvalidStatus);
  }
  if response.headers().contains_key(CONNECTION)
    || response.headers().contains_key(CONTENT_LENGTH)
    || response.headers().contains_key(TRANSFER_ENCODING)
    || response.headers().contains_key(UPGRADE)
  {
    return Err(SendError::ForbiddenHeader);
  }
  let header_bytes = response
    .headers()
    .iter()
    .try_fold(0usize, |total, (name, value)| {
      total
        .checked_add(name.as_str().len())
        .and_then(|total| total.checked_add(value.as_bytes().len()))
        .and_then(|total| total.checked_add(4))
    });
  match header_bytes.filter(|bytes| *bytes <= MAX_HEADER_BYTES) {
    Some(bytes) => Ok(bytes),
    None => Err(SendError::HeaderTooLarge),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn candidate_requires_one_matching_interop_value() {
    let mut headers = HeaderMap::new();
    headers.insert(
      UPLOAD_DRAFT_INTEROP_VERSION,
      http::HeaderValue::from_static("9"),
    );
    assert!(candidate(&headers));
    headers.append(
      UPLOAD_DRAFT_INTEROP_VERSION,
      http::HeaderValue::from_static("9"),
    );
    assert!(!candidate(&headers));
  }

  #[test]
  fn candidate_uses_the_managed_structured_field_parser() {
    let mut headers = HeaderMap::new();
    headers.insert(
      UPLOAD_DRAFT_INTEROP_VERSION,
      http::HeaderValue::from_static("9; relay=?1"),
    );
    assert!(candidate(&headers));

    headers.insert(
      UPLOAD_DRAFT_INTEROP_VERSION,
      http::HeaderValue::from_static("-9"),
    );
    assert!(!candidate(&headers));
  }

  #[test]
  fn latch_preserves_initial_negotiation_and_no_replay_classification() {
    let mut request = http::Request::new(());
    request.headers_mut().insert(
      UPLOAD_DRAFT_INTEROP_VERSION,
      http::HeaderValue::from_static("9; relay=?1"),
    );
    latch_request(&mut request);
    request.headers_mut().remove(UPLOAD_DRAFT_INTEROP_VERSION);
    assert!(negotiated(request.extensions()));
    assert!(
      request
        .extensions()
        .get::<crate::proxy::http::resumable::NoReplayRequest>()
        .is_some()
    );
  }
}
