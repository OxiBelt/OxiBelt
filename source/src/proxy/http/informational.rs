//! Live informational-response relaying shared by HTTP/1.1, HTTP/2, and HTTP/3.

use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

use http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING, UPGRADE};
use http::{Extensions, HeaderMap, Method, Response, StatusCode};
use tokio::sync::mpsc;

const MAX_RESPONSES: usize = hyper::ext::MAX_INFORMATIONAL_RESPONSES;
const MAX_HEADER_BYTES: usize = hyper::ext::MAX_INFORMATIONAL_HEADER_BYTES;
/// Immutable evidence that the original downstream request carried a complete
/// draft-12 creation or append tuple. Header mutations cannot create it.
#[derive(Clone, Copy, Debug)]
struct ClientInterop;

/// Whether the outbound method and headers still form a strict relay tuple.
fn relay_request(method: &Method, headers: &HeaderMap) -> bool {
  super::managed_upload::relay_request(method, headers)
}

/// Capture transport and replay-relevant request facts before WAF or route
/// transformations can modify the headers. HTTP/3 has already installed its
/// emitter when this runs; HTTP/1.1 and HTTP/2 expose Hyper's sender directly.
pub(crate) fn latch_request<B>(request: &mut http::Request<B>) {
  if relay_request(request.method(), request.headers()) {
    request.extensions_mut().insert(ClientInterop);
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

/// Whether immutable ingress classification and current outbound headers both
/// permit relaying live upload informational responses.
pub(crate) fn relay_armed<B>(request: &http::Request<B>) -> bool {
  relay_armed_parts(request.extensions(), request.method(), request.headers())
}

/// Parts-based form used after the HTTP/3 request body is split.
pub(crate) fn relay_armed_parts(
  extensions: &Extensions,
  method: &Method,
  headers: &HeaderMap,
) -> bool {
  negotiated(extensions) && relay_request(method, headers)
}

/// Whether a received 104 advertises the same draft interop version.
pub(crate) fn compatible_104(headers: &HeaderMap) -> bool {
  super::managed_upload::compatible_interop(headers)
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
  fn response_compatibility_requires_one_matching_interop_value() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "upload-draft-interop-version",
      http::HeaderValue::from_static("9"),
    );
    assert!(compatible_104(&headers));
    headers.append(
      "upload-draft-interop-version",
      http::HeaderValue::from_static("9"),
    );
    assert!(!compatible_104(&headers));
  }

  #[test]
  fn response_compatibility_uses_the_managed_structured_field_parser() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "upload-draft-interop-version",
      http::HeaderValue::from_static("9; relay=?1"),
    );
    assert!(compatible_104(&headers));

    headers.insert(
      "upload-draft-interop-version",
      http::HeaderValue::from_static("-9"),
    );
    assert!(!compatible_104(&headers));
  }

  #[test]
  fn latch_preserves_initial_negotiation_and_no_replay_classification() {
    let mut request = http::Request::builder()
      .method(Method::POST)
      .header("upload-draft-interop-version", "9; relay=?1")
      .header("upload-complete", "?0")
      .body(())
      .unwrap();
    latch_request(&mut request);
    request.headers_mut().remove("upload-draft-interop-version");
    assert!(negotiated(request.extensions()));
    assert!(
      request
        .extensions()
        .get::<crate::proxy::http::resumable::NoReplayRequest>()
        .is_some()
    );
    assert!(!relay_armed(&request));
  }

  #[test]
  fn incomplete_or_inapplicable_headers_do_not_latch() {
    for request in [
      http::Request::builder()
        .method(Method::POST)
        .header("upload-draft-interop-version", "9")
        .body(())
        .unwrap(),
      http::Request::builder()
        .method(Method::GET)
        .header("upload-draft-interop-version", "9")
        .header("upload-complete", "?0")
        .body(())
        .unwrap(),
      http::Request::builder()
        .method(Method::POST)
        .header("upload-draft-interop-version", "9")
        .header("upload-complete", "invalid")
        .body(())
        .unwrap(),
    ] {
      let mut request = request;
      latch_request(&mut request);
      assert!(!negotiated(request.extensions()));
      assert!(!super::super::resumable::request_marked(&request));
    }
  }

  #[test]
  fn outbound_mutations_cannot_create_or_preserve_live_relay_alone() {
    let mut ordinary = http::Request::new(());
    latch_request(&mut ordinary);
    *ordinary.method_mut() = Method::POST;
    ordinary.headers_mut().insert(
      "upload-draft-interop-version",
      http::HeaderValue::from_static("9"),
    );
    ordinary
      .headers_mut()
      .insert("upload-complete", http::HeaderValue::from_static("?0"));
    assert!(!relay_armed(&ordinary));

    let mut relay = http::Request::builder()
      .method(Method::POST)
      .header("upload-draft-interop-version", "9")
      .header("upload-complete", "?0")
      .body(())
      .unwrap();
    latch_request(&mut relay);
    assert!(relay_armed(&relay));
    relay.headers_mut().remove("upload-complete");
    assert!(!relay_armed(&relay));
    assert!(super::super::resumable::request_marked(&relay));
  }
}
