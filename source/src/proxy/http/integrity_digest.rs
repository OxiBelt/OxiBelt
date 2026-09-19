//! RFC 9530 digest negotiation and streaming response generation.
//!
//! The module intentionally owns no request routing.  Callers latch a
//! [`DigestRequest`] before forwarding and invoke [`finalize`] after every
//! representation-changing response transform has completed.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use base64::Engine as _;
use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, TRAILER};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use sha2::{Digest as _, Sha256, Sha512};

use crate::config::{RouteConfig, TrailerMode};
use crate::waf::HeaderMutation;

use super::body::{BoxError, InlinedKnownSmallResponseBody, KnownSmallResponseBody, ProxyBody};

#[path = "integrity_digest/body.rs"]
mod digest_body;
use digest_body::DigestBody;

const MAX_FIELD_BYTES: usize = 8 * 1024;
const MAX_MEMBERS: usize = 64;
const CONTENT_DIGEST: &str = "content-digest";
const REPR_DIGEST: &str = "repr-digest";
const UNENCODED_DIGEST: &str = "unencoded-digest";
const WANT_CONTENT_DIGEST: &str = "want-content-digest";
const WANT_REPR_DIGEST: &str = "want-repr-digest";
const WANT_UNENCODED_DIGEST: &str = "want-unencoded-digest";

/// A materialized full representation supplied by a cache or static responder.
/// It is deliberately bounded by callers to the ordinary known-small limit.
#[derive(Clone, Debug)]
pub(crate) struct AvailableRepresentation(pub Bytes);

/// Provenance of the response representation at the point digest finalization runs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Representation {
  Complete,
  Partial,
  #[default]
  Unknown,
  Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Algorithm {
  Sha256,
  Sha512,
}

impl Algorithm {
  fn name(self) -> &'static str {
    match self {
      Self::Sha256 => "sha-256",
      Self::Sha512 => "sha-512",
    }
  }
}

#[derive(Clone, Debug)]
pub(crate) struct DigestRequest {
  method: Method,
  version: Version,
  trailer_mode: TrailerMode,
  content: Option<Algorithm>,
  repr: Option<Algorithm>,
  unencoded: Option<Algorithm>,
  h1_trailers: bool,
  suppression: DigestFieldSuppression,
}

impl DigestRequest {
  pub(crate) fn new(
    method: &Method,
    version: Version,
    headers: &HeaderMap,
    trailer_mode: TrailerMode,
  ) -> Self {
    Self {
      method: method.clone(),
      version,
      trailer_mode,
      content: wanted_algorithm(headers, WANT_CONTENT_DIGEST),
      repr: wanted_algorithm(headers, WANT_REPR_DIGEST),
      unencoded: wanted_algorithm(headers, WANT_UNENCODED_DIGEST),
      h1_trailers: version == Version::HTTP_11 && te_allows_trailers(headers),
      suppression: DigestFieldSuppression::default(),
    }
  }

  pub(crate) fn requested(headers: &HeaderMap) -> bool {
    [WANT_CONTENT_DIGEST, WANT_REPR_DIGEST, WANT_UNENCODED_DIGEST]
      .into_iter()
      .any(|name| wanted_algorithm(headers, name).is_some())
  }

  pub(crate) fn suppression(&self) -> DigestFieldSuppression {
    self.suppression.clone()
  }

  fn trailer_capable(&self) -> bool {
    self.trailer_mode != TrailerMode::Drop
      && match self.version {
        Version::HTTP_11 => self.h1_trailers,
        Version::HTTP_2 | Version::HTTP_3 => true,
        _ => false,
      }
  }
}

pub(crate) fn unencoded_algorithm(headers: &HeaderMap) -> Option<Algorithm> {
  wanted_algorithm(headers, WANT_UNENCODED_DIGEST)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DigestFieldSuppression(Arc<Mutex<SuppressedFields>>);

#[derive(Debug, Default)]
struct SuppressedFields {
  content: Option<bool>,
  repr: Option<bool>,
  unencoded: Option<bool>,
}

impl DigestFieldSuppression {
  pub(crate) fn record_mutations(&self, mutations: &[HeaderMutation]) {
    let mut fields = self
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    for mutation in mutations {
      let (name, removed) = match mutation {
        HeaderMutation::Remove { name } => (name.as_str(), true),
        HeaderMutation::Set { name, .. } | HeaderMutation::Append { name, .. } => {
          (name.as_str(), false)
        }
      };
      record_name(&mut fields, name, removed);
    }
  }

  pub(crate) fn record_route(&self, route: &RouteConfig) {
    let mut fields = self
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Route actions execute set, append, then remove; preserve that order here.
    for item in &route.actions.response_headers.set {
      record_name(&mut fields, &item.name, false);
    }
    for item in &route.actions.response_headers.add {
      record_name(&mut fields, &item.name, false);
    }
    for name in &route.actions.response_headers.remove {
      record_name(&mut fields, name, true);
    }
  }

  fn contains(&self, name: &str) -> bool {
    let fields = self
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    match name {
      CONTENT_DIGEST => fields.content == Some(true),
      REPR_DIGEST => fields.repr == Some(true),
      UNENCODED_DIGEST => fields.unencoded == Some(true),
      _ => false,
    }
  }

  /// Merge suppression recorded while constructing a replacement response.
  pub(crate) fn merge_from(&self, other: &Self) {
    if Arc::ptr_eq(&self.0, &other.0) {
      return;
    }
    let other = other
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut fields = self
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if other.content.is_some() {
      fields.content = other.content;
    }
    if other.repr.is_some() {
      fields.repr = other.repr;
    }
    if other.unencoded.is_some() {
      fields.unencoded = other.unencoded;
    }
  }
}

fn record_name(fields: &mut SuppressedFields, name: &str, removed: bool) {
  let target = match name.to_ascii_lowercase().as_str() {
    CONTENT_DIGEST => Some(&mut fields.content),
    REPR_DIGEST => Some(&mut fields.repr),
    UNENCODED_DIGEST => Some(&mut fields.unencoded),
    _ => None,
  };
  if let Some(target) = target {
    *target = Some(removed);
  }
}

/// Remove digest metadata invalidated by a body transformation.
pub(crate) fn invalidate(headers: &mut HeaderMap, coding_only: bool) {
  headers.remove(CONTENT_DIGEST);
  headers.remove(REPR_DIGEST);
  if !coding_only {
    headers.remove(UNENCODED_DIGEST);
  }
  remove_trailer_tokens(headers, coding_only);
}

/// Remove only the content digest, retaining representation metadata.
pub(crate) fn invalidate_content(headers: &mut HeaderMap) {
  headers.remove(CONTENT_DIGEST);
  remove_named_trailer_token(headers, CONTENT_DIGEST);
}

/// Filter digest fields from source trailer frames after a body transformation.
pub(crate) fn invalidate_body(body: ProxyBody, coding_only: bool) -> ProxyBody {
  InvalidateDigestTrailers { body, coding_only }.boxed()
}

fn remove_trailer_tokens(headers: &mut HeaderMap, coding_only: bool) {
  for name in [CONTENT_DIGEST, REPR_DIGEST] {
    remove_named_trailer_token(headers, name);
  }
  if !coding_only {
    remove_named_trailer_token(headers, UNENCODED_DIGEST);
  }
}

fn remove_named_trailer_token(headers: &mut HeaderMap, remove: &str) {
  let retained = headers
    .get_all(TRAILER)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .filter(|name| !name.eq_ignore_ascii_case(remove))
    .map(str::to_owned)
    .collect::<Vec<_>>();
  headers.remove(TRAILER);
  if !retained.is_empty()
    && let Ok(value) = HeaderValue::from_str(&retained.join(", "))
  {
    headers.insert(TRAILER, value);
  }
}

struct InvalidateDigestTrailers {
  body: ProxyBody,
  coding_only: bool,
}
impl Body for InvalidateDigestTrailers {
  type Data = Bytes;
  type Error = BoxError;
  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    loop {
      match Pin::new(&mut self.body).poll_frame(cx) {
        Poll::Ready(Some(Ok(frame))) => match frame.into_trailers() {
          Ok(mut trailers) => {
            invalidate(&mut trailers, self.coding_only);
            if trailers.is_empty() {
              continue;
            }
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
          }
          Err(frame) => return Poll::Ready(Some(Ok(frame))),
        },
        other => return other,
      }
    }
  }
  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }
  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

/// State retained through content encoding so `Unencoded-Digest` refers to the
/// pre-compression representation.
#[derive(Clone, Debug)]
pub(crate) struct UnencodedDigestState(Arc<Mutex<UnencodedDigestInner>>);
#[derive(Debug)]
struct UnencodedDigestInner {
  sha256: Option<Sha256>,
  sha512: Option<Sha512>,
  complete: bool,
  source: Vec<HeaderValue>,
}

pub(crate) fn prehash_unencoded_body(
  body: ProxyBody,
  algorithm: Option<Algorithm>,
) -> (ProxyBody, UnencodedDigestState) {
  let state = UnencodedDigestState(Arc::new(Mutex::new(UnencodedDigestInner {
    sha256: (algorithm == Some(Algorithm::Sha256)).then(Sha256::new),
    sha512: (algorithm == Some(Algorithm::Sha512)).then(Sha512::new),
    complete: false,
    source: Vec::new(),
  })));
  (
    PrehashUnencodedBody {
      body,
      state: state.clone(),
      saw_trailers: false,
      terminal: false,
    }
    .boxed(),
    state,
  )
}

impl UnencodedDigestState {
  fn digest(&self, algorithm: Algorithm) -> Option<String> {
    let state = self
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !state.complete {
      return None;
    }
    Some(match algorithm {
      Algorithm::Sha256 => digest_value(algorithm, state.sha256.clone()?.finalize().as_slice()),
      Algorithm::Sha512 => digest_value(algorithm, state.sha512.clone()?.finalize().as_slice()),
    })
  }
  fn source(&self) -> Vec<HeaderValue> {
    self
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .source
      .clone()
  }
}

struct PrehashUnencodedBody {
  body: ProxyBody,
  state: UnencodedDigestState,
  saw_trailers: bool,
  terminal: bool,
}
impl Body for PrehashUnencodedBody {
  type Data = Bytes;
  type Error = BoxError;
  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    if self.terminal {
      return Poll::Ready(None);
    }
    loop {
      match Pin::new(&mut self.body).poll_frame(cx) {
        Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
          Ok(data) => {
            if self.saw_trailers {
              self.terminal = true;
              return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                "body contains data after trailers",
              )))));
            }
            let mut state = self
              .state
              .0
              .lock()
              .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(hash) = &mut state.sha256 {
              hash.update(&data);
            }
            if let Some(hash) = &mut state.sha512 {
              hash.update(&data);
            }
            return Poll::Ready(Some(Ok(Frame::data(data))));
          }
          Err(frame) => match frame.into_trailers() {
            Ok(trailers) => {
              if self.saw_trailers {
                self.terminal = true;
                return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                  "body contains multiple trailer frames",
                )))));
              }
              self.saw_trailers = true;
              let mut state = self
                .state
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
              state
                .source
                .extend(trailers.get_all(UNENCODED_DIGEST).iter().cloned());
              // Source trailer fields are retained in shared state, but a
              // clean EOF is still required before they can be re-emitted.
              continue;
            }
            Err(frame) => return Poll::Ready(Some(Ok(frame))),
          },
        },
        Poll::Ready(Some(Err(error))) => {
          self.terminal = true;
          return Poll::Ready(Some(Err(error)));
        }
        Poll::Ready(None) => {
          self
            .state
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .complete = true;
          self.terminal = true;
          return Poll::Ready(None);
        }
        Poll::Pending => return Poll::Pending,
      }
    }
  }
}

/// Add negotiated digest fields after all response transformations are known.
pub(crate) fn finalize(
  mut response: Response<ProxyBody>,
  context: &DigestRequest,
) -> Response<ProxyBody> {
  if let Some(suppression) = response.extensions().get::<DigestFieldSuppression>() {
    context.suppression.merge_from(suppression);
  }
  let unencoded_state = response.extensions().get::<UnencodedDigestState>().cloned();
  if context.content.is_none()
    && context.repr.is_none()
    && context.unencoded.is_none()
    && unencoded_state.is_none()
  {
    return response;
  }
  let representation = response
    .extensions()
    .get::<Representation>()
    .copied()
    .unwrap_or_else(|| default_representation(context, &response));
  if representation == Representation::Absent || excluded_response(context, &response) {
    return response;
  }

  let available = response
    .extensions()
    .get::<AvailableRepresentation>()
    .cloned();
  let fields = desired_fields(
    &response,
    context,
    representation,
    available.is_some(),
    unencoded_state,
  );
  if fields.is_empty() {
    return response;
  }

  let inlined = response
    .extensions()
    .get::<InlinedKnownSmallResponseBody>()
    .filter(|body| {
      body.data.len() <= super::body::KNOWN_SMALL_BODY_MAX_BYTES && body.trailers.is_none()
    })
    .map(|body| body.data.clone());
  let content_empty =
    context.method == Method::HEAD || response.status() == StatusCode::NOT_MODIFIED;
  let fields = apply_known_digests(
    response.headers_mut(),
    fields,
    inlined.as_deref(),
    available.as_ref().map(|available| available.0.as_ref()),
    content_empty,
  );
  if fields.is_empty() {
    return response;
  }
  if !context.trailer_capable() {
    return response;
  }

  let generated_names = fields.iter().map(Field::name).collect::<Vec<_>>();
  response.headers_mut().remove(CONTENT_LENGTH);
  response
    .extensions_mut()
    .remove::<super::body::CompiledKnownSmallNoopResponse>();
  response.extensions_mut().remove::<KnownSmallResponseBody>();
  response
    .extensions_mut()
    .remove::<InlinedKnownSmallResponseBody>();
  if context.version == Version::HTTP_11 {
    append_trailer_names(response.headers_mut(), &generated_names);
  }
  let (parts, body) = response.into_parts();
  Response::from_parts(parts, DigestBody::new(body, fields).boxed())
}

#[derive(Clone)]
enum Field {
  Content(Algorithm),
  Repr(Algorithm),
  Unencoded {
    algorithm: Option<Algorithm>,
    state: Option<UnencodedDigestState>,
  },
}
impl Field {
  fn name(&self) -> &'static str {
    match self {
      Self::Content(_) => CONTENT_DIGEST,
      Self::Repr(_) => REPR_DIGEST,
      Self::Unencoded { .. } => UNENCODED_DIGEST,
    }
  }
  fn algorithm(&self) -> Option<Algorithm> {
    match self {
      Self::Content(a) | Self::Repr(a) => Some(*a),
      Self::Unencoded { algorithm, .. } => *algorithm,
    }
  }

  fn needs_downstream_hash(&self, algorithm: Algorithm) -> bool {
    matches!(self, Self::Content(value) | Self::Repr(value) if *value == algorithm)
      || matches!(self, Self::Unencoded { algorithm: Some(value), state: None } if *value == algorithm)
  }
}

fn desired_fields(
  response: &Response<ProxyBody>,
  context: &DigestRequest,
  representation: Representation,
  available: bool,
  unencoded_state: Option<UnencodedDigestState>,
) -> Vec<Field> {
  let mut fields = Vec::new();
  // A cache/static responder may retain the whole representation while the
  // response itself is HEAD, 304, or a range.  That material is authoritative
  // for representation and unencoded fields, never for Content-Digest.
  let complete = representation == Representation::Complete || available;
  let bodyless = context.method == Method::HEAD || response.status() == StatusCode::NOT_MODIFIED;
  if let Some(algorithm) = context.content
    && !context.suppression.contains(CONTENT_DIGEST)
    && !response.headers().contains_key(CONTENT_DIGEST)
  {
    fields.push(Field::Content(algorithm));
  }
  if let Some(algorithm) = context.repr
    && !context.suppression.contains(REPR_DIGEST)
    && !response.headers().contains_key(REPR_DIGEST)
    && complete
    && (!bodyless || available)
  {
    fields.push(Field::Repr(algorithm));
  }
  if !context.suppression.contains(UNENCODED_DIGEST) {
    if let Some(state) = unencoded_state {
      // The carrier preserves opaque upstream trailer fields even without a
      // Want header; it contains a hasher only for an explicitly negotiated U.
      fields.push(Field::Unencoded {
        algorithm: (!response.headers().contains_key(UNENCODED_DIGEST))
          .then_some(
            context
              .unencoded
              .filter(|_| complete && (!bodyless || available)),
          )
          .flatten(),
        state: Some(state),
      });
    } else if !response.headers().contains_key(UNENCODED_DIGEST)
      && let Some(algorithm) = context
        .unencoded
        .filter(|_| complete && (!bodyless || available))
      && !has_non_identity_content_encoding(response.headers())
    {
      // An upstream-coded response has no safe identity byte source.
      fields.push(Field::Unencoded {
        algorithm: Some(algorithm),
        state: None,
      });
    }
  }
  fields
}

fn default_representation(
  context: &DigestRequest,
  response: &Response<ProxyBody>,
) -> Representation {
  if response.headers().contains_key(CONTENT_RANGE)
    || response.status() == StatusCode::PARTIAL_CONTENT
  {
    return Representation::Partial;
  }
  if context.method == Method::GET || context.method.as_str() == "QUERY" {
    Representation::Complete
  } else {
    Representation::Unknown
  }
}

fn excluded_response(context: &DigestRequest, response: &Response<ProxyBody>) -> bool {
  response.status().is_informational()
    || response.status() == StatusCode::NO_CONTENT
    || context.method == Method::CONNECT
    || response.status() == StatusCode::SWITCHING_PROTOCOLS
    || response
      .headers()
      .get(CONNECTION)
      .and_then(|value| value.to_str().ok())
      .is_some_and(|value| {
        value
          .split(',')
          .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
      })
}

fn apply_known_digests(
  headers: &mut HeaderMap,
  fields: Vec<Field>,
  body: Option<&[u8]>,
  representation: Option<&[u8]>,
  content_empty: bool,
) -> Vec<Field> {
  let mut remaining = Vec::new();
  for field in fields {
    match &field {
      Field::Content(algorithm) if content_empty => {
        set_digest(headers, CONTENT_DIGEST, *algorithm, b"");
      }
      Field::Content(algorithm) if body.is_some() => {
        if let Some(body) = body {
          set_digest(headers, CONTENT_DIGEST, *algorithm, body);
        }
      }
      Field::Repr(algorithm) if representation.is_some() || (!content_empty && body.is_some()) => {
        if let Some(bytes) = representation.or(body) {
          set_digest(headers, REPR_DIGEST, *algorithm, bytes);
        }
      }
      Field::Unencoded {
        algorithm: Some(algorithm),
        state: None,
      } if representation.is_some() || (!content_empty && body.is_some()) => {
        if let Some(bytes) = representation.or(body) {
          set_digest(headers, UNENCODED_DIGEST, *algorithm, bytes);
        }
      }
      _ => remaining.push(field),
    }
  }
  remaining
}

fn set_digest(headers: &mut HeaderMap, name: &'static str, algorithm: Algorithm, bytes: &[u8]) {
  if let Some(value) = digest_header(algorithm, bytes) {
    headers.insert(name, value);
  }
}

fn append_trailer_names(headers: &mut HeaderMap, names: &[&str]) {
  let mut values = headers
    .get_all(TRAILER)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .filter(|item| !item.is_empty())
    .map(str::to_owned)
    .collect::<Vec<_>>();
  for name in names {
    if !values.iter().any(|item| item.eq_ignore_ascii_case(name)) {
      values.push((*name).to_owned());
    }
  }
  if let Ok(value) = HeaderValue::from_str(&values.join(", ")) {
    headers.insert(TRAILER, value);
  }
}

fn header_map_bytes(headers: &HeaderMap) -> usize {
  headers
    .iter()
    .map(|(name, value)| name.as_str().len() + value.len() + 4)
    .sum()
}
fn digest_header(algorithm: Algorithm, bytes: &[u8]) -> Option<HeaderValue> {
  let hash = match algorithm {
    Algorithm::Sha256 => Sha256::digest(bytes).to_vec(),
    Algorithm::Sha512 => Sha512::digest(bytes).to_vec(),
  };
  HeaderValue::from_str(&digest_value(algorithm, &hash)).ok()
}
fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
  headers.get_all(CONTENT_ENCODING).iter().any(|value| {
    value
      .to_str()
      .map(|value| {
        !value
          .split(',')
          .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
      })
      .unwrap_or(true)
  })
}
fn digest_value(algorithm: Algorithm, bytes: &[u8]) -> String {
  format!(
    "{}=:{}:",
    algorithm.name(),
    base64::engine::general_purpose::STANDARD.encode(bytes)
  )
}
fn te_allows_trailers(headers: &HeaderMap) -> bool {
  headers
    .get_all("te")
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
}

#[path = "integrity_digest/parser.rs"]
mod parser;
use parser::wanted_algorithm;

#[cfg(test)]
#[path = "integrity_digest/tests.rs"]
mod tests;
