use std::fmt;

use bytes::Bytes;
use http::{HeaderMap, StatusCode, Version};

const DEFAULT_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
const DEFAULT_RESPONSE_HEADER_FIELDS: usize = 128;
const DEFAULT_RESPONSE_HEADER_FIELD_BYTES: usize = 8 * 1024;
const DEFAULT_INTERIM_RESPONSES: usize = 8;
const DEFAULT_CHUNK_SIZE_LINE_BYTES: usize = 8 * 1024;
const DEFAULT_CHUNK_EXTENSION_BYTES: usize = 8 * 1024;
const DEFAULT_TRAILER_BLOCK_BYTES: usize = 64 * 1024;
const DEFAULT_TRAILER_FIELDS: usize = 128;
const DEFAULT_TRAILER_FIELD_BYTES: usize = 8 * 1024;
const MAX_VALIDATED_METADATA_BYTES: usize = 1024 * 1024;
const MAX_VALIDATED_FIELDS: usize = 4096;
const MAX_VALIDATED_INTERIMS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseProtocolLimits {
  pub(crate) max_response_head_bytes: usize,
  pub(crate) max_response_header_fields: usize,
  pub(crate) max_response_header_field_bytes: usize,
  pub(crate) max_interim_responses: usize,
  pub(crate) max_chunk_size_line_bytes: usize,
  pub(crate) max_chunk_extension_bytes: usize,
  pub(crate) max_trailer_block_bytes: usize,
  pub(crate) max_trailer_fields: usize,
  pub(crate) max_trailer_field_bytes: usize,
}

impl Default for ResponseProtocolLimits {
  fn default() -> Self {
    Self {
      max_response_head_bytes: DEFAULT_RESPONSE_HEAD_BYTES,
      max_response_header_fields: DEFAULT_RESPONSE_HEADER_FIELDS,
      max_response_header_field_bytes: DEFAULT_RESPONSE_HEADER_FIELD_BYTES,
      max_interim_responses: DEFAULT_INTERIM_RESPONSES,
      max_chunk_size_line_bytes: DEFAULT_CHUNK_SIZE_LINE_BYTES,
      max_chunk_extension_bytes: DEFAULT_CHUNK_EXTENSION_BYTES,
      max_trailer_block_bytes: DEFAULT_TRAILER_BLOCK_BYTES,
      max_trailer_fields: DEFAULT_TRAILER_FIELDS,
      max_trailer_field_bytes: DEFAULT_TRAILER_FIELD_BYTES,
    }
  }
}

impl ResponseProtocolLimits {
  pub(crate) fn validate(self) -> Result<Self, ResponseProtocolLimitsError> {
    let byte_limits = [
      self.max_response_head_bytes,
      self.max_response_header_field_bytes,
      self.max_chunk_size_line_bytes,
      self.max_chunk_extension_bytes,
      self.max_trailer_block_bytes,
      self.max_trailer_field_bytes,
    ];
    if byte_limits
      .iter()
      .any(|value| *value == 0 || *value > MAX_VALIDATED_METADATA_BYTES)
      || self.max_response_header_fields == 0
      || self.max_response_header_fields > MAX_VALIDATED_FIELDS
      || self.max_trailer_fields == 0
      || self.max_trailer_fields > MAX_VALIDATED_FIELDS
      || self.max_interim_responses == 0
      || self.max_interim_responses > MAX_VALIDATED_INTERIMS
    {
      return Err(ResponseProtocolLimitsError);
    }
    Ok(self)
  }

  #[cfg(feature = "fuzzing")]
  pub(crate) fn from_selectors(selectors: [u8; 9]) -> Self {
    let byte_limit =
      |selector: u8, minimum: usize| minimum.saturating_add(usize::from(selector) % 96);
    Self {
      max_response_head_bytes: byte_limit(selectors[0], 32),
      max_response_header_fields: 1 + usize::from(selectors[1] % 16),
      max_response_header_field_bytes: byte_limit(selectors[2], 8),
      max_interim_responses: 1 + usize::from(selectors[3] % 8),
      max_chunk_size_line_bytes: byte_limit(selectors[4], 8),
      max_chunk_extension_bytes: 1 + usize::from(selectors[5] % 96),
      max_trailer_block_bytes: byte_limit(selectors[6], 16),
      max_trailer_fields: 1 + usize::from(selectors[7] % 16),
      max_trailer_field_bytes: byte_limit(selectors[8], 8),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseProtocolLimitsError;

impl fmt::Display for ResponseProtocolLimitsError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("invalid direct H1 response protocol limits")
  }
}

impl std::error::Error for ResponseProtocolLimitsError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseBodyMode {
  None,
  ContentLength(u64),
  Chunked,
  CloseDelimited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResponseState {
  ReadingHead,
  ProcessingInterim,
  WaitingForFinalHead,
  FixedLength { remaining: u64 },
  ChunkSizeLine,
  ChunkData { remaining: u64 },
  ChunkTerminator,
  Trailers,
  CloseDelimited,
  Completed,
  FailedNonReusable,
}

impl ResponseState {
  pub(crate) fn label(&self) -> ResponseStateLabel {
    match self {
      Self::ReadingHead => ResponseStateLabel::ReadingHead,
      Self::ProcessingInterim => ResponseStateLabel::ProcessingInterim,
      Self::WaitingForFinalHead => ResponseStateLabel::WaitingForFinalHead,
      Self::FixedLength { .. } => ResponseStateLabel::FixedLength,
      Self::ChunkSizeLine => ResponseStateLabel::ChunkSizeLine,
      Self::ChunkData { .. } => ResponseStateLabel::ChunkData,
      Self::ChunkTerminator => ResponseStateLabel::ChunkTerminator,
      Self::Trailers => ResponseStateLabel::Trailers,
      Self::CloseDelimited => ResponseStateLabel::CloseDelimited,
      Self::Completed => ResponseStateLabel::Completed,
      Self::FailedNonReusable => ResponseStateLabel::FailedNonReusable,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseStateLabel {
  ReadingHead,
  ProcessingInterim,
  WaitingForFinalHead,
  FixedLength,
  ChunkSizeLine,
  ChunkData,
  ChunkTerminator,
  Trailers,
  CloseDelimited,
  Completed,
  FailedNonReusable,
}

impl ResponseStateLabel {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::ReadingHead => "reading_head",
      Self::ProcessingInterim => "processing_interim",
      Self::WaitingForFinalHead => "waiting_for_final_head",
      Self::FixedLength => "fixed_length",
      Self::ChunkSizeLine => "chunk_size_line",
      Self::ChunkData => "chunk_data",
      Self::ChunkTerminator => "chunk_terminator",
      Self::Trailers => "trailers",
      Self::CloseDelimited => "close_delimited",
      Self::Completed => "completed",
      Self::FailedNonReusable => "failed_non_reusable",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseProtocolFailureReason {
  HeadTooLarge,
  TooManyHeaders,
  HeaderFieldTooLarge,
  TooManyInterimResponses,
  InvalidStatusLine,
  InvalidHeaderSyntax,
  InvalidTransferCodingSequence,
  ChunkLineTooLarge,
  InvalidChunkSize,
  InvalidChunkExtension,
  InvalidChunkTerminator,
  ChunkExtensionTooLarge,
  TrailerBlockTooLarge,
  TooManyTrailers,
  InvalidTrailerField,
  TrailerFieldTooLarge,
  UnexpectedEof,
  IdleTimeout,
  DownstreamCancellation,
  UnsupportedUpgrade,
}

impl ResponseProtocolFailureReason {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::HeadTooLarge => "head too large",
      Self::TooManyHeaders => "too many headers",
      Self::HeaderFieldTooLarge => "header field too large",
      Self::TooManyInterimResponses => "too many interim responses",
      Self::InvalidStatusLine => "invalid status line",
      Self::InvalidHeaderSyntax => "invalid header syntax",
      Self::InvalidTransferCodingSequence => "invalid transfer-coding sequence",
      Self::ChunkLineTooLarge => "chunk line too large",
      Self::InvalidChunkSize => "invalid chunk size",
      Self::InvalidChunkExtension => "invalid chunk extension",
      Self::InvalidChunkTerminator => "invalid chunk terminator",
      Self::ChunkExtensionTooLarge => "chunk extension too large",
      Self::TrailerBlockTooLarge => "trailer block too large",
      Self::TooManyTrailers => "too many trailers",
      Self::InvalidTrailerField => "invalid trailer field",
      Self::TrailerFieldTooLarge => "trailer field too large",
      Self::UnexpectedEof => "unexpected EOF",
      Self::IdleTimeout => "idle timeout",
      Self::DownstreamCancellation => "downstream cancellation",
      Self::UnsupportedUpgrade => "unsupported upgrade",
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResponseProtocolError {
  reason: ResponseProtocolFailureReason,
  state: ResponseStateLabel,
}

impl ResponseProtocolError {
  pub(crate) fn new(reason: ResponseProtocolFailureReason, state: ResponseStateLabel) -> Self {
    Self { reason, state }
  }

  pub(crate) fn reason(&self) -> ResponseProtocolFailureReason {
    self.reason
  }

  #[cfg(test)]
  pub(crate) fn state(&self) -> ResponseStateLabel {
    self.state
  }
}

impl fmt::Display for ResponseProtocolError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "direct H1 response protocol {} while {}",
      self.reason.as_str(),
      self.state.as_str()
    )
  }
}

impl std::error::Error for ResponseProtocolError {}

#[derive(Debug)]
pub(crate) enum ResponseEvent {
  InterimHead {
    status: StatusCode,
    headers: HeaderMap,
  },
  FinalHead {
    version: Version,
    status: StatusCode,
    headers: HeaderMap,
    body_mode: ResponseBodyMode,
  },
  Body(Bytes),
  Trailers(HeaderMap),
  Complete,
}

#[derive(Debug)]
pub(crate) enum ResponseStep {
  Event(ResponseEvent),
  NeedInput,
}
