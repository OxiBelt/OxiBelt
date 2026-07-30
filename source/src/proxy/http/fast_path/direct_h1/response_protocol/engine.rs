use bytes::BytesMut;
use http::{Method, StatusCode};

use super::chunked::parse_chunk_size_line;
use super::head::{parse_head, parse_trailers, response_body_mode};
use super::types::{
  ResponseBodyMode, ResponseEvent, ResponseProtocolError, ResponseProtocolFailureReason,
  ResponseProtocolLimits, ResponseProtocolLimitsError, ResponseState, ResponseStateLabel,
  ResponseStep,
};

pub(crate) struct ResponseProtocolEngine {
  request_method: Method,
  limits: ResponseProtocolLimits,
  state: ResponseState,
  interim_responses: usize,
  terminal_error: Option<ResponseProtocolError>,
  saw_eof: bool,
  complete_emitted: bool,
  head_search_start: usize,
  chunk_line_search_start: usize,
  trailer_search_start: usize,
}

impl ResponseProtocolEngine {
  pub(crate) fn new(
    request_method: Method,
    limits: ResponseProtocolLimits,
  ) -> Result<Self, ResponseProtocolLimitsError> {
    Ok(Self {
      request_method,
      limits: limits.validate()?,
      state: ResponseState::ReadingHead,
      interim_responses: 0,
      terminal_error: None,
      saw_eof: false,
      complete_emitted: false,
      head_search_start: 0,
      chunk_line_search_start: 0,
      trailer_search_start: 0,
    })
  }

  pub(crate) fn state(&self) -> ResponseState {
    self.state.clone()
  }

  pub(crate) fn state_label(&self) -> ResponseStateLabel {
    self.state.label()
  }

  pub(crate) fn limits(&self) -> ResponseProtocolLimits {
    self.limits
  }

  #[cfg(feature = "fuzzing")]
  pub(crate) fn buffered_metadata_bytes(&self, input: &BytesMut) -> usize {
    match &self.state {
      ResponseState::ReadingHead
      | ResponseState::WaitingForFinalHead
      | ResponseState::ChunkSizeLine
      | ResponseState::Trailers => input.len(),
      _ => 0,
    }
  }

  #[cfg(feature = "fuzzing")]
  pub(crate) fn max_buffered_metadata_bytes(&self) -> usize {
    self
      .limits
      .max_response_head_bytes
      .max(self.limits.max_chunk_size_line_bytes.saturating_add(2))
      .max(self.limits.max_trailer_block_bytes)
  }

  pub(crate) fn decode(
    &mut self,
    input: &mut BytesMut,
    eof: bool,
  ) -> Result<ResponseStep, ResponseProtocolError> {
    if let Some(error) = self.terminal_error.clone() {
      return Err(error);
    }
    self.saw_eof |= eof;
    loop {
      match self.state.clone() {
        ResponseState::ReadingHead | ResponseState::WaitingForFinalHead => {
          return self.decode_head(input);
        }
        ResponseState::ProcessingInterim => {
          self.state = ResponseState::WaitingForFinalHead;
        }
        ResponseState::FixedLength { remaining } => {
          if remaining == 0 {
            self.state = ResponseState::Completed;
            continue;
          }
          if input.is_empty() {
            return self.need_input_or_eof();
          }
          let take = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(input.len());
          let bytes = input.split_to(take).freeze();
          let remaining = remaining.saturating_sub(take as u64);
          self.state = if remaining == 0 {
            ResponseState::Completed
          } else {
            ResponseState::FixedLength { remaining }
          };
          return Ok(ResponseStep::Event(ResponseEvent::Body(bytes)));
        }
        ResponseState::ChunkSizeLine => return self.decode_chunk_size(input),
        ResponseState::ChunkData { remaining } => {
          if remaining == 0 {
            self.state = ResponseState::ChunkTerminator;
            continue;
          }
          if input.is_empty() {
            return self.need_input_or_eof();
          }
          let take = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(input.len());
          let bytes = input.split_to(take).freeze();
          let remaining = remaining.saturating_sub(take as u64);
          self.state = if remaining == 0 {
            ResponseState::ChunkTerminator
          } else {
            ResponseState::ChunkData { remaining }
          };
          return Ok(ResponseStep::Event(ResponseEvent::Body(bytes)));
        }
        ResponseState::ChunkTerminator => {
          if input.is_empty() {
            return self.need_input_or_eof();
          }
          if input[0] != b'\r' {
            return self.fail(ResponseProtocolFailureReason::InvalidChunkTerminator);
          }
          if input.len() == 1 {
            return self.need_input_or_eof();
          }
          if input[1] != b'\n' {
            return self.fail(ResponseProtocolFailureReason::InvalidChunkTerminator);
          }
          let _ = input.split_to(2);
          self.state = ResponseState::ChunkSizeLine;
        }
        ResponseState::Trailers => return self.decode_trailers(input),
        ResponseState::CloseDelimited => {
          if !input.is_empty() {
            return Ok(ResponseStep::Event(ResponseEvent::Body(
              input.split().freeze(),
            )));
          }
          if self.saw_eof {
            self.state = ResponseState::Completed;
            continue;
          }
          return Ok(ResponseStep::NeedInput);
        }
        ResponseState::Completed => {
          if self.complete_emitted {
            return Ok(ResponseStep::NeedInput);
          }
          self.complete_emitted = true;
          return Ok(ResponseStep::Event(ResponseEvent::Complete));
        }
        ResponseState::FailedNonReusable => {
          return self.fail(ResponseProtocolFailureReason::UnexpectedEof);
        }
      }
    }
  }

  fn decode_head(&mut self, input: &mut BytesMut) -> Result<ResponseStep, ResponseProtocolError> {
    let Some(head_end) = find_incremental(input, b"\r\n\r\n", &mut self.head_search_start) else {
      if input.len() >= self.limits.max_response_head_bytes {
        return self.fail(ResponseProtocolFailureReason::HeadTooLarge);
      }
      return self.need_input_or_eof();
    };
    let head_end = head_end + 4;
    if head_end > self.limits.max_response_head_bytes {
      return self.fail(ResponseProtocolFailureReason::HeadTooLarge);
    }
    let head = input.split_to(head_end).freeze();
    self.head_search_start = 0;
    let (version, status, headers) = match parse_head(&head, self.limits) {
      Ok(parsed) => parsed,
      Err(reason) => return self.fail(reason),
    };
    if status == StatusCode::SWITCHING_PROTOCOLS {
      return self.fail(ResponseProtocolFailureReason::UnsupportedUpgrade);
    }
    if status.is_informational() {
      self.interim_responses = self.interim_responses.saturating_add(1);
      if self.interim_responses > self.limits.max_interim_responses {
        return self.fail(ResponseProtocolFailureReason::TooManyInterimResponses);
      }
      self.state = ResponseState::ProcessingInterim;
      return Ok(ResponseStep::Event(ResponseEvent::InterimHead {
        status,
        headers,
      }));
    }
    let body_mode = match response_body_mode(&self.request_method, version, status, &headers) {
      Ok(mode) => mode,
      Err(reason) => return self.fail(reason),
    };
    self.state = match body_mode {
      ResponseBodyMode::None => ResponseState::Completed,
      ResponseBodyMode::ContentLength(remaining) => ResponseState::FixedLength { remaining },
      ResponseBodyMode::Chunked => ResponseState::ChunkSizeLine,
      ResponseBodyMode::CloseDelimited => ResponseState::CloseDelimited,
    };
    Ok(ResponseStep::Event(ResponseEvent::FinalHead {
      version,
      status,
      headers,
      body_mode,
    }))
  }

  fn decode_chunk_size(
    &mut self,
    input: &mut BytesMut,
  ) -> Result<ResponseStep, ResponseProtocolError> {
    let Some(line_end) = find_incremental(input, b"\r\n", &mut self.chunk_line_search_start) else {
      let overflow = input
        .get(self.limits.max_chunk_size_line_bytes..)
        .unwrap_or_default();
      if !overflow.is_empty() && overflow != b"\r" {
        return self.fail(ResponseProtocolFailureReason::ChunkLineTooLarge);
      }
      return self.need_input_or_eof();
    };
    if line_end > self.limits.max_chunk_size_line_bytes {
      return self.fail(ResponseProtocolFailureReason::ChunkLineTooLarge);
    }
    let line = input.split_to(line_end + 2).freeze();
    self.chunk_line_search_start = 0;
    let size = match parse_chunk_size_line(&line[..line_end], self.limits.max_chunk_extension_bytes)
    {
      Ok(size) => size,
      Err(reason) => return self.fail(reason),
    };
    self.state = if size == 0 {
      ResponseState::Trailers
    } else {
      ResponseState::ChunkData { remaining: size }
    };
    self.decode(input, false)
  }

  fn decode_trailers(
    &mut self,
    input: &mut BytesMut,
  ) -> Result<ResponseStep, ResponseProtocolError> {
    let trailer_end = if input.starts_with(b"\r\n") {
      Some(2)
    } else {
      find_incremental(input, b"\r\n\r\n", &mut self.trailer_search_start).map(|index| index + 4)
    };
    let Some(trailer_end) = trailer_end else {
      if input.len() >= self.limits.max_trailer_block_bytes {
        return self.fail(ResponseProtocolFailureReason::TrailerBlockTooLarge);
      }
      return self.need_input_or_eof();
    };
    if trailer_end > self.limits.max_trailer_block_bytes {
      return self.fail(ResponseProtocolFailureReason::TrailerBlockTooLarge);
    }
    let block = input.split_to(trailer_end).freeze();
    self.trailer_search_start = 0;
    let trailers = match parse_trailers(&block, self.limits) {
      Ok(trailers) => trailers,
      Err(reason) => return self.fail(reason),
    };
    self.state = ResponseState::Completed;
    Ok(ResponseStep::Event(ResponseEvent::Trailers(trailers)))
  }

  fn need_input_or_eof(&mut self) -> Result<ResponseStep, ResponseProtocolError> {
    if self.saw_eof {
      return self.fail(ResponseProtocolFailureReason::UnexpectedEof);
    }
    Ok(ResponseStep::NeedInput)
  }

  fn fail<T>(&mut self, reason: ResponseProtocolFailureReason) -> Result<T, ResponseProtocolError> {
    if let Some(error) = self.terminal_error.clone() {
      return Err(error);
    }
    let error = ResponseProtocolError::new(reason, self.state.label());
    self.state = ResponseState::FailedNonReusable;
    self.terminal_error = Some(error.clone());
    Err(error)
  }
}

fn find_incremental(haystack: &[u8], needle: &[u8], search_start: &mut usize) -> Option<usize> {
  let start = if *search_start <= haystack.len() {
    *search_start
  } else {
    0
  };
  if let Some(relative) = memchr::memmem::find(&haystack[start..], needle) {
    return Some(start + relative);
  }
  *search_start = haystack
    .len()
    .saturating_sub(needle.len().saturating_sub(1));
  None
}
