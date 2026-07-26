//! Bounded wire-level HTTP/1 request-framing guard.
//!
//! Hyper 1.11 removes `Content-Length` when `Transfer-Encoding` is also present.
//! Inspecting the wire before Hyper parses it preserves OxiBelt's stricter policy:
//! the ambiguous request is rejected before any service handler can observe it.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use self::response_head::{ResponseHeadOutcome, ResponseHeadParser, TunnelKind};

mod response_head;

const READ_CHUNK_BYTES: usize = 8 * 1024;
const BAD_REQUEST_RESPONSE: &[u8] =
  b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
const HEADER_TOO_LARGE_RESPONSE: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
connection: close\r\ncontent-length: 0\r\n\r\n";

pub(in crate::server) struct Http1FramingGuard<I> {
  inner: I,
  max_header_bytes: usize,
  buffered: Vec<u8>,
  buffered_offset: usize,
  eof: bool,
  state: ReadState,
  reader_waker: Option<Waker>,
}

enum ReadState {
  Head,
  ValidatedHead {
    remaining: usize,
    next: AfterHead,
  },
  FixedBody(u64),
  ChunkedBody(ChunkDecoder),
  AwaitingTunnelResponse(ResponseHeadParser),
  Passthrough,
  Rejecting {
    response: &'static [u8],
    offset: usize,
  },
  Rejected,
}

enum AfterHead {
  Head,
  FixedBody(u64),
  ChunkedBody(ChunkDecoder),
  AwaitingTunnelResponse(TunnelKind),
}

#[derive(Debug, Eq, PartialEq)]
enum HeadDisposition {
  NoBody,
  FixedBody(u64),
  ChunkedBody,
  Tunnel(TunnelKind),
  Reject,
}

impl<I> Http1FramingGuard<I> {
  pub(in crate::server) fn new(inner: I, max_header_bytes: usize) -> Self {
    Self {
      inner,
      max_header_bytes: max_header_bytes.max(1),
      buffered: Vec::with_capacity(1024),
      buffered_offset: 0,
      eof: false,
      state: ReadState::Head,
      reader_waker: None,
    }
  }

  fn available(&self) -> &[u8] {
    &self.buffered[self.buffered_offset..]
  }

  fn consume_into(&mut self, destination: &mut ReadBuf<'_>, limit: usize) -> usize {
    let copied = self
      .available()
      .len()
      .min(destination.remaining())
      .min(limit);
    destination.put_slice(&self.available()[..copied]);
    self.buffered_offset += copied;
    if self.buffered_offset == self.buffered.len() {
      self.buffered.clear();
      self.buffered_offset = 0;
    } else if self.buffered_offset >= READ_CHUNK_BYTES {
      self.buffered.drain(..self.buffered_offset);
      self.buffered_offset = 0;
    }
    copied
  }

  fn begin_rejection(&mut self, response: &'static [u8]) {
    self.buffered.clear();
    self.buffered_offset = 0;
    self.state = ReadState::Rejecting {
      response,
      offset: 0,
    };
  }

  fn remember_reader_waker(&mut self, waker: &Waker) {
    if self
      .reader_waker
      .as_ref()
      .is_none_or(|existing| !existing.will_wake(waker))
    {
      self.reader_waker = Some(waker.clone());
    }
  }

  fn wake_reader(&mut self) {
    if let Some(waker) = self.reader_waker.take() {
      waker.wake();
    }
  }

  fn observe_written_response(&mut self, bytes: &[u8]) {
    let outcome = match &mut self.state {
      ReadState::AwaitingTunnelResponse(parser) => parser.consume(bytes),
      _ => return,
    };
    self.state = match outcome {
      ResponseHeadOutcome::Pending => return,
      ResponseHeadOutcome::Accepted => ReadState::Passthrough,
      ResponseHeadOutcome::Rejected => ReadState::Head,
      ResponseHeadOutcome::Invalid => ReadState::Rejected,
    };
    self.wake_reader();
  }

  fn observe_written_vectored_response(&mut self, bufs: &[IoSlice<'_>], mut written: usize) {
    for buf in bufs {
      if written == 0 {
        break;
      }
      let observed = written.min(buf.len());
      self.observe_written_response(&buf[..observed]);
      written -= observed;
    }
  }

  fn fail_pending_response(&mut self) {
    if matches!(self.state, ReadState::AwaitingTunnelResponse(_)) {
      self.state = ReadState::Rejected;
      self.wake_reader();
    }
  }

  fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
  where
    I: AsyncRead + Unpin,
  {
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    let mut read = ReadBuf::new(&mut chunk);
    match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
      Poll::Ready(Ok(())) => {
        self.eof = read.filled().is_empty();
        self.buffered.extend_from_slice(read.filled());
        Poll::Ready(Ok(()))
      }
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    }
  }

  fn poll_rejection(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
  where
    I: AsyncWrite + Unpin,
  {
    loop {
      let ReadState::Rejecting { response, offset } = &mut self.state else {
        return Poll::Ready(Ok(()));
      };
      if *offset < response.len() {
        match Pin::new(&mut self.inner).poll_write(cx, &response[*offset..]) {
          Poll::Ready(Ok(0)) => {
            return Poll::Ready(Err(io::Error::new(
              io::ErrorKind::WriteZero,
              "HTTP/1 framing rejection response write made no progress",
            )));
          }
          Poll::Ready(Ok(written)) => *offset += written,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Pending => return Poll::Pending,
        }
      } else {
        match Pin::new(&mut self.inner).poll_flush(cx) {
          Poll::Ready(Ok(())) => {
            self.state = ReadState::Rejected;
            return Poll::Ready(Ok(()));
          }
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Pending => return Poll::Pending,
        }
      }
    }
  }
}

impl<I> AsyncRead for Http1FramingGuard<I>
where
  I: AsyncRead + AsyncWrite + Unpin,
{
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    destination: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let this = &mut *self;
    loop {
      if destination.remaining() == 0 {
        return Poll::Ready(Ok(()));
      }

      let state = std::mem::replace(&mut this.state, ReadState::Head);
      match state {
        rejecting @ ReadState::Rejecting { .. } => {
          this.state = rejecting;
          return this.poll_rejection(cx);
        }
        ReadState::Rejected => {
          this.state = ReadState::Rejected;
          return Poll::Ready(Ok(()));
        }
        awaiting @ ReadState::AwaitingTunnelResponse(_) => {
          this.state = awaiting;
          this.remember_reader_waker(cx.waker());
          return Poll::Pending;
        }
        ReadState::Passthrough => {
          this.state = ReadState::Passthrough;
          if !this.available().is_empty() {
            this.consume_into(destination, usize::MAX);
            return Poll::Ready(Ok(()));
          }
          return Pin::new(&mut this.inner).poll_read(cx, destination);
        }
        ReadState::ValidatedHead {
          mut remaining,
          next,
        } => {
          let copied = this.consume_into(destination, remaining);
          remaining -= copied;
          this.state = if remaining == 0 {
            match next {
              AfterHead::Head => ReadState::Head,
              AfterHead::FixedBody(length) => ReadState::FixedBody(length),
              AfterHead::ChunkedBody(decoder) => ReadState::ChunkedBody(decoder),
              AfterHead::AwaitingTunnelResponse(kind) => ReadState::AwaitingTunnelResponse(
                ResponseHeadParser::new(kind, this.max_header_bytes),
              ),
            }
          } else {
            ReadState::ValidatedHead { remaining, next }
          };
          return Poll::Ready(Ok(()));
        }
        ReadState::FixedBody(mut remaining) => {
          if remaining == 0 {
            this.state = ReadState::Head;
            continue;
          }
          if !this.available().is_empty() {
            let limit = usize::try_from(remaining).unwrap_or(usize::MAX);
            let copied = this.consume_into(destination, limit);
            remaining -= copied as u64;
            this.state = if remaining == 0 {
              ReadState::Head
            } else {
              ReadState::FixedBody(remaining)
            };
            return Poll::Ready(Ok(()));
          }
          this.state = ReadState::FixedBody(remaining);
        }
        ReadState::ChunkedBody(mut decoder) => {
          if !this.available().is_empty() {
            let progress = decoder.consume(this.available());
            if progress.invalid {
              this.begin_rejection(BAD_REQUEST_RESPONSE);
              continue;
            }
            this.state = if progress.complete {
              ReadState::Head
            } else {
              ReadState::ChunkedBody(decoder)
            };
            if progress.consumed != 0 {
              this.consume_into(destination, progress.consumed);
              return Poll::Ready(Ok(()));
            }
            continue;
          }
          this.state = ReadState::ChunkedBody(decoder);
        }
        ReadState::Head => {
          this.state = ReadState::Head;
          if let Some(end) = memchr::memmem::find(this.available(), b"\r\n\r\n") {
            let header_len = end + 4;
            if header_len > this.max_header_bytes {
              this.begin_rejection(HEADER_TOO_LARGE_RESPONSE);
              continue;
            }
            let next = match classify_head(&this.available()[..header_len]) {
              HeadDisposition::NoBody | HeadDisposition::FixedBody(0) => AfterHead::Head,
              HeadDisposition::FixedBody(length) => AfterHead::FixedBody(length),
              HeadDisposition::ChunkedBody => {
                AfterHead::ChunkedBody(ChunkDecoder::new(this.max_header_bytes))
              }
              HeadDisposition::Tunnel(kind) => AfterHead::AwaitingTunnelResponse(kind),
              HeadDisposition::Reject => {
                this.begin_rejection(BAD_REQUEST_RESPONSE);
                continue;
              }
            };
            this.state = ReadState::ValidatedHead {
              remaining: header_len,
              next,
            };
            continue;
          }
          if this.available().len() >= this.max_header_bytes {
            this.begin_rejection(HEADER_TOO_LARGE_RESPONSE);
            continue;
          }
        }
      }

      match this.poll_fill(cx) {
        Poll::Ready(Ok(())) if this.eof && this.available().is_empty() => {
          return Poll::Ready(Ok(()));
        }
        Poll::Ready(Ok(())) if this.eof => {
          this.begin_rejection(BAD_REQUEST_RESPONSE);
        }
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Pending => return Poll::Pending,
      }
    }
  }
}

impl<I> AsyncWrite for Http1FramingGuard<I>
where
  I: AsyncWrite + Unpin,
{
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    if matches!(
      self.state,
      ReadState::Rejecting { .. } | ReadState::Rejected
    ) {
      return Poll::Ready(Ok(buf.len()));
    }
    match Pin::new(&mut self.inner).poll_write(cx, buf) {
      Poll::Ready(Ok(written)) => {
        self.observe_written_response(&buf[..written]);
        Poll::Ready(Ok(written))
      }
      Poll::Ready(Err(error)) => {
        self.fail_pending_response();
        Poll::Ready(Err(error))
      }
      Poll::Pending => Poll::Pending,
    }
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    if matches!(
      self.state,
      ReadState::Rejecting { .. } | ReadState::Rejected
    ) {
      return Poll::Ready(Ok(bufs.iter().map(|buf| buf.len()).sum()));
    }
    match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
      Poll::Ready(Ok(written)) => {
        self.observe_written_vectored_response(bufs, written);
        Poll::Ready(Ok(written))
      }
      Poll::Ready(Err(error)) => {
        self.fail_pending_response();
        Poll::Ready(Err(error))
      }
      Poll::Pending => Poll::Pending,
    }
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    if matches!(self.state, ReadState::Rejected) {
      return Poll::Ready(Ok(()));
    }
    match Pin::new(&mut self.inner).poll_flush(cx) {
      Poll::Ready(Err(error)) => {
        self.fail_pending_response();
        Poll::Ready(Err(error))
      }
      result => result,
    }
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.fail_pending_response();
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

fn classify_head(head: &[u8]) -> HeadDisposition {
  let Some(lines) = head.strip_suffix(b"\r\n\r\n") else {
    return HeadDisposition::Reject;
  };
  let mut lines = lines.split(|byte| *byte == b'\n');
  let Some(request_line) = lines.next().map(trim_trailing_cr) else {
    return HeadDisposition::Reject;
  };
  let mut request_parts = request_line.split(|byte| *byte == b' ');
  let Some(method) = request_parts.next().filter(|part| !part.is_empty()) else {
    return HeadDisposition::Reject;
  };
  let Some(target) = request_parts.next().filter(|part| !part.is_empty()) else {
    return HeadDisposition::Reject;
  };
  let Some(version) = request_parts.next() else {
    return HeadDisposition::Reject;
  };
  if request_parts.next().is_some()
    || !method.iter().all(|byte| is_header_name_byte(*byte))
    || target.iter().any(|byte| byte.is_ascii_control())
    || !matches!(version, b"HTTP/1.0" | b"HTTP/1.1")
  {
    return HeadDisposition::Reject;
  }
  let connect = method.eq_ignore_ascii_case(b"CONNECT");
  let mut has_transfer_encoding = false;
  let mut final_transfer_coding: Option<&[u8]> = None;
  let mut content_length = None;
  let mut has_upgrade = false;
  let mut connection_upgrade = false;

  for line in lines {
    let line = trim_trailing_cr(line);
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
      return HeadDisposition::Reject;
    };
    let name = &line[..colon];
    let value = trim_ascii_whitespace(&line[colon + 1..]);
    if name.is_empty()
      || !name.iter().all(|byte| is_header_name_byte(*byte))
      || value
        .iter()
        .any(|byte| byte.is_ascii_control() && *byte != b'\t')
    {
      return HeadDisposition::Reject;
    }
    if name.eq_ignore_ascii_case(b"transfer-encoding") {
      has_transfer_encoding = true;
      for coding in value.split(|byte| *byte == b',') {
        let coding = trim_ascii_whitespace(
          coding
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default(),
        );
        if coding.is_empty() || !coding.iter().all(|byte| is_header_name_byte(*byte)) {
          return HeadDisposition::Reject;
        }
        if final_transfer_coding.is_some_and(|previous| previous.eq_ignore_ascii_case(b"chunked")) {
          return HeadDisposition::Reject;
        }
        final_transfer_coding = Some(coding);
      }
    } else if name.eq_ignore_ascii_case(b"content-length") {
      for item in value.split(|byte| *byte == b',') {
        let item = trim_ascii_whitespace(item);
        if item.is_empty() || !item.iter().all(u8::is_ascii_digit) {
          return HeadDisposition::Reject;
        }
        let Ok(item) = std::str::from_utf8(item) else {
          return HeadDisposition::Reject;
        };
        let Ok(length) = item.parse::<u64>() else {
          return HeadDisposition::Reject;
        };
        if content_length.is_some_and(|existing| existing != length) {
          return HeadDisposition::Reject;
        }
        content_length = Some(length);
      }
    } else if name.eq_ignore_ascii_case(b"upgrade") {
      has_upgrade = !value.is_empty();
    } else if name.eq_ignore_ascii_case(b"connection") {
      connection_upgrade |= value
        .split(|byte| *byte == b',')
        .any(|token| trim_ascii_whitespace(token).eq_ignore_ascii_case(b"upgrade"));
    }
  }

  if has_transfer_encoding && content_length.is_some() {
    return HeadDisposition::Reject;
  }
  if has_transfer_encoding
    && !final_transfer_coding.is_some_and(|coding| coding.eq_ignore_ascii_case(b"chunked"))
  {
    return HeadDisposition::Reject;
  }
  if connect || (has_upgrade && connection_upgrade) {
    if has_transfer_encoding || content_length.is_some_and(|length| length != 0) {
      return HeadDisposition::Reject;
    }
    return HeadDisposition::Tunnel(if connect {
      TunnelKind::Connect
    } else {
      TunnelKind::Upgrade
    });
  }
  if has_transfer_encoding {
    HeadDisposition::ChunkedBody
  } else if let Some(length) = content_length {
    HeadDisposition::FixedBody(length)
  } else {
    HeadDisposition::NoBody
  }
}

fn is_header_name_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'!'
        | b'#'
        | b'$'
        | b'%'
        | b'&'
        | b'\''
        | b'*'
        | b'+'
        | b'-'
        | b'.'
        | b'^'
        | b'_'
        | b'`'
        | b'|'
        | b'~'
    )
}

fn trim_trailing_cr(value: &[u8]) -> &[u8] {
  value.strip_suffix(b"\r").unwrap_or(value)
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
  while value.first().is_some_and(u8::is_ascii_whitespace) {
    value = &value[1..];
  }
  while value.last().is_some_and(u8::is_ascii_whitespace) {
    value = &value[..value.len() - 1];
  }
  value
}

struct ChunkDecoder {
  state: ChunkState,
  line: Vec<u8>,
  trailer_bytes: usize,
  max_line_bytes: usize,
}

enum ChunkState {
  Size,
  Data(u64),
  DataEnd(u8),
  Trailers,
}

struct ChunkProgress {
  consumed: usize,
  complete: bool,
  invalid: bool,
}

impl ChunkDecoder {
  fn new(max_line_bytes: usize) -> Self {
    Self {
      state: ChunkState::Size,
      line: Vec::with_capacity(32),
      trailer_bytes: 0,
      max_line_bytes,
    }
  }

  fn consume(&mut self, input: &[u8]) -> ChunkProgress {
    let mut offset = 0;
    while offset < input.len() {
      match &mut self.state {
        ChunkState::Size => {
          self.line.push(input[offset]);
          offset += 1;
          if self.line.len() > self.max_line_bytes {
            return ChunkProgress::invalid(offset);
          }
          if self.line.ends_with(b"\r\n") {
            let size = &self.line[..self.line.len() - 2];
            let size = size.split(|byte| *byte == b';').next().unwrap_or_default();
            let Ok(size) = std::str::from_utf8(trim_ascii_whitespace(size)) else {
              return ChunkProgress::invalid(offset);
            };
            let Ok(size) = u64::from_str_radix(size, 16) else {
              return ChunkProgress::invalid(offset);
            };
            self.line.clear();
            self.state = if size == 0 {
              ChunkState::Trailers
            } else {
              ChunkState::Data(size)
            };
          }
        }
        ChunkState::Data(remaining) => {
          let available = input.len() - offset;
          let consumed = available.min(usize::try_from(*remaining).unwrap_or(usize::MAX));
          offset += consumed;
          *remaining -= consumed as u64;
          if *remaining == 0 {
            self.state = ChunkState::DataEnd(0);
          }
        }
        ChunkState::DataEnd(progress) => {
          let expected = if *progress == 0 { b'\r' } else { b'\n' };
          if input[offset] != expected {
            return ChunkProgress::invalid(offset + 1);
          }
          offset += 1;
          *progress += 1;
          if *progress == 2 {
            self.state = ChunkState::Size;
          }
        }
        ChunkState::Trailers => {
          self.line.push(input[offset]);
          offset += 1;
          self.trailer_bytes += 1;
          if self.line.len() > self.max_line_bytes || self.trailer_bytes > self.max_line_bytes {
            return ChunkProgress::invalid(offset);
          }
          if self.line.ends_with(b"\r\n") {
            if self.line.len() == 2 {
              return ChunkProgress {
                consumed: offset,
                complete: true,
                invalid: false,
              };
            }
            let trailer = &self.line[..self.line.len() - 2];
            let Some(colon) = trailer.iter().position(|byte| *byte == b':') else {
              return ChunkProgress::invalid(offset);
            };
            if colon == 0
              || !trailer[..colon]
                .iter()
                .all(|byte| is_header_name_byte(*byte))
              || trailer[colon + 1..]
                .iter()
                .any(|byte| byte.is_ascii_control() && *byte != b'\t')
            {
              return ChunkProgress::invalid(offset);
            }
            self.line.clear();
          }
        }
      }
    }
    ChunkProgress {
      consumed: offset,
      complete: false,
      invalid: false,
    }
  }
}

impl ChunkProgress {
  fn invalid(consumed: usize) -> Self {
    Self {
      consumed,
      complete: false,
      invalid: true,
    }
  }
}

#[cfg(test)]
mod tests;
