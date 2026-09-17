//! draft-ietf-webtrans-http2-15 capsule framing. Large values are delivered in chunks.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;

pub(crate) const VARINT_MAX: u64 = (1_u64 << 62) - 1;
pub(crate) const PADDING: u64 = 0x190b4d38;
pub(crate) const RESET_STREAM: u64 = 0x190b4d39;
pub(crate) const STOP_SENDING: u64 = 0x190b4d3a;
pub(crate) const STREAM_FIN: u64 = 0x190b4d3b;
pub(crate) const STREAM: u64 = 0x190b4d3c;
pub(crate) const MAX_DATA: u64 = 0x190b4d3d;
pub(crate) const MAX_STREAM_DATA: u64 = 0x190b4d3e;
pub(crate) const MAX_STREAMS_BIDI: u64 = 0x190b4d3f;
pub(crate) const MAX_STREAMS_UNI: u64 = 0x190b4d40;
pub(crate) const DATA_BLOCKED: u64 = 0x190b4d41;
pub(crate) const STREAM_DATA_BLOCKED: u64 = 0x190b4d42;
pub(crate) const STREAMS_BLOCKED_BIDI: u64 = 0x190b4d43;
pub(crate) const STREAMS_BLOCKED_UNI: u64 = 0x190b4d44;
pub(crate) const DATAGRAM: u64 = 0;
pub(crate) const CLOSE_SESSION: u64 = 0x2843;
pub(crate) const DRAIN_SESSION: u64 = 0x78ae;
pub(crate) const QUANTUM: usize = 16 * 1024;
pub(crate) const MAX_DATAGRAM: usize = 65_535;
pub(crate) const MAX_CLOSE_REASON: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Event {
  Stream {
    id: u64,
    data: Bytes,
    fin: bool,
    start: bool,
  },
  Control {
    kind: u64,
    values: Vec<u64>,
  },
  Datagram(Bytes),
  Close {
    code: u32,
    reason: String,
  },
  Drain,
}

#[derive(Default)]
pub(crate) struct Decoder {
  header: BytesMut,
  capsule: Option<Capsule>,
}

struct Capsule {
  kind: u64,
  remaining: u64,
  small: BytesMut,
  stream_id: Option<u64>,
  started: bool,
  discard: bool,
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
  let first = *bytes.first()?;
  let size = 1_usize << (first >> 6);
  if bytes.len() < size {
    return None;
  }
  let mut value = u64::from(first & 0x3f);
  for byte in &bytes[1..size] {
    value = (value << 8) | u64::from(*byte);
  }
  Some((value, size))
}

pub(crate) fn put_varint(out: &mut BytesMut, value: u64) -> io::Result<()> {
  if value < (1 << 6) {
    out.put_u8(value as u8);
  } else if value < (1 << 14) {
    out.put_u16(value as u16 | 0x4000);
  } else if value < (1 << 30) {
    out.put_u32(value as u32 | 0x8000_0000);
  } else if value <= VARINT_MAX {
    out.put_u64(value | 0xc000_0000_0000_0000);
  } else {
    return Err(invalid("WebTransport integer overflow"));
  }
  Ok(())
}

pub(crate) fn encode(kind: u64, payload: &[u8]) -> io::Result<Bytes> {
  let mut out = BytesMut::with_capacity(16 + payload.len());
  put_varint(&mut out, kind)?;
  put_varint(&mut out, payload.len() as u64)?;
  out.extend_from_slice(payload);
  Ok(out.freeze())
}

pub(crate) fn control(kind: u64, values: &[u64]) -> io::Result<Bytes> {
  let mut payload = BytesMut::with_capacity(values.len() * 8);
  for value in values {
    put_varint(&mut payload, *value)?;
  }
  encode(kind, &payload)
}

pub(crate) fn stream(id: u64, data: &[u8], fin: bool) -> io::Result<Bytes> {
  let mut payload = BytesMut::with_capacity(8 + data.len());
  put_varint(&mut payload, id)?;
  payload.extend_from_slice(data);
  encode(if fin { STREAM_FIN } else { STREAM }, &payload)
}

pub(crate) fn close(code: u32, reason: &[u8]) -> io::Result<Bytes> {
  let reason = std::str::from_utf8(reason).map_err(|_| invalid("invalid close reason UTF-8"))?;
  let mut end = reason.len().min(MAX_CLOSE_REASON);
  while !reason.is_char_boundary(end) {
    end -= 1;
  }
  let mut payload = BytesMut::with_capacity(4 + end);
  payload.put_u32(code);
  payload.extend_from_slice(&reason.as_bytes()[..end]);
  encode(CLOSE_SESSION, &payload)
}

fn control_values(kind: u64) -> Option<usize> {
  match kind {
    RESET_STREAM => Some(3),
    STOP_SENDING | MAX_STREAM_DATA | STREAM_DATA_BLOCKED => Some(2),
    MAX_DATA | MAX_STREAMS_BIDI | MAX_STREAMS_UNI | DATA_BLOCKED | STREAMS_BLOCKED_BIDI
    | STREAMS_BLOCKED_UNI => Some(1),
    _ => None,
  }
}

impl Decoder {
  /// Yields at most one bounded event and consumes input incrementally.
  pub(crate) fn next(&mut self, input: &mut Bytes) -> io::Result<Option<Event>> {
    loop {
      if self.capsule.is_none() {
        let parsed = read_varint(&self.header).and_then(|(kind, n)| {
          read_varint(&self.header[n..]).map(|(length, m)| (kind, length, n + m))
        });
        if let Some((kind, length, header_len)) = parsed {
          self.header.advance(header_len);
          let discard = match kind {
            STREAM | STREAM_FIN => false,
            DATAGRAM => length > MAX_DATAGRAM as u64,
            CLOSE_SESSION => {
              if !(4..=4 + MAX_CLOSE_REASON as u64).contains(&length) {
                return Err(invalid("invalid WebTransport close length"));
              }
              false
            }
            DRAIN_SESSION => {
              if length != 0 {
                return Err(invalid("nonempty drain capsule"));
              }
              false
            }
            _ if control_values(kind).is_some() => {
              if length > 24 {
                return Err(invalid("oversized WebTransport control"));
              }
              false
            }
            PADDING => true,
            _ => true,
          };
          self.capsule = Some(Capsule {
            kind,
            remaining: length,
            small: BytesMut::new(),
            stream_id: None,
            started: false,
            discard,
          });
        } else {
          if input.is_empty() {
            return Ok(None);
          }
          if self.header.len() >= 16 {
            return Err(invalid("invalid capsule header"));
          }
          self.header.extend_from_slice(&input.split_to(1));
          continue;
        }
      }
      let Some(capsule) = self.capsule.as_mut() else {
        return Err(invalid("missing capsule"));
      };
      if capsule.kind == STREAM || capsule.kind == STREAM_FIN {
        while capsule.stream_id.is_none() {
          if let Some((id, size)) = read_varint(&capsule.small) {
            capsule.small.advance(size);
            capsule.stream_id = Some(id);
            break;
          }
          if capsule.remaining == 0 {
            return Err(invalid("missing WebTransport stream ID"));
          }
          if input.is_empty() {
            return Ok(None);
          }
          capsule.small.extend_from_slice(&input.split_to(1));
          capsule.remaining -= 1;
        }
        if input.is_empty() && capsule.remaining != 0 {
          return Ok(None);
        }
        let count = capsule.remaining.min(input.len().min(QUANTUM) as u64) as usize;
        let data = input.split_to(count);
        capsule.remaining -= count as u64;
        let id = capsule
          .stream_id
          .ok_or_else(|| invalid("missing WebTransport stream ID"))?;
        let start = !capsule.started;
        capsule.started = true;
        let fin = capsule.kind == STREAM_FIN && capsule.remaining == 0;
        if capsule.remaining == 0 {
          self.capsule = None;
        }
        return Ok(Some(Event::Stream {
          id,
          data,
          fin,
          start,
        }));
      }
      if capsule.remaining != 0 {
        if input.is_empty() {
          return Ok(None);
        }
        let count = capsule.remaining.min(input.len() as u64) as usize;
        let bytes = input.split_to(count);
        capsule.remaining -= count as u64;
        if !capsule.discard {
          capsule.small.extend_from_slice(&bytes);
        }
      }
      if capsule.remaining != 0 {
        continue;
      }
      let capsule = self
        .capsule
        .take()
        .ok_or_else(|| invalid("missing capsule"))?;
      if capsule.discard {
        continue;
      }
      let event = match capsule.kind {
        DATAGRAM => Event::Datagram(capsule.small.freeze()),
        DRAIN_SESSION => Event::Drain,
        CLOSE_SESSION => {
          let mut bytes = capsule.small;
          let code = bytes.get_u32();
          let reason = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("invalid close reason UTF-8"))?
            .to_owned();
          Event::Close { code, reason }
        }
        kind => {
          let count = control_values(kind).ok_or_else(|| invalid("unknown control capsule"))?;
          let mut remaining = &capsule.small[..];
          let mut values = Vec::with_capacity(count);
          for _ in 0..count {
            let (value, size) =
              read_varint(remaining).ok_or_else(|| invalid("truncated control capsule"))?;
            remaining = &remaining[size..];
            values.push(value);
          }
          if !remaining.is_empty() {
            return Err(invalid("trailing control capsule bytes"));
          }
          Event::Control { kind, values }
        }
      };
      return Ok(Some(event));
    }
  }

  pub(crate) fn finish(&self) -> io::Result<()> {
    if self.capsule.is_some() || !self.header.is_empty() {
      Err(invalid("truncated WebTransport capsule stream"))
    } else {
      Ok(())
    }
  }
}

#[cfg(test)]
mod tests;
