use bytes::Bytes;
use http::{HeaderMap, StatusCode};

#[derive(Clone, Debug)]
pub(crate) struct StaticResponseHeadBytes {
  keep_alive: Bytes,
  close: Bytes,
}

impl StaticResponseHeadBytes {
  pub(crate) fn new(status: StatusCode, headers: &HeaderMap) -> Self {
    Self {
      keep_alive: Bytes::from(serialize_static_response_head(status, headers, true)),
      close: Bytes::from(serialize_static_response_head(status, headers, false)),
    }
  }

  pub(crate) fn get(&self, keep_alive: bool) -> &Bytes {
    if keep_alive {
      &self.keep_alive
    } else {
      &self.close
    }
  }
}

fn serialize_static_response_head(
  status: StatusCode,
  headers: &HeaderMap,
  keep_alive: bool,
) -> Vec<u8> {
  let mut output = Vec::with_capacity(256 + headers.len() * 48);
  output.extend_from_slice(b"HTTP/1.1 ");
  append_u16_decimal(&mut output, status.as_u16());
  output.push(b' ');
  output.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
  output.extend_from_slice(b"\r\n");
  for (name, value) in headers {
    output.extend_from_slice(name.as_str().as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(b"\r\n");
  }
  if keep_alive {
    output.extend_from_slice(b"Connection: keep-alive\r\n");
  } else {
    output.extend_from_slice(b"Connection: close\r\n");
  }
  output.extend_from_slice(b"\r\n");
  output
}

fn append_u16_decimal(output: &mut Vec<u8>, value: u16) {
  let mut buf = [0_u8; 5];
  let mut value = value;
  let mut index = buf.len();
  loop {
    index -= 1;
    buf[index] = b'0' + (value % 10) as u8;
    value /= 10;
    if value == 0 {
      break;
    }
  }
  output.extend_from_slice(&buf[index..]);
}
