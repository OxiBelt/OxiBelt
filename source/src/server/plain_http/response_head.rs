use http::{HeaderMap, StatusCode};

pub(super) fn response_head_bytes(
  status: StatusCode,
  headers: &HeaderMap,
  keep_alive: bool,
  output: &mut Vec<u8>,
) {
  output.clear();
  output.reserve(256 + headers.len() * 48);
  output.extend_from_slice(b"HTTP/1.1 ");
  append_u16_decimal(output, status.as_u16());
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
