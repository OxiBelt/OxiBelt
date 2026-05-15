use std::path::{Path, PathBuf};

pub(crate) fn resolve_request_path(
  root: &Path,
  route_prefix: &str,
  request_path: &str,
) -> Result<PathBuf, StaticPathError> {
  let relative = if route_prefix == "/" {
    request_path.trim_start_matches('/')
  } else if request_path == route_prefix {
    ""
  } else {
    request_path
      .strip_prefix(route_prefix)
      .ok_or(StaticPathError::NotFound)?
      .trim_start_matches('/')
  };

  let mut candidate = root.to_path_buf();
  for raw_segment in relative.split('/') {
    if raw_segment.is_empty() {
      continue;
    }
    let segment = percent_decode_segment(raw_segment)?;
    if segment == "." || segment == ".." {
      return Err(StaticPathError::Forbidden);
    }
    if segment
      .bytes()
      .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
    {
      return Err(StaticPathError::Invalid);
    }
    candidate.push(segment);
  }

  let canonical = match candidate.canonicalize() {
    Ok(path) => path,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Err(StaticPathError::NotFound);
    }
    Err(_) => return Err(StaticPathError::Forbidden),
  };
  if !canonical.starts_with(root) {
    return Err(StaticPathError::Forbidden);
  }
  Ok(canonical)
}

fn percent_decode_segment(segment: &str) -> Result<String, StaticPathError> {
  let bytes = segment.as_bytes();
  let mut decoded = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] != b'%' {
      decoded.push(bytes[index]);
      index += 1;
      continue;
    }
    if index + 2 >= bytes.len() {
      return Err(StaticPathError::Invalid);
    }
    let high = hex_value(bytes[index + 1]).ok_or(StaticPathError::Invalid)?;
    let low = hex_value(bytes[index + 2]).ok_or(StaticPathError::Invalid)?;
    decoded.push((high << 4) | low);
    index += 3;
  }
  String::from_utf8(decoded).map_err(|_| StaticPathError::Invalid)
}

fn hex_value(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum StaticPathError {
  NotFound,
  Forbidden,
  Invalid,
}
