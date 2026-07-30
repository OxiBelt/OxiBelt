use super::types::ResponseProtocolFailureReason;

pub(super) fn parse_chunk_size_line(
  line: &[u8],
  max_extension_bytes: usize,
) -> Result<u64, ResponseProtocolFailureReason> {
  let (size, extension) = match line.iter().position(|byte| *byte == b';') {
    Some(index) => (&line[..index], Some(&line[index + 1..])),
    None => (line, None),
  };
  if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
    return Err(ResponseProtocolFailureReason::InvalidChunkSize);
  }
  let mut parsed = 0u64;
  for byte in size {
    let digit = match byte {
      b'0'..=b'9' => u64::from(*byte - b'0'),
      b'a'..=b'f' => u64::from(*byte - b'a' + 10),
      b'A'..=b'F' => u64::from(*byte - b'A' + 10),
      _ => return Err(ResponseProtocolFailureReason::InvalidChunkSize),
    };
    parsed = parsed
      .checked_mul(16)
      .and_then(|value| value.checked_add(digit))
      .ok_or(ResponseProtocolFailureReason::InvalidChunkSize)?;
  }
  if let Some(extension) = extension {
    if extension.len() > max_extension_bytes {
      return Err(ResponseProtocolFailureReason::ChunkExtensionTooLarge);
    }
    validate_chunk_extensions(extension)?;
  }
  Ok(parsed)
}

fn validate_chunk_extensions(mut bytes: &[u8]) -> Result<(), ResponseProtocolFailureReason> {
  loop {
    let name_end = bytes
      .iter()
      .position(|byte| *byte == b'=' || *byte == b';')
      .unwrap_or(bytes.len());
    if name_end == 0 || !bytes[..name_end].iter().copied().all(is_token_byte) {
      return Err(ResponseProtocolFailureReason::InvalidChunkExtension);
    }
    bytes = &bytes[name_end..];
    if bytes.first() == Some(&b'=') {
      bytes = &bytes[1..];
      let consumed =
        parse_token_or_quoted(bytes).ok_or(ResponseProtocolFailureReason::InvalidChunkExtension)?;
      bytes = &bytes[consumed..];
    }
    if bytes.is_empty() {
      return Ok(());
    }
    if bytes.first() != Some(&b';') {
      return Err(ResponseProtocolFailureReason::InvalidChunkExtension);
    }
    bytes = &bytes[1..];
  }
}

fn parse_token_or_quoted(bytes: &[u8]) -> Option<usize> {
  if bytes.first() == Some(&b'"') {
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(1) {
      if escaped {
        if (*byte < b' ' && *byte != b'\t') || *byte == 0x7f {
          return None;
        }
        escaped = false;
      } else if *byte == b'\\' {
        escaped = true;
      } else if *byte == b'"' {
        return Some(index + 1);
      } else if (*byte < b' ' && *byte != b'\t') || *byte == 0x7f {
        return None;
      }
    }
    return None;
  }
  let len = bytes
    .iter()
    .copied()
    .take_while(|byte| is_token_byte(*byte))
    .count();
  (len > 0).then_some(len)
}

fn is_token_byte(byte: u8) -> bool {
  matches!(
    byte,
    b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z'
      | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'
  )
}
