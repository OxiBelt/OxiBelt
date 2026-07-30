//! Safe SIMD-dispatched delimiter helper retained for library benchmarks.

pub(crate) fn find_delimiter(buffer: &[u8], delimiter: &[u8]) -> Option<usize> {
  memchr::memmem::find(buffer, delimiter)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn delimiter_search_handles_empty_matches_and_missing_values() {
    assert_eq!(find_delimiter(b"header\r\n\r\nbody", b"\r\n\r\n"), Some(6));
    assert_eq!(find_delimiter(b"payload", b""), Some(0));
    assert_eq!(find_delimiter(b"payload", b"\r\n"), None);
  }
}
