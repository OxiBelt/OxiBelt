//! Incremental delimiter searches for append-only direct-H1 receive buffers.

/// Retains how much of an append-only buffer has already been searched.
#[derive(Debug, Default)]
pub(crate) struct AppendOnlyDelimiterSearch {
  searched_len: usize,
  found: Option<usize>,
}

impl AppendOnlyDelimiterSearch {
  /// Finds the first delimiter while rescanning only the suffix where a split
  /// delimiter can overlap newly appended bytes.
  pub(crate) fn find(&mut self, buffer: &[u8], delimiter: &[u8]) -> Option<usize> {
    if delimiter.is_empty() {
      return Some(0);
    }
    if buffer.len() < self.searched_len {
      self.searched_len = 0;
      self.found = None;
    }
    if let Some(found) = self.found {
      return Some(found);
    }
    let overlap = delimiter.len() - 1;
    let search_start = self.searched_len.saturating_sub(overlap);
    let found =
      find_delimiter(&buffer[search_start..], delimiter).map(|position| search_start + position);
    self.searched_len = buffer.len();
    self.found = found;
    found
  }
}

/// Uses `memchr`'s safe architecture-specific dispatch to find a byte string.
pub(crate) fn find_delimiter(buffer: &[u8], delimiter: &[u8]) -> Option<usize> {
  memchr::memmem::find(buffer, delimiter)
}

pub(crate) fn response_header_end(
  search: &mut AppendOnlyDelimiterSearch,
  buffer: &[u8],
) -> Option<usize> {
  search
    .find(buffer, b"\r\n\r\n")
    .map(|position| position + 4)
}

pub(crate) fn crlf(search: &mut AppendOnlyDelimiterSearch, buffer: &[u8]) -> Option<usize> {
  search.find(buffer, b"\r\n")
}

pub(crate) fn trailer_end(search: &mut AppendOnlyDelimiterSearch, buffer: &[u8]) -> Option<usize> {
  if buffer.starts_with(b"\r\n") {
    Some(2)
  } else {
    response_header_end(search, buffer)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn scalar_find(buffer: &[u8], delimiter: &[u8]) -> Option<usize> {
    if delimiter.is_empty() {
      return Some(0);
    }
    buffer
      .windows(delimiter.len())
      .position(|window| window == delimiter)
  }

  #[test]
  fn memchr_search_matches_scalar_reference() {
    let cases: &[(&[u8], &[u8])] = &[
      (b"", b"\r\n"),
      (b"payload", b""),
      (b"\r\n", b"\r\n"),
      (b"x\r\n", b"\r\n"),
      (b"header\r\n\r\nbody", b"\r\n\r\n"),
      (b"missing", b"\r\n\r\n"),
    ];

    for (buffer, delimiter) in cases {
      assert_eq!(
        find_delimiter(buffer, delimiter),
        scalar_find(buffer, delimiter)
      );
    }
  }

  #[test]
  fn incremental_search_finds_delimiters_split_at_every_append_boundary() {
    let full = b"prefix\r\n\r\nbody";
    for split in 0..=full.len() {
      let mut buffer = full[..split].to_vec();
      let mut search = AppendOnlyDelimiterSearch::default();
      assert_eq!(
        search.find(&buffer, b"\r\n\r\n"),
        scalar_find(&buffer, b"\r\n\r\n")
      );
      buffer.extend_from_slice(&full[split..]);
      assert_eq!(
        search.find(&buffer, b"\r\n\r\n"),
        scalar_find(&buffer, b"\r\n\r\n")
      );
    }
  }

  #[test]
  fn incremental_search_preserves_first_match_and_handles_buffer_reset() {
    let mut search = AppendOnlyDelimiterSearch::default();
    assert_eq!(search.find(b"one\r\n\r\ntwo\r\n\r\n", b"\r\n\r\n"), Some(3));
    assert_eq!(search.find(b"x\r\n\r\n", b"\r\n\r\n"), Some(1));
  }

  #[test]
  fn trailer_search_preserves_empty_trailer_marker() {
    let mut search = AppendOnlyDelimiterSearch::default();
    assert_eq!(trailer_end(&mut search, b"\r\nbody"), Some(2));
  }
}
