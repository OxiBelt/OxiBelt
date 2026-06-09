//! Cache entry body references used by local and shared cache lookups.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};

#[derive(Debug, Clone)]
pub struct CacheBodyFile {
  pub path: PathBuf,
  pub offset: u64,
  pub len: usize,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
  pub status: StatusCode,
  pub headers: HeaderMap,
  pub body: Bytes,
  pub body_file: Option<CacheBodyFile>,
  pub(crate) _body_file_guard: Option<Arc<tempfile::NamedTempFile>>,
  pub body_len: usize,
  pub stored_at: SystemTime,
}

impl CacheEntry {
  pub fn memory(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
    let body_len = body.len();
    Self {
      status,
      headers,
      body,
      body_file: None,
      _body_file_guard: None,
      body_len,
      stored_at: SystemTime::now(),
    }
  }

  pub(crate) fn with_stored_at(mut self, stored_at: SystemTime) -> Self {
    self.stored_at = stored_at;
    self
  }

  pub(crate) fn file(
    status: StatusCode,
    headers: HeaderMap,
    path: PathBuf,
    body_len: usize,
    stored_at: SystemTime,
  ) -> Self {
    Self {
      status,
      headers,
      body: Bytes::new(),
      body_file: Some(CacheBodyFile {
        path,
        offset: 0,
        len: body_len,
      }),
      _body_file_guard: None,
      body_len,
      stored_at,
    }
  }

  pub(crate) fn temporary_file(
    status: StatusCode,
    headers: HeaderMap,
    file: tempfile::NamedTempFile,
    body_len: usize,
    stored_at: SystemTime,
  ) -> Self {
    let path = file.path().to_path_buf();
    Self {
      status,
      headers,
      body: Bytes::new(),
      body_file: Some(CacheBodyFile {
        path,
        offset: 0,
        len: body_len,
      }),
      _body_file_guard: Some(Arc::new(file)),
      body_len,
      stored_at,
    }
  }

  pub fn body_len(&self) -> usize {
    self
      .body_file
      .as_ref()
      .map(|file| file.len)
      .unwrap_or_else(|| self.body.len())
  }

  pub(crate) fn with_body(self, body: Bytes) -> Self {
    Self {
      body_file: None,
      _body_file_guard: None,
      body_len: body.len(),
      body,
      ..self
    }
  }

  pub(super) fn with_file_range(self, offset: u64, len: usize) -> Self {
    let mut entry = self;
    let Some(file) = entry.body_file.take() else {
      return entry;
    };
    entry.body_file = Some(CacheBodyFile {
      path: file.path,
      offset: file.offset.saturating_add(offset),
      len,
    });
    entry.body_len = len;
    entry.body = Bytes::new();
    entry
  }
}
