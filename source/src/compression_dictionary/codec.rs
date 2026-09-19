//! RFC 9842 dictionary-content-coding codecs.
//!
//! This module deliberately has no HTTP or configuration dependency.  The
//! caller supplies the already-selected dictionary and puts blocking work on
//! its own bounded worker pool.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

mod allocation;
use allocation::BoundedAlloc;
use brotli::{Allocator, BrotliDecompressStream, BrotliResult, BrotliState, SliceWrapperMut};
use sha2::{Digest, Sha256};
use zstd::stream::raw::{Decoder as ZstdDecoder, Operation};

/// The two dictionary-aware content codings registered by RFC 9842.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DictionaryCoding {
  /// Dictionary-Compressed Brotli (`dcb`).
  Dcb,
  /// Dictionary-Compressed Zstandard (`dcz`).
  Dcz,
}

/// The largest raw dictionary accepted by the Shared Brotli implementation.
///
/// RFC 9842 requires a `dcb` implementation to support a 16 MiB window.  The
/// Shared Brotli raw-dictionary API reserves 16 bytes from that address space,
/// so accepting a larger dictionary would make its behaviour codec-dependent.
pub const MAX_RAW_DICTIONARY_BYTES: usize = 16 * 1024 * 1024 - 16;

/// Conservative per-operation working-set reservations used by the runtime
/// when converting a profile's total codec-memory budget into permits.
///
/// `dcb` uses the shared bounded allocator with a 384 MiB live-heap ceiling;
/// the remaining envelope covers the pinned raw prefix and fixed I/O buffers.
/// Zstandard uses bounded window/hash/chain logs, no worker arenas, and raw
/// prefixes smaller than 16 MiB. Its 512 MiB envelope conservatively covers
/// the maximum 128 MiB window plus the explicitly bounded tables and buffers.
/// A runtime rejects profiles below one envelope and limits whole-job permits
/// by both configured concurrency and total memory divided by this value.
pub const DCB_MAX_WORKING_SET_BYTES: u64 = 512 * 1024 * 1024;
pub const DCZ_MAX_WORKING_SET_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(test)]
pub const fn max_working_set_bytes(coding: DictionaryCoding) -> u64 {
  match coding {
    DictionaryCoding::Dcb => DCB_MAX_WORKING_SET_BYTES,
    DictionaryCoding::Dcz => DCZ_MAX_WORKING_SET_BYTES,
  }
}

pub const fn maximum_working_set_bytes() -> u64 {
  if DCB_MAX_WORKING_SET_BYTES > DCZ_MAX_WORKING_SET_BYTES {
    DCB_MAX_WORKING_SET_BYTES
  } else {
    DCZ_MAX_WORKING_SET_BYTES
  }
}

pub const DCB_PRELUDE_LEN: usize = 36;
pub const DCZ_PRELUDE_LEN: usize = 40;

const DCB_MAGIC: [u8; 4] = [0xff, 0x44, 0x43, 0x42];
const DCZ_MAGIC: [u8; 8] = [0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00];
const BROTLI_LGWIN: u32 = 24;
const BROTLI_BUFFER_BYTES: usize = 16 * 1024;
const ZSTD_BUFFER_BYTES: usize = 16 * 1024;
const ZSTD_MAX_WINDOW_LOG: u32 = 27;
const ZSTD_MAX_HASH_LOG: u32 = 20;
const ZSTD_MAX_CHAIN_LOG: u32 = 20;

/// Cooperative resource limits for a bounded decode operation.
///
/// The checks run before each read, codec step, and output write.  A blocking
/// `Read` or `Write` implementation itself cannot be interrupted by this
/// synchronous API; callers that need that property must provide a reader or
/// writer with its own I/O deadline.
#[derive(Clone, Debug)]
pub struct DecodeLimits {
  pub max_decoded_bytes: usize,
  pub max_expansion_ratio: usize,
  pub deadline: Option<Instant>,
  pub cancel: Option<Arc<AtomicBool>>,
}

impl DecodeLimits {
  #[cfg(any(test, feature = "fuzzing"))]
  pub fn new(max_decoded_bytes: usize, max_expansion_ratio: usize) -> Self {
    Self {
      max_decoded_bytes,
      max_expansion_ratio,
      deadline: None,
      cancel: None,
    }
  }
}

/// Cooperative controls for a bounded encode operation.
///
/// `compression_level` is deliberately limited to the portable `1..=9`
/// range.  The same numeric level is used for Brotli quality and Zstandard
/// compression, avoiding a content-coding-specific policy knob in callers.
#[derive(Clone, Debug)]
pub struct EncodeOptions {
  pub compression_level: i32,
  pub deadline: Option<Instant>,
  pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for EncodeOptions {
  fn default() -> Self {
    Self {
      compression_level: 3,
      deadline: None,
      cancel: None,
    }
  }
}

/// Encodes an RFC 9842 `dcb` or `dcz` stream from `input` into `output`.
///
/// The prelude always identifies the exact raw dictionary by SHA-256.  `dcb`
/// uses Shared Brotli's raw prefix API with the RFC's maximum `lgwin` of 24;
/// `dcz` uses Zstandard's raw-prefix API rather than dictionary loading.
#[cfg(test)]
pub fn encode<R: Read, W: Write>(
  coding: DictionaryCoding,
  dictionary: &[u8],
  input: R,
  output: W,
) -> io::Result<W> {
  encode_with_options(coding, dictionary, input, output, &EncodeOptions::default())
}

/// As [`encode`], with an explicit portable compression level and cooperative
/// cancellation/deadline controls.
pub fn encode_with_options<R: Read, W: Write>(
  coding: DictionaryCoding,
  dictionary: &[u8],
  input: R,
  output: W,
  options: &EncodeOptions,
) -> io::Result<W> {
  validate_dictionary(dictionary)?;
  validate_encode_options(options)?;
  let mut input = CheckedEncodeReader {
    inner: input,
    options,
  };
  let mut output = CheckedEncodeWriter {
    inner: output,
    options,
  };
  output.write_all(&prelude(coding, dictionary))?;

  match coding {
    DictionaryCoding::Dcb => encode_brotli(
      dictionary,
      &mut input,
      &mut output,
      options.compression_level,
    )?,
    DictionaryCoding::Dcz => encode_zstd(
      dictionary,
      &mut input,
      &mut output,
      options.compression_level,
    )?,
  }
  output.flush()?;
  Ok(output.inner)
}

/// Strictly decodes one or more complete RFC 9842 codec frames.
///
/// The fixed prelude, including the dictionary digest, is consumed and
/// validated before a Brotli or Zstandard context is constructed.  Any
/// truncated data, trailing non-frame data, resource-limit breach, expired
/// deadline, or cancellation request is an error.
pub fn decode<R: Read, W: Write>(
  coding: DictionaryCoding,
  dictionary: &[u8],
  mut input: R,
  mut output: W,
  limits: &DecodeLimits,
) -> io::Result<W> {
  validate_dictionary(dictionary)?;
  validate_limits(limits)?;
  read_and_validate_prelude(coding, dictionary, &mut input, limits)?;

  let compressed = Arc::new(AtomicUsize::new(0));
  let mut input = CountingReader::new(&mut input, compressed.clone());
  let mut budget = DecodeBudget::new(limits, compressed);
  match coding {
    DictionaryCoding::Dcb => decode_brotli(dictionary, &mut input, &mut output, &mut budget)?,
    DictionaryCoding::Dcz => decode_zstd(dictionary, &mut input, &mut output, &mut budget)?,
  }
  output.flush()?;
  Ok(output)
}

/// Convenience helper for a bounded upload/body worker.
///
/// Owning the dictionary in an `Arc` makes the worker's lifetime independent
/// of the runtime snapshot that selected it.  The codec receives a normal
/// slice only after the worker owns that allocation; no self-referential
/// adapter or unsafe lifetime extension is needed.
pub fn decode_bounded(
  coding: DictionaryCoding,
  dictionary: Arc<[u8]>,
  encoded: &[u8],
  limits: &DecodeLimits,
) -> io::Result<Vec<u8>> {
  let mut decoded = Vec::new();
  decode(
    coding,
    dictionary.as_ref(),
    io::Cursor::new(encoded),
    &mut decoded,
    limits,
  )?;
  Ok(decoded)
}

fn validate_dictionary(dictionary: &[u8]) -> io::Result<()> {
  if dictionary.len() > MAX_RAW_DICTIONARY_BYTES {
    return invalid("raw compression dictionary exceeds the 16 MiB minus 16 byte limit");
  }
  Ok(())
}

fn validate_limits(limits: &DecodeLimits) -> io::Result<()> {
  if limits.max_decoded_bytes == 0 || limits.max_expansion_ratio == 0 {
    return invalid("decoded byte and expansion-ratio limits must be greater than zero");
  }
  check_control(limits)
}

fn validate_encode_options(options: &EncodeOptions) -> io::Result<()> {
  if !(1..=9).contains(&options.compression_level) {
    return invalid("dictionary encoding compression level must be in 1..=9");
  }
  check_encode_control(options)
}

fn prelude(coding: DictionaryCoding, dictionary: &[u8]) -> Vec<u8> {
  let magic: &[u8] = match coding {
    DictionaryCoding::Dcb => &DCB_MAGIC,
    DictionaryCoding::Dcz => &DCZ_MAGIC,
  };
  let mut output = Vec::with_capacity(magic.len() + 32);
  output.extend_from_slice(magic);
  output.extend_from_slice(&Sha256::digest(dictionary));
  output
}

fn read_and_validate_prelude<R: Read>(
  coding: DictionaryCoding,
  dictionary: &[u8],
  input: &mut R,
  limits: &DecodeLimits,
) -> io::Result<()> {
  let expected = prelude(coding, dictionary);
  let mut actual = vec![0_u8; expected.len()];
  let mut offset = 0;
  while offset != actual.len() {
    check_control(limits)?;
    let read = input.read(&mut actual[offset..])?;
    if read == 0 {
      return invalid("truncated RFC 9842 dictionary-coding prelude");
    }
    offset += read;
  }
  if actual != expected {
    return invalid("RFC 9842 dictionary-coding prelude does not match the supplied dictionary");
  }
  Ok(())
}

fn encode_brotli<R: Read, W: Write>(
  dictionary: &[u8],
  input: &mut R,
  output: &mut W,
  level: i32,
) -> io::Result<()> {
  allocation::catch(|| encode_brotli_inner(dictionary, input, output, level))
}
fn decode_brotli<R: Read, W: Write>(
  dictionary: &[u8],
  input: &mut R,
  output: &mut W,
  budget: &mut DecodeBudget<'_>,
) -> io::Result<()> {
  allocation::catch(|| decode_brotli_inner(dictionary, input, output, budget))
}

fn encode_brotli_inner<R: Read, W: Write>(
  dictionary: &[u8],
  input: &mut R,
  output: &mut W,
  compression_level: i32,
) -> io::Result<()> {
  let params = brotli::enc::backward_references::BrotliEncoderParams {
    quality: compression_level,
    lgwin: BROTLI_LGWIN as i32,
    ..Default::default()
  };
  let mut input_buffer = [0_u8; BROTLI_BUFFER_BYTES];
  let mut output_buffer = [0_u8; BROTLI_BUFFER_BYTES];
  let mut reader = brotli::IoReaderWrapper(input);
  let mut writer = brotli::IoWriterWrapper(output);
  brotli::BrotliCompressCustomIoCustomDict(
    &mut reader,
    &mut writer,
    &mut input_buffer,
    &mut output_buffer,
    &params,
    BoundedAlloc::default(),
    &mut |_, _, _, _| {},
    dictionary,
    io::Error::new(
      io::ErrorKind::UnexpectedEof,
      "Brotli input ended unexpectedly",
    ),
  )
  .map(|_| ())
}

fn encode_zstd<R: Read, W: Write>(
  dictionary: &[u8],
  input: &mut R,
  output: &mut W,
  compression_level: i32,
) -> io::Result<()> {
  let mut encoder =
    zstd::stream::write::Encoder::with_ref_prefix(output, compression_level, dictionary)?;
  // Fix every table-driving parameter after the level preset. `HashLog` and
  // `ChainLog` each cap their tables at 2^(log + 2) bytes; workers remain off.
  // This makes encoder memory finite and keeps the 512 MiB per-job admission
  // reservation conservative rather than dependent on zstd defaults.
  encoder.window_log(dcz_window_log(dictionary.len()))?;
  encoder.set_parameter(zstd::zstd_safe::CParameter::HashLog(ZSTD_MAX_HASH_LOG))?;
  encoder.set_parameter(zstd::zstd_safe::CParameter::ChainLog(ZSTD_MAX_CHAIN_LOG))?;
  encoder.set_parameter(zstd::zstd_safe::CParameter::NbWorkers(0))?;
  io::copy(input, &mut encoder)?;
  let _ = encoder.finish()?;
  Ok(())
}

fn decode_brotli_inner<R: Read, W: Write>(
  dictionary: &[u8],
  input: &mut R,
  output: &mut W,
  budget: &mut DecodeBudget<'_>,
) -> io::Result<()> {
  let mut dictionary_allocator = BoundedAlloc::default();
  let mut owned_dictionary = dictionary_allocator.alloc_cell(dictionary.len());
  owned_dictionary.slice_mut().copy_from_slice(dictionary);
  let mut state = BrotliState::new_strict(
    dictionary_allocator.clone(),
    dictionary_allocator.clone(),
    dictionary_allocator.clone(),
  );
  if !state.attach_dictionary(owned_dictionary) {
    return invalid("could not attach raw Brotli prefix dictionary");
  }

  let mut encoded = [0_u8; BROTLI_BUFFER_BYTES];
  let mut decoded = [0_u8; BROTLI_BUFFER_BYTES];
  loop {
    budget.check()?;
    let encoded_len = input.read(&mut encoded)?;
    if encoded_len == 0 {
      return invalid("truncated Brotli dictionary-coded stream");
    }
    let mut available_in = encoded_len;
    let mut input_offset = 0;
    while available_in != 0 {
      budget.check()?;
      let previous_in = available_in;
      let previous_offset = input_offset;
      let mut available_out = decoded.len();
      let mut output_offset = 0;
      let mut total_out = 0;
      let result = BrotliDecompressStream(
        &mut available_in,
        &mut input_offset,
        &encoded[..encoded_len],
        &mut available_out,
        &mut output_offset,
        &mut decoded,
        &mut total_out,
        &mut state,
      );
      budget.write(output, &decoded[..output_offset])?;
      match result {
        BrotliResult::ResultSuccess => {
          if available_in != 0 || input_offset != encoded_len {
            return invalid("trailing bytes after Brotli dictionary-coded stream");
          }
          budget.check()?;
          if input.read(&mut [0_u8; 1])? != 0 {
            return invalid("trailing bytes after Brotli dictionary-coded stream");
          }
          return Ok(());
        }
        BrotliResult::ResultFailure => return invalid("invalid Brotli dictionary-coded stream"),
        BrotliResult::NeedsMoreInput | BrotliResult::NeedsMoreOutput => {
          if available_in == previous_in && input_offset == previous_offset && output_offset == 0 {
            return invalid("Brotli dictionary-coded stream made no progress");
          }
        }
      }
    }
  }
}

fn decode_zstd<R: Read, W: Write>(
  dictionary: &[u8],
  input: &mut R,
  output: &mut W,
  budget: &mut DecodeBudget<'_>,
) -> io::Result<()> {
  let window_log = dcz_window_log(dictionary.len());
  let mut decoder = new_zstd_decoder(dictionary, window_log)?;
  let mut encoded = [0_u8; ZSTD_BUFFER_BYTES];
  let mut decoded = [0_u8; ZSTD_BUFFER_BYTES];
  let mut saw_complete_frame = false;
  let mut at_frame_boundary = false;

  loop {
    budget.check()?;
    let encoded_len = input.read(&mut encoded)?;
    if encoded_len == 0 {
      return if saw_complete_frame && at_frame_boundary {
        Ok(())
      } else {
        invalid("truncated Zstandard dictionary-coded stream")
      };
    }
    at_frame_boundary = false;
    let mut offset = 0;
    while offset != encoded_len {
      budget.check()?;
      let status = decoder.run_on_buffers(&encoded[offset..encoded_len], &mut decoded)?;
      offset += status.bytes_read;
      budget.write(output, &decoded[..status.bytes_written])?;
      if status.remaining == 0 {
        saw_complete_frame = true;
        at_frame_boundary = true;
        // A prefix is session state.  Recreate the decoder for every
        // concatenated frame so every valid RFC 9842 frame gets the same raw
        // prefix, including after a zstd library reset.
        decoder = new_zstd_decoder(dictionary, window_log)?;
      } else {
        at_frame_boundary = false;
      }
      if status.bytes_read == 0 && status.bytes_written == 0 {
        return invalid("Zstandard dictionary-coded stream made no progress");
      }
    }
  }
}

fn new_zstd_decoder(dictionary: &[u8], window_log: u32) -> io::Result<ZstdDecoder<'_>> {
  let mut decoder = ZstdDecoder::with_ref_prefix(dictionary)?;
  // `raw::Decoder` exposes the underlying parameter setter directly rather
  // than the read/write wrapper convenience method.
  decoder.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(window_log))?;
  Ok(decoder)
}

fn dcz_window_log(dictionary_len: usize) -> u32 {
  let required = (dictionary_len.saturating_mul(5) / 4).max(8 * 1024 * 1024);
  let max_window = required.min(1_usize << ZSTD_MAX_WINDOW_LOG);
  let mut log = 0_u32;
  let mut window = 1_usize;
  while window <= max_window / 2 {
    window <<= 1;
    log += 1;
  }
  log
}

fn check_control(limits: &DecodeLimits) -> io::Result<()> {
  if limits
    .cancel
    .as_ref()
    .is_some_and(|cancel| cancel.load(Ordering::Relaxed))
  {
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "dictionary decode cancelled",
    ));
  }
  if limits
    .deadline
    .is_some_and(|deadline| Instant::now() >= deadline)
  {
    return Err(io::Error::new(
      io::ErrorKind::TimedOut,
      "dictionary decode deadline expired",
    ));
  }
  Ok(())
}

fn check_encode_control(options: &EncodeOptions) -> io::Result<()> {
  if options
    .cancel
    .as_ref()
    .is_some_and(|cancel| cancel.load(Ordering::Relaxed))
  {
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "dictionary encode cancelled",
    ));
  }
  if options
    .deadline
    .is_some_and(|deadline| Instant::now() >= deadline)
  {
    return Err(io::Error::new(
      io::ErrorKind::TimedOut,
      "dictionary encode deadline expired",
    ));
  }
  Ok(())
}

fn invalid(message: &'static str) -> io::Result<()> {
  Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

struct CountingReader<R> {
  inner: R,
  bytes: Arc<AtomicUsize>,
}

impl<R> CountingReader<R> {
  fn new(inner: R, bytes: Arc<AtomicUsize>) -> Self {
    Self { inner, bytes }
  }
}

impl<R: Read> Read for CountingReader<R> {
  fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
    let read = self.inner.read(buffer)?;
    self.bytes.fetch_add(read, Ordering::Relaxed);
    Ok(read)
  }
}

struct CheckedEncodeReader<'a, R> {
  inner: R,
  options: &'a EncodeOptions,
}

impl<R: Read> Read for CheckedEncodeReader<'_, R> {
  fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
    check_encode_control(self.options)?;
    self.inner.read(buffer)
  }
}

struct CheckedEncodeWriter<'a, W> {
  inner: W,
  options: &'a EncodeOptions,
}

impl<W: Write> Write for CheckedEncodeWriter<'_, W> {
  fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
    check_encode_control(self.options)?;
    self.inner.write(buffer)
  }

  fn flush(&mut self) -> io::Result<()> {
    check_encode_control(self.options)?;
    self.inner.flush()
  }
}

struct DecodeBudget<'a> {
  limits: &'a DecodeLimits,
  compressed: Arc<AtomicUsize>,
  decoded: usize,
}

impl<'a> DecodeBudget<'a> {
  fn new(limits: &'a DecodeLimits, compressed: Arc<AtomicUsize>) -> Self {
    Self {
      limits,
      compressed,
      decoded: 0,
    }
  }

  fn check(&self) -> io::Result<()> {
    check_control(self.limits)
  }

  fn write<W: Write>(&mut self, output: &mut W, bytes: &[u8]) -> io::Result<()> {
    self.check()?;
    let decoded = self
      .decoded
      .checked_add(bytes.len())
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "decoded byte counter overflow"))?;
    if decoded > self.limits.max_decoded_bytes {
      return invalid("decoded dictionary-coded stream exceeds byte limit");
    }
    let compressed = self.compressed.load(Ordering::Relaxed);
    if decoded > compressed.saturating_mul(self.limits.max_expansion_ratio) {
      return invalid("decoded dictionary-coded stream exceeds expansion-ratio limit");
    }
    output.write_all(bytes)?;
    self.decoded = decoded;
    Ok(())
  }
}

#[cfg(test)]
mod tests;
