use std::io::{self, Cursor, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::*;

fn limits() -> DecodeLimits {
  DecodeLimits::new(1024 * 1024, 128)
}

fn roundtrip(coding: DictionaryCoding, dictionary: &[u8], source: &[u8]) -> Vec<u8> {
  let encoded =
    encode(coding, dictionary, Cursor::new(source), Vec::new()).expect("encode fixture");
  decode_bounded(coding, Arc::<[u8]>::from(dictionary), &encoded, &limits())
    .expect("decode fixture")
}

#[test]
fn rfc9842_preludes_are_exact() {
  let dictionary = b"RFC 9842 prelude test dictionary";
  let hash = Sha256::digest(dictionary);
  let dcb = prelude(DictionaryCoding::Dcb, dictionary);
  let dcz = prelude(DictionaryCoding::Dcz, dictionary);
  assert_eq!(dcb.len(), DCB_PRELUDE_LEN);
  assert_eq!(&dcb[..4], &DCB_MAGIC);
  assert_eq!(&dcb[4..], hash.as_slice());
  assert_eq!(dcz.len(), DCZ_PRELUDE_LEN);
  assert_eq!(&dcz[..8], &DCZ_MAGIC);
  assert_eq!(&dcz[8..], hash.as_slice());
}

#[test]
fn conservative_codec_working_set_reservations_cover_bounded_windows() {
  const {
    assert!(DCB_MAX_WORKING_SET_BYTES >= 6 * 16 * 1024 * 1024);
  }
  assert!(DCZ_MAX_WORKING_SET_BYTES >= 128 * 1024 * 1024 + MAX_RAW_DICTIONARY_BYTES as u64);
  assert_eq!(maximum_working_set_bytes(), DCZ_MAX_WORKING_SET_BYTES);
  assert_eq!(
    max_working_set_bytes(DictionaryCoding::Dcb),
    DCB_MAX_WORKING_SET_BYTES
  );
}

#[test]
fn zstd_encoder_uses_bounded_table_logs() {
  assert_eq!(dcz_window_log(usize::MAX), ZSTD_MAX_WINDOW_LOG);
  // zstd documents each hash/chain table as 2^(log + 2) bytes.
  assert!(
    (1_u64 << (ZSTD_MAX_HASH_LOG + 2)).saturating_add(1_u64 << (ZSTD_MAX_CHAIN_LOG + 2))
      < 16 * 1024 * 1024
  );
}

#[test]
fn both_codecs_roundtrip_raw_dictionary_data() {
  let dictionary = b"prefix: GET /assets/app.js HTTP/1.1\r\nhost: example.test\r\n\r\n";
  let source = b"prefix: GET /assets/app.js HTTP/1.1\r\nhost: example.test\r\n\r\nbody";
  for coding in [DictionaryCoding::Dcb, DictionaryCoding::Dcz] {
    assert_eq!(roundtrip(coding, dictionary, source), source);
  }
}

#[test]
fn zstd_uses_raw_prefix_even_when_dictionary_has_trained_magic() {
  // 0x37a430ec is Zstandard's trained-dictionary magic in little-endian
  // byte order.  RFC 9842 requires these bytes to remain a raw prefix.
  let dictionary = b"\x37\xa4\x30\xecraw-prefix dictionary content";
  let source = b"\x37\xa4\x30\xecraw-prefix dictionary content + response";
  assert_eq!(roundtrip(DictionaryCoding::Dcz, dictionary, source), source);
}

#[test]
fn zstd_decodes_an_independent_raw_prefix_vector() {
  // Generated with libzstd's C API (`ZSTD_CCtx_refPrefix`) at level 3 and a
  // 23-bit window, rather than by this Rust encoder.  The bytes deliberately
  // contain only a raw-prefix reference, so `with_dictionary` would treat a
  // magic-like prefix as a trained dictionary and is not interchangeable.
  let dictionary = b"independent raw prefix dictionary";
  let compressed = [
    0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x2a, 0x7d, 0x00, 0x00, 0x48, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f,
    0x6e, 0x73, 0x65, 0x01, 0x00, 0x64, 0x54, 0x40,
  ];
  let mut encoded = prelude(DictionaryCoding::Dcz, dictionary);
  encoded.extend_from_slice(&compressed);
  assert_eq!(
    decode_bounded(
      DictionaryCoding::Dcz,
      Arc::<[u8]>::from(&dictionary[..]),
      &encoded,
      &limits(),
    )
    .expect("independent raw-prefix zstd vector decodes"),
    b"independent raw prefix dictionary response"
  );
}

#[test]
fn digest_is_checked_before_codec_construction() {
  let dictionary = b"right dictionary";
  let encoded = encode(
    DictionaryCoding::Dcb,
    dictionary,
    Cursor::new(b"content"),
    Vec::new(),
  )
  .expect("encode fixture");
  let error = decode_bounded(
    DictionaryCoding::Dcb,
    Arc::from(&b"wrong dictionary"[..]),
    &encoded,
    &limits(),
  )
  .expect_err("different dictionary digest must fail");
  assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn truncated_and_trailing_streams_fail_closed() {
  let dictionary = b"strict dictionary";
  for coding in [DictionaryCoding::Dcb, DictionaryCoding::Dcz] {
    let mut encoded = encode(
      coding,
      dictionary,
      Cursor::new(b"strict content"),
      Vec::new(),
    )
    .expect("encode fixture");
    assert!(
      decode_bounded(
        coding,
        Arc::<[u8]>::from(&dictionary[..]),
        &encoded[..encoded.len() - 1],
        &limits()
      )
      .is_err()
    );
    encoded.push(0);
    assert!(
      decode_bounded(
        coding,
        Arc::<[u8]>::from(&dictionary[..]),
        &encoded,
        &limits()
      )
      .is_err()
    );
  }
}

#[test]
fn zstd_accepts_concatenated_valid_frames_with_the_same_prefix() {
  let dictionary = b"dictionary for concatenated frames";
  let first = encode(
    DictionaryCoding::Dcz,
    dictionary,
    Cursor::new(b"first"),
    Vec::new(),
  )
  .expect("first frame");
  let second = encode(
    DictionaryCoding::Dcz,
    dictionary,
    Cursor::new(b"second"),
    Vec::new(),
  )
  .expect("second frame");
  let mut joined = first;
  joined.extend_from_slice(&second[DCZ_PRELUDE_LEN..]);
  assert_eq!(
    decode_bounded(
      DictionaryCoding::Dcz,
      Arc::<[u8]>::from(&dictionary[..]),
      &joined,
      &limits()
    )
    .expect("frames decode"),
    b"firstsecond"
  );
}

#[test]
fn decoded_size_ratio_deadline_and_cancellation_are_enforced() {
  let dictionary = b"resource guard dictionary";
  let encoded = encode(
    DictionaryCoding::Dcz,
    dictionary,
    Cursor::new(vec![b'x'; 4096]),
    Vec::new(),
  )
  .expect("encode fixture");
  assert!(
    decode_bounded(
      DictionaryCoding::Dcz,
      Arc::<[u8]>::from(&dictionary[..]),
      &encoded,
      &DecodeLimits::new(8, 128)
    )
    .is_err()
  );
  assert!(
    decode_bounded(
      DictionaryCoding::Dcz,
      Arc::<[u8]>::from(&dictionary[..]),
      &encoded,
      &DecodeLimits::new(8192, 1)
    )
    .is_err()
  );

  let mut expired = limits();
  expired.deadline = Some(Instant::now() - Duration::from_millis(1));
  assert_eq!(
    decode_bounded(
      DictionaryCoding::Dcz,
      Arc::<[u8]>::from(&dictionary[..]),
      &encoded,
      &expired
    )
    .unwrap_err()
    .kind(),
    io::ErrorKind::TimedOut
  );

  let cancelled = Arc::new(AtomicBool::new(true));
  let mut cancelled_limits = limits();
  cancelled_limits.cancel = Some(cancelled.clone());
  assert_eq!(
    decode_bounded(
      DictionaryCoding::Dcz,
      Arc::<[u8]>::from(&dictionary[..]),
      &encoded,
      &cancelled_limits
    )
    .unwrap_err()
    .kind(),
    io::ErrorKind::Interrupted
  );
  assert!(cancelled.load(Ordering::Relaxed));
}

#[test]
fn encoding_level_deadline_and_cancellation_are_enforced() {
  let dictionary = b"encode control dictionary";
  for level in [0, 10] {
    let options = EncodeOptions {
      compression_level: level,
      ..EncodeOptions::default()
    };
    assert!(
      encode_with_options(
        DictionaryCoding::Dcz,
        dictionary,
        Cursor::new(b"content"),
        Vec::new(),
        &options,
      )
      .is_err()
    );
  }

  let expired = EncodeOptions {
    deadline: Some(Instant::now() - Duration::from_millis(1)),
    ..EncodeOptions::default()
  };
  assert_eq!(
    encode_with_options(
      DictionaryCoding::Dcb,
      dictionary,
      Cursor::new(b"content"),
      Vec::new(),
      &expired,
    )
    .unwrap_err()
    .kind(),
    io::ErrorKind::TimedOut
  );

  let cancelled = Arc::new(AtomicBool::new(true));
  let options = EncodeOptions {
    cancel: Some(cancelled.clone()),
    ..EncodeOptions::default()
  };
  assert_eq!(
    encode_with_options(
      DictionaryCoding::Dcb,
      dictionary,
      Cursor::new(b"content"),
      Vec::new(),
      &options,
    )
    .unwrap_err()
    .kind(),
    io::ErrorKind::Interrupted
  );
  assert!(cancelled.load(Ordering::Relaxed));
}

#[test]
fn dictionary_size_cap_has_no_truncation_path() {
  let dictionary = vec![0_u8; MAX_RAW_DICTIONARY_BYTES + 1];
  assert!(
    encode(
      DictionaryCoding::Dcb,
      &dictionary,
      Cursor::new(b"x"),
      Vec::new()
    )
    .is_err()
  );
  assert!(
    encode(
      DictionaryCoding::Dcz,
      &dictionary,
      Cursor::new(b"x"),
      Vec::new()
    )
    .is_err()
  );
}

struct ChunkedReader {
  bytes: Cursor<Vec<u8>>,
  chunk: usize,
}

impl Read for ChunkedReader {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    let end = output.len().min(self.chunk);
    self.bytes.read(&mut output[..end])
  }
}

#[test]
fn prelude_and_payload_are_safe_with_short_reads() {
  let dictionary = b"short read dictionary";
  let encoded = encode(
    DictionaryCoding::Dcz,
    dictionary,
    Cursor::new(b"short read payload"),
    Vec::new(),
  )
  .expect("encode fixture");
  let decoded = decode(
    DictionaryCoding::Dcz,
    dictionary,
    ChunkedReader {
      bytes: Cursor::new(encoded),
      chunk: 3,
    },
    Vec::new(),
    &limits(),
  )
  .expect("short reads decode");
  assert_eq!(decoded, b"short read payload");
}

#[test]
fn brotli_decodes_independent_google_raw_prefix_vector() {
  // Google Brotli v1.2.0, commit 028fb5a23661f123017c060daa546b55cf4bde29.
  // C API: PrepareDictionary(RAW, dictionary, quality=9), quality=9,
  // lgwin=24, AttachPreparedDictionary, CompressStream(FINISH).
  // Generated independently of the Rust encoder; most content is a prefix
  // reference, so an ordinary Brotli decoder cannot substitute for Shared Brotli.
  let dictionary = b"independent raw prefix dictionary";
  let compressed = [
    0x1f, 0x29, 0x00, 0x00, 0x24, 0x40, 0xca, 0x91, 0x62, 0xca, 0xd2, 0x0e, 0xc9, 0x01,
  ];
  let mut encoded = prelude(DictionaryCoding::Dcb, dictionary);
  encoded.extend_from_slice(&compressed);
  assert_eq!(
    decode_bounded(
      DictionaryCoding::Dcb,
      Arc::<[u8]>::from(&dictionary[..]),
      &encoded,
      &limits()
    )
    .unwrap(),
    b"independent raw prefix dictionary response"
  );
}

#[test]
fn zstd_window_stays_below_rfc_dictionary_relative_limit() {
  for size in [
    1,
    8 * 1024 * 1024,
    10 * 1024 * 1024,
    MAX_RAW_DICTIONARY_BYTES,
  ] {
    let window = 1_usize << dcz_window_log(size);
    assert!(window <= (size * 5 / 4).clamp(8 * 1024 * 1024, 128 * 1024 * 1024));
  }
}
