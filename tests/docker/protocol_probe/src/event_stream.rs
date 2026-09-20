//! Incremental decoders for Admin WebTransport operation-event streams.

use std::io::Write;

use anyhow::{bail, Context};
use flate2::{Decompress, FlushDecompress, Status};
use http::{HeaderName, HeaderValue};
use zstd::stream::raw::Operation;

const EVENT_STREAM_HEADER: &str = "oxibelt-event-stream";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventStreamCoding {
  Identity,
  Br,
  Zstd,
  Gzip,
  Deflate,
}

impl EventStreamCoding {
  pub(crate) fn request_value(self) -> Option<&'static str> {
    match self {
      Self::Identity => None,
      Self::Br => Some("ndjson-v1; coding=br"),
      Self::Zstd => Some("ndjson-v1; coding=zstd"),
      Self::Gzip => Some("ndjson-v1; coding=gzip"),
      Self::Deflate => Some("ndjson-v1; coding=deflate"),
    }
  }
}

/// Select a decoder only for valid compressed contracts this probe can decode.
/// Other values stay identity so setup-status checks reach server validation.
pub(crate) fn requested_coding<'a>(
  mut headers: impl Iterator<Item = (&'a HeaderName, &'a HeaderValue)>,
) -> EventStreamCoding {
  let value = headers
    .find(|(name, _)| name.as_str().eq_ignore_ascii_case(EVENT_STREAM_HEADER))
    .and_then(|(_, value)| value.to_str().ok());
  match value {
    Some("ndjson-v1; coding=br") => EventStreamCoding::Br,
    Some("ndjson-v1; coding=zstd") => EventStreamCoding::Zstd,
    Some("ndjson-v1; coding=gzip") => EventStreamCoding::Gzip,
    Some("ndjson-v1; coding=deflate") => EventStreamCoding::Deflate,
    _ => EventStreamCoding::Identity,
  }
}

pub(crate) struct EventStreamDecoder {
  inner: DecoderInner,
  ended: bool,
}

enum DecoderInner {
  Identity,
  Brotli(
    Box<
      brotli::BrotliState<
        brotli::enc::StandardAlloc,
        brotli::enc::StandardAlloc,
        brotli::enc::StandardAlloc,
      >,
    >,
  ),
  Zstd(zstd::stream::raw::Decoder<'static>),
  Gzip(flate2::write::GzDecoder<Vec<u8>>),
  Flate(Decompress),
}

impl EventStreamDecoder {
  pub(crate) fn new(coding: EventStreamCoding) -> Self {
    let inner = match coding {
      EventStreamCoding::Identity => DecoderInner::Identity,
      EventStreamCoding::Br => DecoderInner::Brotli(Box::new(brotli::BrotliState::new_strict(
        brotli::enc::StandardAlloc::default(),
        brotli::enc::StandardAlloc::default(),
        brotli::enc::StandardAlloc::default(),
      ))),
      EventStreamCoding::Zstd => {
        DecoderInner::Zstd(zstd::stream::raw::Decoder::new().expect("zstd decoder initialization"))
      }
      EventStreamCoding::Gzip => DecoderInner::Gzip(flate2::write::GzDecoder::new(Vec::new())),
      EventStreamCoding::Deflate => DecoderInner::Flate(Decompress::new(true)),
    };
    Self {
      inner,
      ended: false,
    }
  }

  pub(crate) fn push(&mut self, encoded: &[u8]) -> anyhow::Result<Vec<u8>> {
    match &mut self.inner {
      DecoderInner::Identity => Ok(encoded.to_vec()),
      DecoderInner::Brotli(state) => decode_brotli(state, encoded, &mut self.ended),
      DecoderInner::Zstd(decoder) => decode_zstd(decoder, encoded, &mut self.ended),
      DecoderInner::Gzip(decoder) => {
        if self.ended && !encoded.is_empty() {
          bail!("Admin event stream sent bytes after compressed end-of-stream");
        }
        decoder
          .write_all(encoded)
          .context("Admin event stream gzip decompression failed")?;
        decoder
          .flush()
          .context("Admin event stream gzip decompression flush failed")?;
        Ok(std::mem::take(decoder.get_mut()))
      }
      DecoderInner::Flate(decoder) => {
        if self.ended && !encoded.is_empty() {
          bail!("Admin event stream sent bytes after compressed end-of-stream");
        }
        let mut remaining = encoded;
        let mut decoded = Vec::new();
        while !remaining.is_empty() {
          let mut output = [0_u8; 16 * 1024];
          let before_in = decoder.total_in();
          let before_out = decoder.total_out();
          let status = decoder
            .decompress(remaining, &mut output, FlushDecompress::Sync)
            .context("Admin event stream decompression failed")?;
          let consumed = (decoder.total_in() - before_in) as usize;
          let written = (decoder.total_out() - before_out) as usize;
          decoded.extend_from_slice(&output[..written]);
          remaining = &remaining[consumed..];
          if status == Status::StreamEnd {
            self.ended = true;
            if !remaining.is_empty() {
              bail!("Admin event stream has trailing compressed bytes");
            }
          }
          if consumed == 0 && written == 0 {
            bail!("Admin event stream decompressor made no progress");
          }
        }
        Ok(decoded)
      }
    }
  }

  pub(crate) fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
    match &mut self.inner {
      DecoderInner::Identity => Ok(Vec::new()),
      DecoderInner::Gzip(decoder) => {
        decoder
          .try_finish()
          .context("Admin event stream ended before gzip completion")?;
        self.ended = true;
        Ok(std::mem::take(decoder.get_mut()))
      }
      _ if self.ended => Ok(Vec::new()),
      _ => bail!("Admin event stream ended before compressed end-of-stream"),
    }
  }
}

fn decode_brotli(
  state: &mut brotli::BrotliState<
    brotli::enc::StandardAlloc,
    brotli::enc::StandardAlloc,
    brotli::enc::StandardAlloc,
  >,
  encoded: &[u8],
  ended: &mut bool,
) -> anyhow::Result<Vec<u8>> {
  use brotli::{BrotliDecompressStream, BrotliResult};

  if *ended && !encoded.is_empty() {
    bail!("Admin event stream sent bytes after compressed end-of-stream");
  }
  let mut input_offset = 0;
  let mut available_in = encoded.len();
  let mut decoded = Vec::new();
  loop {
    let mut output = [0_u8; 16 * 1024];
    let mut available_out = output.len();
    let mut output_offset = 0;
    let mut total_out = 0;
    match BrotliDecompressStream(
      &mut available_in,
      &mut input_offset,
      encoded,
      &mut available_out,
      &mut output_offset,
      &mut output,
      &mut total_out,
      state,
    ) {
      BrotliResult::ResultSuccess => {
        decoded.extend_from_slice(&output[..output_offset]);
        *ended = true;
        if available_in != 0 || input_offset != encoded.len() {
          bail!("Admin event stream has trailing compressed bytes");
        }
        return Ok(decoded);
      }
      BrotliResult::NeedsMoreInput => {
        decoded.extend_from_slice(&output[..output_offset]);
        return Ok(decoded);
      }
      BrotliResult::NeedsMoreOutput => decoded.extend_from_slice(&output[..output_offset]),
      BrotliResult::ResultFailure => bail!("Admin event stream Brotli decompression failed"),
    }
  }
}

fn decode_zstd(
  decoder: &mut zstd::stream::raw::Decoder<'static>,
  encoded: &[u8],
  ended: &mut bool,
) -> anyhow::Result<Vec<u8>> {
  if *ended && !encoded.is_empty() {
    decoder
      .reinit()
      .context("Admin event stream zstd decoder reset failed")?;
    *ended = false;
  }
  let mut remaining = encoded;
  let mut decoded = Vec::new();
  while !remaining.is_empty() {
    let mut output = [0_u8; 16 * 1024];
    let status = decoder
      .run_on_buffers(remaining, &mut output)
      .context("Admin event stream zstd decompression failed")?;
    decoded.extend_from_slice(&output[..status.bytes_written]);
    remaining = &remaining[status.bytes_read..];
    if status.remaining == 0 {
      *ended = true;
      if !remaining.is_empty() {
        decoder
          .reinit()
          .context("Admin event stream zstd decoder reset failed")?;
        *ended = false;
      }
    }
    if status.bytes_read == 0 && status.bytes_written == 0 {
      bail!("Admin event stream zstd decompressor made no progress");
    }
  }
  Ok(decoded)
}

#[cfg(test)]
mod tests {
  use std::io::Write;

  use super::*;

  #[test]
  fn decodes_gzip_across_record_flushes() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(b"{\"event\":\"first\"}\n").unwrap();
    encoder.flush().unwrap();
    let split = encoder.get_ref().len();
    encoder.write_all(b"{\"event\":\"second\"}\n").unwrap();
    let encoded = encoder.finish().unwrap();

    let mut decoder = EventStreamDecoder::new(EventStreamCoding::Gzip);
    let mut decoded = decoder.push(&encoded[..split]).unwrap();
    decoded.extend(decoder.push(&encoded[split..]).unwrap());
    decoder.finish().unwrap();
    assert_eq!(decoded, b"{\"event\":\"first\"}\n{\"event\":\"second\"}\n");
  }

  #[test]
  fn preserves_decoded_bytes_for_standard_codings() {
    let input = b"{\"event\":\"record\"}\n";
    let cases = [
      (EventStreamCoding::Br, brotli_encode(input)),
      (
        EventStreamCoding::Zstd,
        zstd::stream::encode_all(&input[..], 1).unwrap(),
      ),
      (EventStreamCoding::Gzip, gzip_encode(input)),
      (EventStreamCoding::Deflate, deflate_encode(input)),
    ];
    for (coding, encoded) in cases {
      let mut decoder = EventStreamDecoder::new(coding);
      let split = encoded.len() / 2;
      let mut decoded = decoder.push(&encoded[..split]).unwrap();
      decoded.extend(decoder.push(&encoded[split..]).unwrap());
      decoder.finish().unwrap();
      assert_eq!(decoded, input, "{coding:?}");
    }
  }

  #[test]
  fn decodes_concatenated_zstd_frames_incrementally() {
    let first = zstd::stream::encode_all(&b"{\"event\":\"first\"}\n"[..], 1).unwrap();
    let second = zstd::stream::encode_all(&b"{\"event\":\"second\"}\n"[..], 1).unwrap();
    let mut decoder = EventStreamDecoder::new(EventStreamCoding::Zstd);
    let mut decoded = decoder.push(&first).unwrap();
    decoded.extend(decoder.push(&second).unwrap());
    decoder.finish().unwrap();
    assert_eq!(decoded, b"{\"event\":\"first\"}\n{\"event\":\"second\"}\n");
  }

  #[test]
  fn absent_or_malformed_contract_keeps_raw_compatibility() {
    assert_eq!(
      requested_coding(std::iter::empty()),
      EventStreamCoding::Identity
    );
    let name = HeaderName::from_static("oxibelt-event-stream");
    let malformed = HeaderValue::from_static("not-an-event-contract");
    assert_eq!(
      requested_coding(std::iter::once((&name, &malformed))),
      EventStreamCoding::Identity
    );
  }

  fn brotli_encode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
      let mut encoder = brotli::CompressorWriter::new(&mut output, 4096, 1, 22);
      encoder.write_all(input).unwrap();
    }
    output
  }

  fn gzip_encode(input: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(input).unwrap();
    encoder.finish().unwrap()
  }

  fn deflate_encode(input: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(input).unwrap();
    encoder.finish().unwrap()
  }
}
