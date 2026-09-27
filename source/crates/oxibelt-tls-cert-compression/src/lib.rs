//! Bounded RFC 8879 certificate compression for OxiBelt-owned rustls configs.

use std::{fmt, io::Write, str::FromStr, sync::Arc};

use rustls::{
  CertificateCompressionAlgorithm, ClientConfig, ServerConfig,
  compress::{
    CertCompressor, CertDecompressor, CompressionCache, CompressionFailed, CompressionLevel,
    DecompressionFailed,
  },
};
use serde::{Deserialize, Serialize};

/// RFC 8879 algorithm, in local preference order when used in a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
  Zstd,
  Brotli,
  Zlib,
}

impl fmt::Display for Algorithm {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Zstd => "zstd",
      Self::Brotli => "brotli",
      Self::Zlib => "zlib",
    })
  }
}

impl FromStr for Algorithm {
  type Err = &'static str;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "zstd" => Ok(Self::Zstd),
      "brotli" => Ok(Self::Brotli),
      "zlib" => Ok(Self::Zlib),
      _ => Err("expected zstd, brotli, or zlib"),
    }
  }
}

fn default_enabled() -> bool {
  true
}

fn default_algorithms() -> Vec<Algorithm> {
  vec![Algorithm::Zstd, Algorithm::Brotli, Algorithm::Zlib]
}

/// Both certificate sending and receiving use this policy. TLS 1.2 ignores it.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CertificateCompressionPolicy {
  pub enabled: bool,
  pub algorithms: Vec<Algorithm>,
}

impl Default for CertificateCompressionPolicy {
  fn default() -> Self {
    Self {
      enabled: default_enabled(),
      algorithms: default_algorithms(),
    }
  }
}

impl CertificateCompressionPolicy {
  pub fn validate(&self) -> Result<(), &'static str> {
    if self.algorithms.is_empty() {
      return Err("certificate compression algorithms must not be empty");
    }
    for (index, algorithm) in self.algorithms.iter().enumerate() {
      if self.algorithms[..index].contains(algorithm) {
        return Err("certificate compression algorithms must not repeat");
      }
    }
    Ok(())
  }
}

pub fn apply_client(
  config: &mut ClientConfig,
  policy: &CertificateCompressionPolicy,
) -> Result<(), &'static str> {
  policy.validate()?;
  config.cert_compressors = compressors(policy);
  config.cert_decompressors = decompressors(policy);
  config.cert_compression_cache = cache(policy);
  Ok(())
}

pub fn apply_server(
  config: &mut ServerConfig,
  policy: &CertificateCompressionPolicy,
) -> Result<(), &'static str> {
  policy.validate()?;
  config.cert_compressors = compressors(policy);
  config.cert_decompressors = decompressors(policy);
  config.cert_compression_cache = cache(policy);
  Ok(())
}

fn compressors(policy: &CertificateCompressionPolicy) -> Vec<&'static dyn CertCompressor> {
  if !policy.enabled {
    return Vec::new();
  }
  policy
    .algorithms
    .iter()
    .map(|a| match a {
      Algorithm::Zstd => &ZSTD as &dyn CertCompressor,
      Algorithm::Brotli => &BROTLI as &dyn CertCompressor,
      Algorithm::Zlib => &ZLIB as &dyn CertCompressor,
    })
    .collect()
}

fn decompressors(policy: &CertificateCompressionPolicy) -> Vec<&'static dyn CertDecompressor> {
  if !policy.enabled {
    return Vec::new();
  }
  policy
    .algorithms
    .iter()
    .map(|a| match a {
      Algorithm::Zstd => &ZSTD as &dyn CertDecompressor,
      Algorithm::Brotli => &BROTLI as &dyn CertDecompressor,
      Algorithm::Zlib => &ZLIB as &dyn CertDecompressor,
    })
    .collect()
}

fn cache(policy: &CertificateCompressionPolicy) -> Arc<CompressionCache> {
  Arc::new(if policy.enabled {
    CompressionCache::new(6)
  } else {
    CompressionCache::Disabled
  })
}

#[derive(Debug)]
struct Zstd;
#[derive(Debug)]
struct Brotli;
#[derive(Debug)]
struct Zlib;

static ZSTD: Zstd = Zstd;
static BROTLI: Brotli = Brotli;
static ZLIB: Zlib = Zlib;

// rustls's compressed certificate parser enforces the same bound.
const MAX_CERTIFICATE_MESSAGE: usize = 64 * 1024;

fn compressed_if_smaller(input_len: usize, output: Vec<u8>) -> Result<Vec<u8>, CompressionFailed> {
  if output.len() >= input_len {
    Err(CompressionFailed)
  } else {
    Ok(output)
  }
}

impl CertCompressor for Zstd {
  fn algorithm(&self) -> CertificateCompressionAlgorithm {
    CertificateCompressionAlgorithm::Zstd
  }

  fn compress(&self, input: Vec<u8>, _: CompressionLevel) -> Result<Vec<u8>, CompressionFailed> {
    let output = zstd::bulk::compress(&input, 1).map_err(|_| CompressionFailed)?;
    compressed_if_smaller(input.len(), output)
  }
}

impl CertDecompressor for Zstd {
  fn algorithm(&self) -> CertificateCompressionAlgorithm {
    CertificateCompressionAlgorithm::Zstd
  }

  fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
    use zstd::stream::raw::{DParameter, Decoder, InBuffer, Operation, OutBuffer};

    if output.len() > MAX_CERTIFICATE_MESSAGE {
      return Err(DecompressionFailed);
    }

    let mut decoder = Decoder::new().map_err(|_| DecompressionFailed)?;
    decoder
      .set_parameter(DParameter::WindowLogMax(20))
      .map_err(|_| DecompressionFailed)?;
    let mut in_buf = InBuffer::around(input);
    let mut written = 0;
    let mut overflow = [0u8; 1];
    loop {
      let before_in = in_buf.pos();
      let (remaining, was_full) = if written < output.len() {
        (&mut output[written..], false)
      } else {
        (&mut overflow[..], true)
      };
      let mut out_buf = OutBuffer::around(remaining);
      let status = decoder
        .run(&mut in_buf, &mut out_buf)
        .map_err(|_| DecompressionFailed)?;
      let produced = out_buf.pos();
      if was_full && produced != 0 {
        return Err(DecompressionFailed);
      }
      written += produced;
      if status == 0 {
        return if written == output.len() && in_buf.pos() == input.len() {
          Ok(())
        } else {
          Err(DecompressionFailed)
        };
      }
      if in_buf.pos() == before_in && produced == 0 {
        return Err(DecompressionFailed);
      }
      if in_buf.pos() == input.len() && produced == 0 {
        return Err(DecompressionFailed);
      }
    }
  }
}

impl CertCompressor for Zlib {
  fn algorithm(&self) -> CertificateCompressionAlgorithm {
    CertificateCompressionAlgorithm::Zlib
  }

  fn compress(&self, input: Vec<u8>, _: CompressionLevel) -> Result<Vec<u8>, CompressionFailed> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&input).map_err(|_| CompressionFailed)?;
    let output = encoder.finish().map_err(|_| CompressionFailed)?;
    compressed_if_smaller(input.len(), output)
  }
}

impl CertDecompressor for Zlib {
  fn algorithm(&self) -> CertificateCompressionAlgorithm {
    CertificateCompressionAlgorithm::Zlib
  }

  fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
    use flate2::{Decompress, FlushDecompress, Status};

    if output.len() > MAX_CERTIFICATE_MESSAGE {
      return Err(DecompressionFailed);
    }

    let mut decoder = Decompress::new(true);
    let mut overflow = [0u8; 1];
    loop {
      let in_pos = decoder.total_in() as usize;
      let out_pos = decoder.total_out() as usize;
      let target = if out_pos < output.len() {
        &mut output[out_pos..]
      } else {
        &mut overflow[..]
      };
      let status = decoder
        .decompress(&input[in_pos..], target, FlushDecompress::Finish)
        .map_err(|_| DecompressionFailed)?;
      let new_out = decoder.total_out() as usize;
      if new_out > output.len() {
        return Err(DecompressionFailed);
      }
      if status == Status::StreamEnd {
        return if new_out == output.len() && decoder.total_in() as usize == input.len() {
          Ok(())
        } else {
          Err(DecompressionFailed)
        };
      }
      if decoder.total_in() as usize == in_pos && new_out == out_pos {
        return Err(DecompressionFailed);
      }
    }
  }
}

impl CertCompressor for Brotli {
  fn algorithm(&self) -> CertificateCompressionAlgorithm {
    CertificateCompressionAlgorithm::Brotli
  }

  fn compress(&self, input: Vec<u8>, _: CompressionLevel) -> Result<Vec<u8>, CompressionFailed> {
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 3, 20);
    encoder.write_all(&input).map_err(|_| CompressionFailed)?;
    let output = encoder.into_inner();
    compressed_if_smaller(input.len(), output)
  }
}

impl CertDecompressor for Brotli {
  fn algorithm(&self) -> CertificateCompressionAlgorithm {
    CertificateCompressionAlgorithm::Brotli
  }

  fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
    decompress_brotli(input, output)
  }
}

fn decompress_brotli(input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
  use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HuffmanCode};

  if output.len() > MAX_CERTIFICATE_MESSAGE {
    return Err(DecompressionFailed);
  }

  // Brotli's maximum standard window is 16 MiB. The decoder may allocate a
  // second ring buffer and Huffman tables, so bound total live allocations
  // separately below before decoding untrusted data.
  let budget = std::rc::Rc::new(std::cell::Cell::new(0usize));
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let mut state = BrotliState::new_strict(
      BudgetAllocator::new(0u8, budget.clone()),
      BudgetAllocator::new(0u32, budget.clone()),
      BudgetAllocator::new(HuffmanCode { bits: 2, value: 1 }, budget),
    );
    let mut available_in = input.len();
    let mut input_offset = 0;
    let mut total_out = 0;
    let mut overflow = [0u8; 1];
    loop {
      let before_in = input_offset;
      let before_out = total_out;
      let full = total_out >= output.len();
      let target = if full {
        &mut overflow[..]
      } else {
        &mut output[total_out..]
      };
      let mut available_out = target.len();
      let mut output_offset = 0;
      let status = BrotliDecompressStream(
        &mut available_in,
        &mut input_offset,
        input,
        &mut available_out,
        &mut output_offset,
        target,
        &mut total_out,
        &mut state,
      );
      if full && output_offset != 0 {
        return Err(DecompressionFailed);
      }
      match status {
        BrotliResult::ResultSuccess => {
          return if total_out == output.len() && input_offset == input.len() {
            Ok(())
          } else {
            Err(DecompressionFailed)
          };
        }
        BrotliResult::ResultFailure => return Err(DecompressionFailed),
        BrotliResult::NeedsMoreInput if available_in == 0 => return Err(DecompressionFailed),
        _ => {}
      }
      if before_in == input_offset && before_out == total_out {
        return Err(DecompressionFailed);
      }
    }
  }));
  result.unwrap_or(Err(DecompressionFailed))
}

const BROTLI_BUDGET: usize = 32 * 1024 * 1024;

/// Tracks decoder-owned allocations; all three Brotli allocation types share one budget.
struct BudgetAllocator<T: Clone> {
  default: T,
  used: std::rc::Rc<std::cell::Cell<usize>>,
}

impl<T: Clone> BudgetAllocator<T> {
  fn new(default: T, used: std::rc::Rc<std::cell::Cell<usize>>) -> Self {
    Self { default, used }
  }
}

struct BudgetMemory<T> {
  data: Box<[T]>,
  used: Option<std::rc::Rc<std::cell::Cell<usize>>>,
}

impl<T> Default for BudgetMemory<T> {
  fn default() -> Self {
    Self {
      data: Box::new([]),
      used: None,
    }
  }
}

impl<T> Drop for BudgetMemory<T> {
  fn drop(&mut self) {
    if let Some(used) = &self.used {
      used.set(
        used
          .get()
          .saturating_sub(std::mem::size_of_val(&*self.data)),
      );
    }
  }
}

impl<T> brotli::SliceWrapper<T> for BudgetMemory<T> {
  fn slice(&self) -> &[T] {
    &self.data
  }
}

impl<T> brotli::SliceWrapperMut<T> for BudgetMemory<T> {
  fn slice_mut(&mut self) -> &mut [T] {
    &mut self.data
  }
}

impl<T: Clone> brotli::Allocator<T> for BudgetAllocator<T> {
  type AllocatedMemory = BudgetMemory<T>;

  fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
    let bytes = len
      .checked_mul(std::mem::size_of::<T>())
      .expect("Brotli allocation overflow");
    let next = self
      .used
      .get()
      .checked_add(bytes)
      .expect("Brotli allocation overflow");
    assert!(next <= BROTLI_BUDGET, "Brotli allocation budget exceeded");
    let data = vec![self.default.clone(); len].into_boxed_slice();
    self.used.set(next);
    BudgetMemory {
      data,
      used: Some(self.used.clone()),
    }
  }

  fn free_cell(&mut self, data: Self::AllocatedMemory) {
    drop(data);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn codecs() -> [(&'static dyn CertCompressor, &'static dyn CertDecompressor); 3] {
    [(&ZSTD, &ZSTD), (&BROTLI, &BROTLI), (&ZLIB, &ZLIB)]
  }

  fn payload() -> Vec<u8> {
    // Certificate messages have highly repeated DER structures and PEM-like
    // names; this exercises each codec's successful compression path.
    b"certificate.example.test; subjectAlternativeName; issuer.example.test;".repeat(128)
  }

  #[test]
  fn all_codecs_round_trip_and_reject_invalid_framing() {
    let original = payload();
    for (compressor, decompressor) in codecs() {
      let frame = compressor
        .compress(original.clone(), CompressionLevel::Interactive)
        .unwrap();
      assert!(frame.len() < original.len());
      let mut decoded = vec![0; original.len()];
      decompressor.decompress(&frame, &mut decoded).unwrap();
      assert_eq!(decoded, original);

      let mut short_output = vec![0; original.len() - 1];
      assert!(decompressor.decompress(&frame, &mut short_output).is_err());
      let mut long_output = vec![0; original.len() + 1];
      assert!(decompressor.decompress(&frame, &mut long_output).is_err());
      assert!(
        decompressor
          .decompress(&frame[..frame.len() - 1], &mut decoded)
          .is_err()
      );
      assert!(decompressor.decompress(&[], &mut decoded).is_err());

      let mut trailing = frame.clone();
      trailing.push(0);
      assert!(decompressor.decompress(&trailing, &mut decoded).is_err());
      let mut concatenated = frame.clone();
      concatenated.extend_from_slice(&frame);
      assert!(
        decompressor
          .decompress(&concatenated, &mut decoded)
          .is_err()
      );
    }
  }

  #[test]
  fn incompressible_data_falls_back_to_plain_certificate() {
    let input: Vec<_> = (0u32..128).flat_map(u32::to_be_bytes).collect();
    for (compressor, _) in codecs() {
      let result = compressor.compress(input.clone(), CompressionLevel::Interactive);
      if let Ok(output) = result {
        assert!(output.len() < input.len());
      }
    }
  }

  #[test]
  fn decompression_rejects_oversize_and_garbage() {
    for (_, decompressor) in codecs() {
      assert!(decompressor.decompress(&[0xff; 16], &mut [0; 32]).is_err());
      assert!(
        decompressor
          .decompress(&[0; 16], &mut vec![0; MAX_CERTIFICATE_MESSAGE + 1])
          .is_err()
      );
    }
  }

  #[test]
  fn mutated_valid_frames_never_unwind() {
    let original = payload();
    for (compressor, decompressor) in codecs() {
      let frame = compressor
        .compress(original.clone(), CompressionLevel::Interactive)
        .unwrap();
      let stride = (frame.len() / 64).max(1);
      for offset in (0..frame.len()).step_by(stride) {
        for bit in [0x01, 0x80] {
          let mut mutated = frame.clone();
          mutated[offset] ^= bit;
          let mut decoded = vec![0; original.len()];
          let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decompressor.decompress(&mutated, &mut decoded)
          }));
          assert!(
            result.is_ok(),
            "{:?} decoder unwound at byte {offset}",
            compressor.algorithm()
          );
        }
      }
    }
  }

  #[test]
  fn brotli_allocations_are_bounded() {
    use brotli::Allocator;
    let used = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut allocator = BudgetAllocator::new(0u8, used.clone());
    let memory = allocator.alloc_cell(4096);
    assert_eq!(used.get(), 4096);
    allocator.free_cell(memory);
    assert_eq!(used.get(), 0);
    assert!(
      std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = allocator.alloc_cell(BROTLI_BUDGET + 1);
      }))
      .is_err()
    );
    assert_eq!(used.get(), 0);
  }

  #[test]
  fn policy_defaults_order_validation_and_serde() {
    let default = CertificateCompressionPolicy::default();
    assert!(default.enabled);
    assert_eq!(
      default.algorithms,
      [Algorithm::Zstd, Algorithm::Brotli, Algorithm::Zlib]
    );
    assert_eq!("zstd".parse::<Algorithm>(), Ok(Algorithm::Zstd));
    assert!("gzip".parse::<Algorithm>().is_err());
    let parsed: CertificateCompressionPolicy =
      toml::from_str("enabled = false\nalgorithms = ['brotli', 'zlib']").unwrap();
    assert!(!parsed.enabled);
    assert_eq!(parsed.algorithms, [Algorithm::Brotli, Algorithm::Zlib]);
    assert!(parsed.validate().is_ok());
    assert!(toml::from_str::<CertificateCompressionPolicy>("algorithms = ['gzip']").is_err());
    assert!(
      CertificateCompressionPolicy {
        algorithms: vec![],
        ..default.clone()
      }
      .validate()
      .is_err()
    );
    assert!(
      CertificateCompressionPolicy {
        algorithms: vec![Algorithm::Zstd, Algorithm::Zstd],
        ..default
      }
      .validate()
      .is_err()
    );
  }

  #[test]
  fn applies_order_and_disable_to_both_peers() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client = ClientConfig::builder_with_provider(provider.clone())
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_root_certificates(rustls::RootCertStore::empty())
      .with_no_client_auth();
    let mut server = ServerConfig::builder_with_provider(provider)
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_no_client_auth()
      .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
    let policy = CertificateCompressionPolicy {
      enabled: true,
      algorithms: vec![Algorithm::Brotli, Algorithm::Zlib],
    };
    apply_client(&mut client, &policy).unwrap();
    apply_server(&mut server, &policy).unwrap();
    let expected = [
      CertificateCompressionAlgorithm::Brotli,
      CertificateCompressionAlgorithm::Zlib,
    ];
    assert_eq!(
      client
        .cert_compressors
        .iter()
        .map(|c| c.algorithm())
        .collect::<Vec<_>>(),
      expected
    );
    assert_eq!(
      client
        .cert_decompressors
        .iter()
        .map(|c| c.algorithm())
        .collect::<Vec<_>>(),
      expected
    );
    assert_eq!(
      server
        .cert_compressors
        .iter()
        .map(|c| c.algorithm())
        .collect::<Vec<_>>(),
      expected
    );
    assert_eq!(
      server
        .cert_decompressors
        .iter()
        .map(|c| c.algorithm())
        .collect::<Vec<_>>(),
      expected
    );

    let mut disabled = policy;
    disabled.enabled = false;
    apply_client(&mut client, &disabled).unwrap();
    apply_server(&mut server, &disabled).unwrap();
    assert!(client.cert_compressors.is_empty() && client.cert_decompressors.is_empty());
    assert!(server.cert_compressors.is_empty() && server.cert_decompressors.is_empty());
    assert!(matches!(
      &*client.cert_compression_cache,
      CompressionCache::Disabled
    ));
    assert!(matches!(
      &*server.cert_compression_cache,
      CompressionCache::Disabled
    ));
  }
}
