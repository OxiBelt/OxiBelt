//! Crypto provider and primitive backend configuration.
//! Defaults preserve the historical AWS-LC rustls provider and RustCrypto primitives.

use anyhow::bail;
use serde::Deserialize;

use super::{Config, TlsKeyExchangeGroup, UpstreamEchMode};

pub(in crate::config) const CRYPTO_CONFIG_KEYS: &[&str] = &[
  "primitive_backend",
  "primitive_backends",
  "primitive_provider",
  "primitives",
  "tls_provider",
];

pub(in crate::config) const CRYPTO_PRIMITIVES_CONFIG_KEYS: &[&str] =
  &["aes_gcm", "chacha20poly1305", "hkdf", "hmac_sha256", "sha2"];
pub(in crate::config) const CRYPTO_PRIMITIVE_BACKENDS_CONFIG_KEYS: &[&str] =
  CRYPTO_PRIMITIVES_CONFIG_KEYS;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CryptoConfig {
  #[serde(default)]
  pub tls_provider: TlsCryptoProvider,
  #[serde(default)]
  pub primitive_provider: CryptoPrimitiveProvider,
  #[serde(default)]
  pub primitive_backend: CryptoPrimitiveBackend,
  #[serde(default)]
  pub primitives: CryptoPrimitiveOverrides,
  #[serde(default)]
  pub primitive_backends: CryptoPrimitiveBackendOverrides,
}

impl Default for CryptoConfig {
  fn default() -> Self {
    Self {
      tls_provider: TlsCryptoProvider::AwsLcRs,
      primitive_provider: CryptoPrimitiveProvider::RustCrypto,
      primitive_backend: CryptoPrimitiveBackend::Auto,
      primitives: CryptoPrimitiveOverrides::default(),
      primitive_backends: CryptoPrimitiveBackendOverrides::default(),
    }
  }
}

impl CryptoConfig {
  pub(crate) fn sha2_provider(&self) -> CryptoPrimitiveProvider {
    self.primitives.sha2.unwrap_or(self.primitive_provider)
  }

  pub(crate) fn hkdf_provider(&self) -> CryptoPrimitiveProvider {
    self.primitives.hkdf.unwrap_or(self.primitive_provider)
  }

  pub(crate) fn hmac_sha256_provider(&self) -> CryptoPrimitiveProvider {
    self
      .primitives
      .hmac_sha256
      .unwrap_or(self.primitive_provider)
  }

  pub(crate) fn aes_gcm_provider(&self) -> CryptoPrimitiveProvider {
    self.primitives.aes_gcm.unwrap_or(self.primitive_provider)
  }

  pub(crate) fn chacha20poly1305_provider(&self) -> CryptoPrimitiveProvider {
    self
      .primitives
      .chacha20poly1305
      .unwrap_or(self.primitive_provider)
  }

  pub(crate) fn sha2_backend(&self) -> CryptoPrimitiveBackend {
    self
      .primitive_backends
      .sha2
      .unwrap_or(self.primitive_backend)
  }

  pub(crate) fn hkdf_backend(&self) -> CryptoPrimitiveBackend {
    self
      .primitive_backends
      .hkdf
      .unwrap_or(self.primitive_backend)
  }

  pub(crate) fn hmac_sha256_backend(&self) -> CryptoPrimitiveBackend {
    self
      .primitive_backends
      .hmac_sha256
      .unwrap_or(self.primitive_backend)
  }

  pub(crate) fn aes_gcm_backend(&self) -> CryptoPrimitiveBackend {
    self
      .primitive_backends
      .aes_gcm
      .unwrap_or(self.primitive_backend)
  }

  pub(crate) fn chacha20poly1305_backend(&self) -> CryptoPrimitiveBackend {
    self
      .primitive_backends
      .chacha20poly1305
      .unwrap_or(self.primitive_backend)
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsCryptoProvider {
  #[default]
  AwsLcRs,
  Ring,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CryptoPrimitiveProvider {
  AwsLcRs,
  #[serde(rename = "rustcrypto", alias = "rust_crypto")]
  #[default]
  RustCrypto,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CryptoPrimitiveBackend {
  #[default]
  Auto,
  Hardware,
  Software,
  #[serde(rename = "soft")]
  Soft,
  #[serde(rename = "x86-sha", alias = "x86_sha")]
  X86Sha,
  #[serde(rename = "x86-avx2", alias = "x86_avx2")]
  X86Avx2,
  #[serde(rename = "aarch64-sha2", alias = "aarch64_sha2")]
  Aarch64Sha2,
  #[serde(rename = "aarch64-sha3", alias = "aarch64_sha3")]
  Aarch64Sha3,
  #[serde(rename = "riscv-zknh", alias = "riscv_zknh")]
  RiscvZknh,
  #[serde(rename = "aes-avx256", alias = "aes_avx256")]
  AesAvx256,
  #[serde(rename = "aes-avx512", alias = "aes_avx512")]
  AesAvx512,
  #[serde(rename = "chacha20-sse2", alias = "chacha20_sse2", alias = "sse2")]
  Chacha20Sse2,
  #[serde(rename = "chacha20-avx2", alias = "chacha20_avx2", alias = "avx2")]
  Chacha20Avx2,
  #[serde(
    rename = "chacha20-avx512",
    alias = "chacha20_avx512",
    alias = "avx512"
  )]
  Chacha20Avx512,
}

impl CryptoPrimitiveBackend {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::Hardware => "hardware",
      Self::Software => "software",
      Self::Soft => "soft",
      Self::X86Sha => "x86-sha",
      Self::X86Avx2 => "x86-avx2",
      Self::Aarch64Sha2 => "aarch64-sha2",
      Self::Aarch64Sha3 => "aarch64-sha3",
      Self::RiscvZknh => "riscv-zknh",
      Self::AesAvx256 => "aes-avx256",
      Self::AesAvx512 => "aes-avx512",
      Self::Chacha20Sse2 => "chacha20-sse2",
      Self::Chacha20Avx2 => "chacha20-avx2",
      Self::Chacha20Avx512 => "chacha20-avx512",
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct CryptoPrimitiveOverrides {
  #[serde(default)]
  pub aes_gcm: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub chacha20poly1305: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub hkdf: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub hmac_sha256: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub sha2: Option<CryptoPrimitiveProvider>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct CryptoPrimitiveBackendOverrides {
  #[serde(default)]
  pub aes_gcm: Option<CryptoPrimitiveBackend>,
  #[serde(default)]
  pub chacha20poly1305: Option<CryptoPrimitiveBackend>,
  #[serde(default)]
  pub hkdf: Option<CryptoPrimitiveBackend>,
  #[serde(default)]
  pub hmac_sha256: Option<CryptoPrimitiveBackend>,
  #[serde(default)]
  pub sha2: Option<CryptoPrimitiveBackend>,
}

pub(super) fn validate_crypto(config: &Config) -> anyhow::Result<()> {
  validate_primitive_backends(&config.crypto)?;
  validate_tls_provider(config)?;
  Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PrimitiveBackendFamily {
  Sha256,
  AesGcm,
  Chacha20Poly1305,
}

fn validate_primitive_backends(config: &CryptoConfig) -> anyhow::Result<()> {
  validate_primitive_backend(
    "sha2",
    config.sha2_provider(),
    config.sha2_backend(),
    inherited_backend_field(config.primitive_backends.sha2, "sha2"),
    PrimitiveBackendFamily::Sha256,
  )?;
  validate_primitive_backend(
    "hkdf",
    config.hkdf_provider(),
    config.hkdf_backend(),
    inherited_backend_field(config.primitive_backends.hkdf, "hkdf"),
    PrimitiveBackendFamily::Sha256,
  )?;
  validate_primitive_backend(
    "hmac_sha256",
    config.hmac_sha256_provider(),
    config.hmac_sha256_backend(),
    inherited_backend_field(config.primitive_backends.hmac_sha256, "hmac_sha256"),
    PrimitiveBackendFamily::Sha256,
  )?;
  validate_primitive_backend(
    "aes_gcm",
    config.aes_gcm_provider(),
    config.aes_gcm_backend(),
    inherited_backend_field(config.primitive_backends.aes_gcm, "aes_gcm"),
    PrimitiveBackendFamily::AesGcm,
  )?;
  validate_primitive_backend(
    "chacha20poly1305",
    config.chacha20poly1305_provider(),
    config.chacha20poly1305_backend(),
    inherited_backend_field(
      config.primitive_backends.chacha20poly1305,
      "chacha20poly1305",
    ),
    PrimitiveBackendFamily::Chacha20Poly1305,
  )?;
  Ok(())
}

fn inherited_backend_field(
  override_value: Option<CryptoPrimitiveBackend>,
  primitive_name: &str,
) -> String {
  if override_value.is_some() {
    format!("crypto.primitive_backends.{primitive_name}")
  } else {
    "crypto.primitive_backend".to_string()
  }
}

fn validate_primitive_backend(
  primitive_name: &str,
  provider: CryptoPrimitiveProvider,
  requested_backend: CryptoPrimitiveBackend,
  field_name: String,
  family: PrimitiveBackendFamily,
) -> anyhow::Result<()> {
  if requested_backend == CryptoPrimitiveBackend::Auto {
    return Ok(());
  }
  if provider == CryptoPrimitiveProvider::AwsLcRs {
    bail!(
      "{field_name} = \"{}\" is not supported for {primitive_name} with provider \"aws_lc_rs\"; use \"auto\"",
      requested_backend.as_str()
    );
  }
  let required_backend =
    resolve_backend_request(family, requested_backend, &field_name, primitive_name)?;
  if !build_supports_backend(family, required_backend) {
    bail!(
      "{field_name} = \"{}\" requires an OxiBelt binary built with {}; use \"auto\" or rebuild with tests/scripts/build-crypto-backend-variant.sh",
      requested_backend.as_str(),
      build_contract(family, required_backend)
    );
  }
  if !runtime_supports_backend(required_backend) {
    bail!(
      "{field_name} = \"{}\" requires CPU support for {}",
      requested_backend.as_str(),
      runtime_requirement(required_backend)
    );
  }
  Ok(())
}

fn resolve_backend_request(
  family: PrimitiveBackendFamily,
  requested_backend: CryptoPrimitiveBackend,
  field_name: &str,
  primitive_name: &str,
) -> anyhow::Result<CryptoPrimitiveBackend> {
  match requested_backend {
    CryptoPrimitiveBackend::Auto => Ok(CryptoPrimitiveBackend::Auto),
    CryptoPrimitiveBackend::Software => Ok(CryptoPrimitiveBackend::Soft),
    CryptoPrimitiveBackend::Hardware => hardware_backend_for_family(family).ok_or_else(|| {
      anyhow::anyhow!(
        "{field_name} = \"hardware\" is not supported for {primitive_name} by this build"
      )
    }),
    backend if backend_supported_for_family(family, backend) => Ok(backend),
    backend => bail!(
      "{field_name} = \"{}\" is not a supported backend for {primitive_name}",
      backend.as_str()
    ),
  }
}

fn hardware_backend_for_family(family: PrimitiveBackendFamily) -> Option<CryptoPrimitiveBackend> {
  let candidates: &[CryptoPrimitiveBackend] = match family {
    PrimitiveBackendFamily::Sha256 => &[
      CryptoPrimitiveBackend::X86Sha,
      CryptoPrimitiveBackend::Aarch64Sha2,
      CryptoPrimitiveBackend::RiscvZknh,
    ],
    PrimitiveBackendFamily::AesGcm => &[
      CryptoPrimitiveBackend::AesAvx512,
      CryptoPrimitiveBackend::AesAvx256,
    ],
    PrimitiveBackendFamily::Chacha20Poly1305 => &[
      CryptoPrimitiveBackend::Chacha20Avx512,
      CryptoPrimitiveBackend::Chacha20Avx2,
      CryptoPrimitiveBackend::Chacha20Sse2,
    ],
  };
  candidates
    .iter()
    .copied()
    .find(|backend| build_supports_backend(family, *backend))
}

fn backend_supported_for_family(
  family: PrimitiveBackendFamily,
  backend: CryptoPrimitiveBackend,
) -> bool {
  match family {
    PrimitiveBackendFamily::Sha256 => matches!(
      backend,
      CryptoPrimitiveBackend::Soft
        | CryptoPrimitiveBackend::X86Sha
        | CryptoPrimitiveBackend::Aarch64Sha2
        | CryptoPrimitiveBackend::RiscvZknh
    ),
    PrimitiveBackendFamily::AesGcm => matches!(
      backend,
      CryptoPrimitiveBackend::Soft
        | CryptoPrimitiveBackend::AesAvx256
        | CryptoPrimitiveBackend::AesAvx512
    ),
    PrimitiveBackendFamily::Chacha20Poly1305 => matches!(
      backend,
      CryptoPrimitiveBackend::Soft
        | CryptoPrimitiveBackend::Chacha20Sse2
        | CryptoPrimitiveBackend::Chacha20Avx2
        | CryptoPrimitiveBackend::Chacha20Avx512
    ),
  }
}

fn build_supports_backend(family: PrimitiveBackendFamily, backend: CryptoPrimitiveBackend) -> bool {
  match (family, backend) {
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::Soft) => {
      cfg!(any(sha2_backend = "soft", sha2_256_backend = "soft"))
    }
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::X86Sha) => {
      cfg!(sha2_256_backend = "x86-sha")
    }
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::Aarch64Sha2) => {
      cfg!(sha2_256_backend = "aarch64-sha2")
    }
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::RiscvZknh) => {
      cfg!(any(
        sha2_backend = "riscv-zknh",
        sha2_256_backend = "riscv-zknh"
      ))
    }
    (PrimitiveBackendFamily::AesGcm, CryptoPrimitiveBackend::Soft) => {
      cfg!(aes_backend = "soft")
    }
    (PrimitiveBackendFamily::AesGcm, CryptoPrimitiveBackend::AesAvx256) => {
      cfg!(aes_backend = "avx256")
    }
    (PrimitiveBackendFamily::AesGcm, CryptoPrimitiveBackend::AesAvx512) => {
      cfg!(aes_backend = "avx512")
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Soft) => {
      cfg!(chacha20_backend = "soft")
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Chacha20Sse2) => {
      cfg!(chacha20_backend = "sse2")
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Chacha20Avx2) => {
      cfg!(chacha20_backend = "avx2")
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Chacha20Avx512) => {
      cfg!(all(chacha20_avx512, chacha20_backend = "avx512"))
    }
    _ => false,
  }
}

fn build_contract(family: PrimitiveBackendFamily, backend: CryptoPrimitiveBackend) -> &'static str {
  match (family, backend) {
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::Soft) => {
      "`--cfg sha2_backend=\"soft\"` or `--cfg sha2_256_backend=\"soft\"`"
    }
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::X86Sha) => {
      "`--cfg sha2_256_backend=\"x86-sha\"`"
    }
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::Aarch64Sha2) => {
      "`--cfg sha2_256_backend=\"aarch64-sha2\"`"
    }
    (PrimitiveBackendFamily::Sha256, CryptoPrimitiveBackend::RiscvZknh) => {
      "`--cfg sha2_backend=\"riscv-zknh\"` or `--cfg sha2_256_backend=\"riscv-zknh\"`"
    }
    (PrimitiveBackendFamily::AesGcm, CryptoPrimitiveBackend::Soft) => {
      "`--cfg aes_backend=\"soft\"`"
    }
    (PrimitiveBackendFamily::AesGcm, CryptoPrimitiveBackend::AesAvx256) => {
      "`--cfg aes_backend=\"avx256\"`"
    }
    (PrimitiveBackendFamily::AesGcm, CryptoPrimitiveBackend::AesAvx512) => {
      "`--cfg aes_backend=\"avx512\"`"
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Soft) => {
      "`--cfg chacha20_backend=\"soft\"`"
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Chacha20Sse2) => {
      "`--cfg chacha20_backend=\"sse2\"`"
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Chacha20Avx2) => {
      "`--cfg chacha20_backend=\"avx2\"`"
    }
    (PrimitiveBackendFamily::Chacha20Poly1305, CryptoPrimitiveBackend::Chacha20Avx512) => {
      "`--cfg chacha20_avx512 --cfg chacha20_backend=\"avx512\"`"
    }
    _ => "a supported crypto backend cfg",
  }
}

fn runtime_supports_backend(backend: CryptoPrimitiveBackend) -> bool {
  match backend {
    CryptoPrimitiveBackend::Auto | CryptoPrimitiveBackend::Soft => true,
    CryptoPrimitiveBackend::X86Sha => cpu_supports_x86_sha(),
    CryptoPrimitiveBackend::X86Avx2 | CryptoPrimitiveBackend::Chacha20Avx2 => {
      cpu_supports_x86_avx2()
    }
    CryptoPrimitiveBackend::AesAvx256 => cpu_supports_x86_aes_avx256(),
    CryptoPrimitiveBackend::AesAvx512 => cpu_supports_x86_aes_avx512(),
    CryptoPrimitiveBackend::Chacha20Sse2 => cpu_supports_x86_sse2(),
    CryptoPrimitiveBackend::Chacha20Avx512 => cpu_supports_x86_avx512vl(),
    CryptoPrimitiveBackend::Aarch64Sha2 => cpu_supports_aarch64_sha2(),
    CryptoPrimitiveBackend::Aarch64Sha3 => cpu_supports_aarch64_sha3(),
    CryptoPrimitiveBackend::RiscvZknh => true,
    CryptoPrimitiveBackend::Hardware | CryptoPrimitiveBackend::Software => false,
  }
}

fn runtime_requirement(backend: CryptoPrimitiveBackend) -> &'static str {
  match backend {
    CryptoPrimitiveBackend::X86Sha => "x86 SHA extensions",
    CryptoPrimitiveBackend::X86Avx2 | CryptoPrimitiveBackend::Chacha20Avx2 => "x86 AVX2",
    CryptoPrimitiveBackend::AesAvx256 => "x86 AES, AVX, and VAES",
    CryptoPrimitiveBackend::AesAvx512 => "x86 AVX-512F, AVX-512VL, and VAES",
    CryptoPrimitiveBackend::Chacha20Sse2 => "x86 SSE2",
    CryptoPrimitiveBackend::Chacha20Avx512 => "x86 AVX-512F and AVX-512VL",
    CryptoPrimitiveBackend::Aarch64Sha2 => "AArch64 SHA2",
    CryptoPrimitiveBackend::Aarch64Sha3 => "AArch64 SHA3",
    CryptoPrimitiveBackend::RiscvZknh => "RISC-V Zknh",
    _ => "the requested backend",
  }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_supports_x86_sha() -> bool {
  std::arch::is_x86_feature_detected!("sha")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_supports_x86_sha() -> bool {
  false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_supports_x86_sse2() -> bool {
  std::arch::is_x86_feature_detected!("sse2")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_supports_x86_sse2() -> bool {
  false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_supports_x86_avx2() -> bool {
  std::arch::is_x86_feature_detected!("avx2")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_supports_x86_avx2() -> bool {
  false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_supports_x86_aes_avx256() -> bool {
  std::arch::is_x86_feature_detected!("aes")
    && std::arch::is_x86_feature_detected!("avx")
    && std::arch::is_x86_feature_detected!("vaes")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_supports_x86_aes_avx256() -> bool {
  false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_supports_x86_aes_avx512() -> bool {
  std::arch::is_x86_feature_detected!("avx512f")
    && std::arch::is_x86_feature_detected!("avx512vl")
    && std::arch::is_x86_feature_detected!("vaes")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_supports_x86_aes_avx512() -> bool {
  false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_supports_x86_avx512vl() -> bool {
  std::arch::is_x86_feature_detected!("avx512f") && std::arch::is_x86_feature_detected!("avx512vl")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_supports_x86_avx512vl() -> bool {
  false
}

#[cfg(target_arch = "aarch64")]
fn cpu_supports_aarch64_sha2() -> bool {
  std::arch::is_aarch64_feature_detected!("sha2")
}

#[cfg(not(target_arch = "aarch64"))]
fn cpu_supports_aarch64_sha2() -> bool {
  false
}

#[cfg(target_arch = "aarch64")]
fn cpu_supports_aarch64_sha3() -> bool {
  std::arch::is_aarch64_feature_detected!("sha3")
}

#[cfg(not(target_arch = "aarch64"))]
fn cpu_supports_aarch64_sha3() -> bool {
  false
}

fn validate_tls_provider(config: &Config) -> anyhow::Result<()> {
  match config.crypto.tls_provider {
    TlsCryptoProvider::AwsLcRs => Ok(()),
    TlsCryptoProvider::Ring => {
      if !cfg!(feature = "crypto-ring") {
        bail!("crypto.tls_provider = \"ring\" requires the crypto-ring build feature");
      }
      validate_ring_tls_compatibility(config)
    }
  }
}

fn validate_ring_tls_compatibility(config: &Config) -> anyhow::Result<()> {
  reject_ring_pq_groups(
    "tls.1_3.key_exchange_groups",
    &config.tls.tls13.key_exchange_groups,
  )?;
  for route in &config.routes {
    if let Some(groups) = &route.tls.tls13.key_exchange_groups {
      reject_ring_pq_groups(
        &format!("route {} tls.1_3.key_exchange_groups", route.name),
        groups,
      )?;
    }
  }
  for upstream in &config.upstreams {
    if upstream.tls.ech.mode != UpstreamEchMode::Disabled {
      bail!(
        "upstream {} tls.ech.mode requires crypto.tls_provider = \"aws_lc_rs\"",
        upstream.name
      );
    }
  }
  Ok(())
}

fn reject_ring_pq_groups(field_name: &str, groups: &[TlsKeyExchangeGroup]) -> anyhow::Result<()> {
  if groups.contains(&TlsKeyExchangeGroup::X25519MlKem768) {
    bail!("{field_name} cannot include x25519mlkem768 when crypto.tls_provider = \"ring\"");
  }
  Ok(())
}
