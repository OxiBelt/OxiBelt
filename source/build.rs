fn main() {
  println!("cargo:rustc-check-cfg=cfg(aes_backend, values(\"soft\", \"avx256\", \"avx512\"))");
  println!("cargo:rustc-check-cfg=cfg(chacha20_avx512)");
  println!(
    "cargo:rustc-check-cfg=cfg(chacha20_backend, values(\"soft\", \"sse2\", \"avx2\", \"avx512\"))"
  );
  println!("cargo:rustc-check-cfg=cfg(sha2_backend, values(\"soft\", \"riscv-zknh\"))");
  println!(
    "cargo:rustc-check-cfg=cfg(sha2_256_backend, values(\"soft\", \"x86-sha\", \"aarch64-sha2\", \"riscv-zknh\"))"
  );
  println!(
    "cargo:rustc-check-cfg=cfg(sha2_512_backend, values(\"soft\", \"x86-avx2\", \"aarch64-sha3\", \"riscv-zknh\"))"
  );
}
