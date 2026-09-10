fn main() {
  println!("cargo:rustc-check-cfg=cfg(oxibelt_strict_artifact)");
  println!("cargo:rustc-cfg=oxibelt_strict_artifact");
  // The shared main source recognizes the integrated binary's opt-in feature.
  // This package does not declare or enable it and keeps its system allocator.
  println!("cargo:rustc-check-cfg=cfg(feature, values(\"allocator-mimalloc-experiment\"))");
}
