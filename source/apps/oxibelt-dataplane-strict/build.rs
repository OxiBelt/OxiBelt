fn main() {
  println!("cargo:rustc-check-cfg=cfg(oxibelt_strict_artifact)");
  println!("cargo:rustc-cfg=oxibelt_strict_artifact");
}
