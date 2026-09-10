#[cfg(feature = "native-mimalloc")]
use std::env;
#[cfg(feature = "native-mimalloc")]
use std::path::PathBuf;

fn main() {
  #[cfg(feature = "native-mimalloc")]
  compile_mimalloc();
}

#[cfg(feature = "native-mimalloc")]
fn required_env(name: &str) -> String {
  env::var(name).unwrap_or_else(|_| panic!("Cargo did not provide {name}"))
}

#[cfg(feature = "native-mimalloc")]
fn reject_native_configuration_overrides() {
  let target = required_env("TARGET");
  let host = required_env("HOST");
  let target_normalized = target.replace(['-', '.'], "_");
  let build_kind = if target == host { "HOST" } else { "TARGET" };
  let names = [
    format!("CFLAGS_{target}"),
    format!("CFLAGS_{target_normalized}"),
    format!("{build_kind}_CFLAGS"),
    "CFLAGS".to_owned(),
  ];
  println!("cargo:rerun-if-env-changed=CC_SHELL_ESCAPED_FLAGS");
  let shell_escaped_flags = env::var_os("CC_SHELL_ESCAPED_FLAGS")
    .is_some_and(|value| !matches!(value.to_str(), Some("" | "0" | "false" | "no")));

  for name in names {
    println!("cargo:rerun-if-env-changed={name}");
    let Some(value) = env::var_os(&name) else {
      continue;
    };
    let value = value
      .into_string()
      .unwrap_or_else(|_| panic!("{name} must be valid UTF-8 for reviewed native builds"));
    assert!(
      !shell_escaped_flags || value.is_empty(),
      "{name} must use cc's reviewable whitespace-separated flag syntax"
    );
    let normalized = value.to_ascii_uppercase();
    let changes_preprocessor_input = normalized.split_ascii_whitespace().any(|argument| {
      let argument = argument.trim_matches(['\'', '"']);
      [
        "-D",
        "-U",
        "/D",
        "/U",
        "-INCLUDE",
        "--INCLUDE",
        "-IMACROS",
        "-WP,",
        "-XPREPROCESSOR",
        "-UNDEF",
        "-FPLUGIN",
        "-SPECS",
        "-WRAPPER",
        "--CONFIG",
        "-CONFIG",
        "@",
      ]
      .iter()
      .any(|prefix| argument.starts_with(prefix))
    });
    assert!(
      !changes_preprocessor_input
        && !normalized.contains("MI_")
        && !normalized.contains("NDEBUG")
        && !normalized.contains("TLS-MODEL")
        && !normalized.contains("OMIT-LEAF-FRAME-POINTER"),
      "{name} must not override or inject mimalloc configuration"
    );
  }
}

#[cfg(feature = "native-mimalloc")]
fn compile_mimalloc() {
  let target_os = required_env("CARGO_CFG_TARGET_OS");
  let target_arch = required_env("CARGO_CFG_TARGET_ARCH");
  let target_pointer_width = required_env("CARGO_CFG_TARGET_POINTER_WIDTH");
  let target_env = required_env("CARGO_CFG_TARGET_ENV");
  assert!(
    target_os == "linux"
      && target_arch == "x86_64"
      && target_pointer_width == "64"
      && matches!(target_env.as_str(), "gnu" | "musl"),
    "allocator-mimalloc-experiment supports only 64-bit x86 Linux GNU and musl targets"
  );
  reject_native_configuration_overrides();

  let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
  let native_root = manifest_dir.join("../../third_party/mimalloc-3.3.2+oxibelt.1");
  let translation_unit = native_root.join("src/static.c");
  println!("cargo:rerun-if-changed={}", native_root.display());

  let mut build = cc::Build::new();
  build.include(native_root.join("include"));
  build.include(native_root.join("src"));
  build.file(translation_unit);
  build.flag("-Wno-error=date-time");
  build.flag("-ftls-model=initial-exec");
  build.flag("-mno-omit-leaf-frame-pointer");
  build.define("MI_SECURE", "4");
  build.define("MI_DEBUG", "0");
  if required_env("DEBUG") == "false" {
    build.define("MI_BUILD_RELEASE", None);
    build.define("NDEBUG", None);
  }
  build.compile("oxibelt_mimalloc");
}
