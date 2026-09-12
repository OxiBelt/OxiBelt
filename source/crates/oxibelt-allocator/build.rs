#[cfg(feature = "native-mimalloc")]
use std::path::PathBuf;
#[cfg(feature = "native-mimalloc")]
use std::{env, fs, process::Command};

#[cfg(feature = "native-mimalloc")]
const REQUIRED_PRIVATE_ALLOCATOR_SYMBOLS: &[&str] = &[
  "mi_malloc_aligned",
  "mi_zalloc_aligned",
  "mi_realloc_aligned",
  "mi_free",
];

#[cfg(feature = "native-mimalloc")]
const FORBIDDEN_PROCESS_ALLOCATOR_SYMBOLS: &[&str] = &[
  "malloc",
  "calloc",
  "realloc",
  "free",
  "aligned_alloc",
  "posix_memalign",
  "memalign",
  "valloc",
  "pvalloc",
  "cfree",
  "malloc_size",
  "malloc_good_size",
  "malloc_usable_size",
  "reallocf",
  "reallocarr",
  "reallocarray",
  "strdup",
  "strndup",
  "vfree",
  "_aligned_malloc",
  "__libc_malloc",
  "__libc_calloc",
  "__libc_realloc",
  "__libc_free",
  "__libc_memalign",
  "__libc_valloc",
  "__libc_pvalloc",
  "__libc_cfree",
  "__posix_memalign",
  "_ZdlPv",
  "_ZdaPv",
  "_ZdlPvm",
  "_ZdaPvm",
  "_Znwm",
  "_Znam",
  "_ZdlPvSt11align_val_t",
  "_ZdaPvSt11align_val_t",
  "_ZdlPvmSt11align_val_t",
  "_ZdaPvmSt11align_val_t",
  "_ZnwmSt11align_val_t",
  "_ZnamSt11align_val_t",
  "_ZdlPvRKSt9nothrow_t",
  "_ZdaPvRKSt9nothrow_t",
  "_ZnwmRKSt9nothrow_t",
  "_ZnamRKSt9nothrow_t",
  "_ZdlPvSt11align_val_tRKSt9nothrow_t",
  "_ZdaPvSt11align_val_tRKSt9nothrow_t",
  "_ZnwmSt11align_val_tRKSt9nothrow_t",
  "_ZnamSt11align_val_tRKSt9nothrow_t",
];

#[cfg(feature = "native-mimalloc")]
const OXIBELT_MIMALLOC_TRANSLATION_UNIT: &str = r#"#if defined(MI_MALLOC_OVERRIDE)
#error "OxiBelt's private mimalloc binding must not override the process C allocator"
#endif
#if !defined(MI_SECURE) || MI_SECURE != 4
#error "OxiBelt's private mimalloc binding requires MI_SECURE=4"
#endif
#if !defined(MI_DEBUG) || MI_DEBUG != 0
#error "OxiBelt's private mimalloc binding requires MI_DEBUG=0"
#endif

#include "src/static.c"

#if defined(MI_MALLOC_OVERRIDE)
#error "OxiBelt's private mimalloc binding must not override the process C allocator"
#endif
#if !defined(MI_SECURE) || MI_SECURE != 4
#error "OxiBelt's private mimalloc binding requires MI_SECURE=4"
#endif
#if !defined(MI_DEBUG) || MI_DEBUG != 0
#error "OxiBelt's private mimalloc binding requires MI_DEBUG=0"
#endif
"#;

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
fn write_guarded_translation_unit() -> PathBuf {
  let path = PathBuf::from(required_env("OUT_DIR")).join("oxibelt-mimalloc.c");
  fs::write(&path, OXIBELT_MIMALLOC_TRANSLATION_UNIT)
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
  path
}

#[cfg(feature = "native-mimalloc")]
fn archive_defines_symbol(symbols: &str, expected: &str) -> bool {
  symbols.lines().any(|line| {
    line
      .split_ascii_whitespace()
      .next_back()
      .is_some_and(|symbol| symbol == expected)
  })
}

#[cfg(feature = "native-mimalloc")]
fn audit_native_archive() {
  let archive = PathBuf::from(required_env("OUT_DIR")).join("liboxibelt_mimalloc.a");
  let output = Command::new("nm")
    .args(["-g", "--defined-only"])
    .arg(&archive)
    .output()
    .unwrap_or_else(|error| panic!("failed to inspect {} with nm: {error}", archive.display()));
  assert!(
    output.status.success(),
    "nm failed while inspecting {}: {}",
    archive.display(),
    String::from_utf8_lossy(&output.stderr)
  );
  let symbols = String::from_utf8(output.stdout)
    .unwrap_or_else(|_| panic!("nm output for {} must be valid UTF-8", archive.display()));
  for symbol in REQUIRED_PRIVATE_ALLOCATOR_SYMBOLS {
    assert!(
      archive_defines_symbol(&symbols, symbol),
      "native allocator archive must define private binding symbol `{symbol}`"
    );
  }
  for symbol in FORBIDDEN_PROCESS_ALLOCATOR_SYMBOLS {
    assert!(
      !archive_defines_symbol(&symbols, symbol),
      "native allocator archive must not define process allocator symbol `{symbol}`"
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
  println!("cargo:rerun-if-changed={}", native_root.display());

  let mut build = cc::Build::new();
  build.include(&native_root);
  build.include(native_root.join("include"));
  build.include(native_root.join("src"));
  build.file(write_guarded_translation_unit());
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
  audit_native_archive();
}
