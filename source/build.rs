use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const PERSON_PROOF_ASSET: &str = "assets/person-proof-challenge.html";
const ADMIN_OPENAPI_ASSET: &str = "assets/admin-openapi.json";
const PERSON_PROOF_OUTPUT: &str = "person-proof-challenge.html";
const ADMIN_OPENAPI_OUTPUT: &str = "admin-openapi.json";

const PERSON_PROOF_PLACEHOLDERS: &[(&str, usize)] = &[
  ("__CLEARANCE_STORAGE_HTML__", 1),
  ("__CSP_NONCE__", 2),
  ("__DIFFICULTY__", 2),
  ("__EXPIRES_UNIX_MS__", 1),
  ("__MODE__", 1),
  ("__RETURN_PATH_JS__", 1),
  ("__SESSION_HTML__", 1),
  ("__SESSION_JS__", 1),
  ("__SESSION_PATH_HTML__", 1),
  ("__SESSION_PATH_JS__", 1),
  ("__VERIFY_PATH_HTML__", 1),
  ("__VERIFY_PATH_JS__", 1),
];

fn main() {
  embed_validated_assets();

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

fn embed_validated_assets() {
  let manifest_dir = PathBuf::from(
    env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must provide CARGO_MANIFEST_DIR"),
  );
  let out_dir =
    PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide the build-script OUT_DIR"));
  let person_proof_path = manifest_dir.join(PERSON_PROOF_ASSET);
  let admin_openapi_path = manifest_dir.join(ADMIN_OPENAPI_ASSET);

  println!("cargo:rerun-if-changed={}", person_proof_path.display());
  println!("cargo:rerun-if-changed={}", admin_openapi_path.display());
  println!("cargo:rerun-if-env-changed=OXIBELT_SOURCE_REVISION");

  let person_proof = read_asset(&person_proof_path, "Person Proof challenge");
  validate_person_proof_asset(&person_proof);
  let admin_openapi = read_asset(&admin_openapi_path, "Admin OpenAPI document");
  validate_admin_openapi(&admin_openapi);

  write_embedded_asset(&out_dir.join(PERSON_PROOF_OUTPUT), &person_proof);
  write_embedded_asset(&out_dir.join(ADMIN_OPENAPI_OUTPUT), &admin_openapi);

  println!(
    "cargo:rustc-env=OXIBELT_PERSON_PROOF_ASSET_SHA256={}",
    sha256_hex(&person_proof)
  );
  println!(
    "cargo:rustc-env=OXIBELT_ADMIN_OPENAPI_SHA256={}",
    sha256_hex(&admin_openapi)
  );
  println!(
    "cargo:rustc-env=OXIBELT_SOURCE_REVISION={}",
    source_revision()
  );
}

fn read_asset(path: &Path, label: &str) -> Vec<u8> {
  fs::read(path)
    .unwrap_or_else(|error| panic!("failed to read {label} {}: {error}", path.display()))
}

fn write_embedded_asset(path: &Path, bytes: &[u8]) {
  fs::write(path, bytes)
    .unwrap_or_else(|error| panic!("failed to write embedded asset {}: {error}", path.display()));
}

fn validate_person_proof_asset(bytes: &[u8]) {
  assert!(
    (4 * 1024..=256 * 1024).contains(&bytes.len()),
    "Person Proof challenge asset size must be between 4 KiB and 256 KiB"
  );
  let html = std::str::from_utf8(bytes).expect("Person Proof challenge asset must be UTF-8");

  for marker in [
    "<!doctype html>",
    "<meta name=\"oxibelt-person-proof-session\" content=\"__SESSION_HTML__\">",
    "<style nonce=\"__CSP_NONCE__\">",
    "<script type=\"module\" nonce=\"__CSP_NONCE__\">",
    "data-status",
  ] {
    assert!(
      html.contains(marker),
      "Person Proof challenge asset is missing required marker {marker:?}"
    );
  }

  assert!(
    !html.contains("http://") && !html.contains("https://") && !html.contains("src=\"//"),
    "Person Proof challenge asset must not reference external network resources"
  );
  assert!(
    !html.contains("sourceMappingURL") && !html.contains(".map\""),
    "Person Proof challenge asset must not contain source-map references"
  );

  let actual = placeholder_counts(html);
  let expected = PERSON_PROOF_PLACEHOLDERS
    .iter()
    .map(|(placeholder, count)| ((*placeholder).to_string(), *count))
    .collect::<BTreeMap<_, _>>();
  assert_eq!(
    actual, expected,
    "Person Proof challenge placeholders must match the reviewed runtime substitution contract"
  );
}

fn placeholder_counts(text: &str) -> BTreeMap<String, usize> {
  let mut placeholders = BTreeMap::new();
  let mut cursor = text;
  while let Some(start) = cursor.find("__") {
    let after_start = &cursor[start + 2..];
    let Some(end) = after_start.find("__") else {
      break;
    };
    let name = &after_start[..end];
    if !name.is_empty()
      && name
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
      let placeholder = format!("__{name}__");
      *placeholders.entry(placeholder).or_insert(0) += 1;
    }
    cursor = &after_start[end + 2..];
  }
  placeholders
}

fn validate_admin_openapi(bytes: &[u8]) {
  assert!(
    (64 * 1024..=1024 * 1024).contains(&bytes.len()),
    "Admin OpenAPI asset size must be between 64 KiB and 1 MiB"
  );
  let document: Value =
    serde_json::from_slice(bytes).expect("Admin OpenAPI asset must be valid UTF-8 JSON");
  assert_eq!(
    document.pointer("/openapi").and_then(Value::as_str),
    Some("3.1.0"),
    "Admin OpenAPI asset must declare OpenAPI 3.1.0"
  );
  assert_eq!(
    document.pointer("/info/version").and_then(Value::as_str),
    Some("v1"),
    "Admin OpenAPI asset must document Admin API v1"
  );
  assert!(
    document
      .pointer("/paths/~1admin~1v1~1version/get")
      .is_some(),
    "Admin OpenAPI asset must document GET /admin/v1/version"
  );
  assert!(
    document
      .pointer("/components/schemas/AdminVersion")
      .is_some(),
    "Admin OpenAPI asset must define the AdminVersion schema"
  );
}

fn sha256_hex(bytes: &[u8]) -> String {
  let digest = Sha256::digest(bytes);
  let mut encoded = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write as _;
    write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
  }
  encoded
}

fn source_revision() -> String {
  let revision = env::var("OXIBELT_SOURCE_REVISION")
    .unwrap_or_else(|_| "unknown".to_string())
    .trim()
    .to_ascii_lowercase();
  if revision == "unknown" {
    return revision;
  }
  assert!(
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
    "OXIBELT_SOURCE_REVISION must be 'unknown' or an exact 40-character Git commit"
  );
  revision
}
