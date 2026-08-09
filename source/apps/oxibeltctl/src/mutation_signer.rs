use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use aws_lc_rs::signature::Ed25519KeyPair;
use http::{HeaderMap, HeaderValue, Method};
use oxibelt::admin_client::{AdminClient, AdminResponse};
use oxibelt::admin_mutation::{
  MUTATION_HEADER, MutationSignature, MutationTarget, SignatureSuite, TranscriptContext,
  UnsignedMutationEnvelope, encode_mutation_header, mutation_transcript,
};
use rustls::pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::MutationArgs;

const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 256 * 1024;

pub(crate) struct MutationSigner {
  signer_id: String,
  principal: String,
  namespace: String,
  expected_revision: String,
  new_revision: String,
  target: MutationTarget,
  request_id: Option<String>,
  issued_at: Option<String>,
  expires_at: Option<String>,
  signing_time_override: Option<i64>,
  validity_seconds: u64,
  keys: SigningKeys,
  signed_request: Mutex<Option<SignedRequest>>,
}

enum SigningKeys {
  Ed25519(Ed25519KeyPair),
  #[cfg(feature = "mutation-pqc")]
  Ed25519MlDsa44 {
    ed25519: Ed25519KeyPair,
    ml_dsa_44: aws_lc_rs::signature::PqdsaKeyPair,
  },
}

struct SignedRequest {
  method: Method,
  endpoint: String,
  content_digest: String,
  precondition_revision: String,
  headers: HeaderMap,
}

impl MutationSigner {
  pub(crate) fn from_args(args: &MutationArgs) -> anyhow::Result<Option<Self>> {
    if !args.enabled {
      return Ok(None);
    }
    Self::from_args_with_time(args, None).map(Some)
  }

  #[cfg(test)]
  pub(crate) fn from_args_at(args: &MutationArgs, now_unix_seconds: i64) -> anyhow::Result<Self> {
    Self::from_args_with_time(args, Some(now_unix_seconds))
  }

  fn from_args_with_time(
    args: &MutationArgs,
    signing_time_override: Option<i64>,
  ) -> anyhow::Result<Self> {
    let signer_id = required(&args.signer_id, "--mutation-signer-id")?;
    let principal = required(&args.principal, "--mutation-principal")?;
    let expected_revision = required(&args.expected_revision, "--mutation-expected-revision")?;
    let new_revision = required(&args.new_revision, "--mutation-new-revision")?;
    let cluster_id = required(&args.cluster_id, "--mutation-cluster-id")?;
    let membership_revision =
      required(&args.membership_revision, "--mutation-membership-revision")?;
    let ed25519_path = resolve_required_key_path(
      args.ed25519_key_file.as_deref(),
      args.ed25519_key_file_env.as_deref(),
      "Ed25519",
    )?;
    let ed25519 = load_ed25519_key(&ed25519_path)?;
    let ml_dsa_path = resolve_optional_key_path(
      args.ml_dsa_44_key_file.as_deref(),
      args.ml_dsa_44_key_file_env.as_deref(),
      "ML-DSA-44",
    )?;
    let keys = load_signing_keys(ed25519, ml_dsa_path.as_deref())?;
    if args.issued_at.is_some() != args.expires_at.is_some() {
      bail!("--mutation-issued-at and --mutation-expires-at must be supplied together");
    }
    Ok(Self {
      signer_id,
      principal,
      namespace: args.namespace.clone(),
      expected_revision,
      new_revision,
      target: MutationTarget {
        cluster_id,
        membership_revision,
      },
      request_id: args.request_id.clone(),
      issued_at: args.issued_at.clone(),
      expires_at: args.expires_at.clone(),
      signing_time_override,
      validity_seconds: args.validity_seconds,
      keys,
      signed_request: Mutex::new(None),
    })
  }

  pub(crate) fn headers_for_request(
    &self,
    method: &Method,
    endpoint: &str,
    body: &[u8],
    if_match: Option<&str>,
  ) -> anyhow::Result<HeaderMap> {
    if !is_protected_mutation(method, endpoint) {
      return Ok(HeaderMap::new());
    }
    let content_digest = sha256_digest(body);
    let precondition_revision = normalized_if_match(if_match)?;
    let mut signed = self
      .signed_request
      .lock()
      .map_err(|_| anyhow::anyhow!("mutation signing state is unavailable"))?;
    if let Some(previous) = signed.as_ref() {
      if previous.method == *method
        && previous.endpoint == endpoint
        && previous.content_digest == content_digest
        && previous.precondition_revision == precondition_revision
      {
        return Ok(previous.headers.clone());
      }
      bail!(
        "one oxibeltctl invocation cannot reuse a mutation request ID for multiple protected requests"
      );
    }

    let now_unix_seconds = match self.signing_time_override {
      Some(value) => value,
      None => current_unix_seconds()?,
    };
    let request_id = match self.request_id.as_deref() {
      Some(value) => value.to_string(),
      None => new_request_id()?,
    };
    let (issued_at, expires_at) = match (&self.issued_at, &self.expires_at) {
      (Some(issued_at), Some(expires_at)) => (issued_at.clone(), expires_at.clone()),
      (None, None) => {
        let expires = now_unix_seconds
          .checked_add(
            i64::try_from(self.validity_seconds)
              .context("mutation validity exceeds the supported range")?,
          )
          .context("mutation expiration exceeds the supported range")?;
        (
          format_utc_timestamp(now_unix_seconds)?,
          format_utc_timestamp(expires)?,
        )
      }
      _ => bail!("mutation timestamp configuration is inconsistent"),
    };
    let unsigned = UnsignedMutationEnvelope {
      version: "1".to_string(),
      signer_id: self.signer_id.clone(),
      request_id,
      issued_at,
      expires_at,
      expected_previous_revision: self.expected_revision.clone(),
      new_revision: self.new_revision.clone(),
      content_digest: content_digest.clone(),
      target: self.target.clone(),
    };
    let suite = self.keys.suite();
    let context = TranscriptContext {
      method,
      path_and_query: endpoint,
      ipm_namespace: &self.namespace,
      authenticated_principal: &self.principal,
      body,
      precondition_revision: &precondition_revision,
      now_unix_seconds,
      maximum_validity_seconds: self.validity_seconds,
      maximum_clock_skew_seconds: 0,
    };
    let transcript = mutation_transcript(&unsigned, suite, &context)
      .context("mutation envelope fields are invalid")?;
    let signature = self.keys.sign(&transcript)?;
    let encoded = encode_mutation_header(&unsigned, &signature)
      .context("failed to encode the mutation envelope")?;
    let mut headers = HeaderMap::new();
    headers.insert(
      MUTATION_HEADER,
      HeaderValue::from_str(&encoded).context("mutation envelope is not header-safe")?,
    );
    *signed = Some(SignedRequest {
      method: method.clone(),
      endpoint: endpoint.to_string(),
      content_digest,
      precondition_revision,
      headers: headers.clone(),
    });
    Ok(headers)
  }
}

pub(crate) async fn request_json(
  client: &AdminClient,
  signer: Option<&MutationSigner>,
  method: Method,
  endpoint: &str,
  body: Option<serde_json::Value>,
  if_match: Option<&str>,
) -> anyhow::Result<AdminResponse> {
  let Some(signer) = signer else {
    return client.request_json(method, endpoint, body, if_match).await;
  };
  let body = body
    .map(|value| serde_json::to_vec(&value))
    .transpose()
    .context("failed to encode Admin JSON body")?;
  let headers = signer.headers_for_request(
    &method,
    endpoint,
    body.as_deref().unwrap_or_default(),
    if_match,
  )?;
  client
    .request_with_extra_headers(method, endpoint, body, if_match, &headers)
    .await
}

impl SigningKeys {
  const fn suite(&self) -> SignatureSuite {
    match self {
      Self::Ed25519(_) => SignatureSuite::Ed25519,
      #[cfg(feature = "mutation-pqc")]
      Self::Ed25519MlDsa44 { .. } => SignatureSuite::Ed25519MlDsa44,
    }
  }

  fn sign(&self, transcript: &[u8]) -> anyhow::Result<MutationSignature> {
    match self {
      Self::Ed25519(key) => Ok(MutationSignature::Ed25519(ed25519_signature(
        key, transcript,
      )?)),
      #[cfg(feature = "mutation-pqc")]
      Self::Ed25519MlDsa44 { ed25519, ml_dsa_44 } => {
        use aws_lc_rs::signature::ML_DSA_44_SIGNING;

        let mut ml_dsa_signature = vec![0_u8; ML_DSA_44_SIGNING.signature_len()];
        let written = ml_dsa_44
          .sign(transcript, &mut ml_dsa_signature)
          .map_err(|_| anyhow::anyhow!("ML-DSA-44 mutation signing failed"))?;
        if written != ml_dsa_signature.len() {
          bail!("ML-DSA-44 mutation signing returned an invalid signature length");
        }
        Ok(MutationSignature::Ed25519MlDsa44 {
          ed25519: ed25519_signature(ed25519, transcript)?,
          ml_dsa_44: ml_dsa_signature,
        })
      }
    }
  }
}

fn ed25519_signature(key: &Ed25519KeyPair, transcript: &[u8]) -> anyhow::Result<[u8; 64]> {
  key
    .try_sign(transcript)
    .map_err(|_| anyhow::anyhow!("Ed25519 mutation signing failed"))?
    .as_ref()
    .try_into()
    .map_err(|_| anyhow::anyhow!("Ed25519 mutation signing returned an invalid signature length"))
}

fn load_signing_keys(
  ed25519: Ed25519KeyPair,
  ml_dsa_path: Option<&Path>,
) -> anyhow::Result<SigningKeys> {
  let Some(path) = ml_dsa_path else {
    return Ok(SigningKeys::Ed25519(ed25519));
  };
  #[cfg(feature = "mutation-pqc")]
  {
    let ml_dsa_44 = load_ml_dsa_44_key(path)?;
    Ok(SigningKeys::Ed25519MlDsa44 { ed25519, ml_dsa_44 })
  }
  #[cfg(not(feature = "mutation-pqc"))]
  {
    let _ = path;
    let _ = ed25519;
    bail!("ML-DSA-44 mutation signing requires the mutation-pqc build feature")
  }
}

fn load_ed25519_key(path: &Path) -> anyhow::Result<Ed25519KeyPair> {
  with_pkcs8_der(path, |der| {
    Ed25519KeyPair::from_pkcs8(der).map_err(|_| {
      anyhow::anyhow!(
        "Ed25519 mutation private key {} is not valid unencrypted PKCS#8",
        path.display()
      )
    })
  })
}

#[cfg(feature = "mutation-pqc")]
fn load_ml_dsa_44_key(path: &Path) -> anyhow::Result<aws_lc_rs::signature::PqdsaKeyPair> {
  use aws_lc_rs::signature::{ML_DSA_44_SIGNING, PqdsaKeyPair};

  with_pkcs8_der(path, |der| {
    PqdsaKeyPair::from_pkcs8(&ML_DSA_44_SIGNING, der).map_err(|_| {
      anyhow::anyhow!(
        "ML-DSA-44 mutation private key {} is not valid unencrypted PKCS#8",
        path.display()
      )
    })
  })
}

fn with_pkcs8_der<T>(
  path: &Path,
  parse: impl FnOnce(&[u8]) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
  let bytes = read_private_key(path)?;
  let first_non_whitespace = bytes
    .iter()
    .position(|byte| !byte.is_ascii_whitespace())
    .unwrap_or(bytes.len());
  if bytes[first_non_whitespace..].starts_with(b"-----BEGIN") {
    let mut keys = Vec::new();
    for item in PrivatePkcs8KeyDer::pem_slice_iter(&bytes) {
      match item {
        Ok(key) => keys.push(key),
        Err(_) => {
          keys.iter_mut().for_each(Zeroize::zeroize);
          bail!(
            "mutation private key {} must contain one unencrypted PKCS#8 key",
            path.display()
          );
        }
      }
    }
    if keys.len() != 1 {
      keys.iter_mut().for_each(Zeroize::zeroize);
      bail!(
        "mutation private key {} must contain one unencrypted PKCS#8 key",
        path.display()
      );
    }
    let result = parse(keys[0].secret_pkcs8_der());
    keys.iter_mut().for_each(Zeroize::zeroize);
    result
  } else {
    parse(&bytes)
  }
}

fn read_private_key(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  let file = open_private_key(path)?;
  let metadata = file
    .metadata()
    .with_context(|| format!("failed to inspect mutation private key {}", path.display()))?;
  if !metadata.is_file() {
    bail!(
      "mutation private key {} must be a regular file",
      path.display()
    );
  }
  if metadata.len() > MAX_PRIVATE_KEY_FILE_BYTES {
    bail!("mutation private key {} is too large", path.display());
  }
  validate_private_key_permissions(path, &metadata)?;
  let mut bytes = Zeroizing::new(Vec::new());
  file
    .take(MAX_PRIVATE_KEY_FILE_BYTES + 1)
    .read_to_end(&mut bytes)
    .with_context(|| format!("failed to read mutation private key {}", path.display()))?;
  if bytes.is_empty() || bytes.len() as u64 > MAX_PRIVATE_KEY_FILE_BYTES {
    bail!(
      "mutation private key {} has an invalid size",
      path.display()
    );
  }
  Ok(bytes)
}

fn open_private_key(path: &Path) -> anyhow::Result<File> {
  let mut options = OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  options
    .open(path)
    .with_context(|| format!("failed to open mutation private key {}", path.display()))
}

#[cfg(unix)]
fn validate_private_key_permissions(
  path: &Path,
  metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
  use std::os::unix::fs::PermissionsExt;

  if metadata.permissions().mode() & 0o077 != 0 {
    bail!(
      "mutation private key {} must not be accessible by group or other users",
      path.display()
    );
  }
  Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(
  _path: &Path,
  _metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
  Ok(())
}

fn resolve_required_key_path(
  file: Option<&Path>,
  file_env: Option<&str>,
  label: &str,
) -> anyhow::Result<PathBuf> {
  resolve_optional_key_path(file, file_env, label)?.ok_or_else(|| {
    anyhow::anyhow!(
      "--sign-mutation requires --mutation-{}-key-file or --mutation-{}-key-file-env",
      label.to_ascii_lowercase(),
      label.to_ascii_lowercase()
    )
  })
}

fn resolve_optional_key_path(
  file: Option<&Path>,
  file_env: Option<&str>,
  label: &str,
) -> anyhow::Result<Option<PathBuf>> {
  match (file, file_env) {
    (Some(path), None) => Ok(Some(path.to_path_buf())),
    (None, Some(name)) => {
      let path = std::env::var_os(name).ok_or_else(|| {
        anyhow::anyhow!("{label} mutation private-key path environment variable {name} is not set")
      })?;
      if path.is_empty() {
        bail!("{label} mutation private-key path environment variable {name} is empty");
      }
      Ok(Some(PathBuf::from(path)))
    }
    (None, None) => Ok(None),
    (Some(_), Some(_)) => bail!("select only one {label} mutation private-key path source"),
  }
}

fn required(value: &Option<String>, flag: &str) -> anyhow::Result<String> {
  value
    .as_ref()
    .filter(|value| !value.is_empty())
    .cloned()
    .ok_or_else(|| anyhow::anyhow!("--sign-mutation requires {flag}"))
}

fn normalized_if_match(value: Option<&str>) -> anyhow::Result<String> {
  let value = value.context("signed mutation requires If-Match")?;
  value
    .strip_prefix('"')
    .and_then(|value| value.strip_suffix('"'))
    .filter(|value| !value.is_empty() && !value.contains('"'))
    .map(str::to_string)
    .context("signed mutation If-Match must contain one strong quoted ETag")
}

pub(crate) fn is_protected_mutation(method: &Method, endpoint: &str) -> bool {
  if !matches!(*method, Method::POST | Method::PATCH | Method::DELETE) {
    return false;
  }
  let path = endpoint.split('?').next().unwrap_or(endpoint);
  matches!(
    path,
    "/admin/v1/config/load"
      | "/admin/v1/config/rollback"
      | "/admin/v1/files/sync"
      | "/admin/v1/tls/downstream/reload"
      | "/admin/v1/keys/rotate"
      | "/admin/v1/config/secret-references/update"
      | "/admin/v1/break-glass/activations"
  ) || is_path_or_child(path, "/admin/v1/ipm/principals")
    || is_path_or_child(path, "/admin/v1/ipm/credentials")
    || is_path_or_child(path, "/admin/v1/ipm/policies")
    || is_path_or_child(path, "/admin/v1/ipm/bindings")
    || (path.starts_with("/admin/v1/break-glass/activations/") && path.ends_with("/revoke"))
    || path == "/admin/v1/membership/transitions"
    || (path.starts_with("/admin/v1/membership/transitions/")
      && (path.ends_with("/activate") || path.ends_with("/cancel")))
}

fn is_path_or_child(path: &str, base: &str) -> bool {
  path == base
    || path
      .strip_prefix(base)
      .is_some_and(|rest| rest.starts_with('/'))
}

fn sha256_digest(value: &[u8]) -> String {
  let digest = Sha256::digest(value);
  let mut output = String::with_capacity(71);
  output.push_str("sha256:");
  for byte in digest {
    let _ = write!(output, "{byte:02x}");
  }
  output
}

fn current_unix_seconds() -> anyhow::Result<i64> {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock is before the Unix epoch")?;
  i64::try_from(now.as_secs()).context("system clock is outside the supported range")
}

fn new_request_id() -> anyhow::Result<String> {
  let mut bytes = [0_u8; 16];
  getrandom::fill(&mut bytes).context("failed to generate a mutation request ID")?;
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  Ok(format!(
    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
    bytes[0],
    bytes[1],
    bytes[2],
    bytes[3],
    bytes[4],
    bytes[5],
    bytes[6],
    bytes[7],
    bytes[8],
    bytes[9],
    bytes[10],
    bytes[11],
    bytes[12],
    bytes[13],
    bytes[14],
    bytes[15]
  ))
}

fn format_utc_timestamp(unix_seconds: i64) -> anyhow::Result<String> {
  if unix_seconds < 0 {
    bail!("mutation timestamps before 1970 are not supported");
  }
  let days = unix_seconds.div_euclid(86_400);
  let seconds = unix_seconds.rem_euclid(86_400);
  let (year, month, day) = civil_from_days(days);
  if !(1970..=9999).contains(&year) {
    bail!("mutation timestamp is outside the supported range");
  }
  let hour = seconds / 3_600;
  let minute = (seconds % 3_600) / 60;
  let second = seconds % 60;
  Ok(format!(
    "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
  ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
  let days = days_since_epoch + 719_468;
  let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
  let day_of_era = days - era * 146_097;
  let year_of_era =
    (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
  let mut year = year_of_era + era * 400;
  let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  let month_prime = (5 * day_of_year + 2) / 153;
  let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
  let month = month_prime + if month_prime < 10 { 3 } else { -9 };
  year += i64::from(month <= 2);
  (year, month, day)
}
