use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let _ = safe_test_path_component(prefix, "temporary directory prefix");
        let root = test_artifact_root();
        fs::create_dir_all(&root).expect("failed to create test artifact root");
        let root = root
            .canonicalize()
            .expect("failed to resolve test artifact root");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let id = next_test_id();
        let path = root.join(format!("oxibelt-test-{nanos}-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("failed to create temp directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn create_self_signed_cert(dir: &Path, common_name: &str) -> (PathBuf, PathBuf) {
    let common_name = safe_test_path_component(common_name, "certificate common name");
    let dir = safe_existing_test_dir(dir);
    let id = next_test_id();
    let key_path = dir.join(format!("cert-{id}.key"));
    let cert_path = dir.join(format!("cert-{id}.pem"));
    let config_path = dir.join(format!("cert-{id}.cnf"));

    fs::write(
        &config_path,
        format!(
            "[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n\n[req_distinguished_name]\nCN = {common_name}\n\n[req_ext]\nsubjectAltName = @alt_names\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign, digitalSignature\n\n[alt_names]\nDNS.1 = {common_name}\n"
        ),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", config_path.display()));

    let args = [
        OsStr::new("req"),
        OsStr::new("-x509"),
        OsStr::new("-newkey"),
        OsStr::new("rsa:2048"),
        OsStr::new("-sha256"),
        OsStr::new("-nodes"),
        OsStr::new("-days"),
        OsStr::new("1"),
        OsStr::new("-config"),
        config_path.as_os_str(),
        OsStr::new("-keyout"),
        key_path.as_os_str(),
        OsStr::new("-out"),
        cert_path.as_os_str(),
    ];
    run_command("openssl", &args);

    (cert_path, key_path)
}

#[allow(dead_code)]
pub fn create_ca_signed_server_cert(
    dir: &Path,
    common_name: &str,
    ca_cert_path: &Path,
    ca_key_path: &Path,
) -> (PathBuf, PathBuf) {
    let common_name = safe_test_path_component(common_name, "certificate common name");
    let dir = safe_existing_test_dir(dir);
    let ca_cert_path = ca_cert_path.canonicalize().unwrap_or_else(|error| {
        panic!(
            "failed to resolve CA certificate {}: {error}",
            ca_cert_path.display()
        )
    });
    let ca_key_path = ca_key_path.canonicalize().unwrap_or_else(|error| {
        panic!(
            "failed to resolve CA key {}: {error}",
            ca_key_path.display()
        )
    });
    let id = next_test_id();
    let key_path = dir.join(format!("server-{id}.key"));
    let cert_path = dir.join(format!("server-{id}.pem"));
    let csr_path = dir.join(format!("server-{id}.csr"));
    let config_path = dir.join(format!("server-{id}.cnf"));

    fs::write(
        &config_path,
        format!(
            "[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = req_ext\nprompt = no\n\n[req_distinguished_name]\nCN = {common_name}\n\n[req_ext]\nsubjectAltName = @alt_names\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n\n[alt_names]\nDNS.1 = {common_name}\n"
        ),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", config_path.display()));

    let csr_args = [
        OsStr::new("req"),
        OsStr::new("-newkey"),
        OsStr::new("rsa:2048"),
        OsStr::new("-sha256"),
        OsStr::new("-nodes"),
        OsStr::new("-config"),
        config_path.as_os_str(),
        OsStr::new("-keyout"),
        key_path.as_os_str(),
        OsStr::new("-out"),
        csr_path.as_os_str(),
    ];
    run_command("openssl", &csr_args);

    let sign_args = [
        OsStr::new("x509"),
        OsStr::new("-req"),
        OsStr::new("-in"),
        csr_path.as_os_str(),
        OsStr::new("-CA"),
        ca_cert_path.as_os_str(),
        OsStr::new("-CAkey"),
        ca_key_path.as_os_str(),
        OsStr::new("-CAcreateserial"),
        OsStr::new("-days"),
        OsStr::new("1"),
        OsStr::new("-sha256"),
        OsStr::new("-extfile"),
        config_path.as_os_str(),
        OsStr::new("-extensions"),
        OsStr::new("req_ext"),
        OsStr::new("-out"),
        cert_path.as_os_str(),
    ];
    run_command("openssl", &sign_args);

    (cert_path, key_path)
}

fn next_test_id() -> u64 {
    NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
}

fn test_artifact_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/oxibelt-test-fixtures")
}

fn safe_existing_test_dir(dir: &Path) -> PathBuf {
    let test_root = test_artifact_root()
        .canonicalize()
        .expect("failed to resolve test artifact root");
    let canonical_dir = dir.canonicalize().unwrap_or_else(|error| {
        panic!(
            "failed to resolve test directory {}: {error}",
            dir.display()
        )
    });

    assert!(
        canonical_dir.starts_with(&test_root),
        "test directory must stay under the test artifact root"
    );

    canonical_dir
}

fn safe_test_path_component(value: &str, field_name: &str) -> String {
    assert!(!value.is_empty(), "{field_name} must not be empty");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')),
        "{field_name} must contain only ASCII letters, digits, '-' or '.'"
    );
    assert!(
        !value.split('.').any(|segment| segment.is_empty()) && !value.contains(".."),
        "{field_name} must not contain empty or parent-directory-like segments"
    );
    value.to_string()
}

#[allow(dead_code)]
pub fn minimal_config_toml(cert_path: &Path, key_path: &Path) -> String {
    minimal_config_toml_with_paths(
        &cert_path.display().to_string(),
        &key_path.display().to_string(),
    )
}

#[allow(dead_code)]
pub fn minimal_config_toml_with_paths(cert_path: &str, key_path: &str) -> String {
    format!(
        r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.forwarded_headers]
mode = "overwrite"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true

[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#,
        cert = cert_path,
        key = key_path,
    )
}

fn run_command(command: &str, args: &[impl AsRef<OsStr>]) {
    let status = Command::new(command)
        .args(args.iter().map(AsRef::as_ref))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("failed to spawn {command}: {error}"));
    assert!(status.success(), "{command} failed with status {status}");
}
