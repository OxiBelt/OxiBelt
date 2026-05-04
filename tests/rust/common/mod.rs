use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let prefix = safe_test_path_component(prefix, "temporary directory prefix");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("oxibelt-{prefix}-{nanos}-{}", std::process::id()));
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

pub fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|error| {
        panic!("failed to write {}: {error}", path.display());
    });
}

pub fn create_self_signed_cert(dir: &Path, common_name: &str) -> (PathBuf, PathBuf) {
    let common_name = safe_test_path_component(common_name, "certificate common name");
    let key_path = dir.join(format!("{common_name}.key"));
    let cert_path = dir.join(format!("{common_name}.pem"));
    let config_path = dir.join(format!("{common_name}.cnf"));

    write_file(
        &config_path,
        &format!(
            "[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n\n[req_distinguished_name]\nCN = {common_name}\n\n[req_ext]\nsubjectAltName = @alt_names\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign, digitalSignature\n\n[alt_names]\nDNS.1 = {common_name}\n"
        ),
    );

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
        cert = cert_path.display(),
        key = key_path.display(),
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
