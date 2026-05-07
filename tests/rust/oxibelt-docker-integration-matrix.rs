use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct DockerCase {
    category: &'static str,
    name: &'static str,
    description: &'static str,
    expect_start: ExpectStart,
    needs: Needs,
    checks: &'static str,
    failure_contains: Option<&'static str>,
}

struct BrowserScenario {
    name: &'static str,
    description: &'static str,
}

#[derive(Clone, Copy)]
enum ExpectStart {
    Success,
    Failure,
}

#[derive(Clone, Copy, Default)]
struct Needs {
    http_upstream: bool,
    https_upstream: bool,
    alt_upstream: bool,
    h2_upstream: bool,
    h2c_upstream: bool,
    h3_upstream: bool,
    protocol_probe: bool,
    pq_probe: bool,
    postgres: bool,
    postgres_mtls: bool,
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        return Err("missing command".into());
    }

    match args.remove(0).as_str() {
        "list" => list_command(&args),
        "materialize" => materialize_command(&args),
        _ => {
            usage();
            Err("unknown command".into())
        }
    }
}

fn list_command(args: &[String]) -> Result<()> {
    let suite = arg_value(args, "--suite")?;
    let format = arg_value(args, "--format")?;
    if format != "github-matrix" {
        return Err(format!("unsupported list format: {format}").into());
    }

    match suite.as_str() {
        "docker" => print_docker_matrix(),
        "browser" => print_browser_matrix(),
        _ => Err(format!("unsupported suite: {suite}").into()),
    }
}

fn materialize_command(args: &[String]) -> Result<()> {
    let suite = arg_value(args, "--suite")?;
    let category = arg_value(args, "--category")?;
    let case_name = arg_value(args, "--case")?;
    let output = PathBuf::from(arg_value(args, "--output")?);

    match suite.as_str() {
        "docker" => {
            let case = docker_cases()
                .into_iter()
                .find(|case| case.category == category && case.name == case_name)
                .ok_or_else(|| format!("unknown docker case {category}/{case_name}"))?;
            materialize_docker_case(&case, &output)
        }
        "browser" => {
            let scenario = browser_scenarios()
                .into_iter()
                .find(|scenario| category == "webdriver" && scenario.name == case_name)
                .ok_or_else(|| format!("unknown browser scenario {category}/{case_name}"))?;
            materialize_browser_scenario(&scenario, &output)
        }
        _ => Err(format!("unsupported suite: {suite}").into()),
    }
}

fn usage() {
    eprintln!(
        "usage:\n  oxibelt-docker-integration-matrix list --suite <docker|browser> --format github-matrix\n  oxibelt-docker-integration-matrix materialize --suite <docker|browser> --category <name> --case <name> --output <dir>"
    );
}

fn arg_value(args: &[String], name: &str) -> Result<String> {
    args.windows(2)
        .find(|items| items[0] == name)
        .map(|items| items[1].clone())
        .ok_or_else(|| format!("missing argument {name}").into())
}

fn print_docker_matrix() -> Result<()> {
    let cases = docker_cases();
    print!("{{\"include\":[");
    for (index, case) in cases.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!(
            "{{\"category\":\"{}\",\"case\":\"{}\",\"name\":\"{}\",\"description\":\"{}\"}}",
            json_escape(case.category),
            json_escape(case.name),
            json_escape(&format!("{}/{}", case.category, case.name)),
            json_escape(case.description)
        );
    }
    println!("]}}");
    Ok(())
}

fn print_browser_matrix() -> Result<()> {
    let scenarios = browser_scenarios();
    print!("{{\"include\":[");
    let mut first = true;
    for browser in ["chromium", "firefox"] {
        for scenario in &scenarios {
            if !first {
                print!(",");
            }
            first = false;
            print!(
                "{{\"browser\":\"{}\",\"category\":\"webdriver\",\"case\":\"{}\",\"name\":\"{}\",\"description\":\"{}\"}}",
                browser,
                json_escape(scenario.name),
                json_escape(&format!("{browser}/{}", scenario.name)),
                json_escape(scenario.description)
            );
        }
    }
    println!("]}}");
    Ok(())
}

fn materialize_docker_case(case: &DockerCase, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let output = canonical_existing_dir(output, "docker case output directory")?;
    let mut manifest = String::new();
    manifest.push_str(&format!("CASE_CATEGORY={}\n", shell_quote(case.category)));
    manifest.push_str(&format!("CASE_NAME={}\n", shell_quote(case.name)));
    manifest.push_str(&format!(
        "CASE_DESCRIPTION={}\n",
        shell_quote(case.description)
    ));
    manifest.push_str(&format!(
        "CASE_EXPECT_START={}\n",
        shell_quote(match case.expect_start {
            ExpectStart::Success => "success",
            ExpectStart::Failure => "failure",
        })
    ));
    manifest.push_str(&format!(
        "CASE_NEED_HTTP_UPSTREAM={}\n",
        bool_env(case.needs.http_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_HTTPS_UPSTREAM={}\n",
        bool_env(case.needs.https_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_ALT_UPSTREAM={}\n",
        bool_env(case.needs.alt_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_H2_UPSTREAM={}\n",
        bool_env(case.needs.h2_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_H2C_UPSTREAM={}\n",
        bool_env(case.needs.h2c_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_H3_UPSTREAM={}\n",
        bool_env(case.needs.h3_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_PROTOCOL_PROBE={}\n",
        bool_env(case.needs.protocol_probe)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_PQ_PROBE={}\n",
        bool_env(case.needs.pq_probe)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_POSTGRES={}\n",
        bool_env(case.needs.postgres)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_POSTGRES_MTLS={}\n",
        bool_env(case.needs.postgres_mtls)
    ));
    manifest.push_str(&format!(
        "CASE_EXPECT_FAILURE_CONTAINS={}\n",
        shell_quote(case.failure_contains.unwrap_or(""))
    ));
    write_file(&output, "manifest.env", &manifest)?;
    write_file(&output, "checks.sh", case.checks)?;
    copy_case_fixture_tree(case, &output)?;
    Ok(())
}

fn materialize_browser_scenario(scenario: &BrowserScenario, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let output = canonical_existing_dir(output, "browser scenario output directory")?;
    write_file(
        &output,
        "manifest.env",
        &format!(
            "CASE_CATEGORY='webdriver'\nCASE_NAME={}\nCASE_DESCRIPTION={}\n",
            shell_quote(scenario.name),
            shell_quote(scenario.description)
        ),
    )
}

fn write_file(root: &Path, relative: &str, content: &str) -> Result<()> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn copy_case_fixture_tree(case: &DockerCase, output: &Path) -> Result<()> {
    let fixture_root = docker_fixture_root()
        .canonicalize()
        .map_err(|err| format!("failed to resolve docker fixture root: {err}"))?;
    let category = safe_path_component(OsStr::new(case.category), "docker case category")?;
    let name = safe_path_component(OsStr::new(case.name), "docker case name")?;
    let source = fixture_root.join(category).join(name);
    if !source.is_dir() {
        return Err(format!("missing docker fixture directory: {}", source.display()).into());
    }
    let source = source.canonicalize().map_err(|err| {
        format!(
            "failed to resolve docker fixture directory {}: {err}",
            source.display()
        )
    })?;
    ensure_path_under(&fixture_root, &source, "docker fixture directory")?;
    copy_dir_contents(&source, output)
}

fn docker_fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/oxibelt-docker-integration-matrix/docker")
}

fn copy_dir_contents(source: &Path, target: &Path) -> Result<()> {
    let source_root = canonical_existing_dir(source, "fixture source directory")?;
    let target_root = canonical_existing_dir(target, "fixture target directory")?;
    copy_dir_contents_inner(&source_root, &source_root, &target_root, &target_root)
}

fn copy_dir_contents_inner(
    source_root: &Path,
    source: &Path,
    target_root: &Path,
    target: &Path,
) -> Result<()> {
    for entry in fs::read_dir(source).map_err(|err| {
        format!(
            "failed to read fixture directory {}: {err}",
            source.display()
        )
    })? {
        let entry = entry?;
        let entry_name = safe_path_component(&entry.file_name(), "fixture entry name")?;
        let source_path = entry.path();
        let target_path = target.join(&entry_name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            fs::create_dir_all(&target_path)?;
            let source_path = source_path.canonicalize().map_err(|err| {
                format!(
                    "failed to resolve fixture directory {}: {err}",
                    source_path.display()
                )
            })?;
            let target_path = target_path.canonicalize().map_err(|err| {
                format!(
                    "failed to resolve fixture output directory {}: {err}",
                    target_path.display()
                )
            })?;
            ensure_path_under(source_root, &source_path, "fixture source directory")?;
            ensure_path_under(target_root, &target_path, "fixture output directory")?;
            copy_dir_contents_inner(source_root, &source_path, target_root, &target_path)?;
        } else if file_type.is_file() {
            let source_path = source_path.canonicalize().map_err(|err| {
                format!(
                    "failed to resolve fixture file {}: {err}",
                    source_path.display()
                )
            })?;
            ensure_path_under(source_root, &source_path, "fixture source file")?;
            let mut target_file = target_path.clone();
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
                let parent = parent.canonicalize().map_err(|err| {
                    format!(
                        "failed to resolve fixture output parent {}: {err}",
                        parent.display()
                    )
                })?;
                ensure_path_under(target_root, &parent, "fixture output parent")?;
                target_file = parent.join(&entry_name);
            }
            fs::copy(&source_path, &target_file).map_err(|err| {
                format!(
                    "failed to copy fixture {} to {}: {err}",
                    source_path.display(),
                    target_file.display()
                )
            })?;
        } else {
            return Err(format!("unsupported fixture entry: {}", source_path.display()).into());
        }
    }
    Ok(())
}

fn canonical_existing_dir(path: &Path, field_name: &str) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .map_err(|err| format!("failed to resolve {field_name} {}: {err}", path.display()))?;
    if !path.is_dir() {
        return Err(format!("{field_name} is not a directory: {}", path.display()).into());
    }
    Ok(path)
}

fn ensure_path_under(root: &Path, path: &Path, field_name: &str) -> Result<()> {
    if !path.starts_with(root) {
        return Err(format!(
            "{field_name} {} must stay under {}",
            path.display(),
            root.display()
        )
        .into());
    }
    Ok(())
}

fn safe_path_component(value: &OsStr, field_name: &str) -> Result<String> {
    let value = value
        .to_str()
        .ok_or_else(|| format!("{field_name} must be valid UTF-8"))?;
    if value.is_empty() || matches!(value, "." | "..") {
        return Err(format!("{field_name} must not be empty or a dot segment").into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "{field_name} must contain only ASCII letters, digits, '.', '_' or '-'"
        )
        .into());
    }
    if value.contains("..") {
        return Err(format!("{field_name} must not contain parent-directory-like segments").into());
    }
    Ok(value.to_string())
}

fn bool_env(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            ch if ch.is_control() => format!("\\u{:04x}", ch as u32).chars().collect(),
            ch => vec![ch],
        })
        .collect()
}

fn docker_cases() -> Vec<DockerCase> {
    vec![
        docker_case(
            "config-valid",
            "minimal-http1",
            "minimal HTTP/1 startup and forwarding",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/ping?case=minimal" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/ping?case=minimal"'
}
"#,
            None,
        ),
        docker_case(
            "config-valid",
            "modular-include-glob",
            "configuration split through sorted include globs",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/include" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/include"'
}
"#,
            None,
        ),
        docker_case(
            "config-valid",
            "static-ocsp-compression-off",
            "static OCSP file with compression disabled",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/no-compression" 200)"
  assert_body_jq "${response}" '.headers["accept-encoding"] == null'
}
"#,
            None,
        ),
        docker_case(
            "proxy-compression",
            "downstream-gzip-response",
            "downstream response compression negotiates and serves gzip",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response decoded identity br_response
  response="$(client_request_with_headers "example.test" "/app/compressible?case=gzip" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${response}" '.headers["content-encoding"] == "gzip"
    and .headers["content-length"] == null
    and (.headers.vary | ascii_downcase | contains("accept-encoding"))'
  decoded="$(
    jq -r '.body_base64' <<<"${response}" |
      python3 -c 'import base64,gzip,sys; sys.stdout.write(gzip.decompress(base64.b64decode(sys.stdin.read())).decode("utf-8"))'
  )"
  if ! jq -e '.upstream == "http-upstream"
      and .path == "/origin/app/compressible?case=gzip"
      and .headers["accept-encoding"] == null' <<<"${decoded}" >/dev/null; then
    echo "Decoded gzip body assertion failed" >&2
    echo "${decoded}" >&2
    fail_with_diagnostics "decoded gzip response body did not match"
  fi

  identity="$(client_request_with_headers "example.test" "/app/identity?case=identity" 200 "GET" "" "Accept-Encoding: identity")"
  assert_response_jq "${identity}" '.headers["content-encoding"] == null'
  assert_body_jq "${identity}" '.upstream == "http-upstream"
    and .path == "/origin/app/identity?case=identity"
    and .headers["accept-encoding"] == null'

  br_response="$(client_request_with_headers "example.test" "/app/br?case=preference" 200 "GET" "" "Accept-Encoding: gzip, br")"
  assert_response_jq "${br_response}" '.headers["content-encoding"] == "br"
    and .headers["content-length"] == null'
}
"#,
            None,
        ),
        docker_case(
            "proxy-compression",
            "secret-bearing-response-skip",
            "downstream response compression skips authenticated and private responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local public_response cookie_response auth_response set_cookie_response private_response

  public_response="$(client_request_with_headers "example.test" "/app/public?case=gzip" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${public_response}" '.headers["content-encoding"] == "gzip"
    and .headers["content-length"] == null'

  cookie_response="$(client_request_with_headers "example.test" "/app/auth-cookie?case=cookie" 200 "GET" "" "Accept-Encoding: gzip" "Cookie: session=secret")"
  assert_response_jq "${cookie_response}" '.headers["content-encoding"] == null'
  assert_body_jq "${cookie_response}" '.headers.cookie == "session=secret"'

  auth_response="$(client_request_with_headers "example.test" "/app/auth-header?case=authorization" 200 "GET" "" "Accept-Encoding: gzip" "Authorization: Bearer secret")"
  assert_response_jq "${auth_response}" '.headers["content-encoding"] == null'
  assert_body_jq "${auth_response}" '.headers.authorization == "Bearer secret"'

  set_cookie_response="$(client_request_with_headers "example.test" "/app/set-cookie?set_cookie=1" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${set_cookie_response}" '.headers["content-encoding"] == null
    and .headers["set-cookie"] == "upstream_session=present; Path=/"'
  assert_body_jq "${set_cookie_response}" '.path == "/origin/app/set-cookie?set_cookie=1"'

  private_response="$(client_request_with_headers "example.test" "/app/private?cache_control=private-no-store" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${private_response}" '.headers["content-encoding"] == null
    and .headers["cache-control"] == "private, no-store"'
  assert_body_jq "${private_response}" '.path == "/origin/app/private?cache_control=private-no-store"'
}
"#,
            None,
        ),
        docker_case(
            "config-valid",
            "https-grease-trusted-ca",
            "HTTPS upstream with trusted CA and ECH GREASE",
            ExpectStart::Success,
            Needs {
                https_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "secure.example.test" "/secure/health" 200)"
  assert_body_jq "${response}" '.upstream == "https-upstream" and .scheme == "https" and .headers.host == "secure.example.test"'
}
"#,
            None,
        ),
        docker_case(
            "config-invalid",
            "strict-unknown-field",
            "strict configuration rejects unknown merged fields by default",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("configuration contains unknown field"),
        ),
        docker_case(
            "listener-http",
            "redirect-to-https",
            "plain HTTP listener redirects to HTTPS",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  local response
  response="$(plain_client_request "example.test" "/app/redirect?x=1" 308)"
  assert_response_jq "${response}" '.headers.location == "https://example.test/app/redirect?x=1"'
}
"#,
            None,
        ),
        docker_case(
            "listener-http",
            "plain-proxy-mode",
            "plain HTTP listener can proxy requests without TLS",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(plain_client_request "example.test" "/app/plain" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .path == "/origin/app/plain"
    and .headers["x-forwarded-proto"] == "http"'
}
"#,
            None,
        ),
        docker_case(
            "ops",
            "metrics-and-health",
            "local metrics and health listeners expose operational endpoints",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/metrics-seed" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/metrics-seed"'

  response="$(plain_client_request_on_port 9091 "ops.test" "/ready" 200)"
  assert_response_jq "${response}" '.body == "ready"'

  response="$(plain_client_request_on_port 9091 "ops.test" "/live" 200)"
  assert_response_jq "${response}" '.body == "live"'

  response="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${response}" '.body | contains("oxibelt_requests_total")'
}
"#,
            None,
        ),
        docker_case(
            "limits",
            "request-body-limit",
            "configured request body limit rejects oversized requests before upstream forwarding",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/body-limit" 413 "POST" "too-large" "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body is too large"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-identity",
            "real-ip-waf",
            "trusted X-Forwarded-For real IP is used by request WAF rules",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/real-ip" 451 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${response}" '.body == "real ip blocked"'

  response="$(client_request "example.test" "/app/real-ip" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/real-ip"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-protocol",
            "trusted-v1",
            "trusted PROXY protocol v1 source address reaches request WAF rules",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  local response
  response="$(proxy_protocol_client_request "PROXY TCP4 203.0.113.10 192.0.2.10 45678 443" "example.test" "/app/proxy-protocol" 409)"
  assert_response_jq "${response}" '.body == "proxy protocol source blocked"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-operations",
            "generic-upgrade",
            "generic HTTP/1.1 upgrade tunnels bytes to the selected upstream",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(upgrade_client_request "example.test" "/app/generic-upgrade" "matrix-upgrade" "hello-upgrade" 101)"
  assert_response_jq "${response}" '.body == "upgraded:hello-upgrade"'
  assert_response_jq "${response}" '.headers.upgrade == "matrix-upgrade"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-operations",
            "connect-tunnel",
            "HTTP/1.1 CONNECT tunnels only to the route-selected upstream origin",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(connect_tunnel_request "example.test" "/origin/connect-tunnel?case=connect" 200)"
  assert_response_jq "${response}" '.body | fromjson | .upstream == "http-upstream"'
  assert_response_jq "${response}" '.body | fromjson | .path == "/origin/connect-tunnel?case=connect"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-operations",
            "stream-listener",
            "TCP stream listener proxies raw HTTP to a fixed target",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(plain_client_request_on_port 15432 "stream.example.test" "/stream/direct?case=tcp" 200)"
  assert_response_jq "${response}" '.body | fromjson | .upstream == "http-upstream"'
  assert_response_jq "${response}" '.body | fromjson | .path == "/stream/direct?case=tcp"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-operations",
            "proxy-protocol-egress-v1",
            "TCP upstream PROXY protocol egress writes the client address before HTTP",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/proxy-egress" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  assert_body_jq "${response}" '.proxy_protocol_line | startswith("PROXY TCP4 ")'
}
"#,
            None,
        ),
        docker_case(
            "protocol-operations",
            "grpc-web-h2c",
            "gRPC-Web requests are translated to HTTP/2 cleartext upstreams",
            ExpectStart::Success,
            Needs {
                h2c_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/grpc.Matrix/Unary" 200 "POST" "abcde" "Content-Type: application/grpc-web+proto" "X-Grpc-Web: 1")"
  assert_response_jq "${response}" '.headers["content-type"] == "application/grpc-web"'
  assert_response_jq "${response}" '.body | contains("h2c-upstream")'
  assert_response_jq "${response}" '.body | contains("application/grpc")'
}
"#,
            None,
        ),
        docker_case(
            "protocol-operations",
            "grpc-active-health",
            "active gRPC health checks can probe an HTTP/2 upstream pool",
            ExpectStart::Success,
            Needs {
                h2c_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  sleep 2
  local response
  response="$(client_request "example.test" "/app/grpc-health" 200)"
  assert_body_jq "${response}" '.upstream == "h2c-upstream" and .request_version == "HTTP/2.0"'
}
"#,
            None,
        ),
        docker_case(
            "upstream-pools",
            "round-robin",
            "routes can select upstream pools with round-robin balancing",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second
  first="$(client_request "example.test" "/app/pool-a" 200)"
  second="$(client_request "example.test" "/app/pool-b" 200)"
  assert_body_jq "${first}" '.upstream == "http-upstream"'
  assert_body_jq "${second}" '.upstream == "alt-upstream"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "tmpfs-route-cache",
            "tmpfs cache serves a route response after the upstream disappears",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/cache?item=1" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  docker rm -f "${http_container}" >/dev/null

  response="$(client_request "example.test" "/app/cache?item=1" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/cache?item=1"'
}
"#,
            None,
        ),
        docker_case(
            "database-access-log",
            "postgres-mtls",
            "OxiRule access logs are written to PostgreSQL over verified mTLS",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                postgres_mtls: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/db-log?case=mtls" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/db-log?case=mtls"'

  local count
  count="$(postgres_query "SELECT count(*) FROM oxibelt_access_log WHERE event = 'oxibelt.access' AND record->>'path' = '/app/db-log' AND record->>'status' = '200' AND record->>'route' = 'main-route';")"
  if [[ "${count}" != "1" ]]; then
    fail_with_diagnostics "expected one PostgreSQL access log row, got ${count}"
  fi
}
"#,
            None,
        ),
        docker_case(
            "hot-reload",
            "oxirule-config",
            "OxiRule-only hot reload updates inline WAF policy without restarting",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/reload" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/reload"'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request "example.test" "/app/reload" 403)"
  assert_response_jq "${response}" '.body == "hot reloaded oxirule"'
}
"#,
            None,
        ),
        docker_case(
            "hot-reload",
            "downstream-tls-only",
            "downstream TLS-only hot reload imports renewed certificate material",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/tls-before" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/tls-before"'

  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 \
    -config "${work_dir}/downstream.cnf" \
    -keyout "${cert_dir}/privkey.pem" \
    -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
  chmod 644 "${cert_dir}/privkey.pem" "${cert_dir}/fullchain.pem"
  docker cp "${cert_dir}/fullchain.pem" "${proxy_container}:/etc/oxibelt/cert/fullchain.pem"
  docker cp "${cert_dir}/privkey.pem" "${proxy_container}:/etc/oxibelt/cert/privkey.pem"
  reload_proxy

  response="$(client_request "example.test" "/app/tls-after" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/tls-after"'
}
"#,
            None,
        ),
        docker_case(
            "hot-reload",
            "full-config-tls-listener-rebind",
            "full hot reload updates configuration, TLS material, and listener bind port",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/full-before" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 \
    -config "${work_dir}/downstream.cnf" \
    -keyout "${cert_dir}/privkey.pem" \
    -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
  chmod 644 "${cert_dir}/privkey.pem" "${cert_dir}/fullchain.pem"
  docker cp "${cert_dir}/fullchain.pem" "${proxy_container}:/etc/oxibelt/cert/fullchain.pem"
  docker cp "${cert_dir}/privkey.pem" "${proxy_container}:/etc/oxibelt/cert/privkey.pem"
  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request_on_port 9443 "example.test" "/app/full-after" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/full-after"'
}
"#,
            None,
        ),
        docker_case(
            "config-invalid",
            "no-http-versions",
            "listener validation rejects all downstream HTTP versions disabled",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("at least one downstream HTTP version must be enabled"),
        ),
        docker_case(
            "config-invalid",
            "privileged-port-unprivileged",
            "unprivileged mode rejects privileged listener ports",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("requires a privileged port"),
        ),
        docker_case(
            "config-invalid",
            "static-ocsp-missing-response",
            "static OCSP mode requires a response file",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("tls.ocsp.response_file is required"),
        ),
        docker_case(
            "config-invalid",
            "http3-upstream-requires-https",
            "HTTP/3 upstream mode rejects cleartext origins",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("must use https:// origin when max_http_version = \"h3\""),
        ),
        docker_case(
            "config-invalid",
            "ech-config-list-missing-file",
            "ECH config-list mode requires a file",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("tls.ech.config_list_file is required"),
        ),
        docker_case(
            "config-invalid",
            "unsafe-route-path",
            "route path validation rejects dot segments",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("must not contain dot segments"),
        ),
        docker_case(
            "proxy-routing",
            "exact-host-beats-wildcard",
            "exact host routes beat wildcard routes",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "api.example.test" "/app/exact" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/exact"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-routing",
            "longer-path-prefix-wins",
            "longer path prefixes beat shorter matches",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/api/users" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/api/users"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-routing",
            "replace-prefix",
            "route prefix replacement rewrites upstream paths",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/v1/items?x=1" 200)"
  assert_body_jq "${response}" '.path == "/origin/edge/v1/items?x=1"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-headers",
            "forwarded-and-host-defaults",
            "default upstream Host and forwarded headers are stable",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(
    client_request_with_headers "example.test" "/app/headers" 200 "GET" "" \
      "Forwarded: for=198.51.100.1;proto=http;host=evil.test" \
      "X-Forwarded-For: 198.51.100.1" \
      "X-Forwarded-Host: evil.test" \
      "X-Forwarded-Proto: http" \
      "X-Forwarded-Port: 80"
  )"
  assert_body_jq "${response}" '.headers.forwarded == null
    and (.headers["x-forwarded-for"] | contains("198.51.100.1") | not)
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"
    and .headers["x-forwarded-port"] != "80"
    and (.headers.host | startswith("mock-http:18080"))'
}
"#,
            None,
        ),
        docker_case(
            "proxy-headers",
            "waf-request-header-mutations",
            "WAF request header set/remove actions reach upstream",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/mutate" 200 "GET" "" "X-Remove-Me: present")"
  assert_body_jq "${response}" '.headers["x-waf-request"] == "set" and .headers["x-remove-me"] == null'
}
"#,
            None,
        ),
        docker_case(
            "proxy-upstream-tls",
            "trusted-https-upstream",
            "trusted upstream CA allows HTTPS forwarding",
            ExpectStart::Success,
            Needs {
                https_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "secure.example.test" "/secure/tls" 200)"
  assert_body_jq "${response}" '.scheme == "https" and .upstream == "https-upstream"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-upstream-tls",
            "untrusted-https-upstream-fails",
            "untrusted HTTPS upstream certificates fail closed at proxy boundary",
            ExpectStart::Success,
            Needs {
                https_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "secure.example.test" "/secure/tls" 502)"
  assert_response_jq "${response}" '.body == "upstream request failed"'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "reject-path",
            "request-phase reject blocks a matching path",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/blocked" 403)"
  assert_response_jq "${response}" '.body == "Blocked by matrix WAF"'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "monitor-mode-allows",
            "monitor mode evaluates but does not enforce request rejection",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/monitor" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/monitor"'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "route-to-upstream",
            "request rule can override the selected upstream",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/canary" 200 "GET" "" "X-Canary: yes")"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/canary"'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "route-to-pool",
            "request rule can override the selected upstream pool",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/pool-canary" 200 "GET" "" "X-Use-Pool: yes")"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/pool-canary"'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "set-tag-chain",
            "request tags created by one rule are visible to later rules",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/login" 429)"
  assert_response_jq "${response}" '.body == "tagged"'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "external-rule-file",
            "external OxiRule files are loaded from the oxirule directory",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/external" 403)"
  assert_response_jq "${response}" '.body == "external rule"'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "route-level-rule",
            "route-scoped OxiRules apply only after route selection",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/route-block" 409)"
  assert_response_jq "${response}" '.body == "route waf"'
}
"#,
            None,
        ),
        docker_case(
            "waf-response",
            "set-remove-response-headers",
            "response rules set and remove headers",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/response-headers" 200)"
  assert_response_jq "${response}" '.headers["x-waf-response"] == "set" and .headers["x-upstream-marker"] == null'
}
"#,
            None,
        ),
        docker_case(
            "waf-response",
            "replace-5xx",
            "response rules can replace upstream 5xx responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/status/503" 502)"
  assert_response_jq "${response}" '.body == "matrix replacement"'
}
"#,
            None,
        ),
        docker_case(
            "waf-response",
            "reject-response",
            "response rules can reject otherwise successful upstream responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/sensitive" 451)"
  assert_response_jq "${response}" '.body == "response rejected"'
}
"#,
            None,
        ),
        docker_case(
            "waf-response",
            "upstream-error-replaced",
            "synthetic upstream errors are visible to response rules",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/missing" 502)"
  assert_response_jq "${response}" '.body == "upstream synthetic error replaced"'
}
"#,
            None,
        ),
        docker_case(
            "waf-validation",
            "route-to-pool-reserved",
            "route_to_pool rejects unknown upstream pool names",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("route_to_pool"),
        ),
        docker_case(
            "waf-validation",
            "set-load-balancing-reserved",
            "set_load_balancing_policy rejects unsupported policies",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("set_load_balancing_policy"),
        ),
        docker_case(
            "waf-validation",
            "response-access-in-request",
            "request phase rejects Response object access",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("Response is unavailable in request-phase rules"),
        ),
        docker_case(
            "waf-validation",
            "reserved-response-body-scan-fail-closed",
            "reserved response body scans fail closed at runtime",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/scan" 403)"
  assert_response_jq "${response}" '.body == "WAF evaluation failed"'
}
"#,
            None,
        ),
        docker_case(
            "waf-helpers",
            "header-query-cookie",
            "header, query, and cookie helpers work together",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/helpers?block=yes" 418 "GET" "" "X-Matrix-Case: yes" "Cookie: matrix=cookie")"
  assert_response_jq "${response}" '.body == "helper matched"'
}
"#,
            None,
        ),
        docker_case(
            "waf-helpers",
            "pattern-set-contains",
            "contains pattern sets can drive request decisions",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/pattern" 403 "GET" "" "User-Agent: MatrixBadBot/1.0")"
  assert_response_jq "${response}" '.body == "pattern set matched"'
}
"#,
            None,
        ),
        docker_case(
            "waf-helpers",
            "body-format-helper",
            "request body byte format helper can reject non-PNG uploads",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/upload" 415 "POST" "plain text body" "Content-Type: application/octet-stream")"
  assert_response_jq "${response}" '.body == "not png"'
}
"#,
            None,
        ),
        docker_case(
            "waf-person-proof",
            "challenge-issued",
            "request-phase person proof challenge is issued",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/proof" 403)"
  assert_response_jq "${response}" '.body | contains("person-proof")'
}
"#,
            None,
        ),
        docker_case(
            "protocol-startup",
            "http1-only",
            "HTTP/1-only downstream listener starts and forwards",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/h1" 200)"
  assert_body_jq "${response}" '.request_version == "HTTP/1.1"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-startup",
            "http1-http2",
            "HTTP/1 and HTTP/2 downstream listener starts",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/h1h2" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/h1h2"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-startup",
            "http3-enabled-startup",
            "HTTP/3-enabled listener starts alongside TCP listeners",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/h3-enabled" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/h3-enabled"'
}
      "#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h2-upstream-h1",
            "downstream HTTP/2 over HTTPS forwards to an HTTP/1.1 upstream",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h2" "example.test" "/app/downstream-h2-upstream-h1" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h2"'
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/downstream-h2-upstream-h1"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h2-upstream-h2",
            "downstream HTTP/2 over HTTPS forwards to an HTTP/2 upstream",
            ExpectStart::Success,
            Needs {
                h2_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h2" "example.test" "/app/downstream-h2-upstream-h2" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h2"'
  assert_body_jq "${response}" '.upstream == "h2-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/2.0"
    and .path == "/h2-origin/app/downstream-h2-upstream-h2"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
      "#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h2-upstream-h2c",
            "downstream HTTP/2 over HTTPS forwards to a cleartext HTTP/2 upstream",
            ExpectStart::Success,
            Needs {
                h2c_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h2" "example.test" "/app/downstream-h2-upstream-h2c" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h2"'
  assert_body_jq "${response}" '.upstream == "h2c-upstream"
    and .scheme == "http"
    and .request_version == "HTTP/2.0"
    and .path == "/h2c-origin/app/downstream-h2-upstream-h2c"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h2-upstream-h3-pooled",
            "downstream HTTP/2 forwards sequential requests over one pooled HTTP/3 upstream connection",
            ExpectStart::Success,
            Needs {
                h3_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second first_id second_id
  first="$(protocol_probe_client "h2" "example.test" "/app/pooled-first" 200)"
  second="$(protocol_probe_client "h2" "example.test" "/app/pooled-second" 200)"
  assert_body_jq "${first}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/pooled-first"'
  assert_body_jq "${second}" '.path == "/h3-origin/app/pooled-second"'
  first_id="$(jq -r '.body | fromjson | .connection_id' <<<"${first}")"
  second_id="$(jq -r '.body | fromjson | .connection_id' <<<"${second}")"
  if [[ "${first_id}" != "${second_id}" ]]; then
    echo "expected pooled upstream H3 connection id to be reused; got ${first_id} then ${second_id}" >&2
    fail_with_diagnostics "upstream H3 pool did not reuse the connection"
  fi
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h2-upstream-h3-pooled-reconnect",
            "pooled upstream HTTP/3 entries are discarded and reconnected after the upstream closes",
            ExpectStart::Success,
            Needs {
                h3_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second first_instance second_instance
  first="$(protocol_probe_client "h2" "example.test" "/app/reconnect-before" 200)"
  assert_body_jq "${first}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/reconnect-before"'

  docker restart "${h3_container}" >/dev/null

  second="$(protocol_probe_client "h2" "example.test" "/app/reconnect-after" 200)"
  assert_body_jq "${second}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/reconnect-after"'
  first_instance="$(jq -r '.body | fromjson | .instance_id' <<<"${first}")"
  second_instance="$(jq -r '.body | fromjson | .instance_id' <<<"${second}")"
  if [[ "${first_instance}" == "${second_instance}" ]]; then
    echo "expected pooled upstream H3 request to reach a restarted upstream instance; got ${first_instance}" >&2
    fail_with_diagnostics "upstream H3 pool did not reconnect after upstream restart"
  fi
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "alt-svc-https-response",
            "HTTPS HTTP/1.1 and HTTP/2 responses advertise HTTP/3 with Alt-Svc",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local h1 h2
  h1="$(client_request "example.test" "/app/alt-svc-h1" 200)"
  assert_response_jq "${h1}" '.headers["alt-svc"] == "h3=\":8443\"; ma=86400"'
  h2="$(protocol_probe_client "h2" "example.test" "/app/alt-svc-h2" 200)"
  assert_response_jq "${h2}" '.headers["alt-svc"] == "h3=\":8443\"; ma=86400"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "alt-svc-skip-rules",
            "Alt-Svc is not advertised on plain HTTP, downstream HTTP/3, or 101 responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local plain h3 upgrade
  plain="$(plain_client_request "example.test" "/app/plain-alt-svc-skip" 200)"
  assert_response_jq "${plain}" '.headers["alt-svc"] == null'

  h3="$(protocol_probe_client "h3" "example.test" "/app/h3-alt-svc-skip" 200)"
  assert_response_jq "${h3}" '.headers["alt-svc"] == null'

  upgrade="$(upgrade_client_request "example.test" "/app/upgrade-alt-svc-skip" "matrix-upgrade" "hello-upgrade" 101)"
  assert_response_jq "${upgrade}" '.headers["alt-svc"] == null'
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h3-retry",
            "downstream HTTP/3 requests succeed when QUIC Retry is enabled",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h3" "example.test" "/app/retry-enabled" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.path == "/origin/app/retry-enabled"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h3-zero-rtt-policy",
            "HTTP/3 early-data policy ignores spoofed Early-Data headers",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local get_response post_response
  get_response="$(protocol_probe_client_with_headers "h3" "example.test" "/app/early-get" 200 "GET" "" "Early-Data: 1")"
  assert_body_jq "${get_response}" '.path == "/origin/app/early-get"'
  post_response="$(protocol_probe_client_with_headers "h3" "example.test" "/app/early-post" 200 "POST" "unsafe" "Early-Data: 1")"
  assert_body_jq "${post_response}" '.path == "/origin/app/early-post" and .method == "POST"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h3-upstream-h1",
            "downstream HTTP/3 over HTTPS forwards to an HTTP/1.1 upstream",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h3" "example.test" "/app/downstream-h3-upstream-h1" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/downstream-h3-upstream-h1"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h3-upstream-h2",
            "downstream HTTP/3 over HTTPS forwards to an HTTP/2 upstream",
            ExpectStart::Success,
            Needs {
                h2_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h3" "example.test" "/app/downstream-h3-upstream-h2" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.upstream == "h2-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/2.0"
    and .path == "/h2-origin/app/downstream-h3-upstream-h2"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
      "#,
            None,
        ),
        docker_case(
            "protocol-proxying",
            "downstream-h3-upstream-h2c",
            "downstream HTTP/3 over HTTPS forwards to a cleartext HTTP/2 upstream",
            ExpectStart::Success,
            Needs {
                h2c_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h3" "example.test" "/app/downstream-h3-upstream-h2c" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.upstream == "h2c-upstream"
    and .scheme == "http"
    and .request_version == "HTTP/2.0"
    and .path == "/h2c-origin/app/downstream-h3-upstream-h2c"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
"#,
            None,
        ),
        docker_case(
            "protocol-startup",
            "pq-tls-groups",
            "downstream TLS negotiates both X25519 and X25519MLKEM768 groups",
            ExpectStart::Success,
            Needs {
                pq_probe: true,
                ..Needs::default()
            },
            "",
            None,
        ),
    ]
}

fn browser_scenarios() -> Vec<BrowserScenario> {
    vec![
        BrowserScenario {
            name: "basic-navigation",
            description: "browser reaches OxiBelt and upstream receives forwarded metadata",
        },
        BrowserScenario {
            name: "waf-request",
            description: "browser-visible request WAF rejection",
        },
        BrowserScenario {
            name: "waf-response",
            description: "browser-visible response WAF mutation and replacement",
        },
        BrowserScenario {
            name: "person-proof",
            description: "browser solves person proof and reuses clearance",
        },
        BrowserScenario {
            name: "hot-reload",
            description: "browser observes full config and TLS hot reload",
        },
    ]
}

fn docker_case(
    category: &'static str,
    name: &'static str,
    description: &'static str,
    expect_start: ExpectStart,
    needs: Needs,
    checks: &'static str,
    failure_contains: Option<&'static str>,
) -> DockerCase {
    DockerCase {
        category,
        name,
        description,
        expect_start,
        needs,
        checks,
        failure_contains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_path_component_accepts_fixture_style_names() {
        assert_eq!(
            safe_path_component(OsStr::new("config-valid"), "test field").unwrap(),
            "config-valid"
        );
        assert_eq!(
            safe_path_component(OsStr::new("10-upstreams.toml"), "test field").unwrap(),
            "10-upstreams.toml"
        );
        assert_eq!(
            safe_path_component(OsStr::new("conf.d"), "test field").unwrap(),
            "conf.d"
        );
    }

    #[test]
    fn safe_path_component_rejects_traversal_and_separators() {
        for value in [
            "..",
            "../escape",
            "escape/child",
            "escape\\child",
            "bad..name",
        ] {
            assert!(
                safe_path_component(OsStr::new(value), "test field").is_err(),
                "{value} should be rejected"
            );
        }
    }

    #[test]
    fn every_docker_case_has_a_fixture_directory() {
        let fixture_root = docker_fixture_root();
        for case in docker_cases() {
            let path = fixture_root.join(case.category).join(case.name);
            assert!(
                path.is_dir(),
                "missing fixture directory for {}/{} at {}",
                case.category,
                case.name,
                path.display()
            );
        }
    }
}
