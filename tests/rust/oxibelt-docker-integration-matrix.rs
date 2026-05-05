use std::env;
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
    write_file(output, "manifest.env", &manifest)?;
    write_file(output, "checks.sh", case.checks)?;
    copy_case_fixture_tree(case, output)?;
    Ok(())
}

fn materialize_browser_scenario(scenario: &BrowserScenario, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    write_file(
        output,
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
    let source = docker_fixture_root().join(case.category).join(case.name);
    if !source.is_dir() {
        return Err(format!("missing docker fixture directory: {}", source.display()).into());
    }
    copy_dir_contents(&source, output)
}

fn docker_fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/oxibelt-docker-integration-matrix/docker")
}

fn copy_dir_contents(source: &Path, target: &Path) -> Result<()> {
    for entry in fs::read_dir(source).map_err(|err| {
        format!(
            "failed to read fixture directory {}: {err}",
            source.display()
        )
    })? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            fs::create_dir_all(&target_path)?;
            copy_dir_contents(&source_path, &target_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &target_path).map_err(|err| {
                format!(
                    "failed to copy fixture {} to {}: {err}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
        } else {
            return Err(format!("unsupported fixture entry: {}", source_path.display()).into());
        }
    }
    Ok(())
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
  response="$(client_request "example.test" "/app/headers" 200)"
  assert_body_jq "${response}" '.headers["x-forwarded-proto"] == "https" and .headers["x-forwarded-host"] == "example.test" and (.headers.host | startswith("mock-http:18080"))'
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
            "reserved route_to_pool action is rejected at startup",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("route_to_pool"),
        ),
        docker_case(
            "waf-validation",
            "set-load-balancing-reserved",
            "reserved load-balancing action is rejected at startup",
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
