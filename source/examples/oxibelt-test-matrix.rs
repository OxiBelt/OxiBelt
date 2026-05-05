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
  files: Vec<CaseFile>,
  checks: &'static str,
  failure_contains: Option<&'static str>,
}

struct BrowserScenario {
  name: &'static str,
  description: &'static str,
}

struct CaseFile {
  path: &'static str,
  content: String,
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
    "usage:\n  oxibelt-test-matrix list --suite <docker|browser> --format github-matrix\n  oxibelt-test-matrix materialize --suite <docker|browser> --category <name> --case <name> --output <dir>"
  );
}

fn arg_value(args: &[String], name: &str) -> Result<String> {
  args
    .windows(2)
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
    "CASE_EXPECT_FAILURE_CONTAINS={}\n",
    shell_quote(case.failure_contains.unwrap_or(""))
  ));
  write_file(output, "manifest.env", &manifest)?;
  write_file(output, "checks.sh", case.checks)?;
  for file in &case.files {
    write_file(output, file.path, &file.content)?;
  }
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
      vec![config_file(default_config(
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![
        CaseFile {
          path: "config/oxibelt.toml",
          content: r#"include = ["conf.d/*.toml"]

"#
          .to_string()
            + &top_config(
              DEFAULT_LISTENERS,
              DEFAULT_TLS_OCSP,
              DEFAULT_PROXY,
              DEFAULT_COMPRESSION,
              default_waf(),
            ),
        },
        CaseFile {
          path: "config/conf.d/10-upstreams.toml",
          content: HTTP_UPSTREAM.to_string(),
        },
        CaseFile {
          path: "config/conf.d/20-routes.toml",
          content: MAIN_ROUTE.to_string(),
        },
      ],
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
      vec![config_file(config_with(
        DEFAULT_LISTENERS,
        r#"[tls.ocsp]
mode = "static_file"
response_file = "ocsp.der"
"#,
        DEFAULT_PROXY,
        r#"[compression]
enabled = false
gzip = true
deflate = true
zstd = true
"#,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(config_with(
        DEFAULT_LISTENERS,
        DEFAULT_TLS_OCSP,
        TRUSTED_CA_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTPS_UPSTREAM_GREASE,
        SECURE_ROUTE,
      ))],
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
      "no-http-versions",
      "listener validation rejects all downstream HTTP versions disabled",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(config_with(
        r#"[listeners]
https_bind = "0.0.0.0:8443"
http1 = false
http2 = false
http3 = false
"#,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
      "",
      Some("at least one downstream HTTP version must be enabled"),
    ),
    docker_case(
      "config-invalid",
      "privileged-port-unprivileged",
      "unprivileged mode rejects privileged listener ports",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(config_with(
        r#"[listeners]
https_bind = "0.0.0.0:443"
http1 = true
http2 = false
http3 = false
"#,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
      "",
      Some("requires a privileged port"),
    ),
    docker_case(
      "config-invalid",
      "static-ocsp-missing-response",
      "static OCSP mode requires a response file",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(config_with(
        DEFAULT_LISTENERS,
        r#"[tls.ocsp]
mode = "static_file"
"#,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
      "",
      Some("tls.ocsp.response_file is required"),
    ),
    docker_case(
      "config-invalid",
      "http3-upstream-requires-https",
      "HTTP/3 upstream mode rejects cleartext origins",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(default_config(
        default_waf(),
        r#"[[upstreams]]
name = "http-upstream"
origin = "http://mock-http:18080/origin"
max_http_version = "h3"
"#,
        MAIN_ROUTE,
      ))],
      "",
      Some("must use https:// origin when max_http_version = \"h3\""),
    ),
    docker_case(
      "config-invalid",
      "ech-config-list-missing-file",
      "ECH config-list mode requires a file",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(default_config(
        default_waf(),
        r#"[[upstreams]]
name = "http-upstream"
origin = "https://mock-https:18443/backend"
max_http_version = "h2"

[upstreams.tls.ech]
mode = "config_list"
"#,
        MAIN_ROUTE,
      ))],
      "",
      Some("tls.ech.config_list_file is required"),
    ),
    docker_case(
      "config-invalid",
      "unsafe-route-path",
      "route path validation rejects dot segments",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(default_config(
        default_waf(),
        HTTP_UPSTREAM,
        r#"[[routes]]
name = "bad-route"
hosts = ["example.test"]
path_prefix = "/../admin"
upstream = "http-upstream"
"#,
      ))],
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
      vec![config_file(default_config(
        default_waf(),
        &(HTTP_UPSTREAM.to_string() + ALT_UPSTREAM),
        r#"[[routes]]
name = "wild-route"
hosts = ["*.example.test"]
path_prefix = "/"
upstream = "http-upstream"

[[routes]]
name = "exact-route"
hosts = ["api.example.test"]
path_prefix = "/"
upstream = "alt-upstream"
"#,
      ))],
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
      vec![config_file(default_config(
        default_waf(),
        &(HTTP_UPSTREAM.to_string() + ALT_UPSTREAM),
        r#"[[routes]]
name = "root-route"
hosts = ["example.test"]
path_prefix = "/"
upstream = "http-upstream"

[[routes]]
name = "api-route"
hosts = ["example.test"]
path_prefix = "/api"
upstream = "alt-upstream"
"#,
      ))],
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
      vec![config_file(default_config(
        default_waf(),
        HTTP_UPSTREAM,
        r#"[[routes]]
name = "rewrite-route"
hosts = ["example.test"]
path_prefix = "/app"
replace_prefix_with = "/edge"
upstream = "http-upstream"
"#,
      ))],
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
      vec![config_file(default_config(
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "request-header-mutations"
phase = "request"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "set_request_header"
name = "X-Waf-Request"
value = "set"

[[waf.rules.actions]]
type = "remove_request_header"
name = "X-Remove-Me"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(config_with(
        DEFAULT_LISTENERS,
        DEFAULT_TLS_OCSP,
        TRUSTED_CA_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTPS_UPSTREAM_DISABLED,
        SECURE_ROUTE,
      ))],
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
      vec![config_file(config_with(
        DEFAULT_LISTENERS,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTPS_UPSTREAM_DISABLED,
        SECURE_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-blocked-path"
phase = "request"
priority = 10
when = "Request.Http.Path.endsWith('/blocked')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked by matrix WAF"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "monitor"
fail_policy = "closed"

[[waf.rules]]
name = "monitor-reject"
phase = "request"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "reject"
status = 403
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "route-canary"
phase = "request"
priority = 10
when = "Request.Headers.get('X-Canary') == 'yes'"

[[waf.rules.actions]]
type = "route_to_upstream"
upstream = "alt-upstream"
"#,
        &(HTTP_UPSTREAM.to_string() + ALT_UPSTREAM),
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "tag-login"
phase = "request"
priority = 1
when = "Request.Http.Path.endsWith('/login')"

[[waf.rules.actions]]
type = "set_tag"
key = "Login"
value = "true"

[[waf.rules]]
name = "reject-tagged-login"
phase = "request"
priority = 2
when = "Request.Tags.get('Login') == 'true'"

[[waf.rules.actions]]
type = "reject"
status = 429
body = "tagged"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![
        config_file(default_config(
          r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "external-block"
phase = "request"
priority = 10
path = "rules/external-block.oxirule.toml"
"#,
          HTTP_UPSTREAM,
          MAIN_ROUTE,
        )),
        CaseFile {
          path: "oxirule/rules/external-block.oxirule.toml",
          content: r#"when = "Request.Http.Path.endsWith('/external')"

[[actions]]
type = "reject"
status = 403
body = "external rule"
"#
          .to_string(),
        },
      ],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"
"#,
        HTTP_UPSTREAM,
        r#"[[routes]]
name = "route-waf"
hosts = ["example.test"]
path_prefix = "/app"
upstream = "http-upstream"

[[routes.waf.rules]]
name = "route-level-block"
phase = "request"
priority = 10
when = "Request.Http.Path.endsWith('/route-block')"

[[routes.waf.rules.actions]]
type = "reject"
status = 409
body = "route waf"
"#,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "response-header-mutations"
phase = "response"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "set_response_header"
name = "X-Waf-Response"
value = "set"

[[waf.rules.actions]]
type = "remove_response_header"
name = "X-Upstream-Marker"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "replace-upstream-5xx"
phase = "response"
priority = 10
when = "Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "matrix replacement"
"#,
        r#"[[upstreams]]
name = "http-upstream"
origin = "http://mock-http:18080"
max_http_version = "h1"
"#,
        r#"[[routes]]
name = "main-route"
hosts = ["example.test"]
path_prefix = "/"
upstream = "http-upstream"
"#,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-sensitive-response"
phase = "response"
priority = 10
when = "Request.Http.Path.endsWith('/sensitive')"

[[waf.rules.actions]]
type = "reject_response"
status = 451
body = "response rejected"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "replace-upstream-error"
phase = "response"
priority = 10
when = "Response.Upstream.Error != null"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "upstream synthetic error replaced"
"#,
        MISSING_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reserved-pool"
phase = "request"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "route_to_pool"
pool = "blue"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
      "",
      Some("route_to_pool"),
    ),
    docker_case(
      "waf-validation",
      "set-load-balancing-reserved",
      "reserved load-balancing action is rejected at startup",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reserved-lb"
phase = "request"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "set_load_balancing_policy"
policy = "least_connections"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
      "",
      Some("set_load_balancing_policy"),
    ),
    docker_case(
      "waf-validation",
      "response-access-in-request",
      "request phase rejects Response object access",
      ExpectStart::Failure,
      Needs::default(),
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "bad-response-access"
phase = "request"
priority = 10
when = "Response.Http.Status == 200"

[[waf.rules.actions]]
type = "reject"
status = 403
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.pattern_sets]]
name = "body-patterns"
kind = "contains"
patterns = ["anything"]

[[waf.rules]]
name = "reserved-response-body-scan"
phase = "response"
priority = 10
when = "Response.Body.containsAny('body-patterns')"

[[waf.rules.actions]]
type = "replace_response"
status = 200
body = "unreachable"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "helper-block"
phase = "request"
priority = 10
when = "Request.Headers.anyNameMatches('^X-Matrix-') && Request.QueryParams.get('block') == 'yes' && Request.Cookies.get('matrix') == 'cookie'"

[[waf.rules.actions]]
type = "reject"
status = 418
body = "helper matched"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.pattern_sets]]
name = "bad-agents"
kind = "contains"
patterns = ["MatrixBadBot"]

[[waf.rules]]
name = "pattern-set-user-agent"
phase = "request"
priority = 10
when = "Request.Client.UserAgent.containsAny('bad-agents')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "pattern set matched"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "png-only"
phase = "request"
priority = 10
when = "Request.Http.Method == 'POST' && !Request.Body.isFormat('png')"

[[waf.rules.actions]]
type = "reject"
status = 415
body = "not png"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "person-proof"
phase = "request"
priority = 10
when = "Request.Http.Path.endsWith('/proof') && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__matrix_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
success_tag = "PersonProof"
"#,
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(config_with(
        r#"[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = false
http3 = false
"#,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(default_config(
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(config_with(
        r#"[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = true
http3 = true
"#,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(config_with(
        HTTP2_ONLY_LISTENERS,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(config_with(
        HTTP2_ONLY_LISTENERS,
        DEFAULT_TLS_OCSP,
        TRUSTED_CA_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        H2_UPSTREAM,
        H2_ROUTE,
      ))],
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
      vec![config_file(config_with(
        HTTP2_ONLY_LISTENERS,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        H2C_UPSTREAM,
        H2C_ROUTE,
      ))],
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
      vec![config_file(config_with(
        HTTP3_ONLY_LISTENERS,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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
      vec![config_file(config_with(
        HTTP3_ONLY_LISTENERS,
        DEFAULT_TLS_OCSP,
        TRUSTED_CA_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        H2_UPSTREAM,
        H2_ROUTE,
      ))],
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
      vec![config_file(config_with(
        HTTP3_ONLY_LISTENERS,
        DEFAULT_TLS_OCSP,
        DEFAULT_PROXY,
        DEFAULT_COMPRESSION,
        default_waf(),
        H2C_UPSTREAM,
        H2C_ROUTE,
      ))],
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
      vec![config_file(default_config(
        default_waf(),
        HTTP_UPSTREAM,
        MAIN_ROUTE,
      ))],
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

#[allow(clippy::too_many_arguments)]
fn docker_case(
  category: &'static str,
  name: &'static str,
  description: &'static str,
  expect_start: ExpectStart,
  needs: Needs,
  files: Vec<CaseFile>,
  checks: &'static str,
  failure_contains: Option<&'static str>,
) -> DockerCase {
  DockerCase {
    category,
    name,
    description,
    expect_start,
    needs,
    files,
    checks,
    failure_contains,
  }
}

fn config_file(content: String) -> CaseFile {
  CaseFile {
    path: "config/oxibelt.toml",
    content,
  }
}

fn default_config(waf: &str, upstreams: &str, routes: &str) -> String {
  config_with(
    DEFAULT_LISTENERS,
    DEFAULT_TLS_OCSP,
    DEFAULT_PROXY,
    DEFAULT_COMPRESSION,
    waf,
    upstreams,
    routes,
  )
}

fn config_with(
  listeners: &str,
  tls_ocsp: &str,
  proxy: &str,
  compression: &str,
  waf: &str,
  upstreams: &str,
  routes: &str,
) -> String {
  format!(
    r#"[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

{listeners}
[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

{tls_ocsp}
{proxy}
{compression}
{waf}
{upstreams}
{routes}
"#
  )
}

fn top_config(
  listeners: &str,
  tls_ocsp: &str,
  proxy: &str,
  compression: &str,
  waf: &str,
) -> String {
  format!(
    r#"[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

{listeners}
[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

{tls_ocsp}
{proxy}
{compression}
{waf}
"#
  )
}

fn default_waf() -> &'static str {
  r#"[waf]
enabled = false
mode = "enforcing"
fail_policy = "closed"
"#
}

const DEFAULT_LISTENERS: &str = r#"[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = true
http3 = false
"#;

const HTTP2_ONLY_LISTENERS: &str = r#"[listeners]
https_bind = "0.0.0.0:8443"
http1 = false
http2 = true
http3 = false
"#;

const HTTP3_ONLY_LISTENERS: &str = r#"[listeners]
https_bind = "0.0.0.0:8443"
http1 = false
http2 = false
http3 = true
"#;

const DEFAULT_TLS_OCSP: &str = r#"[tls.ocsp]
mode = "disabled"
"#;

const DEFAULT_PROXY: &str = r#"[proxy]
trusted_ca_certs = []

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"
"#;

const TRUSTED_CA_PROXY: &str = r#"[proxy]
trusted_ca_certs = ["upstream-ca.pem"]

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"
"#;

const DEFAULT_COMPRESSION: &str = r#"[compression]
enabled = true
gzip = true
deflate = true
zstd = true
"#;

const HTTP_UPSTREAM: &str = r#"[[upstreams]]
name = "http-upstream"
origin = "http://mock-http:18080/origin"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "disabled"
"#;

const ALT_UPSTREAM: &str = r#"
[[upstreams]]
name = "alt-upstream"
origin = "http://mock-alt:18081/alt"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "disabled"
"#;

const HTTPS_UPSTREAM_DISABLED: &str = r#"[[upstreams]]
name = "https-upstream"
origin = "https://mock-https:18443/backend"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = true
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "disabled"
"#;

const HTTPS_UPSTREAM_GREASE: &str = r#"[[upstreams]]
name = "https-upstream"
origin = "https://mock-https:18443/backend"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = true
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "grease"
"#;

const H2_UPSTREAM: &str = r#"[[upstreams]]
name = "h2-upstream"
origin = "https://mock-h2:18444/h2-origin"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "disabled"
"#;

const H2C_UPSTREAM: &str = r#"[[upstreams]]
name = "h2c-upstream"
origin = "http://mock-h2c:18082/h2c-origin"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "disabled"
"#;

const MISSING_UPSTREAM: &str = r#"[[upstreams]]
name = "http-upstream"
origin = "http://missing-upstream:19999/origin"
max_http_version = "h1"
connect_timeout_ms = 200
request_timeout_ms = 1000
preserve_host = false
"#;

const MAIN_ROUTE: &str = r#"[[routes]]
name = "main-route"
hosts = ["example.test"]
path_prefix = "/"
upstream = "http-upstream"
"#;

const SECURE_ROUTE: &str = r#"[[routes]]
name = "secure-route"
hosts = ["secure.example.test"]
path_prefix = "/secure"
upstream = "https-upstream"
"#;

const H2_ROUTE: &str = r#"[[routes]]
name = "h2-route"
hosts = ["example.test"]
path_prefix = "/"
upstream = "h2-upstream"
"#;

const H2C_ROUTE: &str = r#"[[routes]]
name = "h2c-route"
hosts = ["example.test"]
path_prefix = "/"
upstream = "h2c-upstream"
"#;
