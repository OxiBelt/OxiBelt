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
    h1_stall_upstream: bool,
    h3_upstream: bool,
    webtransport_upstream: bool,
    dns_server: bool,
    protocol_probe: bool,
    pq_probe: bool,
    postgres: bool,
    postgres_mtls: bool,
    redis: bool,
    second_proxy: bool,
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
        "CASE_NEED_H1_STALL_UPSTREAM={}\n",
        bool_env(case.needs.h1_stall_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_H3_UPSTREAM={}\n",
        bool_env(case.needs.h3_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_WEBTRANSPORT_UPSTREAM={}\n",
        bool_env(case.needs.webtransport_upstream)
    ));
    manifest.push_str(&format!(
        "CASE_NEED_DNS_SERVER={}\n",
        bool_env(case.needs.dns_server)
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
    manifest.push_str(&format!("CASE_NEED_REDIS={}\n", bool_env(case.needs.redis)));
    manifest.push_str(&format!(
        "CASE_NEED_SECOND_PROXY={}\n",
        bool_env(case.needs.second_proxy)
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

const SHARED_STATE_REDIS_CHECKS: &str = r#"
run_case_checks() {
  assert_redis_reload_generation
  assert_shared_rate_limit
  assert_shared_person_proof
  assert_shared_pool_health
  assert_shared_cache_uri_isolation
  assert_shared_cache
}

assert_redis_reload_generation() {
  local keys
  keys="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli KEYS "matrix-shared:reload:instance:*"; else redis-cli KEYS "matrix-shared:reload:instance:*"; fi')"
  if ! grep -F 'matrix-shared:reload:instance:proxy-a' <<<"${keys}" >/dev/null ||
     ! grep -F 'matrix-shared:reload:instance:proxy-b' <<<"${keys}" >/dev/null; then
    echo "${keys}" >&2
    fail_with_diagnostics "expected reload heartbeat records for both proxy instances in Redis"
  fi
}

assert_shared_rate_limit() {
  local first second
  first="$(client_request_with_headers "example.test" "/app/rate" 200 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_body_jq "${first}" '.path == "/origin/app/rate"'

  second="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/rate" 429 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${second}" '.body == "rate limit exceeded"'
}

assert_shared_person_proof() {
  local challenge cookie allowed replay
  challenge="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.20")"
  assert_response_jq "${challenge}" '.body | contains("person-proof")'
  cookie="$(solve_person_proof_cookie "${challenge}")"

  allowed="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/proof" 200 "GET" "" "X-Forwarded-For: 203.0.113.21" "Cookie: ${cookie}")"
  assert_body_jq "${allowed}" '.path == "/origin/app/proof"'

  replay="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.22" "Cookie: ${cookie}")"
  assert_response_jq "${replay}" '.body | contains("person-proof")'
}

solve_person_proof_cookie() {
  local response="$1"
  jq -r '.body' <<<"${response}" | python3 -c '
import hashlib
import re
import sys

body = sys.stdin.read()
token = re.search(r"name=\"oxibelt-person-proof-token\" content=\"([^\"]+)\"", body).group(1)
difficulty = int(re.search(r"(\d+) leading zero bits", body).group(1))

def leading_zero_bits(data):
    total = 0
    for byte in hashlib.sha256(data).digest():
        if byte == 0:
            total += 8
        else:
            return total + 8 - byte.bit_length()
    return total

nonce = 0
while True:
    if leading_zero_bits(f"{token}.{nonce}".encode("utf-8")) >= difficulty:
        print(f"__matrix_person_proof={token}.{nonce}")
        break
    nonce += 1
'
}

assert_shared_pool_health() {
  local attempt recovered state

  seed_shared_pool_alt_unhealthy
  for attempt in $(seq 1 10); do
    if shared_pool_alt_unhealthy_on_proxy_b; then
      break
    fi
    sleep 1
  done

  if ! shared_pool_alt_unhealthy_on_proxy_b; then
    state="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/upstream-pools/shared-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    echo "${state}" >&2
    fail_with_diagnostics "expected shared pool health to mark alt server unhealthy"
  fi

  recovered="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/pool/shared-health" 200 "GET" "" "X-Forwarded-For: 203.0.113.31")"
  assert_body_jq "${recovered}" '.upstream == "http-upstream" and .path == "/origin/pool/shared-health"'
}

seed_shared_pool_alt_unhealthy() {
  docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli SET "matrix-shared:pool:health:pool:shared-pool:0" "{\"healthy\":false,\"consecutive_successes\":0,\"consecutive_failures\":1}"; else redis-cli SET "matrix-shared:pool:health:pool:shared-pool:0" "{\"healthy\":false,\"consecutive_successes\":0,\"consecutive_failures\":1}"; fi' >/dev/null
}

shared_pool_alt_unhealthy_on_proxy_b() {
  local state
  state="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/upstream-pools/shared-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -e '.body | fromjson | ([.servers[] | select(.id == "0" and .healthy == false)] | length) == 1' <<<"${state}" >/dev/null
}

assert_shared_cache_uri_isolation() {
  local seed other
  seed="$(client_request_with_headers "example.test" "/cache-key/shared-uri?body=secret-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.35")"
  assert_response_jq "${seed}" '.body == "secret-cache"'

  other="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/cache-key/shared-uri?body=other-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.36")"
  assert_response_jq "${other}" '.body == "other-cache"'
}

assert_shared_cache() {
  local seed hit purge miss
  seed="$(client_request_with_headers "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.40")"
  assert_response_jq "${seed}" '.body == "shared-cache"'

  docker rm -f "${http_container}" >/dev/null

  hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.41")"
  assert_response_jq "${hit}" '.body == "shared-cache"'

  purge="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/shared-cache%3Fbody%3Dshared-cache%26cache_control%3Dpublic%26content_type%3Dtext/plain" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${purge}" '.body == "purged=2\n"'

  miss="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 502,504 "GET" "" "X-Forwarded-For: 203.0.113.42")"
  assert_response_jq "${miss}" '.status == 502 or .status == 504'
}
"#;

const SHARED_STATE_POSTGRES_CHECKS: &str = r#"
run_case_checks() {
  assert_postgres_reload_generation
  assert_shared_rate_limit
  assert_shared_access_token_route_rate_limit
  assert_shared_waf_access_token_rate_limit
  assert_shared_person_proof
  assert_shared_pool_health
  assert_shared_cache_uri_isolation
  assert_shared_cache
}

assert_postgres_reload_generation() {
  local count
  count="$(postgres_query "SELECT count(*) FROM oxibelt_shared_state WHERE key IN ('matrix-shared:reload:instance:proxy-a', 'matrix-shared:reload:instance:proxy-b');")"
  if [[ "${count}" != "2" ]]; then
    fail_with_diagnostics "expected reload heartbeat rows for both proxy instances in PostgreSQL, got ${count}"
  fi
}

assert_shared_rate_limit() {
  local first second
  first="$(client_request_with_headers "example.test" "/app/rate" 200 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_body_jq "${first}" '.path == "/origin/app/rate"'

  second="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/rate" 429 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${second}" '.body == "rate limit exceeded"'
}

assert_shared_access_token_route_rate_limit() {
  local first second third count
  first="$(client_request_with_headers "example.test" "/app/token-route-rate" 200 "GET" "" "X-Forwarded-For: 203.0.113.11" "Authorization: Bearer postgres-route-token")"
  assert_body_jq "${first}" '.path == "/origin/app/token-route-rate"'

  second="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/token-route-rate" 429 "GET" "" "X-Forwarded-For: 203.0.113.12" "Authorization: Bearer postgres-route-token")"
  assert_response_jq "${second}" '.body == "rate limit exceeded"'

  third="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/token-route-rate" 200 "GET" "" "X-Forwarded-For: 203.0.113.13" "Authorization: Bearer postgres-route-token-other")"
  assert_body_jq "${third}" '.path == "/origin/app/token-route-rate"'

  count="$(postgres_query "SELECT count(*) FROM oxibelt_shared_state WHERE key LIKE 'matrix-shared:rate:shared-token-route:access_token_route:token:%:app-route';")"
  if (( count < 2 )); then
    fail_with_diagnostics "expected PostgreSQL token route rate-limit rows, got ${count}"
  fi
}

assert_shared_waf_access_token_rate_limit() {
  local first second third count
  first="$(client_request_with_headers "example.test" "/app/waf-token-rate" 200 "GET" "" "X-Forwarded-For: 203.0.113.14" "X-Api-Token: postgres-waf-token")"
  assert_body_jq "${first}" '.path == "/origin/app/waf-token-rate"'

  second="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/waf-token-rate" 429 "GET" "" "X-Forwarded-For: 203.0.113.15" "X-Api-Token: postgres-waf-token")"
  assert_response_jq "${second}" '.body == "postgres waf rate limit exceeded"'

  third="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/waf-token-rate" 200 "GET" "" "X-Forwarded-For: 203.0.113.16" "X-Api-Token: postgres-waf-token-other")"
  assert_body_jq "${third}" '.path == "/origin/app/waf-token-rate"'

  count="$(postgres_query "SELECT count(*) FROM oxibelt_shared_state WHERE key LIKE 'matrix-shared:rate:shared-waf-token-route:access_token_route:token:%:app-route';")"
  if (( count < 2 )); then
    fail_with_diagnostics "expected PostgreSQL WAF token rate-limit rows, got ${count}"
  fi
}

assert_shared_person_proof() {
  local challenge cookie allowed replay
  challenge="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.20")"
  assert_response_jq "${challenge}" '.body | contains("person-proof")'
  cookie="$(solve_person_proof_cookie "${challenge}")"

  allowed="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/proof" 200 "GET" "" "X-Forwarded-For: 203.0.113.21" "Cookie: ${cookie}")"
  assert_body_jq "${allowed}" '.path == "/origin/app/proof"'

  replay="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.22" "Cookie: ${cookie}")"
  assert_response_jq "${replay}" '.body | contains("person-proof")'
}

solve_person_proof_cookie() {
  local response="$1"
  jq -r '.body' <<<"${response}" | python3 -c '
import hashlib
import re
import sys

body = sys.stdin.read()
token = re.search(r"name=\"oxibelt-person-proof-token\" content=\"([^\"]+)\"", body).group(1)
difficulty = int(re.search(r"(\d+) leading zero bits", body).group(1))

def leading_zero_bits(data):
    total = 0
    for byte in hashlib.sha256(data).digest():
        if byte == 0:
            total += 8
        else:
            return total + 8 - byte.bit_length()
    return total

nonce = 0
while True:
    if leading_zero_bits(f"{token}.{nonce}".encode("utf-8")) >= difficulty:
        print(f"__matrix_person_proof={token}.{nonce}")
        break
    nonce += 1
'
}

assert_shared_pool_health() {
  local attempt recovered state

  seed_shared_pool_alt_unhealthy
  for attempt in $(seq 1 10); do
    if shared_pool_alt_unhealthy_on_proxy_b; then
      break
    fi
    sleep 1
  done

  if ! shared_pool_alt_unhealthy_on_proxy_b; then
    state="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/upstream-pools/shared-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    echo "${state}" >&2
    fail_with_diagnostics "expected shared pool health to mark alt server unhealthy"
  fi

  recovered="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/pool/shared-health" 200 "GET" "" "X-Forwarded-For: 203.0.113.31")"
  assert_body_jq "${recovered}" '.upstream == "http-upstream" and .path == "/origin/pool/shared-health"'
}

seed_shared_pool_alt_unhealthy() {
  postgres_query "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ('matrix-shared:pool:health:pool:shared-pool:0', convert_to('{\"healthy\":false,\"consecutive_successes\":0,\"consecutive_failures\":1}', 'UTF8'), NULL) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = NULL;" >/dev/null
}

shared_pool_alt_unhealthy_on_proxy_b() {
  local state
  state="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/upstream-pools/shared-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -e '.body | fromjson | ([.servers[] | select(.id == "0" and .healthy == false)] | length) == 1' <<<"${state}" >/dev/null
}

assert_shared_cache_uri_isolation() {
  local seed other
  seed="$(client_request_with_headers "example.test" "/cache-key/shared-uri?body=secret-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.35")"
  assert_response_jq "${seed}" '.body == "secret-cache"'

  other="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/cache-key/shared-uri?body=other-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.36")"
  assert_response_jq "${other}" '.body == "other-cache"'
}

assert_shared_cache() {
  local seed hit purge miss
  seed="$(client_request_with_headers "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.40")"
  assert_response_jq "${seed}" '.body == "shared-cache"'

  docker rm -f "${http_container}" >/dev/null

  hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.41")"
  assert_response_jq "${hit}" '.body == "shared-cache"'

  purge="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/shared-cache%3Fbody%3Dshared-cache%26cache_control%3Dpublic%26content_type%3Dtext/plain" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${purge}" '.body == "purged=2\n"'

  miss="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 502,504 "GET" "" "X-Forwarded-For: 203.0.113.42")"
  assert_response_jq "${miss}" '.status == 502 or .status == 504'
}
"#;

const DYNAMIC_POLICY_POSTGRES_CHECKS: &str = r#"
run_case_checks() {
  seed_dynamic_policy_reject
  wait_for_dynamic_policy_refresh
  assert_dynamic_policy_rejects_path
  assert_expired_policy_passes
  assert_route_mismatch_passes
  assert_dynamic_rate_limit
  assert_noncanonical_ipv6_dynamic_policies
  assert_refresh_failure_keeps_last_good
  assert_dynamic_policies_use_dedicated_table
}

bump_dynamic_policy_generation() {
  postgres_query "INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at) VALUES ('matrix-dynamic', 1, now()) ON CONFLICT (namespace) DO UPDATE SET generation = oxibelt_dynamic_policy_generation.generation + 1, updated_at = now();" >/dev/null
}

wait_for_dynamic_policy_refresh() {
  sleep 3
}

seed_dynamic_policy_reject() {
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, path_prefix, status, body, reason) VALUES ('matrix-dynamic', 10, 'vaultwarden-block', 'reject', 'client_ip_path', '203.0.113.50|/app/identity', '/app/identity', 429, 'vaultwarden dynamic block', 'vaultwarden failed-login TTL block');" >/dev/null
  bump_dynamic_policy_generation
}

assert_dynamic_policy_rejects_path() {
  local response
  response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.50")"
  assert_response_jq "${response}" '.body == "vaultwarden dynamic block"'
}

assert_expired_policy_passes() {
  local response
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, path_prefix, status, body, expires_at) VALUES ('matrix-dynamic', 20, 'expired-block', 'reject', 'client_ip_path', '203.0.113.51|/app/identity', '/app/identity', 429, 'expired block', now() - interval '1 second');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  response="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.51")"
  assert_body_jq "${response}" '.path == "/origin/app/identity/login"'
}

assert_route_mismatch_passes() {
  local response
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, route_name, status, body) VALUES ('matrix-dynamic', 30, 'admin-only-block', 'reject', 'client_ip_route', '203.0.113.53|admin-route', 'admin-route', 429, 'admin block');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  response="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.53")"
  assert_body_jq "${response}" '.path == "/origin/app/identity/login"'
}

assert_dynamic_rate_limit() {
  local first second
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, rate, burst, status, body) VALUES ('matrix-dynamic', 40, 'dynamic-login-rate', 'rate_limit', 'client_ip', '203.0.113.52', '1r/h', 1, 429, 'dynamic rate limited');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  first="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.52")"
  assert_body_jq "${first}" '.path == "/origin/app/identity/login"'
  second="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.52")"
  assert_response_jq "${second}" '.body == "dynamic rate limited"'
}

assert_noncanonical_ipv6_dynamic_policies() {
  local path_response route_response first second
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, path_prefix, status, body) VALUES ('matrix-dynamic', 41, 'ipv6-path-block', 'reject', 'client_ip_path', '2001:0DB8:0000:0000:0000:0000:0000:0001|/app/identity', '/app/identity', 429, 'ipv6 path block');" >/dev/null
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, route_name, status, body) VALUES ('matrix-dynamic', 42, 'ipv6-route-block', 'reject', 'client_ip_route', '2001:0DB8:0000:0000:0000:0000:0000:0002|app-route', 'app-route', 429, 'ipv6 route block');" >/dev/null
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, rate, burst, status, body) VALUES ('matrix-dynamic', 43, 'ipv6-client-rate', 'rate_limit', 'client_ip', '2001:0DB8:0000:0000:0000:0000:0000:0003', '1r/h', 1, 429, 'ipv6 rate limited');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh

  path_response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 2001:db8::1")"
  assert_response_jq "${path_response}" '.body == "ipv6 path block"'

  route_response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 2001:db8::2")"
  assert_response_jq "${route_response}" '.body == "ipv6 route block"'

  first="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 2001:db8::3")"
  assert_body_jq "${first}" '.path == "/origin/app/identity/login"'
  second="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 2001:db8::3")"
  assert_response_jq "${second}" '.body == "ipv6 rate limited"'
}

assert_refresh_failure_keeps_last_good() {
  local response
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, status, body) VALUES ('matrix-dynamic', 5, 'invalid-active-policy', 'reject', 'client_ip', 'not-an-ip', 429, 'invalid');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.50")"
  assert_response_jq "${response}" '.body == "vaultwarden dynamic block"'
}

assert_dynamic_policies_use_dedicated_table() {
  local policy_count shared_policy_count
  policy_count="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic';")"
  if (( policy_count < 4 )); then
    fail_with_diagnostics "expected dynamic policies in dedicated table, got ${policy_count}"
  fi
  shared_policy_count="$(postgres_query "SELECT count(*) FROM oxibelt_shared_state WHERE key LIKE '%vaultwarden-block%';")"
  if [[ "${shared_policy_count}" != "0" ]]; then
    fail_with_diagnostics "dynamic policy rows must not be stored in oxibelt_shared_state"
  fi
}
"#;

const DYNAMIC_POLICY_AUTOMATION_API_CHECKS: &str = r#"
run_case_checks() {
  create_policy_blocks_after_refresh
  patch_to_dry_run_stops_blocking
  import_upserts_existing_policy
  delete_disables_policy
  tampered_signature_keeps_last_good_snapshot
  default_source_quota_blocks_spoofed_source_rotation
  import_rejects_spoofed_default_source_over_quota
  patch_rejects_enabling_policy_over_default_quota
  global_active_policy_cap_blocks_cross_source_growth
}

wait_for_dynamic_policy_refresh() {
  sleep 3
}

policy_json_field() {
  local response="$1"
  local filter="$2"
  jq -r ".body | fromjson | ${filter}" <<<"${response}"
}

create_policy_blocks_after_refresh() {
  local response request
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" '{"source":"vaultwarden","name":"failed-login","action":"reject","subject_type":"client_ip_path","subject":"203.0.113.60|/app/identity","path_prefix":"/app/identity","status":429,"body":"automation block","reason":"failed login","code":"vaultwarden.failed_login","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  policy_id="$(policy_json_field "${response}" '.id')"
  assert_response_jq "${response}" '.body | fromjson | .source == "vaultwarden" and .code == "vaultwarden.failed_login" and .mode == "enforce" and .signature_version == "hmac-sha256-v1" and (.row_signature | length) == 64'

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.60")"
  assert_response_jq "${request}" '.body == "automation block"'
}

patch_to_dry_run_stops_blocking() {
  local response request
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/${policy_id}" 200 "PATCH" '{"mode":"dry_run"}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | fromjson | .mode == "dry_run" and .enabled == true'

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.60")"
  assert_body_jq "${request}" '.path == "/origin/app/identity/login"'
}

import_upserts_existing_policy() {
  local response request old_request active_count
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/import" 200 "POST" '{"policies":[{"source":"vaultwarden","name":"failed-login","action":"reject","subject_type":"client_ip_path","subject":"203.0.113.61|/app/identity","path_prefix":"/app/identity","status":429,"body":"import block","reason":"imported failed login","code":"vaultwarden.imported","ttl_seconds":3600}]}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | fromjson | .policies | length == 1'
  imported_policy_id="$(policy_json_field "${response}" '.policies[0].id')"
  if [[ "${imported_policy_id}" != "${policy_id}" ]]; then
    fail_with_diagnostics "import should upsert the existing dynamic policy id"
  fi
  active_count="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND source = 'vaultwarden' AND name = 'failed-login' AND enabled = true;")"
  if [[ "${active_count}" != "1" ]]; then
    fail_with_diagnostics "import should leave exactly one active source/name policy"
  fi

  wait_for_dynamic_policy_refresh
  old_request="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.60")"
  assert_body_jq "${old_request}" '.path == "/origin/app/identity/login"'
  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.61")"
  assert_response_jq "${request}" '.body == "import block"'
}

delete_disables_policy() {
  local response request enabled
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/${policy_id}" 200 "DELETE" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'
  enabled="$(postgres_query "SELECT enabled FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND id = ${policy_id};")"
  if [[ "${enabled}" != "f" ]]; then
    fail_with_diagnostics "delete should disable the dynamic policy"
  fi

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.61")"
  assert_body_jq "${request}" '.path == "/origin/app/identity/login"'
}

tampered_signature_keeps_last_good_snapshot() {
  local response request
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" '{"source":"automation","name":"tamper-check","action":"reject","subject_type":"client_ip","subject":"203.0.113.62","status":429,"body":"signed block","reason":"tamper baseline","code":"tamper.baseline","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  tamper_policy_id="$(policy_json_field "${response}" '.id')"

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.62")"
  assert_response_jq "${request}" '.body == "signed block"'

  postgres_query "UPDATE oxibelt_dynamic_policies SET body = 'tampered block', updated_at = now() WHERE namespace = 'matrix-dynamic-api' AND id = ${tamper_policy_id};" >/dev/null
  postgres_query "INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at) VALUES ('matrix-dynamic-api', 1, now()) ON CONFLICT (namespace) DO UPDATE SET generation = oxibelt_dynamic_policy_generation.generation + 1, updated_at = now();" >/dev/null
  wait_for_dynamic_policy_refresh

  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.62")"
  assert_response_jq "${request}" '.body == "signed block"'
}

default_source_quota_blocks_spoofed_source_rotation() {
  local index response body default_bucket_count
  for index in $(seq 1 9); do
    body="{\"source\":\"spoof-${index}\",\"name\":\"spoof-${index}\",\"action\":\"reject\",\"subject_type\":\"client_ip\",\"subject\":\"203.0.113.$((70 + index))\",\"status\":429,\"body\":\"spoof block\",\"reason\":\"spoofed source\",\"code\":\"spoof.${index}\",\"ttl_seconds\":3600}"
    response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" "${body}" "Authorization: Bearer matrix-security-token")"
    assert_response_jq "${response}" ".body | fromjson | .source == \"spoof-${index}\""
  done

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 400 "POST" '{"source":"spoof-overflow","name":"spoof-overflow","action":"reject","subject_type":"client_ip","subject":"203.0.113.80","status":429,"body":"spoof overflow","reason":"spoofed source","code":"spoof.overflow","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | contains("default source quota")'

  default_bucket_count="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND enabled = true AND (expires_at IS NULL OR expires_at > now()) AND source <> 'vaultwarden';")"
  if [[ "${default_bucket_count}" != "10" ]]; then
    fail_with_diagnostics "default source quota should cap all unconfigured sources together, got ${default_bucket_count}"
  fi
}

import_rejects_spoofed_default_source_over_quota() {
  local response
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/import" 400 "POST" '{"policies":[{"source":"spoof-import","name":"spoof-import","action":"reject","subject_type":"client_ip","subject":"203.0.113.81","status":429,"body":"spoof import","reason":"spoofed import","code":"spoof.import","ttl_seconds":3600}]}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | contains("default source quota")'
}

patch_rejects_enabling_policy_over_default_quota() {
  local response disabled_policy_id enabled
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" '{"enabled":false,"source":"spoof-disabled","name":"spoof-disabled","action":"reject","subject_type":"client_ip","subject":"203.0.113.82","status":429,"body":"spoof disabled","reason":"disabled spoof","code":"spoof.disabled","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  disabled_policy_id="$(policy_json_field "${response}" '.id')"

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/${disabled_policy_id}" 400 "PATCH" '{"enabled":true}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | contains("default source quota")'

  enabled="$(postgres_query "SELECT enabled FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND id = ${disabled_policy_id};")"
  if [[ "${enabled}" != "f" ]]; then
    fail_with_diagnostics "patch over default source quota must leave the policy disabled"
  fi
}

global_active_policy_cap_blocks_cross_source_growth() {
  local index response body active_total
  for index in $(seq 1 2); do
    body="{\"source\":\"vaultwarden\",\"name\":\"global-cap-${index}\",\"action\":\"reject\",\"subject_type\":\"client_ip\",\"subject\":\"203.0.113.$((90 + index))\",\"status\":429,\"body\":\"global cap\",\"reason\":\"global cap\",\"code\":\"global.cap.${index}\",\"ttl_seconds\":3600}"
    response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" "${body}" "Authorization: Bearer matrix-security-token")"
    assert_response_jq "${response}" ".body | fromjson | .source == \"vaultwarden\" and .name == \"global-cap-${index}\""
  done

  active_total="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND enabled = true AND (expires_at IS NULL OR expires_at > now());")"
  if [[ "${active_total}" != "12" ]]; then
    fail_with_diagnostics "expected active policy count to reach max_policies before overflow, got ${active_total}"
  fi

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 400 "POST" '{"source":"vaultwarden","name":"global-cap-overflow","action":"reject","subject_type":"client_ip","subject":"203.0.113.93","status":429,"body":"global cap overflow","reason":"global cap","code":"global.cap.overflow","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | contains("max_policies")'
}
"#;

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
            "http-semantics",
            "early-hints-pass",
            "HTTP semantics accepts early hints pass mode and forwards final responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/early?early_hints=1&early_link=</app.css>; rel=preload; as=style" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/early?early_hints=1&early_link=%3C/app.css%3E;%20rel=preload;%20as=style"'
}
"#,
            None,
        ),
        docker_case(
            "http-semantics",
            "expect-priority",
            "HTTP semantics validates Expect and can strip Priority headers",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/expect" 200 "POST" "hello" "Expect: 100-continue")"
  assert_body_jq "${response}" '.body == "hello" and .headers.expect == null'

  response="$(client_request_with_headers "example.test" "/app/bad-expect" 417 "GET" "" "Expect: custom-token")"
  assert_response_jq "${response}" '.status == 417'

  response="$(client_request_with_headers "example.test" "/app/priority" 200 "GET" "" "Priority: u=1")"
  assert_body_jq "${response}" '.headers.priority == null'
}
"#,
            None,
        ),
        docker_case(
            "http-semantics",
            "sse-grpc-errors",
            "HTTP semantics keeps SSE streaming and maps proxy errors for gRPC and JSON clients",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/events/stream?body=data:%20hello%0A%0A&content_type=text/event-stream" 200)"
  assert_response_jq "${response}" '.headers["content-type"] == "text/event-stream" and .body == "data: hello\n\n"'

  response="$(client_request_with_headers_to_target "proxy" 8443 "missing.example.test" "/app/error" 502,504 "GET" "")"
  assert_response_jq "${response}" '(.status == 502 or .status == 504) and (.body | fromjson | (.code == "connect_error" or .code == "read_timeout"))'

  response="$(client_request_with_headers "grpc.example.test" "/grpc.Matrix/Unary" 200 "POST" "" "Content-Type: application/grpc" "Grpc-Timeout: 1S")"
  assert_response_jq "${response}" '.headers["grpc-status"] == "4"'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "external-auth-response-body-timeout",
            "external auth timeout covers response body collection",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local timed_out allowed
  timed_out="$(client_request "slow-auth.example.test" "/app/protected" 503)"
  assert_response_jq "${timed_out}" '.body == "external authorization failed"'

  allowed="$(client_request "quick-auth.example.test" "/app/protected" 200)"
  assert_body_jq "${allowed}" '.upstream == "http-upstream" and .path == "/origin/app/protected"'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "grpc-timeout-pool-health",
            "client gRPC deadlines do not poison passive upstream pool health",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first_timeout second_timeout recovered
  first_timeout="$(client_request_with_headers "grpc-pool.example.test" "/matrix.Security/Unary?header_delay_ms=100" 200 "POST" "" "Content-Type: application/grpc" "Grpc-Timeout: 0n")"
  assert_response_jq "${first_timeout}" '.headers["grpc-status"] == "4"'

  second_timeout="$(client_request_with_headers "grpc-pool.example.test" "/matrix.Security/Unary?header_delay_ms=100" 200 "POST" "" "Content-Type: application/grpc" "Grpc-Timeout: 0n")"
  assert_response_jq "${second_timeout}" '.headers["grpc-status"] == "4"'

  recovered="$(client_request "grpc-pool.example.test" "/after-timeout" 200)"
  assert_body_jq "${recovered}" '(.upstream == "http-upstream" or .upstream == "alt-upstream")
    and (.path == "/origin/after-timeout" or .path == "/alt/after-timeout")'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "fast-general-proxy-equivalence",
            "plain proxy fast path and forced general path preserve security semantics",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
assert_security_headers() {
  local response="$1"
  assert_response_jq "${response}" '.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains; preload"'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == "nosniff"'
  assert_response_jq "${response}" '.headers["referrer-policy"] == "no-referrer"'
  assert_response_jq "${response}" '.headers["permissions-policy"] == "geolocation=(), camera=()"'
}

assert_same_body_projection() {
  local left="$1"
  local right="$2"
  local filter="$3"
  local left_value right_value
  left_value="$(jq -c ".body | fromjson | ${filter}" <<<"${left}")"
  right_value="$(jq -c ".body | fromjson | ${filter}" <<<"${right}")"
  if [[ "${left_value}" != "${right_value}" ]]; then
    echo "fast projection: ${left_value}" >&2
    echo "general projection: ${right_value}" >&2
    fail_with_diagnostics "fast/general upstream observations diverged"
  fi
}

run_case_checks() {
  local fast general fast_bad general_bad

  fast="$(client_request "example.test" "/fast/echo?case=get" 200)"
  general="$(client_request "example.test" "/general/echo?case=get" 200)"
  assert_security_headers "${fast}"
  assert_security_headers "${general}"
  assert_same_body_projection "${fast}" "${general}" '{method, path, body, headers: {
    host: .headers.host,
    "x-forwarded-host": .headers["x-forwarded-host"],
    "x-forwarded-proto": .headers["x-forwarded-proto"]
  }}'

  fast="$(client_request_with_headers "example.test" "/fast/post?case=body" 200 "POST" "posted body" "Content-Type: text/plain")"
  general="$(client_request_with_headers "example.test" "/general/post?case=body" 200 "POST" "posted body" "Content-Type: text/plain")"
  assert_same_body_projection "${fast}" "${general}" '{method, path, body, headers: {
    "content-type": .headers["content-type"],
    "content-length": .headers["content-length"]
  }}'

  fast="$(client_request_with_headers "example.test" "/fast/hop" 200 "GET" "" \
    "Connection: X-Remove-Hop, keep-alive" \
    "X-Remove-Hop: remove-me" \
    "Proxy-Authorization: Basic remove-me" \
    "Proxy-Authenticate: remove-me" \
    "Keep-Alive: timeout=5")"
  general="$(client_request_with_headers "example.test" "/general/hop" 200 "GET" "" \
    "Connection: X-Remove-Hop, keep-alive" \
    "X-Remove-Hop: remove-me" \
    "Proxy-Authorization: Basic remove-me" \
    "Proxy-Authenticate: remove-me" \
    "Keep-Alive: timeout=5")"
  assert_same_body_projection "${fast}" "${general}" '{path, headers: {
    connection: .headers.connection,
    "x-remove-hop": .headers["x-remove-hop"],
    "proxy-authorization": .headers["proxy-authorization"],
    "proxy-authenticate": .headers["proxy-authenticate"],
    "keep-alive": .headers["keep-alive"]
  }}'
  assert_body_jq "${fast}" '.headers.connection == null
    and .headers["x-remove-hop"] == null
    and .headers["proxy-authorization"] == null
    and .headers["proxy-authenticate"] == null
    and .headers["keep-alive"] == null'

  fast="$(client_request_with_headers "example.test" "/fast/forwarded" 200 "GET" "" \
    "Forwarded: for=198.51.100.1;proto=http;host=evil.test" \
    "X-Forwarded-For: 198.51.100.1" \
    "X-Forwarded-Host: evil.test" \
    "X-Forwarded-Proto: http" \
    "X-Forwarded-Port: 80")"
  general="$(client_request_with_headers "example.test" "/general/forwarded" 200 "GET" "" \
    "Forwarded: for=198.51.100.1;proto=http;host=evil.test" \
    "X-Forwarded-For: 198.51.100.1" \
    "X-Forwarded-Host: evil.test" \
    "X-Forwarded-Proto: http" \
    "X-Forwarded-Port: 80")"
  assert_same_body_projection "${fast}" "${general}" '{path, headers: {
    host: .headers.host,
    forwarded: .headers.forwarded,
    "x-forwarded-host": .headers["x-forwarded-host"],
    "x-forwarded-proto": .headers["x-forwarded-proto"]
  }}'
  assert_body_jq "${fast}" '.headers.forwarded == null
    and (.headers["x-forwarded-for"] | contains("198.51.100.1") | not)
    and .headers["x-forwarded-host"] == "example.test"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-port"] != "80"
    and (.headers.host | startswith("mock-http:18080"))'
  assert_body_jq "${general}" '.headers.forwarded == null
    and (.headers["x-forwarded-for"] | contains("198.51.100.1") | not)
    and .headers["x-forwarded-port"] != "80"'

  fast_bad="$(chunked_body_client_request "example.test" "/fast/ambiguous" 400 "POST" "abcd" "Content-Type: text/plain" "Content-Length: 4")"
  general_bad="$(chunked_body_client_request "example.test" "/general/ambiguous" 400 "POST" "abcd" "Content-Type: text/plain" "Content-Length: 4")"
  assert_response_jq "${fast_bad}" '.status == 400'
  assert_response_jq "${general_bad}" '.status == 400'

  protocol_probe_generated_body_request_expect_error "h2" "example.test" "/fast/h2-cl0-data" "POST" 8 4 "stream error received: unspecific protocol error detected" --omit-content-length --header "Content-Length: 0"
  protocol_probe_generated_body_request_expect_error "h2" "example.test" "/general/h2-cl0-data" "POST" 8 4 "stream error received: unspecific protocol error detected" --omit-content-length --header "Content-Length: 0"

  fast_bad="$(protocol_probe_generated_body_request "h3" "example.test" "/fast/h3-cl0-data" "POST" 8 4 --omit-content-length --header "Content-Length: 0" --expect-status 413)"
  general_bad="$(protocol_probe_generated_body_request "h3" "example.test" "/general/h3-cl0-data" "POST" 8 4 --omit-content-length --header "Content-Length: 0" --expect-status 413)"
  assert_response_jq "${fast_bad}" '.body == "request body is too large"'
  assert_response_jq "${general_bad}" '.body == "request body is too large"'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "static-openat2-blocking-isolated",
            "blocking Linux static-file opens do not occupy Tokio runtime workers",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
start_static_fifo_request() {
  BLOCKING_STATIC_CLIENT_CONTAINER="$(unique_docker_container_name "oxibelt-static-openat2-blocking-client")"
  BLOCKING_STATIC_CLIENT_LOG="${logs_dir}/${BLOCKING_STATIC_CLIENT_CONTAINER}.log"
  docker create \
    --name "${BLOCKING_STATIC_CLIENT_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import http.client
import json
import socket
import ssl

context = ssl.create_default_context(cafile="/tmp/proxy-ca.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_2
sock = socket.create_connection(("proxy", 8443), timeout=5)
try:
    sock = context.wrap_socket(sock, server_hostname="proxy")
    sock.sendall(
        b"GET /static/blocking.fifo HTTP/1.1\r\n"
        b"Host: static-blocking.example.test\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    print("static FIFO request sent", flush=True)
    sock.settimeout(15)
    response = http.client.HTTPResponse(sock, method="GET")
    response.begin()
    body = response.read().decode("utf-8", "replace")
    print(json.dumps({"status": response.status, "body": body}, sort_keys=True), flush=True)
    if response.status != 403 or body != "forbidden":
        raise SystemExit(f"unexpected static FIFO response {response.status}: {body!r}")
finally:
    sock.close()
' >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${BLOCKING_STATIC_CLIENT_CONTAINER}:/tmp/proxy-ca.pem"
  docker start -a "${BLOCKING_STATIC_CLIENT_CONTAINER}" >"${BLOCKING_STATIC_CLIENT_LOG}" 2>&1 &
  BLOCKING_STATIC_CLIENT_PID=$!
}

wait_for_static_fifo_request_sent() {
  local attempt state
  for attempt in $(seq 1 50); do
    if grep -F "static FIFO request sent" "${BLOCKING_STATIC_CLIENT_LOG}" >/dev/null 2>&1; then
      return 0
    fi
    state="$(docker inspect -f '{{.State.Status}}' "${BLOCKING_STATIC_CLIENT_CONTAINER}" 2>/dev/null || echo missing)"
    if [[ "${state}" == "exited" || "${state}" == "dead" || "${state}" == "missing" ]]; then
      cat "${BLOCKING_STATIC_CLIENT_LOG}" >&2 || true
      fail_with_diagnostics "blocking static FIFO request exited before sending"
    fi
    sleep 0.1
  done
  cat "${BLOCKING_STATIC_CLIENT_LOG}" >&2 || true
  fail_with_diagnostics "blocking static FIFO request was not sent"
}

short_timeout_upstream_request() {
  local client_container output status
  client_container="$(unique_docker_container_name "oxibelt-openat2-upstream-probe")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --path "/app/openat2-worker?body=runtime-free" \
    --host "app-blocking.example.test" \
    --port 8443 \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    --expect-status 200 \
    --timeout 1 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if output="$(docker_start_stdout_only "${client_container}")"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    printf '%s' "${output}"
    return 0
  fi
  status=$?
  append_container_stderr "${client_container}"
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  echo "${output}" >&2
  fail_with_diagnostics "unrelated upstream request timed out while static FIFO open was pending"
}

run_case_checks() {
  local response

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu \
    'rm -f /etc/oxibelt/config/public/blocking.fifo && mkfifo /etc/oxibelt/config/public/blocking.fifo'

  start_static_fifo_request
  wait_for_static_fifo_request_sent
  sleep 1

  response="$(short_timeout_upstream_request)"
  assert_response_jq "${response}" '.body == "runtime-free"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu \
    'timeout 5 sh -c "printf x > /etc/oxibelt/config/public/blocking.fifo"'
  if ! wait "${BLOCKING_STATIC_CLIENT_PID}"; then
    cat "${BLOCKING_STATIC_CLIENT_LOG}" >&2 || true
    fail_with_diagnostics "blocking static FIFO request did not finish as forbidden"
  fi
  docker rm -f "${BLOCKING_STATIC_CLIENT_CONTAINER}" >/dev/null 2>&1 || true
}
"#,
            None,
        ),
        docker_case(
            "security",
            "static-file-symlink-race",
            "static file serving does not leak out-of-root files during symlink swaps",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  local response swapper_pid worker_pids failed

  response="$(client_request "static.example.test" "/static/ok.txt" 200)"
  assert_response_jq "${response}" '.body == "static ok\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    rm -f /etc/oxibelt/config/public/direct.txt
    ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/direct.txt
  '
  response="$(client_request "static.example.test" "/static/direct.txt" 403)"
  assert_response_jq "${response}" '.body == "forbidden"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    while :; do
      printf "race safe body\n" > /etc/oxibelt/config/public/race.tmp
      mv /etc/oxibelt/config/public/race.tmp /etc/oxibelt/config/public/race.txt
      rm -f /etc/oxibelt/config/public/race.txt
      ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/race.txt
      sleep 0.01
      rm -f /etc/oxibelt/config/public/race.txt
    done
  ' &
  swapper_pid=$!
  worker_pids=()
  failed=0

  for worker in $(seq 1 4); do
    (
      local index response status
      for index in $(seq 1 50); do
        response="$(client_request_with_headers_to_target "proxy" 8443 "static.example.test" "/static/race.txt" "200,403,404" "GET" "")"
        if jq -e '.body | contains("STATIC_RACE_SECRET")' <<<"${response}" >/dev/null; then
          echo "${response}" >&2
          exit 1
        fi
        status="$(jq -r '.status' <<<"${response}")"
        if [[ "${status}" == "200" ]] && ! jq -e '.body == "race safe body\n"' <<<"${response}" >/dev/null; then
          echo "${response}" >&2
          exit 1
        fi
      done
    ) &
    worker_pids+=("$!")
  done

  for pid in "${worker_pids[@]}"; do
    if ! wait "${pid}"; then
      failed=1
    fi
  done

  kill "${swapper_pid}" >/dev/null 2>&1 || true
  wait "${swapper_pid}" >/dev/null 2>&1 || true

  if [[ "${failed}" != "0" ]]; then
    fail_with_diagnostics "static symlink race leaked or served unexpected content"
  fi
}
"#,
            None,
        ),
        docker_case(
            "security",
            "static-hot-cache-security",
            "static hot-object cache revalidates through secure static root resolution",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  local first cached refreshed escaped body

  first="$(client_request "static-hot-cache.example.test" "/static/hot.txt" 200)"
  assert_response_jq "${first}" '.body == "hot cache v1\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu \
    'printf "hot cache v2\n" > /etc/oxibelt/config/public/hot.txt'
  cached="$(client_request "static-hot-cache.example.test" "/static/hot.txt" 200)"
  assert_response_jq "${cached}" '.body == "hot cache v1\n"'

  sleep 2
  refreshed="$(client_request "static-hot-cache.example.test" "/static/hot.txt" 200)"
  assert_response_jq "${refreshed}" '.body == "hot cache v2\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    rm -f /etc/oxibelt/config/public/hot.txt
    ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/hot.txt
  '
  sleep 2
  escaped="$(client_request_with_headers_to_target "proxy" 8443 "static-hot-cache.example.test" "/static/hot.txt" "403,404" "GET" "")"
  body="$(jq -r '.body' <<<"${escaped}")"
  if grep -F "STATIC_HOT_CACHE_SECRET" <<<"${body}" >/dev/null; then
    echo "${escaped}" >&2
    fail_with_diagnostics "static hot cache served an out-of-root symlink target"
  fi
}
"#,
            None,
        ),
        docker_case(
            "security",
            "static-sendfile-general-equivalence",
            "plaintext static sendfile fast path matches HTTPS static general path",
            ExpectStart::Success,
            Needs::default(),
            r#"
assert_same_static_response() {
  local left="$1"
  local right="$2"
  local filter="$3"
  local left_value right_value
  left_value="$(jq -c "${filter}" <<<"${left}")"
  right_value="$(jq -c "${filter}" <<<"${right}")"
  if [[ "${left_value}" != "${right_value}" ]]; then
    echo "plain static: ${left_value}" >&2
    echo "https static: ${right_value}" >&2
    fail_with_diagnostics "static sendfile/general responses diverged"
  fi
}

run_case_checks() {
  local plain https etag logged logs matching

  plain="$(plain_client_request "static-equivalence.example.test" "/static/ok.txt" 200)"
  https="$(client_request "static-equivalence.example.test" "/static/ok.txt" 200)"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    "content-length": .headers["content-length"],
    "content-type": .headers["content-type"],
    "accept-ranges": .headers["accept-ranges"]
  }}'
  assert_response_jq "${plain}" '.body == "static ok\n"'

  logged="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/ok.txt?case=system-log" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_response_jq "${logged}" '.body == "static ok\n"'
  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  matching="$(grep -F '"scope":"system"' <<<"${logs}" | grep -F '"path":"/static/ok.txt"' | grep -F '"status":200' | grep -F '"route":"static-equivalence"' || true)"
  if [[ -z "${matching}" ]]; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected static sendfile system access log JSON on stdout"
  fi
  if ! grep -F '"user_agent":{"values":["first-agent","second-agent"],"is_truncated":false}' <<<"${matching}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected static sendfile system access log to preserve duplicate User-Agent values"
  fi

  plain="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/ok.txt" 200 "HEAD" "")"
  https="$(client_request_with_headers "static-equivalence.example.test" "/static/ok.txt" 200 "HEAD" "")"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    "content-length": .headers["content-length"],
    "content-type": .headers["content-type"]
  }}'
  assert_response_jq "${plain}" '.body == ""'

  plain="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/range.txt" 206 "GET" "" "Range: bytes=0-5")"
  https="$(client_request_with_headers "static-equivalence.example.test" "/static/range.txt" 206 "GET" "" "Range: bytes=0-5")"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    "content-length": .headers["content-length"],
    "content-range": .headers["content-range"],
    "accept-ranges": .headers["accept-ranges"]
  }}'
  assert_response_jq "${plain}" '.body == "012345"'

  etag="$(jq -r '.headers.etag' <<<"${https}")"
  plain="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/range.txt" 304 "GET" "" "If-None-Match: ${etag}")"
  https="$(client_request_with_headers "static-equivalence.example.test" "/static/range.txt" 304 "GET" "" "If-None-Match: ${etag}")"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    etag: .headers.etag,
    "accept-ranges": .headers["accept-ranges"]
  }}'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    rm -f /etc/oxibelt/config/public/link.txt
    ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/link.txt
  '
  plain="$(plain_client_request "static-equivalence.example.test" "/static/link.txt" 403)"
  https="$(client_request "static-equivalence.example.test" "/static/link.txt" 403)"
  assert_same_static_response "${plain}" "${https}" '{status, body}'
  assert_response_jq "${plain}" '.body == "forbidden"'

  plain="$(plain_client_request "static-equivalence.example.test" "/static/%2e%2e/outside-secret.txt" 400)"
  https="$(client_request "static-equivalence.example.test" "/static/%2e%2e/outside-secret.txt" 400)"
  assert_same_static_response "${plain}" "${https}" '{status, body}'
  assert_response_jq "${plain}" '.body == "invalid request path"'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "static-sendfile-real-ip-waf",
            "plaintext static sendfile WAF uses resolved Real-IP client identity",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  local allowed plain_blocked https_blocked

  allowed="$(plain_client_request "static-real-ip.example.test" "/static/ok.txt" 200)"
  assert_response_jq "${allowed}" '.body == "static ok\n"'

  plain_blocked="$(plain_client_request_with_headers_on_port 8080 "static-real-ip.example.test" "/static/ok.txt" 451 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${plain_blocked}" '.body == "real ip blocked"'

  https_blocked="$(client_request_with_headers "static-real-ip.example.test" "/static/ok.txt" 451 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${https_blocked}" '.body == "real ip blocked"'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "static-sendfile-response-timeout",
            "plaintext static sendfile responses release connection permits after downstream send timeout",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  local slow_client response

  response="$(plain_client_request "static-timeout.example.test" "/static/ok.txt" 200)"
  assert_response_jq "${response}" '.body == "static ok\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    dd if=/dev/zero of=/etc/oxibelt/config/public/large.bin bs=1 count=0 seek=536870912 >/dev/null 2>&1
  '

  slow_client="$(start_unread_static_sendfile_client)"
  sleep 2
  probe_plain_static_ok_once
  docker rm -f "${slow_client}" >/dev/null 2>&1 || true
}

start_unread_static_sendfile_client() {
  local client_container
  client_container="$(unique_docker_container_name "oxibelt-static-sendfile-slow-client")"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -u -c '
import socket
import time

sock = socket.create_connection(("proxy", 8080), timeout=5)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
sock.sendall(
    b"GET /static/large.bin HTTP/1.1\r\n"
    b"Host: static-timeout.example.test\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
print("slow static request sent", flush=True)
time.sleep(45)
sock.close()
' >/dev/null
  docker start "${client_container}" >/dev/null

  for _attempt in $(seq 1 50); do
    if docker logs "${client_container}" 2>&1 | grep -F "slow static request sent" >/dev/null; then
      printf '%s' "${client_container}"
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "${client_container}" 2>/dev/null || echo false)" != "true" ]]; then
      docker logs "${client_container}" >&2 || true
      fail_with_diagnostics "slow static sendfile client exited before sending the request"
    fi
    sleep 0.1
  done

  docker logs "${client_container}" >&2 || true
  fail_with_diagnostics "slow static sendfile client did not send its request"
}

probe_plain_static_ok_once() {
  local client_container output
  client_container="$(unique_docker_container_name "oxibelt-static-sendfile-probe")"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import http.client

connection = http.client.HTTPConnection("proxy", 8080, timeout=5)
try:
    connection.request(
        "GET",
        "/static/ok.txt",
        headers={"Host": "static-timeout.example.test", "Connection": "close"},
    )
    response = connection.getresponse()
    body = response.read()
    if response.status != 200:
        raise RuntimeError(f"expected 200, got {response.status}: {body!r}")
    if body != b"static ok\n":
        raise RuntimeError(f"unexpected response body: {body!r}")
finally:
    connection.close()

print("second static request succeeded")
' >/dev/null

  if ! output="$(docker start -a "${client_container}" 2>&1)"; then
    echo "${output}" >&2
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "second static request failed while slow sendfile client was still open"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  if ! grep -F "second static request succeeded" <<<"${output}" >/dev/null; then
    echo "${output}" >&2
    fail_with_diagnostics "second static request assertion did not run"
  fi
}
"#,
            None,
        ),
        docker_case(
            "security",
            "connection-task-registry-reaping",
            "completed downstream connection tasks are reaped during long-lived listener generations",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local warmup_count batch_count load_workers max_second_batch_growth_kb
  local rss_before rss_after_first rss_after_second second_batch_growth
  local response

  warmup_count="${OXIBELT_TASK_REGISTRY_WARMUP_CONNECTIONS:-1000}"
  batch_count="${OXIBELT_TASK_REGISTRY_LOAD_CONNECTIONS:-12000}"
  load_workers="${OXIBELT_TASK_REGISTRY_LOAD_WORKERS:-32}"
  max_second_batch_growth_kb="${OXIBELT_TASK_REGISTRY_MAX_SECOND_BATCH_RSS_GROWTH_KB:-8192}"

  run_short_lived_plain_connection_load "${warmup_count}" "${load_workers}"
  rss_before="$(proxy_rss_kb)"
  run_short_lived_plain_connection_load "${batch_count}" "${load_workers}"
  rss_after_first="$(proxy_rss_kb)"
  run_short_lived_plain_connection_load "${batch_count}" "${load_workers}"
  rss_after_second="$(proxy_rss_kb)"

  second_batch_growth=$((rss_after_second - rss_after_first))
  if (( second_batch_growth < 0 )); then
    second_batch_growth=0
  fi
  echo "proxy RSS KB: before=${rss_before} after_first=${rss_after_first} after_second=${rss_after_second} second_batch_growth=${second_batch_growth}"
  if (( second_batch_growth > max_second_batch_growth_kb )); then
    fail_with_diagnostics "proxy RSS grew by ${second_batch_growth} KiB during the second short-lived connection batch"
  fi

  response="$(plain_client_request "example.test" "/app/task-registry-final?body=alive" 200)"
  assert_response_jq "${response}" '.body == "alive"'
}

proxy_rss_kb() {
  local rss
  rss="$(docker exec "${proxy_container}" /bin/sh -c "awk '/VmRSS:/ { print \$2 }' /proc/1/status")"
  if [[ -z "${rss}" ]]; then
    fail_with_diagnostics "failed to read proxy RSS from /proc/1/status"
  fi
  printf '%s' "${rss}"
}

run_short_lived_plain_connection_load() {
  local count="$1"
  local workers="$2"
  local client_container="oxibelt-task-registry-load-${run_id}-${RANDOM}"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import concurrent.futures
import http.client
import sys

count = int(sys.argv[1])
workers = int(sys.argv[2])

def request(index):
    connection = http.client.HTTPConnection("proxy", 8080, timeout=5)
    try:
        path = f"/app/task-registry-{index}?body=ok"
        connection.request(
            "GET",
            path,
            headers={"Host": "example.test", "Connection": "close"},
        )
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"request {index} returned {response.status}: {body!r}")
        if body != b"ok":
            raise RuntimeError(f"request {index} returned unexpected body: {body!r}")
    finally:
        connection.close()

with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
    for _ in executor.map(request, range(count)):
        pass

print(f"completed {count} short-lived connections with {workers} workers")
' "${count}" "${workers}" >/dev/null

  if ! docker start -a "${client_container}"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "short-lived connection load client failed"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
}
"#,
            None,
        ),
        docker_case(
            "security",
            "tls-stateful-resumption-cache-bounded",
            "stateful downstream TLS resumption cache stays bounded under repeated resumes",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local connections min_resumed first second final
  connections="${OXIBELT_TLS_RESUMPTION_LOAD_CONNECTIONS:-64}"
  min_resumed="${OXIBELT_TLS_RESUMPTION_MIN_RESUMED:-32}"

  first="$(protocol_probe_tls_resumption_load "example.test" "/app/tls-resumption?body=first" "${connections}" "${min_resumed}")"
  assert_response_jq "${first}" ".connections == ${connections}
    and .resumed >= ${min_resumed}
    and .full >= 1
    and .tickets_received >= ${min_resumed}"

  second="$(protocol_probe_tls_resumption_load "example.test" "/app/tls-resumption?body=second" "${connections}" "${min_resumed}")"
  assert_response_jq "${second}" ".connections == ${connections}
    and .resumed >= ${min_resumed}
    and .full >= 1
    and .tickets_received >= ${min_resumed}"

  final="$(client_request "example.test" "/app/tls-resumption-final?body=alive" 200)"
  assert_response_jq "${final}" '.body == "alive"'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "webtransport-session-limit",
            "multiplexed WebTransport sessions are limited per client on one HTTP/3 connection",
            ExpectStart::Success,
            Needs {
                protocol_probe: true,
                webtransport_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_webtransport_multiplex "example.test" "/wt/session" 2 "200,429")"
  assert_response_jq "${response}" '.statuses == [200, 429]'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "webtransport-real-ip-connection-limit",
            "WebTransport sessions honor normal Real-IP connection limits",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                webtransport_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local holder_log="${work_dir}/held-real-ip-request.json"
  local holder_pid=""
  local response
  local blocked

  protocol_probe_client_with_headers \
    h3 \
    "example.test" \
    "/app/hold?header_delay_ms=15000&body=held" \
    200 \
    "GET" \
    "" \
    "X-Forwarded-For: 203.0.113.77" >"${holder_log}" &
  holder_pid="$!"

  blocked="$(protocol_probe_client_with_headers \
    h3 \
    "example.test" \
    "/app/blocked-while-held" \
    429 \
    "GET" \
    "" \
    "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${blocked}" '.status == 429'

  response="$(protocol_probe_webtransport_multiplex \
    "example.test" \
    "/wt/session" \
    1 \
    "429" \
    --header "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${response}" '.statuses == [429]'

  if ! wait "${holder_pid}"; then
    cat "${holder_log}" >&2 || true
    fail_with_diagnostics "held Real-IP request failed"
  fi

  response="$(protocol_probe_webtransport_multiplex \
    "example.test" \
    "/wt/session-after-release" \
    1 \
    "200" \
    --header "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${response}" '.statuses == [200]'
}
"#,
            None,
        ),
        docker_case(
            "security",
            "websocket-stream-waf-frame-limit",
            "WebSocket stream WAF rejects frames above the inspection limit",
            ExpectStart::Success,
            Needs::default(),
            r#"
run_case_checks() {
  start_websocket_echo_upstream
  assert_websocket_stream_waf_frame_limit
}

start_websocket_echo_upstream() {
  docker run -d \
    --name "oxibelt-ws-upstream-${run_id}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias ws-upstream \
    --entrypoint python \
    "${mock_image}" \
    -c '
import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data

def read_http_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before headers")
        data += chunk
    return data.decode("iso-8859-1", "replace")

def read_frame(sock):
    head = read_exact(sock, 2)
    if not head:
        return None
    opcode = head[0] & 0x0f
    masked = (head[1] & 0x80) != 0
    length = head[1] & 0x7f
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if masked else b"\x00\x00\x00\x00"
    payload = bytearray(read_exact(sock, length))
    if len(payload) != length:
        return None
    if masked:
        for index in range(length):
            payload[index] ^= mask[index % 4]
    return opcode, bytes(payload)

def send_frame(sock, opcode, payload):
    length = len(payload)
    if length < 126:
        head = bytes([0x80 | opcode, length])
    elif length <= 65535:
        head = bytes([0x80 | opcode, 126]) + struct.pack("!H", length)
    else:
        head = bytes([0x80 | opcode, 127]) + struct.pack("!Q", length)
    sock.sendall(head + payload)

def handle(conn):
    with conn:
        try:
            headers = {}
            for line in read_http_headers(conn).split("\r\n")[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.lower()] = value.strip()
            accept = base64.b64encode(
                hashlib.sha1((headers["sec-websocket-key"] + GUID).encode("ascii")).digest()
            ).decode("ascii")
            conn.sendall((
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "\r\n"
            ).encode("ascii"))
            frame = read_frame(conn)
            if frame is None:
                return
            opcode, payload = frame
            print(f"ws-upstream received {len(payload)} bytes", flush=True)
            send_frame(conn, opcode, payload)
        except Exception as error:
            print(f"ws-upstream connection failed: {error}", file=sys.stderr, flush=True)

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 18081))
server.listen()
while True:
    conn, _addr = server.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
' >/dev/null
  sleep 1
}

assert_websocket_stream_waf_frame_limit() {
  local client_container output
  client_container="oxibelt-ws-frame-limit-${run_id}-${RANDOM}"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import base64
import os
import socket
import ssl
import struct

def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            if not data:
                return b""
            raise RuntimeError("unexpected EOF while reading frame")
        data += chunk
    return data

def read_http_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before WebSocket response")
        data += chunk
    return data.decode("iso-8859-1", "replace")

def connect_ws():
    context = ssl.create_default_context(cafile="/tmp/proxy-ca.pem")
    raw = socket.create_connection(("proxy", 8443), timeout=5)
    sock = context.wrap_socket(raw, server_hostname="proxy")
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    sock.sendall((
        "GET /ws HTTP/1.1\r\n"
        "Host: ws.example.test\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii"))
    response = read_http_headers(sock)
    if not response.startswith("HTTP/1.1 101 "):
        raise RuntimeError(f"unexpected WebSocket response: {response!r}")
    return sock

def send_masked_frame(sock, payload):
    mask = b"\x01\x02\x03\x04"
    length = len(payload)
    if length < 126:
        head = bytes([0x82, 0x80 | length])
    elif length <= 65535:
        head = bytes([0x82, 0x80 | 126]) + struct.pack("!H", length)
    else:
        head = bytes([0x82, 0x80 | 127]) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(head + mask + masked)

def read_frame(sock):
    head = read_exact(sock, 2)
    if not head:
        return None
    opcode = head[0] & 0x0f
    masked = (head[1] & 0x80) != 0
    length = head[1] & 0x7f
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if masked else b"\x00\x00\x00\x00"
    payload = bytearray(read_exact(sock, length))
    if len(payload) != length:
        return None
    if masked:
        for index in range(length):
            payload[index] ^= mask[index % 4]
    return opcode, bytes(payload)

small = b"safe websocket frame"
small_sock = connect_ws()
try:
    send_masked_frame(small_sock, small)
    echoed = read_frame(small_sock)
    if echoed != (2, small):
        raise RuntimeError(f"small WebSocket frame was not echoed: {echoed!r}")
finally:
    small_sock.close()

large = b"x" * 2048
large_sock = connect_ws()
try:
    send_masked_frame(large_sock, large)
    large_sock.settimeout(3)
    try:
        frame = read_frame(large_sock)
    except socket.timeout as error:
        raise RuntimeError("oversized frame left the WebSocket open") from error
    except (ConnectionResetError, OSError, ssl.SSLError):
        frame = None
    if frame is not None and frame[0] in (1, 2) and frame[1] == large:
        raise RuntimeError("oversized WebSocket frame was proxied instead of rejected")
finally:
    large_sock.close()

print("small frame echoed")
print("oversized frame rejected")
' >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if ! output="$(docker start -a "${client_container}" 2>&1)"; then
    echo "${output}" >&2
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "WebSocket stream-WAF frame-limit client failed"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  if ! grep -F "oversized frame rejected" <<<"${output}" >/dev/null; then
    echo "${output}" >&2
    fail_with_diagnostics "WebSocket frame-limit assertion did not run"
  fi
}
"#,
            None,
        ),
        docker_case(
            "security",
            "turn-udp-session-cleanup",
            "TURN UDP proxy sessions close upstream sockets after idle expiration",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local baseline after_create after_expire create_delta expire_delta

  start_udp_turn_echo
  sleep 1

  baseline="$(proxy_socket_fd_count)"
  assert_udp_round_trip
  send_udp_packets_from_unique_ports 32 "session-load"
  sleep 1
  after_create="$(proxy_socket_fd_count)"
  create_delta=$((after_create - baseline))
  if (( create_delta < 12 )); then
    echo "socket fd counts: baseline=${baseline} after_create=${after_create}" >&2
    fail_with_diagnostics "TURN UDP load did not create the expected upstream sockets"
  fi

  sleep 1
  send_udp_packets_from_unique_ports 1 "expiration-trigger"
  sleep 1
  after_expire="$(proxy_socket_fd_count)"
  expire_delta=$((after_expire - baseline))
  echo "TURN UDP socket fd counts: baseline=${baseline} after_create=${after_create} after_expire=${after_expire} create_delta=${create_delta} expire_delta=${expire_delta}"
  if (( expire_delta > 4 )); then
    fail_with_diagnostics "expired TURN UDP sessions still retained upstream sockets"
  fi

  assert_udp_round_trip
}

start_udp_turn_echo() {
  docker run -d \
    --name "oxibelt-turn-upstream-${run_id}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-turn \
    --entrypoint python \
    "${mock_image}" \
    -c '
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 3478))
while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
' >/dev/null
}

proxy_socket_fd_count() {
  docker exec "${proxy_container}" sh -c 'count=0; for fd in /proc/1/fd/*; do target="$(readlink "$fd" 2>/dev/null || true)"; case "$target" in socket:*) count=$((count + 1));; esac; done; printf "%s" "$count"'
}

assert_udp_round_trip() {
  local client_container="oxibelt-turn-udp-roundtrip-${run_id}-${RANDOM}"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import socket

payload = b"roundtrip"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(payload, ("proxy", 3478))
data, _ = sock.recvfrom(65535)
if data != payload:
    raise RuntimeError(f"unexpected TURN UDP echo: {data!r}")
' >/dev/null
  if ! docker start -a "${client_container}"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "TURN UDP round trip failed"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
}

send_udp_packets_from_unique_ports() {
  local count="$1"
  local payload="$2"
  local client_container="oxibelt-turn-udp-load-${run_id}-${RANDOM}"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import socket
import sys
import time

count = int(sys.argv[1])
payload = sys.argv[2].encode("utf-8")
sockets = []
for index in range(count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sockets.append(sock)
    sock.sendto(payload + b":" + str(index).encode("ascii"), ("proxy", 3478))
time.sleep(0.2)
for sock in sockets:
    sock.close()
' "${count}" "${payload}" >/dev/null
  if ! docker start -a "${client_container}"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "TURN UDP load client failed"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
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
            "config-invalid",
            "emit-mitigation-udf-payload-exclusion",
            "mitigation field validation rejects UDF payload indirection",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("cannot read request, response, or stream body bytes"),
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
            "ops",
            "observability-detail",
            "detailed Prometheus metrics, tracecontext propagation, and admin-only WAF cost telemetry work in Docker",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response metrics admin incoming_traceparent
  incoming_traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

  response="$(client_request_with_headers "example.test" "/app/observability-seed" 200 "GET" "" "traceparent: ${incoming_traceparent}")"
  assert_body_jq "${response}" '.path == "/origin/app/observability-seed"'
  assert_body_jq "${response}" '.headers.traceparent | test("^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$")'
  assert_body_jq "${response}" ".headers.traceparent != \"${incoming_traceparent}\""

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_http_requests_total{")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_http_request_duration_ms_bucket{")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_requests_total{")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_request_duration_ms_bucket{")'
  assert_response_jq "${metrics}" '.body | contains("route=\"main-route\"")'
  assert_response_jq "${metrics}" '.body | contains("upstream=\"http-upstream\"")'
  assert_response_jq "${metrics}" '.body | contains("method=\"GET\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"h1\"")'
  assert_response_jq "${metrics}" '.body | contains("status=\"200\"")'
  assert_response_jq "${metrics}" '.body | contains("status_class=\"2xx\"")'
  assert_response_jq "${metrics}" '.body | contains("upstream_protocol=\"http\"")'
  assert_response_jq "${metrics}" '.body | contains("outcome=\"success\"")'
  assert_response_jq "${metrics}" '.body | contains("rule_name") | not'
  assert_response_jq "${metrics}" '.body | contains("rule_id") | not'
  assert_response_jq "${metrics}" '.body | contains("obs-cost-rule") | not'
  assert_response_jq "${metrics}" '.body | contains("obs-cost-tag") | not'

  admin="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/rule-costs" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "global" and .route == null and .phase == "request" and .name == "obs-cost-rule" and .id == "obs-cost-rule" and (.tags | index("obs-cost-tag") != null) and .effective_mode == "monitor" and .evaluations >= 1 and .total_duration_ns >= .average_duration_ns)] | length) == 1'
}
"#,
            None,
        ),
        docker_case(
            "ops",
            "admin-config-file-sync",
            "Admin API config load/rollback, file sync, fine-grained RBAC, and downstream TLS reload work in Docker",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
admin_config_etag() {
  local status
  status="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/status" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -r '.body | fromjson | .etag' <<<"${status}"
}

run_case_checks() {
  local response raw_config validate_body loaded_config load_body etag synced_group sync_body bad_body

  response="$(client_request "example.test" "/app/admin-before" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/admin-before"'

  response="$(client_request "example.test" "/app/admin-synced" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/admin-synced"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/status" 200 "GET" "" "Authorization: Bearer matrix-upstream-token")"
  assert_response_jq "${response}" '.body | fromjson | .revision == 1'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/effective" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .config | contains("[admin]")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/effective" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '.body | fromjson | .config | contains("rest_shared_secret = \"<redacted>\"")'
  assert_response_jq "${response}" '.body | fromjson | .config | contains("password = \"<redacted>\"")'
  assert_response_jq "${response}" '(.body | fromjson | .config | contains("REST-SHARED-SECRET-LEAK")) | not'
  assert_response_jq "${response}" '(.body | fromjson | .config | contains("STATIC-PASSWORD-LEAK")) | not'

  raw_config="$(docker exec "${proxy_container}" cat /etc/oxibelt/config/oxibelt.toml)"
  validate_body="$(jq -cn --arg config "${raw_config}" '{format:"toml",config:$config}')"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/validate" 200 "POST" "${validate_body}" "Authorization: Bearer matrix-upstream-token")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  loaded_config="${raw_config}"$'\n\n'
  loaded_config+="$(cat <<'TOML'
[[waf.rules]]
name = "admin-runtime-block"
phase = "request"
priority = 20
when = "Request.Http.Path == '/app/admin-loaded'"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "loaded config"
TOML
)"
  load_body="$(jq -cn --arg config "${loaded_config}" '{format:"toml",config:$config}')"

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/diff" 200 "POST" "${load_body}" "Authorization: Bearer matrix-upstream-token")"
  assert_response_jq "${response}" '(.body | fromjson | .changes | length) > 0'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/load" 403 "POST" "${load_body}" "Authorization: Bearer matrix-upstream-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body == "forbidden"'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/load" 200 "POST" "${load_body}" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  response="$(client_request "example.test" "/app/admin-loaded" 403)"
  assert_response_jq "${response}" '.body == "loaded config"'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/rollback" 200 "POST" "" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  response="$(client_request "example.test" "/app/admin-loaded" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/admin-loaded"'

  docker exec --user root "${proxy_container}" chown -R oxibelt:oxibelt /etc/oxibelt/config /etc/oxibelt/oxirule

  synced_group="$(cat <<'TOML'
[[rule_groups]]
name = "synced-block"
when = "Request.Http.Path == '/app/admin-synced'"
TOML
)"
  sync_body="$(jq -cn --arg content "${synced_group}" '{apply:"oxirule",operations:[{op:"put",root:"oxirule_group",path:"groups/admin.oxirule-group.toml",content:$content}]}')"
  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/files/sync" 200 "POST" "${sync_body}" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true and .operations == 1'

  response="$(client_request "example.test" "/app/admin-synced" 403)"
  assert_response_jq "${response}" '.body == "synced group"'

  docker exec "${proxy_container}" test -f /etc/oxibelt/oxirule/groups/admin.oxirule-group.toml

  bad_body="$(jq -cn --arg content "[section]\n" '{apply:"none",operations:[{op:"put",root:"config",path:"bad-sync.toml",expected_sha256:"0000000000000000000000000000000000000000000000000000000000000000",content:$content}]}')"
  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/files/sync" 400 "POST" "${bad_body}" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .error | contains("expected_sha256")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/status" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .last_operation.operation == "files_sync" and .last_operation.outcome == "rejected"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/tls/downstream" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '.body | fromjson | .private_key_configured == true'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/tls/downstream/reload" 403 "POST" "" "Authorization: Bearer matrix-viewer-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body == "forbidden"'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/tls/downstream/reload" 200 "POST" "" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'
}
"#,
            None,
        ),
        docker_case(
            "ops",
            "kernel-extension-installer",
            "kernel extension installer stages and verifies Linux 7.0.x host tuning files",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response output kernel_container
  response="$(client_request "example.test" "/app/kernel-extension" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/kernel-extension"'

  kernel_container="oxibelt-kernel-extension-${run_id}-${RANDOM}"
  docker create \
    --name "${kernel_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint /bin/sh \
    "${proxy_image}" \
    -ceu '
      mkdir -p /tmp/oxibelt-root
      /bin/sh /tmp/kernel-extension/install.sh --apply --root /tmp/oxibelt-root --kernel-release 7.0.3
      /bin/sh /tmp/kernel-extension/verify.sh --root /tmp/oxibelt-root --kernel-release 7.0.3
      limits_file=/tmp/oxibelt-root/etc/security/limits.d/90-oxibelt-edge.conf
      if awk '"'"'$1 == "*" && $3 == "nofile" { found = 1 } END { exit found ? 0 : 1 }'"'"' "${limits_file}"; then
        echo "${limits_file} grants nofile limits to wildcard principal *" >&2
        exit 45
      fi
      grep -Fx "oxibelt soft nofile 1048576" "${limits_file}" >/dev/null
      grep -Fx "oxibelt hard nofile 1048576" "${limits_file}" >/dev/null
      if /bin/sh /tmp/kernel-extension/install.sh --dry-run --root /tmp/old-root --kernel-release 6.19.14 >/tmp/old-kernel.log 2>&1; then
        cat /tmp/old-kernel.log >&2
        exit 44
      fi
      grep -F "targets Linux 7.0.x" /tmp/old-kernel.log >/dev/null
    ' >/dev/null
  docker cp "${repo_root}/kernel-extension" "${kernel_container}:/tmp/kernel-extension"

  if ! output="$(docker start -a "${kernel_container}" 2>&1)"; then
    echo "${output}" >&2
    docker rm -f "${kernel_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "kernel extension installer container failed"
  fi
  docker rm -f "${kernel_container}" >/dev/null 2>&1 || true
  if ! grep -F "verified /tmp/oxibelt-root/etc/sysctl.d/90-oxibelt-edge.conf" <<<"${output}" >/dev/null; then
    echo "${output}" >&2
    fail_with_diagnostics "kernel extension verifier did not report sysctl template"
  fi
}
"#,
            None,
        ),
        docker_case(
            "ops",
            "system-access-log-stdout",
            "system-wide access log emits structured stdout records without WAF rules",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response logs matching
  response="$(client_request_with_headers "example.test" "/app/system-log?case=stdout" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_body_jq "${response}" '.path == "/origin/app/system-log?case=stdout"'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  matching="$(grep -F '"scope":"system"' <<<"${logs}" | grep -F '"path":"/app/system-log"' | grep -F '"status":200' || true)"
  if [[ -z "${matching}" ]]; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected system access log JSON on stdout"
  fi
  if ! grep -F '"user_agent":{"values":["first-agent","second-agent"],"is_truncated":false}' <<<"${matching}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected system access log to preserve duplicate User-Agent values"
  fi
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
            "limits",
            "http3-content-length-zero-body-limit",
            "HTTP/3 Content-Length zero requests still apply body limits to DATA frames",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local empty_response oversized_response
  empty_response="$(protocol_probe_client_with_headers "h3" "example.test" "/app/cl0-empty" 200 "GET" "")"
  assert_body_jq "${empty_response}" '.path == "/origin/app/cl0-empty" and .body == ""'

  oversized_response="$(protocol_probe_generated_body_request "h3" "example.test" "/app/cl0-too-large" "GET" 8 8 --omit-content-length --header "Content-Length: 0" --expect-status 413)"
  assert_response_jq "${oversized_response}" '.body == "request body is too large"'
}
"#,
            None,
        ),
        docker_case(
            "limits",
            "rate-limit-bucket-cap",
            "local rate-limit bucket caps reject attacker-controlled token/path churn",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second repeated
  first="$(client_request_with_headers "example.test" "/app/rate-a" 200 "GET" "" "Authorization: Bearer first-token")"
  assert_body_jq "${first}" '.path == "/origin/app/rate-a"'

  second="$(client_request_with_headers "example.test" "/app/rate-b" 429 "GET" "" "Authorization: Bearer second-token")"
  assert_response_jq "${second}" '.body == "rate limit exceeded"'

  repeated="$(client_request_with_headers "example.test" "/app/rate-a" 429 "GET" "" "Authorization: Bearer first-token")"
  assert_response_jq "${repeated}" '.body == "rate limit exceeded"'
}
"#,
            None,
        ),
        docker_case(
            "buffering",
            "request-spool",
            "request body spooling preserves uploads and cleans temp files after success and rejection",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  assert_no_buffer_temp_files() {
    local label="$1"
    local temp_count
    temp_count="$(docker exec "${proxy_container}" sh -c 'find /var/cache/oxibelt -maxdepth 1 -type f -name "oxibelt-buffer-*" | wc -l' | tr -d "[:space:]")"
    if [[ "${temp_count}" != "0" ]]; then
      docker exec "${proxy_container}" sh -c 'ls -la /var/cache/oxibelt' >&2 || true
      fail_with_diagnostics "expected ${label} buffering temp files to be removed"
    fi
  }

  local oversized_body response
  response="$(client_request_with_headers "example.test" "/app/upload" 200 "POST" "spooled-request-body" "Content-Type: text/plain")"
  assert_body_jq "${response}" '.body == "spooled-request-body"'
  assert_no_buffer_temp_files "successful request"

  printf -v oversized_body '%*s' 135 ''
  oversized_body="${oversized_body// /x}"
  response="$(split_body_client_request "example.test" "/app/upload" 413 "POST" "${oversized_body}" 5 100 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body is too large"'
  assert_no_buffer_temp_files "oversized request"
}
"#,
            None,
        ),
        docker_case(
            "buffering",
            "response-spool",
            "response body spooling protects upstream and cleans temp files after success and rejection",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  assert_no_buffer_temp_files() {
    local label="$1"
    local temp_count
    temp_count="$(docker exec "${proxy_container}" sh -c 'find /var/cache/oxibelt -maxdepth 1 -type f -name "oxibelt-buffer-*" | wc -l' | tr -d "[:space:]")"
    if [[ "${temp_count}" != "0" ]]; then
      docker exec "${proxy_container}" sh -c 'ls -la /var/cache/oxibelt' >&2 || true
      fail_with_diagnostics "expected ${label} buffering temp files to be removed"
    fi
  }

  local oversized_body response
  start_holding_client_request_with_headers "proxy" 8443 "https" "" "example.test" "/app/download?body=spooled-response-body-0123456789" 200 3000
  wait_holding_client
  response="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${response}" '.body == "spooled-response-body-0123456789"'
  assert_no_buffer_temp_files "successful response"

  printf -v oversized_body '%*s' 135 ''
  oversized_body="${oversized_body// /x}"
  response="$(client_request "example.test" "/app/download?body=${oversized_body}&body_split_at=5&body_split_delay_ms=100" 502)"
  assert_response_jq "${response}" '.body == "upstream response body is too large"'
  assert_no_buffer_temp_files "oversized response"
}
"#,
            None,
        ),
        docker_case(
            "timeouts",
            "route-first-byte-timeout",
            "route-level upstream first-byte timeout can fail one route while another succeeds",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local short_response long_response
  short_response="$(client_request "example.test" "/short/delay?header_delay_ms=1200" 504)"
  assert_response_jq "${short_response}" '.body == "upstream request failed"'

  long_response="$(client_request "example.test" "/long/delay?header_delay_ms=1200" 200)"
  assert_body_jq "${long_response}" '.path == "/origin/app/delay?header_delay_ms=1200"'
}
"#,
            None,
        ),
        docker_case(
            "timeouts",
            "route-client-body-timeout",
            "route-level client body timeout rejects a slow upload",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(slow_body_client_request "example.test" "/app/slow-upload" 408 "POST" "slow-body" 1200 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body timed out"'
}
"#,
            None,
        ),
        docker_case(
            "timeouts",
            "zero-length-body-timeout",
            "HTTP/2 zero-length bodies that delay END_STREAM still hit client body timeout",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_zero_length_body_delay_request "example.test" "/app/zero-length-stall" 408 "POST" 1200)"
  assert_response_jq "${response}" '.body == "request body timed out"'
}
"#,
            None,
        ),
        docker_case(
            "timeouts",
            "route-upstream-read-timeout",
            "route-level upstream read timeout fails a stalled buffered response",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/stalled-body?body_delay_ms=1200" 504)"
  assert_response_jq "${response}" '.body == "upstream response body timed out"'
}
"#,
            None,
        ),
        docker_case(
            "timeouts",
            "route-upstream-send-timeout",
            "route-level upstream send timeout aborts a backpressured request body",
            ExpectStart::Success,
            Needs {
                h1_stall_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_generated_body_request "h2" "example.test" "/upload" "POST" 67108864 16384 --omit-content-length)"
  if jq -e '.status == 200' <<<"${response}" >/dev/null; then
    echo "${response}" >&2
    fail_with_diagnostics "upstream send timeout cleanly truncated the request body"
  fi
  assert_response_jq "${response}" '(.status == 400 or .status == 502 or .status == 504)
    and (.body | contains("upstream request failed") or contains("failed to read upstream request body"))'
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
            "proxy-identity",
            "connection-limit-first-request-real-ip",
            "first-request Real-IP connection limits use trusted forwarded client IPs",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local same other after
  start_holding_client_request_with_headers \
    "proxy" 8443 "https" "" \
    "example.test" "/app/hold-first?body_delay_ms=3000" 200 4000 \
    "X-Forwarded-For: 203.0.113.10"

  same="$(client_request_with_headers "example.test" "/app/same-client" 429 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${same}" '.body == "connection limit exceeded"'

  other="$(client_request_with_headers "example.test" "/app/other-client" 200 "GET" "" "X-Forwarded-For: 203.0.113.11")"
  assert_body_jq "${other}" '.path == "/origin/app/other-client"'

  wait_holding_client

  after="$(client_request_with_headers "example.test" "/app/after-release" 200 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_body_jq "${after}" '.path == "/origin/app/after-release"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-identity",
            "connection-limit-per-request-real-ip",
            "per-request Real-IP connection limits release after response body completion",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local same after
  start_holding_client_request_with_headers \
    "proxy" 8443 "https" "" \
    "example.test" "/app/hold-per-request?body_delay_ms=3000" 200 4000 \
    "X-Forwarded-For: 203.0.113.20"

  same="$(client_request_with_headers "example.test" "/app/same-client" 429 "GET" "" "X-Forwarded-For: 203.0.113.20")"
  assert_response_jq "${same}" '.body == "connection limit exceeded"'

  wait_holding_client

  after="$(client_request_with_headers "example.test" "/app/after-release" 200 "GET" "" "X-Forwarded-For: 203.0.113.20")"
  assert_body_jq "${after}" '.path == "/origin/app/after-release"'
}
"#,
            None,
        ),
        docker_case(
            "proxy-identity",
            "connection-limit-per-request-real-ip-http1-tunnels",
            "per-request Real-IP connection limits stay held for HTTP/1 tunnel lifetimes",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local same after

  start_holding_upgrade_client_request_with_headers \
    "example.test" "/upgrade-held" "matrix-upgrade" "held-upgrade" 101 2500 \
    "X-Forwarded-For: 203.0.113.30"

  same="$(upgrade_client_request_with_headers "example.test" "/upgrade-same" "matrix-upgrade" "blocked-upgrade" 429 "X-Forwarded-For: 203.0.113.30")"
  assert_response_jq "${same}" '.body == "connection limit exceeded"'

  wait_holding_client

  after="$(upgrade_client_request_with_headers "example.test" "/upgrade-after" "matrix-upgrade" "after-upgrade" 101 "X-Forwarded-For: 203.0.113.30")"
  assert_response_jq "${after}" '.body == "upgraded:after-upgrade"'

  start_holding_connect_tunnel_request_with_headers \
    "example.test" "/origin/connect-held?case=held" 200 2500 \
    "X-Forwarded-For: 203.0.113.31"

  same="$(connect_tunnel_request_with_headers "example.test" "/origin/connect-same?case=same" 429 "X-Forwarded-For: 203.0.113.31")"
  assert_response_jq "${same}" '.body == "connection limit exceeded"'

  wait_holding_client

  after="$(connect_tunnel_request_with_headers "example.test" "/origin/connect-after?case=after" 200 "X-Forwarded-For: 203.0.113.31")"
  assert_response_jq "${after}" '.body | fromjson | .path == "/origin/connect-after?case=after"'
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
            "proxy-protocol",
            "connection-limit-source-ip",
            "PROXY protocol source IP is used for downstream connection limits",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local same other
  start_holding_client_request_with_headers \
    "proxy" 8443 "https" "PROXY TCP4 203.0.113.30 192.0.2.10 45678 443" \
    "example.test" "/app/hold-proxy?body_delay_ms=3000" 200 4000

  if same="$(probe_proxy_protocol_client_request "PROXY TCP4 203.0.113.30 192.0.2.10 45679 443" "example.test" "/app/same-client" 2>/dev/null)"; then
    echo "${same}" >&2
    fail_with_diagnostics "same PROXY source IP unexpectedly reached the proxy while the first connection was held"
  fi

  other="$(proxy_protocol_client_request "PROXY TCP4 203.0.113.31 192.0.2.10 45680 443" "example.test" "/app/other-client" 200)"
  assert_body_jq "${other}" '.path == "/origin/app/other-client"'

  wait_holding_client
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
            "upstream-discovery",
            "file-provider",
            "file discovery adds and removes upstream pool servers without full reload",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second third
  sleep 1
  first="$(client_request "example.test" "/app/file-discovery-a" 200)"
  second="$(client_request "example.test" "/app/file-discovery-b" 200)"
  assert_body_jq "${first}" '.upstream == "http-upstream"'
  assert_body_jq "${second}" '.upstream == "alt-upstream"'

  cat >"${case_dir}/config/discovery/app-pool.json" <<'JSON'
{
  "servers": []
}
JSON
  docker cp "${case_dir}/config/discovery/app-pool.json" "${proxy_container}:/etc/oxibelt/config/discovery/app-pool.json"
  sleep 1

  third="$(client_request "example.test" "/app/file-discovery-after-remove" 200)"
  assert_body_jq "${third}" '.upstream == "http-upstream"'
}
"#,
            None,
        ),
        docker_case(
            "upstream-discovery",
            "dns-spoofed-answers",
            "DNS discovery rejects spoofed answers while accepting matching responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                dns_server: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  sleep 2

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/spoof-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '(.body | fromjson | [.servers[] | select(.source == "dns")] | length) == 0'

  response="$(client_request "spoof.example.test" "/app/spoof-static" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/spoof-static"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/valid-dns-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '(.body | fromjson | [.servers[] | select(.source == "dns")] | length) == 1'

  response="$(client_request "valid.example.test" "/app/valid-dns" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/app/valid-dns"'
}
"#,
            None,
        ),
        docker_case(
            "upstream-discovery",
            "admin-runtime-control",
            "admin API can drain/down pool servers and update runtime weights",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response first second third
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 200 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  first="$(client_request "example.test" "/app/admin-down-a" 200)"
  second="$(client_request "example.test" "/app/admin-down-b" 200)"
  assert_body_jq "${first}" '.upstream == "alt-upstream"'
  assert_body_jq "${second}" '.upstream == "alt-upstream"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 200 "PATCH" '{"state":"ready","weight":2}' "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/alt" 200 "PATCH" '{"weight":1}' "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  first="$(client_request "example.test" "/app/admin-weight-a" 200)"
  second="$(client_request "example.test" "/app/admin-weight-b" 200)"
  third="$(client_request "example.test" "/app/admin-weight-c" 200)"
  assert_body_jq "${first}" '.upstream == "http-upstream"'
  assert_body_jq "${second}" '.upstream == "http-upstream"'
  assert_body_jq "${third}" '.upstream == "alt-upstream"'
}
"#,
            None,
        ),
        docker_case(
            "upstream-discovery",
            "admin-rbac",
            "admin RBAC allows pool reads while protecting mutations",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '.body | fromjson | length == 1'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 403 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '.body == "forbidden"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 200 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-upstream-token")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools" 401 "GET" "" "Authorization: Bearer wrong-token")"
  assert_response_jq "${response}" '.body == "unauthorized"'
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
            "cache",
            "http-semantics-revalidate",
            "cache revalidates stale entries with ETag validators",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/revalidate?etag=matrix-v1&cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  response="$(client_request_with_headers "example.test" "/app/revalidate?etag=matrix-v1&cache_control=public" 200 "GET" "" "Cache-Control: no-cache")"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/revalidate?etag=matrix-v1&cache_control=public"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "vary-header-isolation",
            "cache keeps Vary header variants isolated",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second third
  first="$(client_request_with_headers "example.test" "/app/vary?vary=X-Variant&cache_control=public" 200 "GET" "" "X-Variant: a")"
  second="$(client_request_with_headers "example.test" "/app/vary?vary=X-Variant&cache_control=public" 200 "GET" "" "X-Variant: b")"
  third="$(client_request_with_headers "example.test" "/app/vary?vary=X-Variant&cache_control=public" 200 "GET" "" "X-Variant: a")"
  assert_body_jq "${first}" '.headers["x-variant"] == "a"'
  assert_body_jq "${second}" '.headers["x-variant"] == "b"'
  assert_body_jq "${third}" '.headers["x-variant"] == "a"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "range-hit",
            "cache serves byte ranges from a stored full response",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/range?body=0123456789&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${response}" '.body == "0123456789"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request_with_headers "example.test" "/app/range?body=0123456789&cache_control=public&content_type=text/plain" 206 "GET" "" "Range: bytes=2-5")"
  assert_response_jq "${response}" '.body == "2345" and .headers["content-range"] == "bytes 2-5/10"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "memory-then-disk-fallback",
            "memory_then_disk cache falls back to disk when memory budget is exhausted",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/hybrid?body=abcdefghijklmnopqrstuvwxyz&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${response}" '.body == "abcdefghijklmnopqrstuvwxyz"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request "example.test" "/app/hybrid?body=abcdefghijklmnopqrstuvwxyz&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${response}" '.body == "abcdefghijklmnopqrstuvwxyz"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "disk-policy-by-mime",
            "cache policy stores selected response MIME types on disk",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/assets/app.css?body=body-css&cache_control=public&content_type=text/css" 200)"
  assert_response_jq "${response}" '.body == "body-css"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request "example.test" "/assets/app.css?body=body-css&cache_control=public&content_type=text/css" 200)"
  assert_response_jq "${response}" '.body == "body-css"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "admin-purge-tls-sni",
            "admin API purges cache over TLS with SNI certificate selection",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/admin-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  response="$(client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-purge?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request "example.test" "/app/admin-purge?cache_control=public" 502)"
  assert_response_jq "${response}" '.status == 502'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "admin-purge-docker-plaintext-allowlist",
            "admin API can allow plaintext purge from Docker bridge CIDRs",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/admin-plain-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-plain-purge?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'
  response="$(client_request "example.test" "/app/admin-json-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/cache/purge" 200 "POST" "{\"type\":\"exact\",\"policy\":\"default\",\"scheme\":\"https\",\"host\":\"example.test\",\"uri\":\"/app/admin-json-purge?cache_control=public\"}" "Authorization: Bearer matrix-admin-token" "Content-Type: application/json")"
  assert_response_jq "${response}" '(.body | fromjson | .purged) == 1'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request "example.test" "/app/admin-plain-purge?cache_control=public" 502)"
  assert_response_jq "${response}" '.status == 502'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "tag-purge",
            "admin API purges cache entries by Surrogate-Key tag",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second purge first_after second_after
  first="$(client_request "example.test" "/app/tag-a?sequence_key=tag-a&body_sequence=tag-a%7Ctag-a-after&cache_control=public&content_type=text/plain&surrogate_key=release-1%20assets" 200)"
  second="$(client_request "example.test" "/app/tag-b?sequence_key=tag-b&body_sequence=tag-b%7Ctag-b-after&cache_control=public&content_type=text/plain&surrogate_key=release-2%20assets" 200)"
  assert_response_jq "${first}" '.body == "tag-a"'
  assert_response_jq "${second}" '.body == "tag-b"'

  purge="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge-tag?policy=default&tag=release-1" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${purge}" '.body == "purged=1\n"'

  first_after="$(client_request "example.test" "/app/tag-a?sequence_key=tag-a&body_sequence=tag-a%7Ctag-a-after&cache_control=public&content_type=text/plain&surrogate_key=release-1%20assets" 200)"
  second_after="$(client_request "example.test" "/app/tag-b?sequence_key=tag-b&body_sequence=tag-b%7Ctag-b-after&cache_control=public&content_type=text/plain&surrogate_key=release-2%20assets" 200)"
  assert_response_jq "${first_after}" '.body == "tag-a-after"'
  assert_response_jq "${second_after}" '.body == "tag-b"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "signed-purge",
            "HMAC signed cache purge works without bearer credentials and rejects replay",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response purge replay
  response="$(client_request "example.test" "/app/signed-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  purge="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/signed-purge?cache_control=public" 200 "POST" "" \
    "X-OxiBelt-Cache-Timestamp: 1700000000" \
    "X-OxiBelt-Cache-Nonce: matrix-signed-purge" \
    "X-OxiBelt-Cache-Signature: 8PmsDoehRk/B9RyQnNWI9mWFMgXw6brivm7pa/5Da08=")"
  assert_response_jq "${purge}" '.body == "purged=1\n"'

  replay="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/signed-purge?cache_control=public" 401 "POST" "" \
    "X-OxiBelt-Cache-Timestamp: 1700000000" \
    "X-OxiBelt-Cache-Nonce: matrix-signed-purge" \
    "X-OxiBelt-Cache-Signature: 8PmsDoehRk/B9RyQnNWI9mWFMgXw6brivm7pa/5Da08=")"
  assert_response_jq "${replay}" '.body == "unauthorized"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "tenant-partition-isolation",
            "cache partition keys isolate tenants sharing one URI",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local path tenant_a tenant_b tenant_a_hit tenant_b_hit
  path="/app/tenant?sequence_key=tenant-partition&body_sequence=tenant-a%7Ctenant-b%7Ctenant-miss&cache_control=public&content_type=text/plain"
  tenant_a="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-a")"
  tenant_b="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-b")"
  assert_response_jq "${tenant_a}" '.body == "tenant-a"'
  assert_response_jq "${tenant_b}" '.body == "tenant-b"'

  docker rm -f "${http_container}" >/dev/null
  tenant_a_hit="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-a")"
  tenant_b_hit="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-b")"
  assert_response_jq "${tenant_a_hit}" '.body == "tenant-a"'
  assert_response_jq "${tenant_b_hit}" '.body == "tenant-b"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "surrogate-control",
            "Surrogate-Control overrides origin no-store and is stripped downstream",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local path first cached
  path="/app/surrogate?sequence_key=surrogate-control&body_sequence=surrogate-a%7Csurrogate-b&cache_control=no-store&surrogate_control=max-age%3D60&content_type=text/plain"
  first="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${first}" '.body == "surrogate-a" and (.headers["surrogate-control"] == null)'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${cached}" '.body == "surrogate-a" and (.headers["surrogate-control"] == null)'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "vary-explosion-rejection",
            "Vary variant caps reject extra variants without poisoning cached variants",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local path first rejected cached miss
  path="/app/vary-cap?sequence_key=vary-cap&body_sequence=vary-a%7Cvary-b%7Cvary-c&vary=X-Variant&cache_control=public&content_type=text/plain"
  first="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Variant: a")"
  rejected="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Variant: b")"
  assert_response_jq "${first}" '.body == "vary-a"'
  assert_response_jq "${rejected}" '.body == "vary-b"'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Variant: a")"
  miss="$(client_request_with_headers "example.test" "${path}" 502 "GET" "" "X-Variant: b")"
  assert_response_jq "${cached}" '.body == "vary-a"'
  assert_response_jq "${miss}" '.status == 502'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "json-warming",
            "admin JSON cache warming stores a GET response before client traffic",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local path warm cached
  path="/app/warm?body=warmed&cache_control=public&content_type=text/plain"
  warm="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/cache/warm" 200 "POST" "{\"items\":[{\"scheme\":\"https\",\"host\":\"example.test\",\"uri\":\"${path}\"}]}" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${warm}" '(.body | fromjson | .items[0].result) == "stored"'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${cached}" '.body == "warmed"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "large-object-cache",
            "large cacheable objects survive upstream removal",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local path first cached
  path="/app/large?body_repeat=131072&body_repeat_char=L&cache_control=public&content_type=text/plain"
  first="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${first}" '(.body | length) == 131072'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${cached}" '(.body | length) == 131072'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "large-object-over-memory-not-cached",
            "cache streams responses larger than the proxy memory body limit without storing them",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local path first miss
  path="/app/large-over-memory?body_repeat=131072&body_repeat_char=M&cache_control=public&content_type=text/plain"
  first="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${first}" '(.body | length) == 131072'

  docker rm -f "${http_container}" >/dev/null
  miss="$(client_request "example.test" "${path}" 502)"
  assert_response_jq "${miss}" '.status == 502'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "background-refresh",
            "stale-while-revalidate serves stale while refreshing in the background",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first stale second_stale refreshed
  first="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${first}" '.body == "old"'
  sleep 2
  stale="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${stale}" '.body == "old"'
  sleep 2
  second_stale="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${second_stale}" '.body == "old" or .body == "new"'
  sleep 1
  refreshed="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${refreshed}" '.body == "new"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "shared-background-refresh-disabled",
            "shared cache stale hits honor disabled background refresh policy",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                redis: true,
                second_proxy: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local path seed revalidated
  path="/no-bg/shared-stale?sequence_key=no-bg-shared-disabled&body_sequence=old%7Cnew&cache_control_value=public%2C%20max-age%3D1%2C%20stale-while-revalidate%3D30%2C%20stale-if-error%3D30&last_modified=Wed%2C%2021%20Oct%202015%2007%3A28%3A00%20GMT&content_type=text/plain"

  seed="$(client_request_with_headers "example.test" "${path}" 200 "GET" "")"
  assert_response_jq "${seed}" '.body == "old"'

  sleep 2

  revalidated="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${path}" 200 "GET" "")"
  assert_response_jq "${revalidated}" '.body == "new"'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "admission-stale-errors",
            "cache admission policy and stale-if-error status handling work together",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second third stale rejected
  first="$(client_request "example.test" "/app/admit?sequence_key=admit&body_sequence=admitted%7Cadmitted%7Cshould-not-serve&status_sequence=200%7C200%7C500&cache_control=public-stale-error&content_type=text/plain" 200)"
  second="$(client_request "example.test" "/app/admit?sequence_key=admit&body_sequence=admitted%7Cadmitted%7Cshould-not-serve&status_sequence=200%7C200%7C500&cache_control=public-stale-error&content_type=text/plain" 200)"
  assert_response_jq "${first}" '.body == "admitted"'
  assert_response_jq "${second}" '.body == "admitted"'
  sleep 2
  stale="$(client_request "example.test" "/app/admit?sequence_key=admit&body_sequence=admitted%7Cadmitted%7Cshould-not-serve&status_sequence=200%7C200%7C500&cache_control=public-stale-error&content_type=text/plain" 200)"
  assert_response_jq "${stale}" '.body == "admitted"'

  rejected="$(client_request "example.test" "/app/reject-content-type?body=json&cache_control=public&content_type=application/json" 200)"
  assert_response_jq "${rejected}" '.body == "json"'
  docker rm -f "${http_container}" >/dev/null
  third="$(client_request "example.test" "/app/reject-content-type?body=json&cache_control=public&content_type=application/json" 502)"
  assert_response_jq "${third}" '.status == 502'
}
"#,
            None,
        ),
        docker_case(
            "cache",
            "collapsed-forwarding-metrics",
            "collapsed forwarding exposes waiter metrics for concurrent cache fills",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first_file second_file first second metrics
  first_file="${work_dir}/first-cache-fill.json"
  second_file="${work_dir}/second-cache-fill.json"
  client_request "example.test" "/app/collapse?body=collapsed&cache_control=public&content_type=text/plain&header_delay_ms=800" 200 >"${first_file}" &
  sleep 0.1
  client_request "example.test" "/app/collapse?body=collapsed&cache_control=public&content_type=text/plain&header_delay_ms=800" 200 >"${second_file}" &
  wait
  first="$(cat "${first_file}")"
  second="$(cat "${second_file}")"
  assert_response_jq "${first}" '.body == "collapsed"'
  assert_response_jq "${second}" '.body == "collapsed"'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_waiters_total 1")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_lock_timeouts_total 0")'
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
            "database-access-log",
            "system-postgres",
            "system-wide access logs use a separate PostgreSQL sink",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response count
  response="$(client_request_with_headers "example.test" "/app/system-db-log?case=postgres" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_body_jq "${response}" '.path == "/origin/app/system-db-log?case=postgres"'

  count="$(postgres_query "SELECT count(*) FROM oxibelt_access_log WHERE event = 'oxibelt.access' AND record->>'scope' = 'system' AND record->>'path' = '/app/system-db-log' AND record->>'status' = '200' AND record->>'route' = 'main-route' AND record->'user_agent'->'values' = '[\"first-agent\",\"second-agent\"]'::jsonb AND record->'user_agent'->>'is_truncated' = 'false';")"
  if [[ "${count}" != "1" ]]; then
    fail_with_diagnostics "expected one system PostgreSQL access log row preserving duplicate User-Agent values, got ${count}"
  fi
}
"#,
            None,
        ),
        docker_case(
            "database-mitigation",
            "managed-postgres",
            "OxiRule mitigation events aggregate into a managed PostgreSQL table",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            r#"
wait_for_managed_mitigation() {
  local status=""
  local count=""
  for _attempt in $(seq 1 30); do
    status="$(postgres_query "SELECT status FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
    count="$(postgres_query "SELECT count FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
    if [[ "${status}" == "pending" && "${count}" == "2" ]]; then
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "expected managed mitigation row to reach pending/count=2, got status=${status:-<empty>} count=${count:-<empty>}"
}

run_case_checks() {
  local first second row_count status count target_ip custom_path metrics
  first="$(client_request_with_headers "example.test" "/app/mitigate?case=one" 200 "GET" "" "X-Mitigation-Target: 203.0.113.80" "User-Agent: mitigation-one")"
  assert_body_jq "${first}" '.path == "/origin/app/mitigate?case=one"'

  second="$(client_request_with_headers "example.test" "/app/mitigate?case=two" 200 "GET" "" "X-Mitigation-Target: 203.0.113.80" "User-Agent: mitigation-two")"
  assert_body_jq "${second}" '.path == "/origin/app/mitigate?case=two"'

  wait_for_managed_mitigation

  row_count="$(postgres_query "SELECT count(*) FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  if [[ "${row_count}" != "1" ]]; then
    fail_with_diagnostics "expected one managed mitigation aggregate row, got ${row_count}"
  fi

  status="$(postgres_query "SELECT status FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  count="$(postgres_query "SELECT count FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  target_ip="$(postgres_query "SELECT host(target_ip) FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  custom_path="$(postgres_query "SELECT record->'custom'->>'path' FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  if [[ "${status}" != "pending" || "${count}" != "2" || "${target_ip}" != "203.0.113.80" || "${custom_path}" != "/app/mitigate" ]]; then
    fail_with_diagnostics "unexpected managed mitigation row status=${status} count=${count} target_ip=${target_ip} custom_path=${custom_path}"
  fi

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_mitigation_queued_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_mitigation_write_errors_total 0")'
}
"#,
            None,
        ),
        docker_case(
            "database-mitigation",
            "existing-postgres",
            "OxiRule mitigation events write to an existing minimal PostgreSQL table",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            r#"
wait_for_existing_mitigation() {
  local status=""
  local count=""
  for _attempt in $(seq 1 30); do
    status="$(postgres_query "SELECT status FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
    count="$(postgres_query "SELECT count FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
    if [[ "${status}" == "pending" && "${count}" == "1" ]]; then
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "expected existing mitigation row to reach pending/count=1, got status=${status:-<empty>} count=${count:-<empty>}"
}

run_case_checks() {
  local response row_count count status record_event record_target intent_columns
  response="$(client_request "example.test" "/app/existing-mitigation?case=minimal" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/existing-mitigation?case=minimal"'

  wait_for_existing_mitigation

  row_count="$(postgres_query "SELECT count(*) FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  count="$(postgres_query "SELECT count FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  status="$(postgres_query "SELECT status FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  record_event="$(postgres_query "SELECT record->>'event' FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  record_target="$(postgres_query "SELECT record->>'target' FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  intent_columns="$(postgres_query "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'existing_mitigation_events' AND column_name = 'intent';")"
  if [[ "${row_count}" != "1" || "${count}" != "1" || "${status}" != "pending" || "${record_event}" != "oxibelt.mitigation" || "${record_target}" != "198.51.100.44" || "${intent_columns}" != "0" ]]; then
    fail_with_diagnostics "unexpected existing mitigation row rows=${row_count} count=${count} status=${status} event=${record_event} target=${record_target} intent_columns=${intent_columns}"
  fi
}
"#,
            None,
        ),
        docker_case(
            "shared-state",
            "redis-valkey-cluster-state",
            "Redis/Valkey shared state coordinates two proxy instances",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                redis: true,
                second_proxy: true,
                ..Needs::default()
            },
            SHARED_STATE_REDIS_CHECKS,
            None,
        ),
        docker_case(
            "shared-state",
            "postgres-cluster-state",
            "PostgreSQL shared state coordinates representative cluster paths",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                postgres: true,
                second_proxy: true,
                ..Needs::default()
            },
            SHARED_STATE_POSTGRES_CHECKS,
            None,
        ),
        docker_case(
            "dynamic-policy",
            "postgres-snapshot",
            "PostgreSQL dynamic policy snapshot rejects and rate-limits without hot-path DB reads",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            DYNAMIC_POLICY_POSTGRES_CHECKS,
            None,
        ),
        docker_case(
            "dynamic-policy",
            "automation-api",
            "signed Admin dynamic policy automation API creates, imports, disables, and verifies rows",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            DYNAMIC_POLICY_AUTOMATION_API_CHECKS,
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
            "hot-reload",
            "telemetry-tracing-disable",
            "full hot reload rebuilds telemetry tracing and stops traceparent propagation when disabled",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response reloaded_response attempt

  response="$(client_request "example.test" "/app/telemetry-before" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/telemetry-before"'
  assert_body_jq "${response}" '.headers.traceparent | test("^00-[0-9a-f]{32}-[0-9a-f]{16}-01$")'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  reloaded_response=""
  for attempt in $(seq 1 30); do
    response="$(client_request "example.test" "/app/telemetry-after" 200)"
    if jq -e '.body | fromjson | .path == "/reloaded/app/telemetry-after"' <<<"${response}" >/dev/null; then
      reloaded_response="${response}"
      break
    fi
    sleep 1
  done
  if [[ -z "${reloaded_response}" ]]; then
    echo "${response}" >&2
    fail_with_diagnostics "new HTTPS request did not observe the reloaded telemetry-disabled snapshot"
  fi

  assert_body_jq "${reloaded_response}" '.headers.traceparent == null'
}
"#,
            None,
        ),
        docker_case(
            "hot-reload",
            "admin-listener-rebind",
            "full hot reload rebinds the admin listener and closes the old admin port",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/admin-rebind-before?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-rebind-before?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request "example.test" "/app/admin-rebind-after?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  response="$(plain_client_request_with_headers_on_port 9093 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-rebind-after?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'

  assert_old_admin_port_closed
}

assert_old_admin_port_closed() {
  local output=""
  local client_container="oxibelt-old-admin-client-${run_id}-${RANDOM}"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --scheme http \
    --path "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-rebind-after?cache_control=public" \
    --host "proxy" \
    --port 9092 \
    --method POST \
    --body "" \
    --dump-response-json \
    --expect-status 200 \
    --header "Authorization: Bearer matrix-admin-token" >/dev/null

  if output="$(docker start -a "${client_container}" 2>&1)"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    echo "${output}" >&2
    fail_with_diagnostics "old admin listener stayed reachable after rebind"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
}
"#,
            None,
        ),
        docker_case(
            "hot-reload",
            "graceful-http-drain",
            "full hot reload drains old HTTP/1 and HTTP/2 listener generations",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response h1_output h2_output

  start_holding_client_request_with_headers \
    "proxy" \
    8443 \
    "https" \
    "" \
    "example.test" \
    "/app/h1-drain?body=slow-h1&body_delay_ms=4500" \
    200 \
    0
  start_holding_h2_probe "/app/h2-drain?body=slow-h2&body_delay_ms=4500"

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request_on_port 9443 "example.test" "/app/after-reload" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/after-reload"'

  wait_holding_h2_probe
  h2_output="$(cat "${H2_HOLD_LOG}")"
  assert_response_jq "${h2_output}" '.negotiated_protocol == "h2" and .status == 200 and .body == "slow-h2"'

  wait_holding_client
  h1_output="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${h1_output}" '.status == 200 and .body == "slow-h1"'
}

start_holding_h2_probe() {
  local path="$1"
  H2_HOLD_CONTAINER="oxibelt-holding-h2-client-${run_id}-${RANDOM}"
  H2_HOLD_LOG="${logs_dir}/${H2_HOLD_CONTAINER}.log"
  docker create \
    --name "${H2_HOLD_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${protocol_probe_image}" \
    downstream \
    --protocol h2 \
    --host proxy \
    --port 8443 \
    --server-name proxy \
    --authority example.test \
    --path "${path}" \
    --ca-cert /tmp/proxy-ca.pem \
    --expect-status 200 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${H2_HOLD_CONTAINER}:/tmp/proxy-ca.pem"
  docker start -a "${H2_HOLD_CONTAINER}" >"${H2_HOLD_LOG}" 2>&1 &
  H2_HOLD_PID=$!
  sleep 1
}

wait_holding_h2_probe() {
  if ! wait "${H2_HOLD_PID}"; then
    cat "${H2_HOLD_LOG}" >&2 || true
    fail_with_diagnostics "holding HTTP/2 protocol probe failed"
  fi
  docker rm -f "${H2_HOLD_CONTAINER}" >/dev/null 2>&1 || true
}
"#,
            None,
        ),
        docker_case(
            "hot-reload",
            "graceful-upgrade-drain",
            "full hot reload protects upgraded connections during old listener drain",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response upgrade_output

  start_holding_upgrade_client_request_with_headers \
    "example.test" \
    "/app/upgrade-drain" \
    "matrixproto" \
    "drain-body" \
    101 \
    1500

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request_on_port 9443 "example.test" "/app/after-upgrade-reload" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/after-upgrade-reload"'

  wait_holding_client
  upgrade_output="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${upgrade_output}" '.status == 101 and .body == "upgraded:drain-body"'
}
"#,
            None,
        ),
        docker_case(
            "hot-reload",
            "webtransport-stale-snapshot-drain",
            "full hot reload rejects new WebTransport-connection requests on a stale snapshot",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                protocol_probe: true,
                webtransport_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  local reloaded_response=""
  local attempt

  start_webtransport_reload_probe

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  for attempt in $(seq 1 30); do
    response="$(protocol_probe_client h3 "example.test" "/app/reloaded-check" 200)"
    if jq -e '.body | fromjson | .upstream == "alt-upstream"' <<<"${response}" >/dev/null; then
      reloaded_response="${response}"
      break
    fi
    sleep 1
  done
  if [[ -z "${reloaded_response}" ]]; then
    echo "${response}" >&2
    fail_with_diagnostics "new HTTP/3 connection did not observe the reloaded snapshot"
  fi
  assert_body_jq "${reloaded_response}" '.upstream == "alt-upstream" and .path == "/alt/app/reloaded-check"'

  docker exec "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" touch /tmp/resume
  wait_webtransport_reload_probe
  response="$(cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}")"
  assert_response_jq "${response}" '.initial_webtransport_status == 200 and .drained_webtransport_status == 503 and .drained_http_status == 503'
}

start_webtransport_reload_probe() {
  WEBTRANSPORT_RELOAD_PROBE_CONTAINER="$(unique_docker_container_name "oxibelt-webtransport-reload-client")"
  WEBTRANSPORT_RELOAD_PROBE_LOG="${logs_dir}/${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}.log"
  docker create \
    --name "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${protocol_probe_image}" \
    webtransport-reload-gated \
    --host proxy \
    --port 8443 \
    --server-name proxy \
    --authority example.test \
    --path /wt/session \
    --http-path /app/stale-after-reload \
    --ca-cert /tmp/proxy-ca.pem \
    --first-ready-path /tmp/first-ready \
    --resume-path /tmp/resume \
    --expect-initial-status 200 \
    --expect-drained-status 503 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}:/tmp/proxy-ca.pem"
  docker start -a "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" >"${WEBTRANSPORT_RELOAD_PROBE_LOG}" 2>&1 &
  WEBTRANSPORT_RELOAD_PROBE_PID=$!

  for _attempt in $(seq 1 100); do
    if docker exec "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" test -f /tmp/first-ready >/dev/null 2>&1; then
      return
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" 2>/dev/null || true)" != "true" ]]; then
      cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}" >&2 || true
      fail_with_diagnostics "WebTransport reload probe exited before first session was ready"
    fi
    sleep 0.2
  done

  cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}" >&2 || true
  fail_with_diagnostics "WebTransport reload probe did not report first session readiness"
}

wait_webtransport_reload_probe() {
  if ! wait "${WEBTRANSPORT_RELOAD_PROBE_PID}"; then
    cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}" >&2 || true
    fail_with_diagnostics "WebTransport reload probe failed"
  fi
  docker rm -f "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" >/dev/null 2>&1 || true
}
"#,
            None,
        ),
        docker_case(
            "lifecycle",
            "admin-drain-readiness",
            "admin lifecycle drain flips readiness, rejects new requests, and preserves in-flight work",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response held_output

  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "ready"'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/live" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "live"'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${response}" '.draining == false and .reason == "ready"'

  start_holding_client_request_with_headers \
    "proxy" \
    8443 \
    "https" \
    "" \
    "example.test" \
    "/app/held?body=held-ok&body_delay_ms=3500" \
    200 \
    0

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle/drain" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_body_jq "${response}" '.ok == true'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${response}" '.draining == true and .reason == "admin"'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 503 "GET" "")"
  assert_response_jq "${response}" '.body == "draining"'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/live" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "live"'
  response="$(client_request_with_headers "example.test" "/app/rejected" 503 "GET" "")"
  assert_response_jq "${response}" '.body == "draining" and (.headers.connection | ascii_downcase) == "close"'

  wait_holding_client
  held_output="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${held_output}" '.status == 200 and .body == "held-ok"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle/undrain" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_body_jq "${response}" '.ok == true'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "ready"'
  response="$(client_request_with_headers "example.test" "/app/restored?body=restored" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "restored"'
}
"#,
            None,
        ),
        docker_case(
            "config-invalid",
            "no-http-versions",
            "listener validation rejects all downstream HTTP versions and SNI forwarding protocols disabled",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("at least one downstream HTTP version or SNI forwarding protocol must be enabled"),
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
            "accept-workers-without-reuseport",
            "multi-worker TCP accept requires SO_REUSEPORT",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("runtime.accept.reuse_port must be true"),
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
            "quic-receive-window-above-dynamic-cap",
            "QUIC receive window rejects values above the stream concurrency cap",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some(
                "quic.transport.receive_window_bytes must be at most 3072 based on quic.transport.stream_receive_window_bytes",
            ),
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
            "config-invalid",
            "crs-allowlist-header-selector",
            "CRS allowlists reject client-spoofable request header selectors",
            ExpectStart::Failure,
            Needs::default(),
            "",
            Some("header_equals is not supported because request headers are client-controlled"),
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
            "leading-dot-host-falls-back",
            "empty host labels do not match wildcard routes",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local valid leading_dot
  valid="$(client_request "api.example.test" "/app/valid-wildcard" 200)"
  assert_body_jq "${valid}" '.upstream == "http-upstream" and .path == "/origin/app/valid-wildcard"'

  leading_dot="$(client_request ".example.test" "/app/leading-dot" 200)"
  assert_body_jq "${leading_dot}" '.upstream == "alt-upstream" and .path == "/alt/app/leading-dot"'
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
            "proxy-headers",
            "security-response-headers",
            "configured response security headers are added to downstream responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/security-headers" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/security-headers"'
  assert_response_jq "${response}" '.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains; preload"'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == "nosniff"'
  assert_response_jq "${response}" '.headers["referrer-policy"] == "no-referrer"'
  assert_response_jq "${response}" '.headers["permissions-policy"] == "geolocation=(), camera=()"'
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
            "body-size-chunked",
            "request Body.Size rules reject chunked bodies without Content-Length",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(chunked_body_client_request "example.test" "/app/upload" 413 "POST" "123456789" "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body too large"'
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
            "rule-mode-hit-counters",
            "rule-level WAF modes expose per-rule hit telemetry only through admin",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response metrics admin
  response="$(client_request "example.test" "/app/shadow" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/shadow"'

  response="$(client_request "example.test" "/app/block" 451)"
  assert_response_jq "${response}" '.body == "blocked by rule"'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_requests_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_waf_rule_hits_total") | not'
  assert_response_jq "${metrics}" '.body | contains("rule_name") | not'
  assert_response_jq "${metrics}" '.body | contains("rule_id") | not'
  assert_response_jq "${metrics}" '.body | contains("shadow-path") | not'
  assert_response_jq "${metrics}" '.body | contains("block-path") | not'

  admin="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/rule-hits" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "global" and .route == null and .phase == "request" and .name == "shadow-path" and .id == "shadow-path" and .effective_mode == "monitor" and .hits == 1)] | length) == 1'
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "global" and .route == null and .phase == "request" and .name == "block-path" and .id == "block-path" and .effective_mode == "enforcing" and .hits == 1)] | length) == 1'
}
"#,
            None,
        ),
        docker_case(
            "waf-crs",
            "request-response-full",
            "CRS-compatible rules enforce request and response phases 1 through 4",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/phase1" 403 "GET" "" "User-Agent: phase1-probe")"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(split_body_client_request "example.test" "/app/phase2" 403 "POST" "prefix body-threat suffix" 10 100 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/encoding-safe?q=%E2%9C%93%20ok" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/encoding-safe?q=%E2%9C%93%20ok"'

  response="$(client_request "example.test" "/app/malformed-url?q=%ZZ" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/invalid-utf8?q=%C0%AF" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/phase3?content_type=text/crs-phase3&body=safe" 502)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/phase4?content_type=text/plain&body=prefix-secret-leak-suffix" 502)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'
}
"#,
            None,
        ),
        docker_case(
            "waf-crs",
            "monitor-first",
            "default CRS monitor mode allows traffic while recording hits and anomaly scores",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response admin compat metrics
  response="$(client_request "example.test" "/app/monitor?q=UNION%20SELECT" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/monitor?q=UNION%20SELECT"'

  response="$(client_request "example.test" "/app/leak?content_type=text/plain&body=secret-leak" 200)"
  assert_response_jq "${response}" '.body == "secret-leak"'

  admin="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/rule-hits" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "crs" and .phase == "request" and .id == "942100" and .effective_mode == "monitor" and .hits == 1 and .latest_inbound_anomaly_score == 5)] | length) == 1'
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "crs" and .phase == "response" and .id == "951100" and .effective_mode == "monitor" and .hits == 1 and .latest_outbound_anomaly_score == 4)] | length) == 1'

  compat="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/crs/compatibility" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${compat}" '([.release_lines[] | select(.name == "current" and .version == "v4.25.0")] | length) == 1'
  assert_body_jq "${compat}" '.supported.directives | index("SecRule") != null'
  assert_body_jq "${compat}" '.accepted_but_ignored.directives | index("SecRuleRemoveById") != null'
  assert_body_jq "${compat}" '.known_unsupported | any(contains("WebTransport"))'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_waf_rule_hits_total") | not'
  assert_response_jq "${metrics}" '.body | contains("942100") | not'
  assert_response_jq "${metrics}" '.body | contains("951100") | not'
}
"#,
            None,
        ),
        docker_case(
            "waf-request",
            "normalized-crs-request",
            "CRS transforms detect encoded traversal and SQLi request payloads",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/download?file=%2e%2e%2fetc%2fpasswd" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/search?q=UNION%20SELECT" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'
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
            "body-size-chunked",
            "response Body.Size rules reject chunked upstream bodies without Content-Length",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/chunked-response?body=123456789&chunked_response=1&body_split_at=4" 451)"
  assert_response_jq "${response}" '.body == "response body too large"'
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
            "waf-helpers",
            "response-body-scan",
            "bounded response body scan can reject matching upstream bodies",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/scan" 451)"
  assert_response_jq "${response}" '.body == "response body scan matched"'
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
            "waf-helpers",
            "body-streaming-scan",
            "bounded request body scan detects a pattern split across body frames",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(split_body_client_request "example.test" "/app/stream" 403 "POST" "prefix split-secret suffix" 11 100 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "streaming scan matched"'
}
"#,
            None,
        ),
        docker_case(
            "waf-helpers",
            "udf-body-object",
            "body object arguments passed into UDFs trigger request and response body inspection",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local request response
  request="$(client_request_with_headers "example.test" "/app/udf-request" 403 "POST" "prefix blocked suffix" "Content-Type: text/plain")"
  assert_response_jq "${request}" '.body == "udf request body blocked"'

  response="$(client_request "example.test" "/app/udf-response?body=prefix%20leak%20suffix" 451)"
  assert_response_jq "${response}" '.body == "udf response body blocked"'
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
            "sni-forwarding",
            "tcp-and-quic-passthrough",
            "SNI forwarding preserves local routes and forwards TCP TLS plus same-port QUIC",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                https_upstream: true,
                h3_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local local_tcp explicit_tcp default_tcp local_quic forwarded_quic metrics

  local_tcp="$(client_request_with_sni "example.test" "example.test" "/app/sni-local-tcp" 200)"
  assert_body_jq "${local_tcp}" '.upstream == "http-upstream"
    and .scheme == "http"
    and .path == "/origin/app/sni-local-tcp"'

  explicit_tcp="$(sni_forward_tls_request "sni-forward.test" "/tcp-explicit?case=sni" 200)"
  assert_body_jq "${explicit_tcp}" '.upstream == "https-upstream"
    and .scheme == "https"
    and .path == "/tcp-explicit?case=sni"
    and .headers.host == "sni-forward.test"'

  default_tcp="$(sni_forward_tls_request "sni-default.test" "/tcp-default?case=sni" 200)"
  assert_body_jq "${default_tcp}" '.upstream == "https-upstream"
    and .scheme == "https"
    and .path == "/tcp-default?case=sni"
    and .headers.host == "sni-default.test"'

  local_quic="$(protocol_probe_client_with_sni_and_ca "h3" "example.test" "example.test" "/app/sni-local-h3" 200 "${cert_dir}/fullchain.pem")"
  assert_response_jq "${local_quic}" '.negotiated_protocol == "h3"'
  assert_body_jq "${local_quic}" '.upstream == "http-upstream"
    and .path == "/origin/app/sni-local-h3"'

  forwarded_quic="$(protocol_probe_client_with_sni_and_ca "h3" "quic-forward.test" "quic-forward.test" "/quic-explicit?case=sni" 200 "${upstream_tls_dir}/ca.pem")"
  assert_response_jq "${forwarded_quic}" '.negotiated_protocol == "h3"'
  assert_body_jq "${forwarded_quic}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .path == "/quic-explicit?case=sni"'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_sni_forward_decisions_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_sni_forward_tcp_bytes_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_sni_forward_udp_bytes_total")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"tcp_tls\",decision=\"forward\",rule=\"tcp-explicit\",target=\"mock-https:18443\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"tcp_tls\",decision=\"forward\",rule=\"default\",target=\"mock-https:18443\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"tcp_tls\",decision=\"local\",rule=\"local_route\",target=\"local\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"quic\",decision=\"forward\",rule=\"quic-explicit\",target=\"mock-h3:18445\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"quic\",decision=\"local\",rule=\"local_route\",target=\"local\"")'
}
      "#,
            None,
        ),
        docker_case(
            "sni-forwarding",
            "resource-limits",
            "SNI forwarding bounds partial TLS and QUIC pre-classification resources",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                https_upstream: true,
                h3_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
quic_active_session_count() {
  local metrics="$1"
  jq -r '.body' <<<"${metrics}" | awk '$1 == "oxibelt_sni_forward_active_quic_sessions" { print int($2); found=1 } END { if (!found) print "-1" }'
}

start_partial_sni_client() {
  local client_container
  client_container="$(unique_docker_container_name "oxibelt-partial-sni-client")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c 'import socket, time; sock = socket.create_connection(("proxy", 8443), timeout=3); sock.sendall(bytes([0x16, 0x03, 0x01, 0xff, 0xff])); time.sleep(2); sock.close()' >/dev/null
  docker start "${client_container}" >/dev/null
  printf '%s' "${client_container}"
}

run_case_checks() {
  local partial_client local_tcp explicit_tcp local_quic forwarded_quic metrics active

  partial_client="$(start_partial_sni_client)"
  sleep 1

  local_tcp="$(client_request_with_sni "example.test" "example.test" "/app/resource-local-tcp" 200)"
  assert_body_jq "${local_tcp}" '.upstream == "http-upstream"
    and .scheme == "http"
    and .path == "/origin/app/resource-local-tcp"'

  explicit_tcp="$(sni_forward_tls_request "sni-forward.test" "/resource-tcp?case=limits" 200)"
  assert_body_jq "${explicit_tcp}" '.upstream == "https-upstream"
    and .scheme == "https"
    and .path == "/resource-tcp?case=limits"
    and .headers.host == "sni-forward.test"'

  local_quic="$(protocol_probe_client_with_sni_and_ca "h3" "example.test" "example.test" "/app/resource-local-h3" 200 "${cert_dir}/fullchain.pem")"
  assert_response_jq "${local_quic}" '.negotiated_protocol == "h3"'
  assert_body_jq "${local_quic}" '.upstream == "http-upstream"
    and .path == "/origin/app/resource-local-h3"'

  for attempt in one two three four; do
    forwarded_quic="$(protocol_probe_client_with_sni_and_ca "h3" "quic-forward.test" "quic-forward.test" "/resource-quic-${attempt}?case=limits" 200 "${upstream_tls_dir}/ca.pem")"
    assert_response_jq "${forwarded_quic}" '.negotiated_protocol == "h3"'
    assert_body_jq "${forwarded_quic}" '.upstream == "h3-upstream"
      and .scheme == "https"
      and .path == "/resource-quic-'"${attempt}"'?case=limits"'
  done

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  active="$(quic_active_session_count "${metrics}")"
  if [[ "${active}" -lt 0 || "${active}" -gt 2 ]]; then
    echo "unexpected active QUIC SNI forwarding sessions: ${active}" >&2
    fail_with_diagnostics "SNI forwarding QUIC sessions exceeded configured resource limit"
  fi

  docker rm -f "${partial_client}" >/dev/null 2>&1 || true
}
      "#,
            None,
        ),
        docker_case(
            "protocol-startup",
            "listener-reuseport-workers",
            "in-process SO_REUSEPORT accept workers start and forward",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/reuseport-workers" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/reuseport-workers"'
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
            "downstream-h2-adaptive-window-default",
            "downstream HTTP/2 uses the default adaptive flow-control window",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_client "h2" "example.test" "/app/downstream-h2-adaptive-window-default" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h2"'
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/downstream-h2-adaptive-window-default"
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
            "downstream-h2-upstream-h3-one-shot",
            "downstream HTTP/2 forwards ordinary HTTP/3 upstream requests without the H3 pool",
            ExpectStart::Success,
            Needs {
                h3_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local first second first_id second_id
  first="$(protocol_probe_client "h2" "example.test" "/app/one-shot-first" 200)"
  second="$(protocol_probe_client_with_headers "h2" "example.test" "/app/one-shot-post" 200 "POST" "one-shot-body")"
  assert_body_jq "${first}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/one-shot-first"'
  assert_body_jq "${second}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .method == "POST"
    and .path == "/h3-origin/app/one-shot-post"
    and .body == "one-shot-body"'
  first_id="$(jq -r '.body | fromjson | .connection_id' <<<"${first}")"
  second_id="$(jq -r '.body | fromjson | .connection_id' <<<"${second}")"
  if [[ "${first_id}" == "${second_id}" ]]; then
    echo "expected one-shot upstream H3 connection id to change; both requests used ${first_id}" >&2
    fail_with_diagnostics "one-shot upstream H3 reused the connection"
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
            "downstream-h3-bounded-receive-window",
            "downstream HTTP/3 forwards a request body with a bounded QUIC receive window",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                protocol_probe: true,
                ..Needs::default()
            },
            r#"
run_case_checks() {
  local response
  response="$(protocol_probe_generated_body_request "h3" "example.test" "/app/bounded-window" "POST" 65536 8192 --expect-status 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .method == "POST"
    and .path == "/origin/app/bounded-window"
    and (.body | length) == 65536'
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
