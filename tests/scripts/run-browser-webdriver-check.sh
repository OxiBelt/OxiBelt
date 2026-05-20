#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <chromium|firefox> [basic-navigation|waf-request|waf-response|person-proof|hot-reload]" >&2
}

browser="${1:-}"
scenario="${2:-person-proof}"
if [[ -z "${browser}" ]]; then
  usage
  exit 2
fi

case "${browser}" in
  chromium|firefox) ;;
  *)
    usage
    exit 2
    ;;
esac

case "${scenario}" in
  basic-navigation|waf-request|waf-response|person-proof|hot-reload) ;;
  *)
    usage
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
runner_temp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
upstream_port="${OXIBELT_BROWSER_UPSTREAM_PORT:-18080}"
proxy_port="${OXIBELT_BROWSER_PROXY_PORT:-18443}"
session_id=""
driver_base_url=""
upstream_pid=""
proxy_pid=""
proxy_container=""
driver_pid=""

if [[ -n "${CHROMEWEBDRIVER:-}" ]]; then
  export PATH="${CHROMEWEBDRIVER}:${PATH}"
fi

if [[ -n "${GECKOWEBDRIVER:-}" ]]; then
  export PATH="${GECKOWEBDRIVER}:${PATH}"
fi

mkdir -p "${runner_temp}"
work_dir="$(mktemp -d "${runner_temp%/}/oxibelt-browser-${browser}-${scenario}.XXXXXX")"
config_dir="${work_dir}/config"
cert_dir="${work_dir}/cert"
upstream_log="${work_dir}/mock-upstream.log"
proxy_log="${work_dir}/oxibelt.log"

find_first_command() {
  local candidate=""

  for candidate in "$@"; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      command -v "${candidate}"
      return 0
    fi
  done

  return 0
}

show_log() {
  local label="$1"
  local path="$2"

  if [[ -s "${path}" ]]; then
    echo "${label}:" >&2
    cat "${path}" >&2
  fi
}

show_diagnostics() {
  if [[ -n "${proxy_container}" ]]; then
    docker logs "${proxy_container}" >"${proxy_log}" 2>&1 || true
  fi

  show_log "Mock upstream log" "${upstream_log}"
  show_log "OxiBelt log" "${proxy_log}"
  show_log "Driver log" "${driver_log:-}"

  if [[ -n "${OXIBELT_TEST_ARTIFACT_DIR:-}" ]]; then
    mkdir -p "${OXIBELT_TEST_ARTIFACT_DIR}"
    cp "${upstream_log}" "${OXIBELT_TEST_ARTIFACT_DIR}/mock-upstream.log" 2>/dev/null || true
    cp "${proxy_log}" "${OXIBELT_TEST_ARTIFACT_DIR}/oxibelt.log" 2>/dev/null || true
    cp "${driver_log:-}" "${OXIBELT_TEST_ARTIFACT_DIR}/webdriver.log" 2>/dev/null || true
    cp "${config_dir}/oxibelt.toml" "${OXIBELT_TEST_ARTIFACT_DIR}/oxibelt.toml" 2>/dev/null || true
  fi
}

fail_with_diagnostics() {
  echo "$1" >&2
  show_diagnostics
  exit 1
}

webdriver_navigate() {
  local url="$1"

  curl --silent --show-error --fail-with-body \
    --header "Content-Type: application/json" \
    --request POST \
    --data "$(jq -n --arg url "${url}" '{url: $url}')" \
    "${driver_base_url}/session/${session_id}/url" >/dev/null
}

webdriver_execute_sync() {
  local script="$1"

  curl --silent --show-error --fail-with-body \
    --header "Content-Type: application/json" \
    --request POST \
    --data "$(jq -n --arg script "${script}" '{script: $script, args: []}')" \
    "${driver_base_url}/session/${session_id}/execute/sync" | jq -r ".value"
}

webdriver_execute_async() {
  local script="$1"

  curl --silent --show-error --fail-with-body \
    --header "Content-Type: application/json" \
    --request POST \
    --data "$(jq -n --arg script "${script}" '{script: $script, args: []}')" \
    "${driver_base_url}/session/${session_id}/execute/async" | jq -c ".value"
}

webdriver_body_text() {
  webdriver_execute_sync "return document.body.innerText;"
}

wait_for_body_contains() {
  local expected="$1"
  local label="$2"
  local body_text=""

  for _ in {1..30}; do
    if body_text="$(webdriver_body_text 2>/dev/null)"; then
      if grep -F "${expected}" <<<"${body_text}" >/dev/null; then
        echo "${body_text}"
        return 0
      fi
    fi

    sleep 1
  done

  echo "Unexpected ${browser} ${label} body:" >&2
  if [[ -n "${body_text}" ]]; then
    echo "${body_text}" >&2
  fi
  show_diagnostics
  exit 1
}

wait_for_upstream_json() {
  local expected_path="$1"
  local label="$2"
  local body_text=""

  for _ in {1..30}; do
    if body_text="$(webdriver_body_text 2>/dev/null)"; then
      if jq -e \
        --arg expected_path "${expected_path}" \
        '.upstream == "browser-upstream"
          and .scheme == "http"
          and .method == "GET"
          and .path == $expected_path
          and .headers["x-forwarded-proto"] == "https"
          and .headers["x-forwarded-host"] == "localhost"' <<<"${body_text}" >/dev/null 2>&1; then
        echo "${body_text}"
        return 0
      fi
    fi

    sleep 1
  done

  echo "Unexpected ${browser} ${label} response:" >&2
  if [[ -n "${body_text}" ]]; then
    echo "${body_text}" >&2
  fi
  show_diagnostics
  exit 1
}

webdriver_cookie() {
  local name="$1"

  curl --silent --show-error --fail-with-body \
    "${driver_base_url}/session/${session_id}/cookie/${name}"
}

reload_proxy() {
  if [[ -n "${proxy_container}" ]]; then
    docker cp "${config_dir}/oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
    docker cp "${cert_dir}/." "${proxy_container}:/etc/oxibelt/cert"
    docker kill --signal HUP "${proxy_container}" >/dev/null
  else
    kill -HUP "${proxy_pid}"
  fi
}

cleanup() {
  if [[ -n "${session_id}" && -n "${driver_base_url}" ]]; then
    curl --silent --show-error --fail-with-body \
      --request DELETE "${driver_base_url}/session/${session_id}" >/dev/null || true
  fi

  if [[ -n "${proxy_pid}" ]]; then
    kill "${proxy_pid}" >/dev/null 2>&1 || true
    wait "${proxy_pid}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${upstream_pid}" ]]; then
    kill "${upstream_pid}" >/dev/null 2>&1 || true
    wait "${upstream_pid}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${driver_pid}" ]]; then
    kill "${driver_pid}" >/dev/null 2>&1 || true
    wait "${driver_pid}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${proxy_container}" ]]; then
    docker rm -f "${proxy_container}" >/dev/null 2>&1 || true
  fi

  rm -rf "${work_dir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

case "${browser}" in
  chromium)
    browser_binary="$(
      find_first_command \
        "${BROWSER_COMMAND:-chromium}" \
        chromium-browser \
        chromium
    )"
    driver_binary="$(find_first_command "${DRIVER_COMMAND:-chromedriver}" chromedriver)"
    driver_port="${DRIVER_PORT:-9515}"
    driver_log="${work_dir}/chromedriver.log"
    capabilities="$(
      jq -n --arg binary "${browser_binary}" '{
        capabilities: {
          alwaysMatch: {
            browserName: "chrome",
            acceptInsecureCerts: true,
            pageLoadStrategy: "none",
            "goog:chromeOptions": {
              binary: $binary,
              args: [
                "--headless=new",
                "--no-sandbox",
                "--disable-dev-shm-usage"
              ]
            }
          }
        }
      }'
    )"
    ;;
  firefox)
    browser_binary="$(find_first_command "${BROWSER_COMMAND:-firefox}" firefox)"
    driver_binary="$(find_first_command "${DRIVER_COMMAND:-geckodriver}" geckodriver)"
    driver_port="${DRIVER_PORT:-4444}"
    driver_log="${work_dir}/geckodriver.log"
    capabilities="$(
      jq -n --arg binary "${browser_binary}" '{
        capabilities: {
          alwaysMatch: {
            browserName: "firefox",
            acceptInsecureCerts: true,
            pageLoadStrategy: "none",
            "moz:firefoxOptions": {
              binary: $binary,
              args: [
                "-headless"
              ],
              prefs: {
                "devtools.jsonview.enabled": false
              }
            }
          }
        }
      }'
    )"
    ;;
esac

if [[ -z "${browser_binary}" ]]; then
  echo "Unable to find ${browser} browser binary." >&2
  exit 1
fi

if [[ -z "${driver_binary}" ]]; then
  echo "Unable to find ${browser} WebDriver binary." >&2
  exit 1
fi

driver_base_url="http://127.0.0.1:${driver_port}"

mkdir -p "${config_dir}" "${cert_dir}"

"${browser_binary}" --version
"${driver_binary}" --version

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "${cert_dir}/privkey.pem" \
  -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
chmod 644 "${cert_dir}/privkey.pem" "${cert_dir}/fullchain.pem"

if [[ -n "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required when OXIBELT_DOCKER_IMAGE is set." >&2
    exit 1
  fi

  proxy_bind_addr="0.0.0.0"
  proxy_origin_host="host.docker.internal"
  cert_chain="fullchain.pem"
  private_key="privkey.pem"
else
  proxy_bind_addr="127.0.0.1"
  proxy_origin_host="127.0.0.1"
  cert_chain="fullchain.pem"
  private_key="privkey.pem"
fi

hot_reload_mode="off"
if [[ "${scenario}" == "hot-reload" ]]; then
  hot_reload_mode="full"
fi

cat > "${config_dir}/oxibelt.toml" <<EOF
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true

[runtime.hot_reload]
mode = "${hot_reload_mode}"
poll_interval_ms = 2000

[listeners]
https_bind = "${proxy_bind_addr}:${proxy_port}"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "${cert_chain}"
private_key = "${private_key}"

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

[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "browser-person-proof"
phase = "request"
priority = 10
when = "Request.Http.Path.startsWith('/app/person-proof') && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__webdriver_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 32
single_use = true
success_tag = "PersonProof"

[[waf.rules]]
name = "browser-request-block"
phase = "request"
priority = 20
when = "Request.Http.Path.endsWith('/browser-blocked')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "browser request blocked"

[[waf.rules]]
name = "browser-response-header"
phase = "response"
priority = 30
when = "Request.Http.Path.endsWith('/browser-header')"

[[waf.rules.actions]]
type = "set_response_header"
name = "X-Browser-Waf"
value = "set"

[[waf.rules]]
name = "browser-response-replace"
phase = "response"
priority = 40
when = "Request.Http.Path.endsWith('/browser-replace')"

[[waf.rules.actions]]
type = "replace_response"
status = 202
body = "browser response replaced"

[[waf.rules]]
name = "browser-hot-reload"
phase = "request"
priority = 50
when = "false"

[[waf.rules.actions]]
type = "reject"
status = 409
body = "browser hot reloaded"

[[upstreams]]
name = "browser-upstream"
origin = "http://${proxy_origin_host}:${upstream_port}/origin"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "disabled"

[[routes]]
name = "browser-route"
hosts = ["localhost"]
path_prefix = "/app"
upstream = "browser-upstream"
EOF

LISTEN_PORT="${upstream_port}" \
  UPSTREAM_NAME="browser-upstream" \
  python3 "${repo_root}/tests/docker/mock_upstream/server.py" >"${upstream_log}" 2>&1 &
upstream_pid="$!"

for _ in {1..30}; do
  if curl --silent --fail "http://127.0.0.1:${upstream_port}/ready" >/dev/null; then
    break
  fi
  sleep 1
done
if ! curl --silent --fail "http://127.0.0.1:${upstream_port}/ready" >/dev/null; then
  fail_with_diagnostics "Mock upstream did not become ready."
fi

if [[ -n "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  proxy_container="oxibelt-browser-proxy-${browser}-$(date +%s)-$$"
  docker create \
    --name "${proxy_container}" \
    --add-host host.docker.internal:host-gateway \
    -p "127.0.0.1:${proxy_port}:${proxy_port}" \
    "${OXIBELT_DOCKER_IMAGE}" >/dev/null
  docker cp "${config_dir}/oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  docker cp "${cert_dir}/." "${proxy_container}:/etc/oxibelt/cert"
  docker start "${proxy_container}" >/dev/null
else
  host_triple="$(rustc -Vv | sed -n 's/^host: //p')"
  oxibelt_binary="${repo_root}/target/${host_triple}/release/oxibelt"
  if [[ ! -x "${oxibelt_binary}" ]]; then
    echo "Expected OxiBelt binary was not found: ${oxibelt_binary}" >&2
    find "${repo_root}/target" -path "*/release/oxibelt" -type f -print >&2 || true
    exit 1
  fi

  "${oxibelt_binary}" --config "${config_dir}/oxibelt.toml" >"${proxy_log}" 2>&1 &
  proxy_pid="$!"
fi

for _ in {1..30}; do
  if curl --silent --fail --insecure "https://localhost:${proxy_port}/app/preflight" >/dev/null; then
    break
  fi
  sleep 1
done
if ! curl --silent --fail --insecure "https://localhost:${proxy_port}/app/preflight" >/dev/null; then
  if [[ -n "${proxy_container}" ]]; then
    docker logs "${proxy_container}" >"${proxy_log}" 2>&1 || true
  fi
  fail_with_diagnostics "OxiBelt proxy did not become ready."
fi

case "${browser}" in
  chromium)
    "${driver_binary}" --port="${driver_port}" >"${driver_log}" 2>&1 &
    ;;
  firefox)
    "${driver_binary}" --port "${driver_port}" >"${driver_log}" 2>&1 &
    ;;
esac
driver_pid="$!"

for _ in {1..30}; do
  if curl --silent --fail "${driver_base_url}/status" >/dev/null; then
    break
  fi
  sleep 1
done
if ! curl --silent --show-error --fail-with-body "${driver_base_url}/status" >/dev/null; then
  fail_with_diagnostics "${driver_binary} did not become ready."
fi

session_response="$(
  curl --silent --show-error --fail-with-body \
    --header "Content-Type: application/json" \
    --request POST \
    --data "${capabilities}" \
    "${driver_base_url}/session"
)"
session_id="$(jq -r '.value.sessionId // .sessionId // empty' <<<"${session_response}")"

if [[ -z "${session_id}" ]]; then
  echo "Unable to create ${browser} WebDriver session." >&2
  echo "${session_response}" >&2
  show_diagnostics
  exit 1
fi

case "${scenario}" in
  basic-navigation)
    test_url="https://localhost:${proxy_port}/app/webdriver?browser=${browser}"
    webdriver_navigate "${test_url}"
    wait_for_upstream_json "/origin/app/webdriver?browser=${browser}" "proxy" >/dev/null
    echo "${browser} WebDriver basic navigation reached OxiBelt."
    ;;
  waf-request)
    blocked_url="https://localhost:${proxy_port}/app/browser-blocked?browser=${browser}"
    webdriver_navigate "${blocked_url}"
    wait_for_body_contains "browser request blocked" "request WAF block" >/dev/null
    echo "${browser} WebDriver observed a request-phase WAF block."
    ;;
  waf-response)
    replace_url="https://localhost:${proxy_port}/app/browser-replace?browser=${browser}"
    webdriver_navigate "${replace_url}"
    wait_for_body_contains "browser response replaced" "response WAF replacement" >/dev/null

    header_result="$(
      webdriver_execute_async \
        "const done = arguments[arguments.length - 1]; fetch('/app/browser-header?browser=${browser}', {cache: 'no-store'}).then((response) => done({status: response.status, header: response.headers.get('x-browser-waf')})).catch((error) => done({error: String(error)}));"
    )"
    if ! jq -e '.status == 200 and .header == "set"' <<<"${header_result}" >/dev/null; then
      echo "Expected ${browser} fetch to see response WAF header:" >&2
      echo "${header_result}" >&2
      show_diagnostics
      exit 1
    fi
    echo "${browser} WebDriver observed response-phase WAF behavior."
    ;;
  person-proof)
    protected_url="https://localhost:${proxy_port}/app/person-proof?browser=${browser}"
    webdriver_navigate "${protected_url}"
    protected_result="$(
      wait_for_upstream_json \
        "/origin/app/person-proof?browser=${browser}" \
        "person proof challenge"
    )"

    if ! jq -e \
      '.headers.cookie | contains("__webdriver_person_proof=clearance.v2.")' <<<"${protected_result}" >/dev/null; then
      echo "Expected ${browser} person proof request to submit an API-issued clearance cookie:" >&2
      echo "${protected_result}" >&2
      show_diagnostics
      exit 1
    fi

    clearance_cookie="$(webdriver_cookie "__webdriver_person_proof")"
    if ! jq -e \
      '.value.name == "__webdriver_person_proof"
        and (.value.value | startswith("clearance.v2."))
        and .value.secure == true' <<<"${clearance_cookie}" >/dev/null; then
      echo "Expected ${browser} to receive a secure person proof clearance cookie:" >&2
      echo "${clearance_cookie}" >&2
      show_diagnostics
      exit 1
    fi

    clearance_url="https://localhost:${proxy_port}/app/person-proof/clearance?browser=${browser}"
    webdriver_navigate "${clearance_url}"
    clearance_result="$(
      wait_for_upstream_json \
        "/origin/app/person-proof/clearance?browser=${browser}" \
        "person proof clearance"
    )"

    if ! jq -e \
      '.headers.cookie | contains("__webdriver_person_proof=clearance.v2.")' <<<"${clearance_result}" >/dev/null; then
      echo "Expected ${browser} person proof clearance request to reuse the clearance cookie:" >&2
      echo "${clearance_result}" >&2
      show_diagnostics
      exit 1
    fi

    echo "${browser} WebDriver solved the person proof challenge and reused the clearance cookie."
    ;;
  hot-reload)
    reload_url="https://localhost:${proxy_port}/app/hot-reload?browser=${browser}"
    webdriver_navigate "${reload_url}"
    wait_for_upstream_json "/origin/app/hot-reload?browser=${browser}" "hot reload before" >/dev/null

    python3 - "${config_dir}/oxibelt.toml" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace('when = "false"', "when = \"Request.Http.Path.endsWith('/hot-reload')\"")
path.write_text(text)
PY
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
      -days 1 \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      -keyout "${cert_dir}/privkey.pem" \
      -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
    chmod 644 "${cert_dir}/privkey.pem" "${cert_dir}/fullchain.pem"
    reload_proxy

    webdriver_navigate "${reload_url}"
    wait_for_body_contains "browser hot reloaded" "hot reload after" >/dev/null
    echo "${browser} WebDriver observed hot-reloaded config and TLS material."
    ;;
esac
