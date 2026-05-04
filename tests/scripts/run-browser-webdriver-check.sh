#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <chromium|firefox>" >&2
}

browser="${1:-}"
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
work_dir="$(mktemp -d "${runner_temp%/}/oxibelt-browser-${browser}.XXXXXX")"
tls_dir="${work_dir}/tls"
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
}

fail_with_diagnostics() {
  echo "$1" >&2
  show_diagnostics
  exit 1
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
            "moz:firefoxOptions": {
              binary: $binary,
              args: [
                "-headless"
              ]
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

mkdir -p "${tls_dir}"

"${browser_binary}" --version
"${driver_binary}" --version

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "${tls_dir}/privkey.pem" \
  -out "${tls_dir}/fullchain.pem" >/dev/null 2>&1
chmod 644 "${tls_dir}/privkey.pem" "${tls_dir}/fullchain.pem"

if [[ -n "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required when OXIBELT_DOCKER_IMAGE is set." >&2
    exit 1
  fi

  proxy_bind_addr="0.0.0.0"
  proxy_origin_host="host.docker.internal"
  cert_chain="/etc/oxibelt/tls/fullchain.pem"
  private_key="/etc/oxibelt/tls/privkey.pem"
else
  proxy_bind_addr="127.0.0.1"
  proxy_origin_host="127.0.0.1"
  cert_chain="tls/fullchain.pem"
  private_key="tls/privkey.pem"
fi

cat > "${work_dir}/oxibelt.toml" <<EOF
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

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
enabled = false
mode = "enforcing"
fail_policy = "closed"

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
  docker cp "${work_dir}/oxibelt.toml" "${proxy_container}:/etc/oxibelt/oxibelt.toml"
  docker cp "${tls_dir}/." "${proxy_container}:/etc/oxibelt/tls"
  docker start "${proxy_container}" >/dev/null
else
  host_triple="$(rustc -Vv | sed -n 's/^host: //p')"
  oxibelt_binary="${repo_root}/target/${host_triple}/release/oxibelt"
  if [[ ! -x "${oxibelt_binary}" ]]; then
    echo "Expected OxiBelt binary was not found: ${oxibelt_binary}" >&2
    find "${repo_root}/target" -path "*/release/oxibelt" -type f -print >&2 || true
    exit 1
  fi

  "${oxibelt_binary}" --config "${work_dir}/oxibelt.toml" >"${proxy_log}" 2>&1 &
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

test_url="https://localhost:${proxy_port}/app/webdriver?browser=${browser}"
curl --silent --show-error --fail-with-body \
  --header "Content-Type: application/json" \
  --request POST \
  --data "$(jq -n --arg url "${test_url}" '{url: $url}')" \
  "${driver_base_url}/session/${session_id}/url" >/dev/null

result="$(
  curl --silent --show-error --fail-with-body \
    --header "Content-Type: application/json" \
    --request POST \
    --data '{
      "script": "return document.body.innerText;",
      "args": []
    }' \
    "${driver_base_url}/session/${session_id}/execute/sync" | jq -r ".value"
)"

if ! jq -e \
  --arg browser "${browser}" \
  '.upstream == "browser-upstream"
    and .scheme == "http"
    and .method == "GET"
    and .path == ("/origin/app/webdriver?browser=" + $browser)
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "localhost"' <<<"${result}" >/dev/null; then
  echo "Unexpected ${browser} proxy response:" >&2
  echo "${result}" >&2
  show_diagnostics
  exit 1
fi

echo "${browser} WebDriver reached OxiBelt and received the expected proxied upstream response."
