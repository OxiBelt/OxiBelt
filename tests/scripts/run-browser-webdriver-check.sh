#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <chromium|firefox> [basic-navigation|waf-request|waf-response|person-proof|hot-reload|webrtc-turn]" >&2
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
  basic-navigation|waf-request|waf-response|person-proof|hot-reload|webrtc-turn) ;;
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
turn_udp_port="${OXIBELT_BROWSER_TURN_UDP_PORT:-13478}"
turn_tcp_port="${OXIBELT_BROWSER_TURN_TCP_PORT:-13479}"
turn_tls_port="${OXIBELT_BROWSER_TURN_TLS_PORT:-15349}"
turn_relay_start="${OXIBELT_BROWSER_TURN_RELAY_START:-15000}"
turn_relay_end="${OXIBELT_BROWSER_TURN_RELAY_END:-15031}"
turn_v6_udp_port="${OXIBELT_BROWSER_TURN_V6_UDP_PORT:-23478}"
turn_v6_tcp_port="${OXIBELT_BROWSER_TURN_V6_TCP_PORT:-23479}"
turn_v6_tls_port="${OXIBELT_BROWSER_TURN_V6_TLS_PORT:-25349}"
turn_v6_relay_start="${OXIBELT_BROWSER_TURN_V6_RELAY_START:-25000}"
turn_v6_relay_end="${OXIBELT_BROWSER_TURN_V6_RELAY_END:-25031}"
session_id=""
driver_base_url=""
upstream_pid=""
proxy_pid=""
proxy_container=""
proxy_network=""
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

generate_test_ca() {
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 \
    -subj "/CN=OxiBelt WebDriver Test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${cert_dir}/ca-key.pem" \
    -out "${cert_dir}/ca.pem" >/dev/null 2>&1
  chmod 600 "${cert_dir}/ca-key.pem"
  chmod 644 "${cert_dir}/ca.pem"
}

generate_server_certificate() {
  openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:ip6-localhost,IP:127.0.0.1,IP:::1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "${cert_dir}/privkey.pem" \
    -out "${cert_dir}/localhost.csr" >/dev/null 2>&1
  openssl x509 -req -sha256 \
    -days 1 \
    -in "${cert_dir}/localhost.csr" \
    -CA "${cert_dir}/ca.pem" \
    -CAkey "${cert_dir}/ca-key.pem" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
  chmod 644 "${cert_dir}/privkey.pem" "${cert_dir}/fullchain.pem"
}

copy_server_tls_to_container() {
  docker cp \
    "${cert_dir}/fullchain.pem" \
    "${proxy_container}:/etc/oxibelt/cert/fullchain.pem"
  docker cp \
    "${cert_dir}/privkey.pem" \
    "${proxy_container}:/etc/oxibelt/cert/privkey.pem"
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

webdriver_set_script_timeout() {
  local timeout_ms="$1"

  curl --silent --show-error --fail-with-body \
    --header "Content-Type: application/json" \
    --request POST \
    --data "$(jq -n --argjson timeout_ms "${timeout_ms}" '{script: $timeout_ms}')" \
    "${driver_base_url}/session/${session_id}/timeouts" >/dev/null
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

create_webdriver_session() {
  local session_response=""

  if ! session_response="$(
    curl --silent --show-error --fail-with-body \
      --header "Content-Type: application/json" \
      --request POST \
      --data "${capabilities}" \
      "${driver_base_url}/session"
  )"; then
    echo "Unable to create ${browser} WebDriver session." >&2
    if [[ -n "${session_response}" ]]; then
      echo "${session_response}" >&2
    fi
    show_diagnostics
    exit 1
  fi

  session_id="$(jq -r '.value.sessionId // .sessionId // empty' <<<"${session_response}")"
  if [[ -z "${session_id}" ]]; then
    echo "Unable to create ${browser} WebDriver session." >&2
    echo "${session_response}" >&2
    show_diagnostics
    exit 1
  fi
}

delete_webdriver_session() {
  if [[ -n "${session_id}" && -n "${driver_base_url}" ]]; then
    curl --silent --show-error --fail-with-body \
      --request DELETE "${driver_base_url}/session/${session_id}" >/dev/null || true
    session_id=""
  fi
}

reload_proxy() {
  if [[ -n "${proxy_container}" ]]; then
    docker cp "${config_dir}/oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
    copy_server_tls_to_container
    docker kill --signal HUP "${proxy_container}" >/dev/null
  else
    kill -HUP "${proxy_pid}"
  fi
}

refresh_proxy_log() {
  if [[ -n "${proxy_container}" ]]; then
    docker logs "${proxy_container}" >"${proxy_log}" 2>&1 || true
  fi
}

hot_reload_applied_count() {
  refresh_proxy_log

  if [[ -s "${proxy_log}" ]]; then
    awk 'index($0, "hot reload applied") { count++ } END { print count + 0 }' "${proxy_log}"
  else
    echo 0
  fi
}

wait_for_hot_reload_applied() {
  local previous_count="$1"
  local current_count=""

  for _ in {1..30}; do
    current_count="$(hot_reload_applied_count)"
    if (( current_count > previous_count )); then
      return 0
    fi

    sleep 1
  done

  fail_with_diagnostics "OxiBelt hot reload did not apply."
}

cleanup() {
  delete_webdriver_session

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

  if [[ -n "${proxy_network}" ]]; then
    docker network rm "${proxy_network}" >/dev/null 2>&1 || true
  fi

  rm -rf "${work_dir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

webrtc_turn_scenario=false
if [[ "${scenario}" == "webrtc-turn" ]]; then
  webrtc_turn_scenario=true
fi

turn_tls_url="turns:127.0.0.1:${turn_tls_port}?transport=tcp"
turn_v6_udp_url="turn:[::1]:${turn_v6_udp_port}?transport=udp"
turn_v6_tcp_url="turn:[::1]:${turn_v6_tcp_port}?transport=tcp"
turn_v6_tls_url="turns:[::1]:${turn_v6_tls_port}?transport=tcp"
# Firefox rejects IP-literal TURNS endpoints before TLS (Bugzilla 2019255) and
# prefers IPv4 for localhost (Bugzilla 2020530). The IPv6-only alias and
# family-specific ports keep each case bound to its intended listener.
if [[ "${browser}" == "firefox" ]]; then
  turn_tls_url="turns:localhost:${turn_tls_port}?transport=tcp"
  turn_v6_udp_url="turn:ip6-localhost:${turn_v6_udp_port}?transport=udp"
  turn_v6_tcp_url="turn:ip6-localhost:${turn_v6_tcp_port}?transport=tcp"
  turn_v6_tls_url="turns:ip6-localhost:${turn_v6_tls_port}?transport=tcp"
fi

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
      jq -n \
        --arg binary "${browser_binary}" \
        --argjson webrtc_turn_scenario "${webrtc_turn_scenario}" \
        '{
        capabilities: {
          alwaysMatch: {
            browserName: "chrome",
            acceptInsecureCerts: true,
            pageLoadStrategy: "none",
            "goog:chromeOptions": {
              binary: $binary,
              args: ([
                  "--headless=new",
                  "--no-sandbox",
                  "--disable-dev-shm-usage"
                ] + if $webrtc_turn_scenario then
                  ["--allow-loopback-in-peer-connection"]
                else
                  []
                end)
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

generate_test_ca
generate_server_certificate

if [[ "${browser}" == "firefox" ]]; then
  firefox_profile=""
  if [[ "${scenario}" == "webrtc-turn" ]]; then
    for required_command in certutil zip base64 getent; do
      if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "${required_command} is required for the Firefox WebRTC TURN trust profile." >&2
        exit 1
      fi
    done

    if ! getent ahostsv6 ip6-localhost | awk '
      $1 == "::1" { found = 1; next }
      NF > 0 { unexpected = 1 }
      END { exit !(found && !unexpected) }
    '; then
      echo "ip6-localhost must resolve exclusively to ::1 for Firefox WebRTC TURN coverage." >&2
      exit 1
    fi

    firefox_profile_dir="${work_dir}/firefox-profile"
    mkdir -p "${firefox_profile_dir}"
    certutil -N --empty-password -d "sql:${firefox_profile_dir}"
    certutil -A \
      -d "sql:${firefox_profile_dir}" \
      -n "OxiBelt WebDriver Test CA" \
      -t "C,," \
      -i "${cert_dir}/ca.pem"
    firefox_profile="$(
      (
        cd -- "${firefox_profile_dir}"
        zip -q -r - .
      ) | base64 -w 0
    )"
  fi

  capabilities="$(
    jq -n \
      --arg binary "${browser_binary}" \
      --arg profile "${firefox_profile}" \
      --argjson webrtc_turn_scenario "${webrtc_turn_scenario}" \
      '{
      capabilities: {
        alwaysMatch: {
          browserName: "firefox",
          acceptInsecureCerts: (if $webrtc_turn_scenario then false else true end),
          pageLoadStrategy: "none",
          "moz:firefoxOptions": ({
            binary: $binary,
            args: [
              "-headless"
            ],
            prefs: ({
                "devtools.jsonview.enabled": false
              } + if $webrtc_turn_scenario then
                {"media.peerconnection.ice.loopback": true}
              else
                {}
              end)
          } + if $webrtc_turn_scenario then
            {profile: $profile}
          else
            {}
          end)
        }
      }
    }'
  )"
fi

if [[ -n "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required when OXIBELT_DOCKER_IMAGE is set." >&2
    exit 1
  fi

  proxy_bind_addr="0.0.0.0"
  turn_bind_addr="0.0.0.0"
  turn_v6_bind_addr="::"
  turn_v6_relay_bind_addr="0.0.0.0"
  proxy_origin_host="host.docker.internal"
  cert_chain="fullchain.pem"
  private_key="privkey.pem"
else
  proxy_bind_addr="127.0.0.1"
  turn_bind_addr="127.0.0.1"
  turn_v6_bind_addr="::1"
  turn_v6_relay_bind_addr="127.0.0.1"
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
person_proof_mode = "built_in"
difficulty = 4
token_validity_seconds = 60
clearance.cookie.key = "__webdriver_person_proof"
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
name = "person-proof-api-route"
hosts = ["localhost"]
path_prefix = "/.oxibelt"
upstream = "browser-upstream"

[[routes]]
name = "browser-route"
hosts = ["localhost"]
path_prefix = "/app"
upstream = "browser-upstream"
EOF

if [[ "${scenario}" == "webrtc-turn" ]]; then
  cat >> "${config_dir}/oxibelt.toml" <<EOF

[[webrtc_turn_listeners]]
name = "browser-turn-edge"
mode = "edge_relay"
bind_udp = "${turn_bind_addr}:${turn_udp_port}"
bind_tcp = "${turn_bind_addr}:${turn_tcp_port}"
bind_tls = "${turn_bind_addr}:${turn_tls_port}"
realm = "turn.localhost"
idle_timeout_ms = 30000

[[webrtc_turn_listeners.relay_families]]
family = "ipv4"
public_ip = "127.0.0.1"
relay_bind_ip = "${turn_bind_addr}"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = ${turn_relay_start}
end = ${turn_relay_end}

[webrtc_turn_listeners.peer_policy]
allow_loopback_peers = true

[webrtc_turn_listeners.auth]
mode = "enforce"
nonce_ttl_seconds = 60

[[webrtc_turn_listeners.auth.static_credentials]]
username = "browser-turn-user"
password = "browser-turn-password"

[[webrtc_turn_listeners]]
name = "browser-turn-control-v6"
mode = "edge_relay"
bind_udp = "[${turn_v6_bind_addr}]:${turn_v6_udp_port}"
bind_tcp = "[${turn_v6_bind_addr}]:${turn_v6_tcp_port}"
bind_tls = "[${turn_v6_bind_addr}]:${turn_v6_tls_port}"
realm = "turn.localhost"
idle_timeout_ms = 30000

[[webrtc_turn_listeners.relay_families]]
family = "ipv4"
public_ip = "127.0.0.1"
relay_bind_ip = "${turn_v6_relay_bind_addr}"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = ${turn_v6_relay_start}
end = ${turn_v6_relay_end}

[webrtc_turn_listeners.peer_policy]
allow_loopback_peers = true

[webrtc_turn_listeners.auth]
mode = "enforce"
nonce_ttl_seconds = 60

[[webrtc_turn_listeners.auth.static_credentials]]
username = "browser-turn-user"
password = "browser-turn-password"
EOF
fi

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
  if [[ "${scenario}" == "webrtc-turn" ]]; then
    proxy_network="oxibelt-browser-turn-${browser}-$(date +%s)-$$"
    docker network create \
      --ipv6 \
      --label "com.oxibelt.test.browser-webdriver=true" \
      "${proxy_network}" >/dev/null
  fi
  docker_create_args=(
    --name "${proxy_container}" \
    --add-host host.docker.internal:host-gateway \
    -p "127.0.0.1:${proxy_port}:${proxy_port}"
  )
  if [[ "${scenario}" == "webrtc-turn" ]]; then
    docker_create_args+=(
      --network "${proxy_network}"
      -p "127.0.0.1:${turn_udp_port}:${turn_udp_port}/udp"
      -p "127.0.0.1:${turn_tcp_port}:${turn_tcp_port}/tcp"
      -p "127.0.0.1:${turn_tls_port}:${turn_tls_port}/tcp"
      -p "127.0.0.1:${turn_relay_start}-${turn_relay_end}:${turn_relay_start}-${turn_relay_end}/udp"
      -p "[::1]:${turn_v6_udp_port}:${turn_v6_udp_port}/udp"
      -p "[::1]:${turn_v6_tcp_port}:${turn_v6_tcp_port}/tcp"
      -p "[::1]:${turn_v6_tls_port}:${turn_v6_tls_port}/tcp"
      -p "127.0.0.1:${turn_v6_relay_start}-${turn_v6_relay_end}:${turn_v6_relay_start}-${turn_v6_relay_end}/udp"
    )
  fi
  docker create "${docker_create_args[@]}" "${OXIBELT_DOCKER_IMAGE}" >/dev/null
  docker cp "${config_dir}/oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  copy_server_tls_to_container
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

create_webdriver_session

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
    reload_applied_count="$(hot_reload_applied_count)"
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
    generate_server_certificate
    reload_proxy
    wait_for_hot_reload_applied "${reload_applied_count}"

    delete_webdriver_session
    create_webdriver_session
    webdriver_navigate "${reload_url}"
    wait_for_body_contains "browser hot reloaded" "hot reload after" >/dev/null
    echo "${browser} WebDriver observed hot-reloaded config and TLS material."
    ;;
  webrtc-turn)
    test_url="https://localhost:${proxy_port}/app/webrtc-turn?browser=${browser}"
    webdriver_navigate "${test_url}"
    wait_for_upstream_json "/origin/app/webrtc-turn?browser=${browser}" "WebRTC TURN bootstrap" >/dev/null
    webdriver_set_script_timeout 150000

    turn_result="$(
      webdriver_execute_async \
        "const done = arguments[arguments.length - 1];
         const cases = [
           {url: 'turn:127.0.0.1:${turn_udp_port}?transport=udp', controlFamily: 'ipv4', relayFamily: 'ipv4'},
           {url: 'turn:127.0.0.1:${turn_tcp_port}?transport=tcp', controlFamily: 'ipv4', relayFamily: 'ipv4'},
           {url: '${turn_tls_url}', controlFamily: 'ipv4', relayFamily: 'ipv4'},
           {url: '${turn_v6_udp_url}', controlFamily: 'ipv6', relayFamily: 'ipv4'},
           {url: '${turn_v6_tcp_url}', controlFamily: 'ipv6', relayFamily: 'ipv4'},
           {url: '${turn_v6_tls_url}', controlFamily: 'ipv6', relayFamily: 'ipv4'}
         ];
         const run = async (testCase) => {
           const {url, controlFamily, relayFamily} = testCase;
           const configuration = {
             iceServers: [{urls: [url], username: 'browser-turn-user', credential: 'browser-turn-password'}],
             iceTransportPolicy: 'relay'
           };
           const left = new RTCPeerConnection(configuration);
           const right = new RTCPeerConnection(configuration);
           const relayCandidates = {left: 0, right: 0, expectedFamilyMatches: 0};
           const diagnostics = {
             iceCandidateErrors: [],
             candidateSummaries: {left: [], right: []}
           };
           let received = null;
           let opened = false;
           const close = () => { left.close(); right.close(); };
           const recordCandidate = (side, candidate) => {
             if (diagnostics.candidateSummaries[side].length >= 32) return;
             const fields = candidate.candidate.split(' ');
             const address = candidate.address || fields[4] || '';
             diagnostics.candidateSummaries[side].push({
               type: candidate.type || 'unknown',
               protocol: candidate.protocol || fields[2] || 'unknown',
               addressFamily: address === '' ? 'unknown' : (address.includes(':') ? 'ipv6' : 'ipv4')
             });
           };
           const recordCandidateError = (side, errorCode, errorText, errorUrl) => {
             if (diagnostics.iceCandidateErrors.length >= 16) return;
             diagnostics.iceCandidateErrors.push({
               side,
               errorCode,
               errorText,
               url: errorUrl
             });
           };
           left.onicecandidateerror = (event) => {
             recordCandidateError('left', event.errorCode || null, event.errorText || '', event.url || '');
           };
           right.onicecandidateerror = (event) => {
             recordCandidateError('right', event.errorCode || null, event.errorText || '', event.url || '');
           };
           left.onicecandidate = async (event) => {
             if (event.candidate) {
               recordCandidate('left', event.candidate);
               if (event.candidate.type === 'relay' || event.candidate.candidate.includes(' typ relay ')) {
                 relayCandidates.left += 1;
                 const address = event.candidate.address || event.candidate.candidate.split(' ')[4] || '';
                 if ((relayFamily === 'ipv6') === address.includes(':')) relayCandidates.expectedFamilyMatches += 1;
               }
               try {
                 await right.addIceCandidate(event.candidate);
               } catch (_) {
                 recordCandidateError('right', null, 'addIceCandidate failed', url);
               }
             }
           };
           right.onicecandidate = async (event) => {
             if (event.candidate) {
               recordCandidate('right', event.candidate);
               if (event.candidate.type === 'relay' || event.candidate.candidate.includes(' typ relay ')) {
                 relayCandidates.right += 1;
                 const address = event.candidate.address || event.candidate.candidate.split(' ')[4] || '';
                 if ((relayFamily === 'ipv6') === address.includes(':')) relayCandidates.expectedFamilyMatches += 1;
               }
               try {
                 await left.addIceCandidate(event.candidate);
               } catch (_) {
                 recordCandidateError('left', null, 'addIceCandidate failed', url);
               }
             }
           };
           right.ondatachannel = (event) => {
             event.channel.onmessage = (message) => { received = message.data; };
           };
           const channel = left.createDataChannel('oxibelt-turn');
           channel.onopen = () => { opened = true; channel.send('relayed-through-oxibelt'); };
           await left.setLocalDescription(await left.createOffer());
           await right.setRemoteDescription(left.localDescription);
           await right.setLocalDescription(await right.createAnswer());
           await left.setRemoteDescription(right.localDescription);
           const deadline = Date.now() + 20000;
           while (Date.now() < deadline && (left.iceGatheringState !== 'complete' || right.iceGatheringState !== 'complete')) {
             await new Promise((resolve) => setTimeout(resolve, 100));
           }
           while (Date.now() < deadline && received !== 'relayed-through-oxibelt') {
             await new Promise((resolve) => setTimeout(resolve, 100));
           }
           const states = {
             left: {
               iceGatheringState: left.iceGatheringState,
               iceConnectionState: left.iceConnectionState,
               connectionState: left.connectionState,
               signalingState: left.signalingState
             },
             right: {
               iceGatheringState: right.iceGatheringState,
               iceConnectionState: right.iceConnectionState,
               connectionState: right.connectionState,
               signalingState: right.signalingState
             }
           };
           const result = {url, controlFamily, relayFamily, opened, received, relayCandidates, states, diagnostics};
           close();
           if (!opened || received !== 'relayed-through-oxibelt' || relayCandidates.left < 1 || relayCandidates.right < 1 || relayCandidates.expectedFamilyMatches < 2) {
             throw new Error('relay-only data channel did not complete: ' + JSON.stringify(result));
           }
           return result;
         };
         (async () => {
           try {
             const results = [];
             for (const testCase of cases) results.push(await run(testCase));
             done({ok: true, results});
           } catch (error) {
             done({ok: false, error: String(error)});
           }
         })();"
    )"
    if ! jq -e \
      '.ok == true
        and (.results | length) == 6
        and ([.results[].controlFamily] | sort) == ["ipv4", "ipv4", "ipv4", "ipv6", "ipv6", "ipv6"]
        and all(.results[]; .opened == true
          and .received == "relayed-through-oxibelt"
          and .relayFamily == "ipv4"
          and .relayCandidates.left > 0
          and .relayCandidates.right > 0
          and .relayCandidates.expectedFamilyMatches > 1)' <<<"${turn_result}" >/dev/null; then
      echo "Expected ${browser} to establish IPv4 relay-only data channels over IPv4 and IPv6 TURN control endpoints:" >&2
      echo "${turn_result}" >&2
      show_diagnostics
      exit 1
    fi
    echo "${browser} WebDriver relayed WebRTC data over IPv4 and IPv6 OxiBelt TURN control endpoints."
    ;;
esac
