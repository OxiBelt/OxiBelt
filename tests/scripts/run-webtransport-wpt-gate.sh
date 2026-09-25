#!/usr/bin/env bash
# Run the complete pinned WPT WebTransport tree directly and through OxiBelt.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
run_id="wt-wpt-$(date +%s)-$$"
runner="${run_id}-runner"
proxy="${run_id}-proxy"
wpt_image="${OXIBELT_WEBTRANSPORT_WPT_IMAGE:-oxibelt/webtransport-wpt:ece2d7fdc436-git-prefs156}"
proxy_image="${OXIBELT_DOCKER_IMAGE:-}"
firefox_image="${OXIBELT_FIREFOX_WEBDRIVER_IMAGE:-oxibelt/firefox-webdriver:156.0-geckodriver-0.37.1}"
artifact_dir="${OXIBELT_TEST_ARTIFACT_DIR:-$(mktemp -d /tmp/oxibelt-webtransport-wpt-artifacts.XXXXXX)}"
work_dir="$(mktemp -d /tmp/oxibelt-webtransport-wpt.XXXXXX)"
created_wpt_image=false

if [[ -z "${proxy_image}" ]]; then
  echo 'OXIBELT_DOCKER_IMAGE must name a prebuilt OxiBelt image.' >&2
  exit 2
fi
mkdir -p "${artifact_dir}"
chmod 0777 "${artifact_dir}"

cleanup() {
  local status=$?
  if docker container inspect "${proxy}" >/dev/null 2>&1; then
    docker logs "${proxy}" >"${artifact_dir}/proxy.log" 2>&1 || true
  fi
  docker rm -fv "${proxy}" "${runner}" >/dev/null 2>&1 || true
  if [[ "${created_wpt_image}" == true ]]; then
    docker image rm "${wpt_image}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${work_dir}"
  echo "WPT WebTransport artifacts: ${artifact_dir}"
  exit "${status}"
}
trap cleanup EXIT

if ! docker image inspect "${wpt_image}" >/dev/null 2>&1; then
  docker image inspect "${firefox_image}" >/dev/null
  docker build \
    --build-arg "FIREFOX_IMAGE=${firefox_image}" \
    --tag "${wpt_image}" \
    "${repo_root}/tests/docker/webtransport_wpt"
  created_wpt_image=true
fi

docker create \
  --name "${runner}" \
  --label "oxibelt.test.run=${run_id}" \
  --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --shm-size 1g \
  --mount "type=bind,src=${artifact_dir},dst=/artifacts" \
  "${wpt_image}" >/dev/null
docker start "${runner}" >/dev/null

docker exec "${runner}" /bin/sh -c \
  'test "$(cat /opt/wpt/.source-revision)" = "ece2d7fdc436d4b9a3856877163b07ec15c05354"'
docker exec "${runner}" /opt/chrome/chrome --version \
  | grep --fixed-strings -- 'Google Chrome for Testing 154.0.8037.57'
docker exec "${runner}" /opt/firefox/firefox --version \
  | grep --fixed-strings -- 'Mozilla Firefox 156.0'
docker exec "${runner}" /bin/sh -c \
  'cd /opt/wpt/firefox-profiles && sha256sum --check --strict /opt/wpt/firefox-profiles.sha256'

run_wpt() {
  local browser="$1"
  local phase="$2"
  local binary webdriver
  local status=0
  case "${browser}" in
    chrome)
      binary=/opt/chrome/chrome
      webdriver=/opt/chromedriver/chromedriver
      ;;
    firefox)
      binary=/opt/firefox/firefox
      webdriver=/usr/local/bin/geckodriver
      ;;
  esac
  local args=(
    --binary "${binary}"
    --webdriver-binary "${webdriver}"
    --headless
    --enable-webtransport-h3
    --no-fail-on-unexpected
    --test-types testharness crashtest
    --log-wptreport="/artifacts/${browser}-${phase}.json"
    "${browser}" webtransport/
  )
  if [[ "${browser}" == chrome ]]; then
    args=(--binary-arg=--no-sandbox "${args[@]}")
  else
    args=(--channel stable --prefs-root=/opt/wpt/firefox-profiles "${args[@]}")
  fi
  echo "Running pinned WPT WebTransport: ${browser} ${phase}"
  timeout --signal=TERM 20m \
    docker exec --user 10002:10002 \
      --env HOME=/home/wpt \
      --workdir /opt/wpt \
      "${runner}" ./wpt run "${args[@]}" \
      >"${artifact_dir}/${browser}-${phase}.log" 2>&1 || status=$?
  printf '%s\n' "${status}" >"${artifact_dir}/${browser}-${phase}.exit"
  if ((status != 0)); then
    return "${status}"
  fi
  test -s "${artifact_dir}/${browser}-${phase}.json"
}

for browser in chrome firefox; do
  run_wpt "${browser}" direct
done

docker cp "${runner}:/opt/wpt/tools/certs/cacert.pem" "${work_dir}/cacert.pem"
docker cp "${runner}:/opt/wpt/tools/certs/web-platform.test.pem" "${work_dir}/server.pem"
docker cp "${runner}:/opt/wpt/tools/certs/web-platform.test.key" "${work_dir}/server.key"
ca_sha256="$(sha256sum "${work_dir}/cacert.pem")"
ca_sha256="${ca_sha256%% *}"
cat >"${work_dir}/oxibelt.toml" <<EOF
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
[runtime.accept]
workers = 1
reuse_port = false
backlog = 1024
accept_error_backoff_ms = 10
[listeners]
https_bind = "127.0.0.2:11000"
http1 = false
http2 = false
http3 = true
[quic.socket]
workers = 1
reuse_port = false
[tls]
cert_chain = "server.pem"
private_key = "server.key"
[tls.ocsp]
mode = "disabled"
[proxy]
trusted_ca_certs = ["cacert.pem"]
[proxy.auto_upgrade]
enabled = true
max_http_version = "h3"
[proxy.http2.webtransport]
max_total_buffer_bytes = 536870912
[proxy.http3]
webtransport_only_connections = true
[limits]
max_connections = 8192
max_connections_per_ip = 8192
max_webtransport_sessions = 8192
max_webtransport_sessions_per_ip = 8192
max_webtransport_sessions_per_connection = 256
[[upstreams]]
name = "wpt-h3"
origin = "https://127.0.0.1:11000"
max_http_version = "h3"
webtransport = true
preserve_host = true
[upstreams.tls]
server_name = "web-platform.test"
trust = "exclusive"
trusted_ca_certs = ["cacert.pem"]
trusted_ca_sha256 = ["${ca_sha256}"]
[upstreams.tls.ech]
mode = "disabled"
[[routes]]
name = "wpt-webtransport"
hosts = ["web-platform.test", "not-web-platform.test"]
path_prefix = "/webtransport/handlers"
upstream = "wpt-h3"
[routes.actions.cors]
allow_origins = ["https://web-platform.test:8443"]
allow_methods = ["CONNECT"]
EOF

docker create \
  --name "${proxy}" \
  --label "oxibelt.test.run=${run_id}" \
  --network "container:${runner}" \
  "${proxy_image}" >/dev/null
docker cp "${work_dir}/oxibelt.toml" "${proxy}:/etc/oxibelt/config/oxibelt.toml"
for file in cacert.pem server.pem server.key; do
  tar --create --file - --owner=10001 --group=10001 --mode=0440 \
    -C "${work_dir}" "${file}" \
    | docker cp -a - "${proxy}:/etc/oxibelt/cert/"
done
docker start "${proxy}" >/dev/null
sleep 2
if [[ "$(docker inspect --format '{{.State.Running}}' "${proxy}")" != true ]]; then
  echo 'OxiBelt WPT proxy exited during startup.' >&2
  exit 1
fi

# WPT deliberately resolves browser test domains to 127.0.0.1. The upstream
# server remains at 127.0.0.1:11000. Only packets from the browser/WPT user
# to the WebTransport UDP port are redirected to the proxy at 127.0.0.2.
# OxiBelt runs as UID 10001, so its upstream packets are never redirected.
proxy_nat_chain=OXIWPT
docker exec --user root "${runner}" /usr/sbin/iptables -t nat -N "${proxy_nat_chain}"
docker exec --user root "${runner}" \
  /usr/sbin/iptables -t nat -A "${proxy_nat_chain}" \
    -d 127.0.0.1/32 -p udp --dport 11000 \
    -j DNAT --to-destination 127.0.0.2:11000
docker exec --user root "${runner}" \
  /usr/sbin/iptables -t nat -A OUTPUT \
    -m owner --uid-owner 10002 \
    -d 127.0.0.1/32 -p udp --dport 11000 \
    -j "${proxy_nat_chain}"

proxy_nat_packets() {
  docker exec --user root "${runner}" \
    /usr/sbin/iptables -t nat -C OUTPUT \
      -m owner --uid-owner 10002 \
      -d 127.0.0.1/32 -p udp --dport 11000 \
      -j "${proxy_nat_chain}" || return 1
  docker exec --user root "${runner}" \
    /usr/sbin/iptables -t nat -C "${proxy_nat_chain}" \
      -d 127.0.0.1/32 -p udp --dport 11000 \
      -j DNAT --to-destination 127.0.0.2:11000 || return 1
  local packets
  packets="$(docker exec --user root "${runner}" \
    /usr/sbin/iptables -t nat -L "${proxy_nat_chain}" -v -n -x \
    | awk '$3 == "DNAT" { print $1 }')"
  [[ "${packets}" =~ ^[0-9]+$ ]] || {
    echo 'Could not read the WebTransport proxy DNAT packet counter.' >&2
    return 1
  }
  printf '%s\n' "${packets}"
}

for browser in chrome firefox; do
  packets_before="$(proxy_nat_packets)"
  run_wpt "${browser}" proxied
  packets_after="$(proxy_nat_packets)"
  if ((packets_after <= packets_before)); then
    echo "${browser}: no browser WebTransport packets reached the proxy DNAT rule." >&2
    exit 1
  fi
  python3 "${script_dir}/check-webtransport-wpt-report.py" \
    "${browser}" \
    "${artifact_dir}/${browser}-direct.json" \
    "${artifact_dir}/${browser}-proxied.json"
done
