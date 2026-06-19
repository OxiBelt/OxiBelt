
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
