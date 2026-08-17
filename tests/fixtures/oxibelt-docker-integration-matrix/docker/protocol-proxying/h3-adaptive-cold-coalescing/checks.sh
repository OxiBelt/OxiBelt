# shellcheck shell=bash
# shellcheck disable=SC2154 # Sourced by run-proxy-integration-matrix.sh.

run_case_checks() {
  local burst_dir dns_stats query_count a_query_count aaaa_query_count
  local connection_count failed metrics leader_count coalesced_count
  local index container
  local -a containers=()
  local -a pids=()
  burst_dir="${work_dir}/h3-cold-burst"
  mkdir -p "${burst_dir}"
  mock_dns_control RESET >/dev/null

  for index in $(seq 1 8); do
    container="$(unique_docker_container_name "oxibelt-h3-cold-client" "${index}")"
    docker create \
      --name "${container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      downstream \
      --protocol h2 \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority example.test \
      --path "/app/cold-${index}" \
      --ca-cert /tmp/probe-ca.pem \
      --expect-status 200 >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${container}:/tmp/probe-ca.pem"
    containers+=("${container}")
  done

  for index in "${!containers[@]}"; do
    docker_start_stdout_only "${containers[index]}" >"${burst_dir}/$((index + 1)).json" &
    pids+=("$!")
  done

  failed=0
  for index in "${!pids[@]}"; do
    if ! wait "${pids[index]}"; then
      append_container_stderr "${containers[index]}"
      failed=1
    fi
    docker rm -f "${containers[index]}" >/dev/null 2>&1 || true
  done

  dns_stats="$(mock_dns_control STATS | jq -c \
    '{query_count, a_query_count, aaaa_query_count}')"
  metrics="$(protocol_probe_http_get proxy 9090 /)"
  mkdir -p "${logs_dir}"
  printf '%s\n' "${dns_stats}" \
    >"${logs_dir}/h3-adaptive-cold-coalescing-dns-stats.json"
  awk '
    /^# (HELP|TYPE) oxibelt_http3_upstream_/ || /^oxibelt_http3_upstream_/ {
      print
      emitted += 1
      if (emitted >= 256) {
        exit
      }
    }
  ' <<<"${metrics}" \
    >"${logs_dir}/h3-adaptive-cold-coalescing-metrics.log"

  [[ "${failed}" -eq 0 ]] \
    || fail_with_diagnostics "one or more concurrent H3 cold-start probes failed"

  for index in $(seq 1 8); do
    jq -e \
      '.status == 200 and (.body | fromjson | .connection_id | type == "number")' \
      "${burst_dir}/${index}.json" >/dev/null \
      || fail_with_diagnostics "concurrent H3 cold-start probe ${index} returned incomplete output"
  done

  query_count="$(jq -er '.query_count | numbers' <<<"${dns_stats}")"
  a_query_count="$(jq -er '.a_query_count | numbers' <<<"${dns_stats}")"
  aaaa_query_count="$(jq -er '.aaaa_query_count | numbers' <<<"${dns_stats}")"
  [[ "${query_count}" -eq 2 && "${a_query_count}" -eq 1 && "${aaaa_query_count}" -eq 1 ]] \
    || fail_with_diagnostics "concurrent H3 cold start did not coalesce A/AAAA resolution"

  connection_count="$(jq -r '.body | fromjson | .connection_id' "${burst_dir}"/*.json | sort -u | wc -l)"
  [[ "${connection_count}" -eq 1 ]] \
    || fail_with_diagnostics "concurrent H3 cold start created more than one winning connection"

  leader_count="$(awk '$1 == "oxibelt_http3_upstream_pool_events_total{event=\"connect_leader\"}" { print $2 }' <<<"${metrics}")"
  coalesced_count="$(awk '$1 == "oxibelt_http3_upstream_pool_events_total{event=\"connect_coalesced\"}" { print $2 }' <<<"${metrics}")"
  [[ "${leader_count:-0}" -eq 1 ]] \
    || fail_with_diagnostics "concurrent H3 cold start created more than one pool leader"
  [[ "${coalesced_count:-0}" -ge 1 ]] \
    || fail_with_diagnostics "concurrent H3 cold start did not exercise connection coalescing"
}
