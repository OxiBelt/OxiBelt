
run_case_checks() {
  local response state attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/kube-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if jq -e '.body | fromjson | ([.servers[] | select(.source == "kubernetes" and (.origin | contains(":18080/")))] | length) == 1' <<<"${state}" >/dev/null; then
      response="$(client_request "kube.example.test" "/app/kubernetes-initial-${attempt}" 200)"
      if jq -e '.body | fromjson | .upstream == "http-upstream"' <<<"${response}" >/dev/null; then
        break
      fi
    fi
    sleep 0.5
  done
  if ! jq -e '.body | fromjson | .upstream == "http-upstream"' <<<"${response}" >/dev/null; then
    echo "${state}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "EndpointSlice initial list did not route to the HTTP upstream"
  fi

  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/kube-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if jq -e '.body | fromjson | ([.servers[] | select(.source == "kubernetes" and (.origin | contains(":18081/")))] | length) == 1' <<<"${state}" >/dev/null; then
      response="$(client_request "kube.example.test" "/app/kubernetes-watch-modified-${attempt}" 200)"
      if jq -e '.body | fromjson | .upstream == "alt-upstream"' <<<"${response}" >/dev/null; then
        break
      fi
    fi
    sleep 0.5
  done
  if ! jq -e '.body | fromjson | .upstream == "alt-upstream"' <<<"${response}" >/dev/null; then
    echo "${state}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "EndpointSlice watch modification did not route to the alternate upstream"
  fi

  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/kube-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if jq -e '.body | fromjson | ([.servers[] | select(.source == "kubernetes")] | length) == 0' <<<"${state}" >/dev/null; then
      response="$(client_request "kube.example.test" "/app/kubernetes-watch-deleted-${attempt}" 502)"
      break
    fi
    sleep 0.5
  done
  if ! jq -e '.body == "no available upstream pool server"' <<<"${response}" >/dev/null; then
    echo "${state}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "EndpointSlice watch deletion did not remove discovered upstreams"
  fi
}
