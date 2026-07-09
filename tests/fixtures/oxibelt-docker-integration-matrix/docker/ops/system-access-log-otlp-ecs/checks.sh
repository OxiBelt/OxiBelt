
run_case_checks() {
  local response logs otel_container
  otel_container="$(unique_docker_container_name "oxibelt-otlp")"
  docker run -d \
    --name "${otel_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-otel \
    -e LISTEN_PORT=18092 \
    -e CAPTURE_REQUESTS=1 \
    "${mock_image}" >/dev/null

  response="$(client_request_with_headers "example.test" "/app/system-log?case=otlp-ecs" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_body_jq "${response}" '.path == "/origin/app/system-log?case=otlp-ecs"'

  for _attempt in $(seq 1 30); do
    logs="$(docker logs "${otel_container}" 2>&1 || true)"
    if jq -R -s -e '
      [split("\n")[] | fromjson?]
      | any(.[]; .method == "POST"
        and .path == "/v1/logs"
        and .headers["content-type"] == "application/x-protobuf"
        and (.body_text | contains("service.name"))
        and (.body_text | contains("oxibelt-matrix"))
        and (.body_text | contains("ecs.version"))
        and (.body_text | contains("oxibelt.access_log.schema"))
        and (.body_text | contains("oxibelt.access.system"))
        and (.body_text | contains("\"oxibelt\""))
        and (.body_text | contains("\"original\""))
        and (.body_text | contains("first-agent"))
        and (.body_text | contains("second-agent")))
    ' <<<"${logs}" >/dev/null; then
      return
    fi
    sleep 1
  done

  echo "${logs}" >&2
  fail_with_diagnostics "expected ECS system access log OTLP record"
}
