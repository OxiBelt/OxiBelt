
run_case_checks() {
  local first_path second_path first_file second_file first second first_reason second_reason cached_path rejected_path cached miss
  first_path="/app/reserve-a?body_repeat=131072&body_repeat_char=A&cache_control=public&content_type=text/plain&body_delay_ms=5000"
  second_path="/app/reserve-b?body_repeat=131072&body_repeat_char=B&cache_control=public&content_type=text/plain"
  first_file="${work_dir}/reserve-first.json"
  second_file="${work_dir}/reserve-second.json"
  client_request "example.test" "${first_path}" 200 >"${first_file}" &
  sleep 1
  client_request "example.test" "${second_path}" 200 >"${second_file}" &
  wait
  first="$(cat "${first_file}")"
  second="$(cat "${second_file}")"
  assert_response_jq "${first}" '(.body | length) == 131072'
  assert_response_jq "${second}" '(.body | length) == 131072'
  first_reason="$(jq -r '.headers["x-oxibelt-cache-reason"]' <<<"${first}")"
  second_reason="$(jq -r '.headers["x-oxibelt-cache-reason"]' <<<"${second}")"
  if [[ "${first_reason}" == "stored" && "${second_reason}" == "admission_rejected" ]]; then
    cached_path="${first_path}"
    rejected_path="${second_path}"
  elif [[ "${first_reason}" == "admission_rejected" && "${second_reason}" == "stored" ]]; then
    cached_path="${second_path}"
    rejected_path="${first_path}"
  else
    echo "expected one stored and one admission_rejected response, got ${first_reason}/${second_reason}" >&2
    exit 1
  fi
  sleep 1
  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${cached_path}" 200)"
  assert_response_jq "${cached}" '(.body | length) == 131072'
  assert_response_jq "${cached}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'
  miss="$(client_request "example.test" "${rejected_path}" 502)"
  assert_response_jq "${miss}" '.status == 502'
}
