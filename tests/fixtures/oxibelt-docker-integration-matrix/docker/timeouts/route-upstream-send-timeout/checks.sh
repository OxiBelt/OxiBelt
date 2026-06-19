
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
