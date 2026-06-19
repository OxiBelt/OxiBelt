
run_case_checks() {
  assert_redis_reload_generation
  assert_shared_rate_limit
  assert_redis_shared_rate_limit_bucket_cap
  assert_shared_person_proof
  assert_shared_pool_health
  assert_shared_cache_uri_isolation
  assert_shared_cache
}

assert_redis_reload_generation() {
  local keys
  keys="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli KEYS "matrix-shared:reload:instance:*"; else redis-cli KEYS "matrix-shared:reload:instance:*"; fi')"
  if ! grep -F 'matrix-shared:reload:instance:proxy-a' <<<"${keys}" >/dev/null ||
     ! grep -F 'matrix-shared:reload:instance:proxy-b' <<<"${keys}" >/dev/null; then
    echo "${keys}" >&2
    fail_with_diagnostics "expected reload heartbeat records for both proxy instances in Redis"
  fi
}

assert_shared_rate_limit() {
  local first second
  first="$(client_request_with_headers "example.test" "/app/rate" 200 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_body_jq "${first}" '.path == "/origin/app/rate"'

  second="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/rate" 429 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${second}" '.body == "rate limit exceeded"'
}

assert_redis_shared_rate_limit_bucket_cap() {
  local first second
  first="$(client_request_with_headers "example.test" "/app/redis-token-cap" 200 "GET" "" "X-Forwarded-For: 203.0.113.11" "X-Api-Token: redis-cap-token")"
  assert_body_jq "${first}" '.path == "/origin/app/redis-token-cap"'

  second="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/redis-token-cap" 429 "GET" "" "X-Forwarded-For: 203.0.113.12" "X-Api-Token: redis-cap-token-other")"
  assert_response_jq "${second}" '.body == "redis waf token bucket cap exceeded"'
}

assert_shared_person_proof() {
  local challenge cookie allowed replay keys
  challenge="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.20")"
  assert_response_jq "${challenge}" '.body | contains("person-proof")'

  keys="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli KEYS "matrix-shared:person-proof:reuse:challenge:*"; else redis-cli KEYS "matrix-shared:person-proof:reuse:challenge:*"; fi')"
  if [[ -n "${keys}" ]]; then
    echo "${keys}" >&2
    fail_with_diagnostics "challenge issuance should not reserve shared person-proof replay state in Redis"
  fi

  cookie="$(solve_person_proof_cookie "${challenge}")"

  allowed="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/proof" 200 "GET" "" "X-Forwarded-For: 203.0.113.21" "Cookie: ${cookie}")"
  assert_body_jq "${allowed}" '.path == "/origin/app/proof"'

  replay="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.22" "Cookie: ${cookie}")"
  assert_response_jq "${replay}" '.body | contains("person-proof")'
}

solve_person_proof_cookie() {
  local response="$1"
  local parsed session session_path verify_path difficulty nonce verify_body verify
  parsed="$(jq -r '.body' <<<"${response}" | python3 -c '
import hashlib
import re
import sys

body = sys.stdin.read()
session = re.search(r"name=\"oxibelt-person-proof-session\" content=\"([^\"]+)\"", body).group(1)
quote = chr(39)
session_path = re.search("const SessionPath = " + quote + "([^" + quote + "]+)" + quote, body).group(1)
verify_path = re.search("const VerifyPath = " + quote + "([^" + quote + "]+)" + quote, body).group(1)
difficulty = int(re.search(r"(\d+) leading zero bits", body).group(1))

def leading_zero_bits(data):
    total = 0
    for byte in hashlib.sha256(data).digest():
        if byte == 0:
            total += 8
        else:
            return total + 8 - byte.bit_length()
    return total

nonce = 0
while True:
    if leading_zero_bits(f"{session}.{nonce}".encode("utf-8")) >= difficulty:
        print(session)
        print(session_path)
        print(verify_path)
        print(nonce)
        break
    nonce += 1
')"
  session="$(sed -n '1p' <<<"${parsed}")"
  session_path="$(sed -n '2p' <<<"${parsed}")"
  verify_path="$(sed -n '3p' <<<"${parsed}")"
  nonce="$(sed -n '4p' <<<"${parsed}")"

  client_request_with_headers "example.test" "${session_path}?session=${session}" 200 "GET" "" "X-Forwarded-For: 203.0.113.23" >/dev/null
  verify_body="$(python3 -c 'import json, sys; print(json.dumps({"session": sys.argv[1], "response": {"token": sys.argv[2], "fields": {}}}))' "${session}" "${nonce}")"
  verify="$(client_request_with_headers "example.test" "${verify_path}" 200 "POST" "${verify_body}" "X-Forwarded-For: 203.0.113.24" "Content-Type: application/json")"
  jq -r '.headers["set-cookie"]' <<<"${verify}" | cut -d';' -f1
}

assert_shared_pool_health() {
  local attempt recovered state

  seed_shared_pool_alt_unhealthy
  for attempt in $(seq 1 10); do
    if shared_pool_alt_unhealthy_on_proxy_b; then
      break
    fi
    sleep 1
  done

  if ! shared_pool_alt_unhealthy_on_proxy_b; then
    state="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/upstream-pools/shared-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    echo "${state}" >&2
    fail_with_diagnostics "expected shared pool health to mark alt server unhealthy"
  fi

  recovered="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/pool/shared-health" 200 "GET" "" "X-Forwarded-For: 203.0.113.31")"
  assert_body_jq "${recovered}" '.upstream == "http-upstream" and .path == "/origin/pool/shared-health"'
}

seed_shared_pool_alt_unhealthy() {
  docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli SET "matrix-shared:pool:health:pool:shared-pool:0" "{\"healthy\":false,\"consecutive_successes\":0,\"consecutive_failures\":1}"; else redis-cli SET "matrix-shared:pool:health:pool:shared-pool:0" "{\"healthy\":false,\"consecutive_successes\":0,\"consecutive_failures\":1}"; fi' >/dev/null
}

shared_pool_alt_unhealthy_on_proxy_b() {
  local state
  state="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/upstream-pools/shared-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -e '.body | fromjson | ([.servers[] | select(.id == "0" and .healthy == false)] | length) == 1' <<<"${state}" >/dev/null
}

assert_shared_cache_uri_isolation() {
  local seed other
  seed="$(client_request_with_headers "example.test" "/cache-key/shared-uri?body=secret-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.35")"
  assert_response_jq "${seed}" '.body == "secret-cache"'

  other="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/cache-key/shared-uri?body=other-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.36")"
  assert_response_jq "${other}" '.body == "other-cache"'
}

assert_shared_cache() {
  local seed hit purge miss
  seed="$(client_request_with_headers "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.40")"
  assert_response_jq "${seed}" '.body == "shared-cache"'

  docker rm -f "${http_container}" >/dev/null

  hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 200 "GET" "" "X-Forwarded-For: 203.0.113.41")"
  assert_response_jq "${hit}" '.body == "shared-cache"'

  purge="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/shared-cache%3Fbody%3Dshared-cache%26cache_control%3Dpublic%26content_type%3Dtext/plain" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${purge}" '.body == "purged=2\n"'

  miss="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/shared-cache?body=shared-cache&cache_control=public&content_type=text/plain" 502,504 "GET" "" "X-Forwarded-For: 203.0.113.42")"
  assert_response_jq "${miss}" '.status == 502 or .status == 504'
}
