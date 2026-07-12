
run_case_checks() {
  assert_redis_reload_generation
  assert_shared_rate_limit
  assert_redis_shared_rate_limit_bucket_cap
  assert_shared_person_proof
  assert_shared_person_proof_admin_pages
  assert_shared_person_proof_admin_revocation
  assert_shared_pool_health
  assert_shared_cache_uri_isolation
  assert_shared_cache
  assert_no_redis_keys_commands
}

assert_no_redis_keys_commands() {
  local commandstats
  commandstats="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli INFO commandstats; else redis-cli INFO commandstats; fi')"
  if grep -Eq '^cmdstat_keys:calls=[1-9]' <<<"${commandstats}"; then
    echo "${commandstats}" >&2
    fail_with_diagnostics "OxiBelt shared-state fixture must not issue Redis KEYS"
  fi
}

assert_redis_reload_generation() {
  local keys
  keys="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli --scan --pattern "matrix-shared:reload:instance:*"; else redis-cli --scan --pattern "matrix-shared:reload:instance:*"; fi')"
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

  keys="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli --scan --pattern "matrix-shared:person-proof:reuse:challenge:*"; else redis-cli --scan --pattern "matrix-shared:person-proof:reuse:challenge:*"; fi')"
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

assert_shared_person_proof_admin_pages() {
  local first_challenge second_challenge first_page second_page first_cursor first_hash second_hash
  first_challenge="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.25")"
  solve_person_proof_cookie "${first_challenge}" "203.0.113.27" "203.0.113.28" >/dev/null
  second_challenge="$(client_request_with_headers "example.test" "/app/proof" 403 "GET" "" "X-Forwarded-For: 203.0.113.26")"
  solve_person_proof_cookie "${second_challenge}" "203.0.113.29" "203.0.113.30" >/dev/null

  first_page="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/waf/person-proof/clearances?limit=1" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_body_jq "${first_page}" '(.clearances | length) == 1 and (.pagination.next_cursor | type == "string") and (.clearances[0].clearance_hash | test("^clearance:[0-9a-f]{64}$"))'
  first_cursor="$(jq -r '.body | fromjson | .pagination.next_cursor' <<<"${first_page}")"
  second_page="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/waf/person-proof/clearances?limit=1&cursor=${first_cursor}" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_body_jq "${second_page}" '(.clearances | length) == 1 and (.clearances[0].clearance_hash | test("^clearance:[0-9a-f]{64}$"))'
  first_hash="$(jq -r '.body | fromjson | .clearances[0].clearance_hash' <<<"${first_page}")"
  second_hash="$(jq -r '.body | fromjson | .clearances[0].clearance_hash' <<<"${second_page}")"
  if [[ "${first_hash}" == "${second_hash}" ]]; then
    echo "${first_page}" >&2
    echo "${second_page}" >&2
    fail_with_diagnostics "person-proof clearance pagination returned a duplicate instead of the next shared marker"
  fi
}

assert_shared_person_proof_admin_revocation() {
  local page clearance_hash hash revoke_body first replay conflict tombstone active idempotency_count
  page="$(plain_client_request_with_headers_to_target "proxy-a" 9092 "proxy-a" "/admin/v1/waf/person-proof/clearances?limit=1" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  clearance_hash="$(jq -r '.body | fromjson | .clearances[0].clearance_hash' <<<"${page}")"
  hash="${clearance_hash#clearance:}"
  if [[ ! "${hash}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "${page}" >&2
    fail_with_diagnostics "expected a canonical Person proof clearance hash before revocation"
  fi
  revoke_body="$(python3 -c 'import json, sys; print(json.dumps({"clearance_hash": sys.argv[1], "ttl_seconds": 60}))' "${clearance_hash}")"
  first="$(plain_client_request_with_headers_to_target "proxy-a" 9092 "proxy-a" "/admin/v1/waf/person-proof/clearances/revoke" 200 "POST" "${revoke_body}" "Authorization: Bearer matrix-admin-token" "Content-Type: application/json" "Idempotency-Key: matrix-person-proof-revoke")"
  replay="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/waf/person-proof/clearances/revoke" 200 "POST" "${revoke_body}" "Authorization: Bearer matrix-admin-token" "Content-Type: application/json" "Idempotency-Key: matrix-person-proof-revoke")"
  assert_body_jq "${first}" '.revoked == true and .removed_active == true and (.expires_at_unix_ms | type == "number")'
  if [[ "$(jq -cS '.body | fromjson' <<<"${first}")" != "$(jq -cS '.body | fromjson' <<<"${replay}")" ]]; then
    echo "${first}" >&2
    echo "${replay}" >&2
    fail_with_diagnostics "same Person proof idempotency key must replay the original response across proxies"
  fi
  conflict="$(plain_client_request_with_headers_to_target "proxy-b" 9092 "proxy-b" "/admin/v1/waf/person-proof/clearances/revoke" 409 "POST" "$(python3 -c 'import json, sys; print(json.dumps({"clearance_hash": sys.argv[1], "ttl_seconds": 61}))' "${clearance_hash}")" "Authorization: Bearer matrix-admin-token" "Content-Type: application/json" "Idempotency-Key: matrix-person-proof-revoke")"
  assert_response_jq "${conflict}" '.status == 409'
  tombstone="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli EXISTS "$1"; else redis-cli EXISTS "$1"; fi' sh "matrix-shared:person-proof:revoked:clearance:${hash}")"
  active="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli EXISTS "$1"; else redis-cli EXISTS "$1"; fi' sh "matrix-shared:person-proof:reuse:clearance:${hash}")"
  idempotency_count="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli --scan --pattern "matrix-shared:admin-idempotency:person-proof-revoke:*"; else redis-cli --scan --pattern "matrix-shared:admin-idempotency:person-proof-revoke:*"; fi' | wc -l | tr -d '[:space:]')"
  if [[ "${tombstone}" != "1" || "${active}" != "0" || "${idempotency_count}" != "1" ]]; then
    echo "tombstone=${tombstone} active=${active} idempotency_count=${idempotency_count}" >&2
    fail_with_diagnostics "Person proof revocation must atomically tombstone, remove the active marker, and retain one digest-only replay record"
  fi
}

solve_person_proof_cookie() {
  local response="$1"
  local session_client_ip="${2:-203.0.113.23}"
  local verify_client_ip="${3:-203.0.113.24}"
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

  client_request_with_headers "example.test" "${session_path}?session=${session}" 200 "GET" "" "X-Forwarded-For: ${session_client_ip}" >/dev/null
  verify_body="$(python3 -c 'import json, sys; print(json.dumps({"session": sys.argv[1], "response": {"token": sys.argv[2], "fields": {}}}))' "${session}" "${nonce}")"
  verify="$(client_request_with_headers "example.test" "${verify_path}" 200 "POST" "${verify_body}" "X-Forwarded-For: ${verify_client_ip}" "Content-Type: application/json")"
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
