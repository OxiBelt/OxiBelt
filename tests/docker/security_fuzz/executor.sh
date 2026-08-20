#!/usr/bin/env bash
# Target adapters for the bounded Docker security-fuzz driver. Each `start`
# creates one persistent, labelled topology. `case` performs one deterministic
# typed mutation and checks the target oracle; `recovery` proves the same
# service still processes a clean request and, where exposed, that counters
# return to baseline.
set -euo pipefail

command="${1:-}"
run_id="${OXIBELT_SECURITY_FUZZ_RUN_ID:-}"
label="${OXIBELT_SECURITY_FUZZ_LABEL:-}"
target="${OXIBELT_SECURITY_FUZZ_TARGET:-}"
work_dir="${OXIBELT_SECURITY_FUZZ_WORK_DIR:-}"

[[ "${run_id}" =~ ^[0-9]+-[0-9]+-[0-9]+$ ]] || { echo "invalid security-fuzz run id" >&2; exit 2; }
[[ "${target}" =~ ^[a-z0-9_]+$ ]] || { echo "invalid security-fuzz target" >&2; exit 2; }
[[ -n "${label}" && -n "${work_dir}" ]] || { echo "security-fuzz executor environment is incomplete" >&2; exit 2; }

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
proxy_image="${OXIBELT_DOCKER_IMAGE:-oxibelt:security-fuzz}"
mock_image="${OXIBELT_MOCK_UPSTREAM_IMAGE:-oxibelt/mock-upstream:security-fuzz}"
probe_image="${OXIBELT_PROTOCOL_PROBE_IMAGE:-oxibelt/protocol-probe:security-fuzz}"
postgres_image="${OXIBELT_POSTGRES_IMAGE:-oxibelt/postgres:ci}"
network="oxibelt-sf-${run_id}"
proxy="oxibelt-sf-proxy-${run_id}"
postgres="oxibelt-sf-postgres-${run_id}"
fixture_volume="oxibelt-sf-fixture-${run_id}"
cert_dir="${work_dir}/cert"
config_dir="${work_dir}/config"
canary_file="${work_dir}/outside-canary.txt"
credential_dir="${work_dir}/credentials"
admin_token_file="${credential_dir}/admin.token"
denied_token_file="${credential_dir}/denied.token"
turn_username_file="${credential_dir}/turn.username"
turn_password_file="${credential_dir}/turn.password"
turn_allocation_client_file="${work_dir}/turn-allocation-client"
postgres_password_file="${credential_dir}/postgres.password"
mutation_private_key_file="${credential_dir}/mutation-signer.ed25519.pem"
mutation_public_key_file="${credential_dir}/mutation-signer.ed25519.pub"

container_name() {
  printf 'oxibelt-sf-%s-%s' "$1" "${run_id}"
}

ephemeral_name() {
  printf 'oxibelt-sf-client-%s-%s-%s' "${run_id}" "${BASHPID:-$$}" "${RANDOM}"
}

require_image() {
  docker image inspect "$1" >/dev/null 2>&1 || {
    echo "required security-fuzz image is missing: $1" >&2
    return 1
  }
}

generate_credentials() {
  # These values are test-only, per-run, and never placed in the generated
  # configuration.  Keep the source files owner-readable only; the runner
  # removes them before retaining any failure bundle.
  (
    umask 077
    mkdir -p "${credential_dir}"
    openssl rand -hex 32 >"${admin_token_file}"
    openssl rand -hex 32 >"${denied_token_file}"
    printf 'turn-%s\n' "$(openssl rand -hex 12)" >"${turn_username_file}"
    openssl rand -hex 24 >"${turn_password_file}"
    openssl rand -hex 24 >"${postgres_password_file}"
    chmod 0600 "${credential_dir}"/*
  )
}

generate_mutation_signer() {
  [[ "${target}" == "admin_authz" ]] || return 0
  openssl genpkey -algorithm ED25519 -out "${mutation_private_key_file}" >/dev/null 2>&1
  openssl pkey -in "${mutation_private_key_file}" -pubout -outform DER \
    | tail -c 32 >"${mutation_public_key_file}"
  [[ "$(wc -c <"${mutation_public_key_file}")" == "32" ]] || {
    echo "generated mutation signer public key is not raw Ed25519" >&2
    return 1
  }
  chmod 0600 "${mutation_private_key_file}" "${mutation_public_key_file}"
}

read_credential() {
  local file="$1"
  [[ -f "${file}" && ! -L "${file}" ]] || {
    echo "missing controlled security-fuzz credential" >&2
    return 1
  }
  cat "${file}"
}

generate_certificates() {
  mkdir -p "${cert_dir}"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=OxiBelt security fuzz root' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -keyout "${cert_dir}/ca.key" -out "${cert_dir}/ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj '/CN=proxy' \
    -addext 'subjectAltName=DNS:proxy,DNS:example.test,DNS:static.example.test' \
    -keyout "${cert_dir}/privkey.pem" -out "${cert_dir}/proxy.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:proxy,DNS:example.test,DNS:static.example.test\nextendedKeyUsage=serverAuth\n' \
    >"${cert_dir}/proxy.ext"
  openssl x509 -req -days 2 -sha256 -in "${cert_dir}/proxy.csr" \
    -CA "${cert_dir}/ca.pem" -CAkey "${cert_dir}/ca.key" -CAcreateserial \
    -extfile "${cert_dir}/proxy.ext" -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes -subj '/CN=mock-webtransport' \
    -addext 'subjectAltName=DNS:mock-webtransport,DNS:mock-turn-tls' \
    -keyout "${cert_dir}/upstream.key" -out "${cert_dir}/upstream.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:mock-webtransport,DNS:mock-turn-tls\nextendedKeyUsage=serverAuth\n' \
    >"${cert_dir}/upstream.ext"
  openssl x509 -req -days 2 -sha256 -in "${cert_dir}/upstream.csr" \
    -CA "${cert_dir}/ca.pem" -CAkey "${cert_dir}/ca.key" -CAcreateserial \
    -extfile "${cert_dir}/upstream.ext" -out "${cert_dir}/upstream.pem" >/dev/null 2>&1
  cp "${cert_dir}/ca.pem" "${cert_dir}/upstream-ca.pem"
  chmod 0644 "${cert_dir}"/*.pem
  chmod 0600 "${cert_dir}"/*.key
}

start_mock() {
  local role="$1" alias="$2"; shift 2
  docker run -d \
    --name "$(container_name "${role}")" \
    --label "${label}" \
    --network "${network}" \
    --network-alias "${alias}" \
    "$@" \
    "${mock_image}" >/dev/null
}

start_probe_tls_service() {
  local role="$1" alias="$2"; shift 2
  local name
  name="$(container_name "${role}")"
  docker create \
    --name "${name}" \
    --label "${label}" \
    --network "${network}" \
    --network-alias "${alias}" \
    "${probe_image}" "$@" >/dev/null
  docker cp "${cert_dir}/upstream.pem" "${name}:/tls/server.pem"
  docker cp "${cert_dir}/upstream.key" "${name}:/tls/server.key"
  docker start "${name}" >/dev/null
}

prepare_config() {
  local source_config
  case "${target}" in
    path_security) source_config="path_security.toml" ;;
    tls_quic_sni|http_framing) source_config="http_runtime.toml" ;;
    waf_bypass) source_config="waf_bypass.toml" ;;
    auth_bypass) source_config="auth_bypass.toml" ;;
    websocket_webtransport) source_config="websocket_webtransport.toml" ;;
    turn_runtime) source_config="turn_runtime.toml" ;;
    admin_authz) source_config="admin_authz.toml" ;;
    *) echo "unsupported security-fuzz target: ${target}" >&2; return 2 ;;
  esac
  mkdir -p "${config_dir}"
  cp "${script_dir}/config/${source_config}" "${config_dir}/oxibelt.toml"
  cp "${cert_dir}/fullchain.pem" "${config_dir}/fullchain.pem"
  cp "${cert_dir}/privkey.pem" "${config_dir}/privkey.pem"
  cp "${cert_dir}/ca.pem" "${config_dir}/upstream-ca.pem"
  if [[ "${target}" == "turn_runtime" ]]; then
    local turn_username turn_password
    turn_username="$(read_credential "${turn_username_file}")"
    turn_password="$(read_credential "${turn_password_file}")"
    sed -i \
      -e "s/^username = \"turn-user\"$/username = \"${turn_username}\"/" \
      -e "s/^password = \"turn-password\"$/password = \"${turn_password}\"/" \
      "${config_dir}/oxibelt.toml"
  fi
  if [[ "${target}" == "admin_authz" ]]; then
    mkdir -p "${config_dir}/admin-mutation"
    cp "${mutation_public_key_file}" "${config_dir}/admin-mutation/signer.ed25519.pub"
    chmod 0644 "${config_dir}/admin-mutation/signer.ed25519.pub"
  fi
  if [[ "${target}" == "path_security" ]]; then
    mkdir -p "${config_dir}/public/sub" "${config_dir}/should-never-be-readable"
    printf 'public security-fuzz fixture\n' >"${config_dir}/public/public.txt"
    printf 'nested public security-fuzz fixture\n' >"${config_dir}/public/sub/nested.txt"
    sha256sum "${cert_dir}/fullchain.pem" | awk '{print "outside-canary-" $1}' \
      >"${config_dir}/should-never-be-readable/canary.txt"
    cp "${config_dir}/should-never-be-readable/canary.txt" "${canary_file}"
    ln -sfn ../should-never-be-readable/canary.txt "${config_dir}/public/canary-link.txt"
  fi
}

start_target_helpers() {
  case "${target}" in
    path_security) ;;
    tls_quic_sni|http_framing|waf_bypass|admin_authz)
      start_mock http mock-http -e LISTEN_PORT=18080 -e CONTROL_PORT=18081 \
        -e UPSTREAM_NAME=protected-upstream
      if [[ "${target}" == "admin_authz" ]]; then
        start_postgres
      fi
      ;;
    auth_bypass)
      start_mock http mock-http -e LISTEN_PORT=18080 -e CONTROL_PORT=18081 \
        -e UPSTREAM_NAME=protected-upstream
      start_mock auth-deny mock-auth-deny -e LISTEN_PORT=18080 -e CONTROL_PORT=18081 \
        -e UPSTREAM_NAME=auth-deny
      start_mock auth-allow mock-auth-allow -e LISTEN_PORT=18080 -e CONTROL_PORT=18081 \
        -e UPSTREAM_NAME=auth-allow
      ;;
    websocket_webtransport)
      docker run -d \
        --name "$(container_name websocket)" --label "${label}" \
        --network "${network}" --network-alias mock-websocket \
        "${probe_image}" websocket-echo-upstream --listen 0.0.0.0:18081 >/dev/null
      start_probe_tls_service webtransport mock-webtransport \
        webtransport-upstream --listen 0.0.0.0:18446 \
        --cert /tls/server.pem --key /tls/server.key --name webtransport-upstream
      ;;
    turn_runtime)
      docker run -d \
        --name "$(container_name turn-udp)" --label "${label}" \
        --network "${network}" --network-alias mock-turn-udp \
        "${probe_image}" turn-upstream --transport udp --listen 0.0.0.0:3478 >/dev/null
      docker run -d \
        --name "$(container_name turn-tcp)" --label "${label}" \
        --network "${network}" --network-alias mock-turn-tcp \
        "${probe_image}" turn-upstream --transport tcp --listen 0.0.0.0:3479 >/dev/null
      start_probe_tls_service turn-tls mock-turn-tls \
        turn-upstream --transport tls --listen 0.0.0.0:5349 \
        --cert /tls/server.pem --key /tls/server.key
      ;;
  esac
}

start_postgres() {
  local postgres_password
  postgres_password="$(read_credential "${postgres_password_file}")"
  docker run -d \
    --name "${postgres}" \
    --label "${label}" \
    --network "${network}" \
    --network-alias mock-postgres \
    -e POSTGRES_USER=oxibelt \
    -e POSTGRES_PASSWORD="${postgres_password}" \
    -e POSTGRES_DB=oxibelt \
    "${postgres_image}" >/dev/null
  for _attempt in $(seq 1 40); do
    if docker exec "${postgres}" pg_isready -U oxibelt -d oxibelt >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  docker logs "${postgres}" >&2 || true
  echo "security-fuzz PostgreSQL did not become ready" >&2
  return 1
}

seed_proxy_fixture_volume() {
  local seed_container
  seed_container="$(container_name fixture-seed)"
  docker volume create --label "${label}" "${fixture_volume}" >/dev/null
  docker create \
    --name "${seed_container}" \
    --label "${label}" \
    --user 0:0 \
    --mount "type=volume,src=${fixture_volume},dst=/fixture" \
    --entrypoint sh \
    "${mock_image}" \
    -c 'chown -R 10001:10001 /fixture && find /fixture -type d -exec chmod 0500 {} \; && find /fixture -type f -exec chmod 0400 {} \;' >/dev/null
  docker cp "${config_dir}" "${seed_container}:/fixture/config"
  docker cp "${cert_dir}" "${seed_container}:/fixture/cert"
  docker start -a "${seed_container}" >/dev/null
  docker rm "${seed_container}" >/dev/null
}

start_proxy() {
  local admin_token denied_token postgres_password proxy_environment=()
  admin_token="$(read_credential "${admin_token_file}")"
  denied_token="$(read_credential "${denied_token_file}")"
  if [[ "${target}" == "admin_authz" ]]; then
    postgres_password="$(read_credential "${postgres_password_file}")"
    proxy_environment+=( -e "OXIBELT_SECURITY_FUZZ_POSTGRES_URL=postgres://oxibelt:${postgres_password}@mock-postgres:5432/oxibelt" )
  fi
  docker create \
    --name "${proxy}" \
    --label "${label}" \
    --network "${network}" \
    --network-alias proxy \
    --mount "type=volume,src=${fixture_volume},dst=/etc/oxibelt,readonly" \
    -e OXIBELT_ADMIN_TOKEN="${admin_token}" \
    -e OXIBELT_DENIED_TOKEN="${denied_token}" \
    "${proxy_environment[@]}" \
    "${proxy_image}" >/dev/null
  docker start "${proxy}" >/dev/null
}

probe_with_ca() {
  local output_file="$1"; shift
  local client status=0
  client="$(ephemeral_name)"
  docker create \
    --name "${client}" --label "${label}" --network "${network}" \
    "${probe_image}" "$@" >/dev/null
  docker cp "${cert_dir}/ca.pem" "${client}:/tmp/ca.pem"
  docker start -a "${client}" >"${output_file}" 2>&1 || status=$?
  docker rm -f "${client}" >/dev/null 2>&1 || true
  return "${status}"
}

probe_without_files() {
  docker run --rm --label "${label}" --network "${network}" "${probe_image}" "$@"
}

mock_client() {
  local output_file="$1" scheme="$2" host="$3" port="$4" path="$5" expected="$6" method="$7" body="$8"
  shift 8
  local client status=0
  client="$(ephemeral_name)"
  local args=(
    --target-host proxy --scheme "${scheme}" --host "${host}" --port "${port}"
    --path "${path}" --method "${method}" --body "${body}"
    --dump-response-json --expect-status "${expected}" --timeout 3
  )
  local header
  for header in "$@"; do args+=(--header "${header}"); done
  if [[ "${scheme}" == "https" ]]; then
    args+=(--server-name proxy --ca-file /tmp/ca.pem)
  fi
  docker create \
    --name "${client}" --label "${label}" --network "${network}" \
    --entrypoint python "${mock_image}" /opt/mock_upstream/client.py "${args[@]}" >/dev/null
  if [[ "${scheme}" == "https" ]]; then
    docker cp "${cert_dir}/ca.pem" "${client}:/tmp/ca.pem"
  fi
  docker start -a "${client}" >"${output_file}" 2>&1 || status=$?
  docker rm -f "${client}" >/dev/null 2>&1 || true
  return "${status}"
}

downstream_request() {
  local protocol="$1" path="$2" expected="$3" output="$4"; shift 4
  local args=(
    downstream --protocol "${protocol}" --host proxy --port 8443
    --server-name proxy --authority example.test --path "${path}"
    --ca-cert /tmp/ca.pem --expect-status "${expected}"
  )
  local header
  for header in "$@"; do args+=(--header "${header}"); done
  probe_with_ca "${output}" "${args[@]}"
}

downstream_any_status() {
  local protocol="$1" authority="$2" path="$3" output="$4"
  probe_with_ca "${output}" downstream --protocol "${protocol}" \
    --host proxy --port 8443 --server-name proxy --authority "${authority}" \
    --path "${path}" --ca-cert /tmp/ca.pem
}

raw_tls_request() {
  local request_base64="$1" output="$2"
  probe_with_ca "${output}" raw-tls-http --host proxy --port 8443 \
    --server-name proxy --ca-cert /tmp/ca.pem --request-base64 "${request_base64}"
}

upstream_stats() {
  # The helper deliberately binds its observation API to container loopback;
  # query it from inside that same controlled container rather than exposing a
  # test-only control port on the fuzz network.
  docker exec "$(container_name http)" python -c \
    'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:18081/__control/stats", timeout=2).read().decode("utf-8"))'
}

request_count() {
  local key="$1"
  upstream_stats | jq -er --arg key "${key}" '.request_counts[("operation." + $key)] // 0'
}

admin_request() {
  local output="$1" path="$2" expected="$3" method="$4" body="$5"; shift 5
  mock_client "${output}" http proxy 9092 "${path}" "${expected}" "${method}" "${body}" "$@"
}

runtime_connections() {
  local output="${work_dir}/runtime-introspection.json"
  admin_request "${output}" '/admin/v1/runtime/introspection?redact=true' 200 GET '' \
    "Authorization: Bearer $(read_credential "${admin_token_file}")"
  jq -cer '.body | fromjson | .connections' "${output}"
}

admin_state_digest() {
  local admin_token
  admin_token="$(read_credential "${admin_token_file}")"
  docker exec -e "OXIBELT_SECURITY_FUZZ_ADMIN_TOKEN=${admin_token}" "$(container_name http)" python -c '
import hashlib, json, urllib.request
headers = {"Authorization": "Bearer " + __import__("os").environ["OXIBELT_SECURITY_FUZZ_ADMIN_TOKEN"]}
def get(path):
    request = urllib.request.Request("http://proxy:9092" + path, headers=headers)
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.loads(response.read())
status = get("/admin/v1/config/status")
effective = get("/admin/v1/config/effective")
canonical = json.dumps([status, effective], sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(canonical).hexdigest())'
}

admin_admission_context() {
  local output="${work_dir}/admin-admission-context.json"
  admin_request "${output}" /admin/v1/config/status 200 GET '' \
    "Authorization: Bearer $(read_credential "${admin_token_file}")"
  jq -cer '.body | fromjson
    | (.etag | ltrimstr("\"") | rtrimstr("\"")) as $precondition
    | {precondition: $precondition,
       expected_previous_revision: (.mutations.logical_revisions.config.committed_revision // $precondition),
       target: .mutations.target}' \
    "${output}"
}

append_mutation_transcript_field() {
  local destination="$1" value="$2" length escaped
  length="${#value}"
  printf -v escaped '\\x%02x\\x%02x\\x%02x\\x%02x' \
    "$((length >> 24 & 255))" "$((length >> 16 & 255))" \
    "$((length >> 8 & 255))" "$((length & 255))"
  printf '%b' "${escaped}" >>"${destination}"
  printf '%s' "${value}" >>"${destination}"
}

mutation_envelope_header() {
  local body="$1" principal="$2" variant="$3" method="$4" path="$5" precondition="$6" expected_previous_revision="$7" target="$8"
  local content_digest signature wire signer_id issued_at expires_at request_id new_revision
  local cluster_id membership_revision transcript_file signature_file encoded_signature
  content_digest="sha256:$(printf '%s' "${body}" | sha256sum | awk '{print $1}')"
  signer_id="security-fuzz-signer"
  case "${variant}" in
    digest-mismatch) content_digest="sha256:$(printf '%064d' 0)" ;;
    principal-mismatch)
      if [[ "${principal}" == "admin" ]]; then
        signer_id="security-fuzz-denied-signer"
      else
        signer_id="security-fuzz-signer"
      fi
      ;;
    unknown-signer) signer_id="unknown-$(input_hex 3 8)" ;;
  esac
  issued_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  expires_at="$(date -u -d '+120 seconds' +%Y-%m-%dT%H:%M:%SZ)"
  request_id="00000000-0000-4000-8000-$(input_hex 11 6)"
  new_revision="sf-$(input_hex 17 16)"
  cluster_id="$(jq -er '.cluster_id' <<<"${target}")"
  membership_revision="$(jq -er '.membership_revision' <<<"${target}")"
  transcript_file="${work_dir}/admin-mutation-transcript.bin"
  signature_file="${work_dir}/admin-mutation-signature.bin"
  printf 'OXIBELT-ADMIN-MUTATION-TRANSCRIPT\0' >"${transcript_file}"
  local field
  for field in \
    1 ed25519 "${signer_id}" oxibelt "${principal}" "${method}" "${path}" \
    "${precondition}" "${request_id}" "${issued_at}" "${expires_at}" \
    "${expected_previous_revision}" "${new_revision}" "${content_digest}" \
    "${cluster_id}" "${membership_revision}"; do
    append_mutation_transcript_field "${transcript_file}" "${field}"
  done
  openssl pkeyutl -sign -rawin -inkey "${mutation_private_key_file}" \
    -in "${transcript_file}" -out "${signature_file}"
  encoded_signature="$(base64 -w0 "${signature_file}" | tr '+/' '-_' | tr -d '=')"
  if [[ "${variant}" == "signature-invalid" ]]; then
    encoded_signature="$(head -c 64 /dev/zero | base64 -w0 | tr '+/' '-_' | tr -d '=')"
  fi
  signature="ed25519:${encoded_signature}"
  wire="$(jq -cn \
    --arg signer_id "${signer_id}" \
    --arg request_id "${request_id}" \
    --arg issued_at "${issued_at}" \
    --arg expires_at "${expires_at}" \
    --arg expected_previous_revision "${expected_previous_revision}" \
    --arg new_revision "${new_revision}" \
    --arg content_digest "${content_digest}" \
    --arg signature "${signature}" \
    --argjson target "${target}" \
    '{version:"1", signer_id:$signer_id, request_id:$request_id,
      issued_at:$issued_at, expires_at:$expires_at,
      expected_previous_revision:$expected_previous_revision, new_revision:$new_revision,
      content_digest:$content_digest, target:$target,
      signature:$signature}')"
  rm -f "${transcript_file}" "${signature_file}"
  printf '%s' "${wire}" | base64 -w0 | tr '+/' '-_' | tr -d '='
}

input_byte() {
  local offset="$1" value
  value="$(od -An -tu1 -j "${offset}" -N 1 "${OXIBELT_SECURITY_FUZZ_INPUT_FILE}" 2>/dev/null | tr -d ' ')"
  printf '%s' "${value:-0}"
}

input_hex() {
  local offset="$1" length="$2" value
  value="$(od -An -v -tx1 -j "${offset}" -N "${length}" \
    "${OXIBELT_SECURITY_FUZZ_INPUT_FILE:-}" 2>/dev/null | tr -d ' \n')"
  if [[ -n "${value}" ]]; then
    printf '%s' "${value}"
  else
    printf '%0*d' "$((length * 2))" 0
  fi
}

persist_raw_wire() (
  local family="$1" encoded="$2" sensitivity="${3:-public}"
  local raw_dir raw_path stored_path original_digest stored_digest redacted_encoded
  [[ "${family}" =~ ^(h1|h2|tls|quic|ws|admin)$ ]] || {
    echo "unsupported raw wire family" >&2
    return 2
  }
  raw_dir="${work_dir}/raw-wire"
  mkdir -p "${raw_dir}"
  chmod 0700 "${raw_dir}"
  raw_path="${work_dir}/.${OXIBELT_SECURITY_FUZZ_CASE}-${family}.original.bin"
  trap 'rm -f -- "${raw_path}"' EXIT
  printf '%s' "${encoded}" | base64 -d >"${raw_path}"
  [[ "$(wc -c <"${raw_path}")" -le 131072 ]] || {
    echo "raw wire exceeds the bounded capture limit" >&2
    return 1
  }
  original_digest="$(sha256sum "${raw_path}" | awk '{print $1}')"
  stored_path="${raw_dir}/${OXIBELT_SECURITY_FUZZ_CASE}-${family}.bin"
  if [[ "${sensitivity}" == "redact-bearer" ]]; then
    redacted_encoded="$(sed -E 's/([Aa]uthorization:[[:space:]]*Bearer[[:space:]]+)[^[:space:]\r]+/\1<redacted>/g' "${raw_path}" | base64 -w0)"
    printf '%s' "${redacted_encoded}" | base64 -d >"${stored_path}"
    rm -f "${raw_path}"
  else
    mv "${raw_path}" "${stored_path}"
  fi
  chmod 0600 "${stored_path}"
  stored_digest="$(sha256sum "${stored_path}" | awk '{print $1}')"
  jq -n --arg family "${family}" --arg original_sha256 "${original_digest}" \
    --arg stored_sha256 "${stored_digest}" --argjson redacted "$([[ "${sensitivity}" == "redact-bearer" ]] && echo true || echo false)" \
    '{family: $family, original_sha256: $original_sha256, stored_sha256: $stored_sha256, redacted: $redacted}' \
    >"${raw_dir}/${OXIBELT_SECURITY_FUZZ_CASE}-${family}.json"
)

require_concurrency_bound() {
  local requested="$1" maximum="${OXIBELT_SECURITY_FUZZ_MAX_CONCURRENT_SESSIONS:-}"
  [[ "${maximum}" =~ ^[1-9][0-9]*$ ]] || {
    echo "security-fuzz concurrent-session bound is missing" >&2
    return 2
  }
  ((requested <= maximum)) || {
    echo "security-fuzz case exceeds the concurrent-session bound" >&2
    return 2
  }
}

record_mutation() {
  local protocol="$1" profile="$2" variant="$3" transform="$4"
  jq -n --arg target "${target}" --arg protocol "${protocol}" \
    --arg profile "${profile}" --arg variant "${variant}" --arg transform "${transform}" \
    '{target: $target, protocol: $protocol, profile: $profile, variant: $variant, transform: $transform}' \
    >"${work_dir}/mutation.json"
}

case_key() {
  printf 'sf%s' "${OXIBELT_SECURITY_FUZZ_CASE}"
}

case_path_security() {
  local b0 b1 b2 protocol_index path_index path output body canary probe_value
  b0="$(input_byte 0)"; b1="$(input_byte 1)"; b2="$(input_byte 2)"
  require_concurrency_bound 1
  protocol_index=$((b0 % 3))
  path_index=$((b1 % 12))
  local protocol_names=(h1 h2 h3) transforms=(none percent-hex-case unreserved-percent-encoding)
  record_mutation "${protocol_names[protocol_index]}" path-containment "path-${path_index}" \
    "${transforms[b2 % ${#transforms[@]}]}"
  local paths=(
    '/static/public.txt'
    '/static/sub/nested.txt'
    '/static/../should-never-be-readable/canary.txt'
    '/static/%2e%2e/should-never-be-readable/canary.txt'
    '/static/%252e%252e/should-never-be-readable/canary.txt'
    '/static/..%2fshould-never-be-readable%2fcanary.txt'
    '/static/%2e%2e%5cshould-never-be-readable%5ccanary.txt'
    '/static//..//should-never-be-readable//canary.txt'
    '/static/canary-link.txt'
    '/static/%u002e%u002e/should-never-be-readable/canary.txt'
    '/static/sub/%00../should-never-be-readable/canary.txt'
    '/static/sub%E2%88%95..%E2%88%95should-never-be-readable%E2%88%95canary.txt'
  )
  path="${paths[path_index]}"
  case $((b2 % 3)) in
    1) path="${path//%2e/%2E}"; path="${path//%2f/%2F}"; path="${path//%5c/%5C}" ;;
    2) path="${path/\/static/\/%73tatic}" ;;
  esac
  probe_value="$(input_hex 3 16)"
  path+="$([[ "${path}" == *\?* ]] && printf '&' || printf '?')probe=${probe_value}"
  output="${work_dir}/path-case.json"
  if ((protocol_index == 0)); then
    local raw_request
    if ((b0 % 2 == 0)); then
      raw_request="$(printf 'GET %s HTTP/1.1\r\nHost: static.example.test\r\nConnection: close\r\n\r\n' "${path}" | base64 -w0)"
    else
      raw_request="$(printf 'GET https://static.example.test%s HTTP/1.1\r\nHost: static.example.test\r\nConnection: close\r\n\r\n' "${path}" | base64 -w0)"
    fi
    persist_raw_wire h1 "${raw_request}"
    raw_tls_request "${raw_request}" "${output}"
    body="$(jq -r '.response_base64 | @base64d' "${output}")"
  else
    downstream_any_status "$([[ ${protocol_index} == 1 ]] && echo h2 || echo h3)" \
      static.example.test "${path}" "${output}"
    body="$(jq -r '.body' "${output}")"
  fi
  canary="$(cat "${canary_file}")"
  if [[ "${body}" == *"${canary}"* ]]; then
    echo "outside-root canary was disclosed" >&2
    return 1
  fi
}

case_tls_quic_sni() {
  local b0 b1 family input_payload output prefix profile
  b0="$(input_byte 0)"; b1="$(input_byte 1)"
  require_concurrency_bound 1
  family=$((b0 % 3))
  output="${work_dir}/tls-quic-case.json"
  if ((family == 0)); then
    record_mutation tls malformed-record "record-$((b1 % 3))" none
    case $((b1 % 3)) in
      0) input_payload="$( { printf '\x16\x03\x03\x00\x04'; head -c 2 "${OXIBELT_SECURITY_FUZZ_INPUT_FILE}"; } | base64 -w0)" ;;
      1) input_payload="$( { printf '\x16\x03\x01\x00\x01'; head -c 1 "${OXIBELT_SECURITY_FUZZ_INPUT_FILE}"; } | base64 -w0)" ;;
      *) input_payload="$( { printf '\x16\x7f\xff\x00\x02'; head -c 2 "${OXIBELT_SECURITY_FUZZ_INPUT_FILE}"; } | base64 -w0)" ;;
    esac
    persist_raw_wire tls "${input_payload}"
    probe_without_files raw-http --host proxy --port 8443 \
      --request-base64 "${input_payload}" --read-timeout-ms 300 >"${output}"
    prefix="$(jq -r '.response_base64' "${output}" | base64 -d 2>/dev/null | head -c 5 || true)"
    [[ "${prefix}" != 'HTTP/' ]] || { echo "malformed TLS bytes reached HTTP parsing" >&2; return 1; }
  elif ((family == 1)); then
    local crypto_offset=$((b1 % 16 + 1))
    record_mutation quic initial-crypto-integrity-bitflip \
      "xor-offset-from-end-${crypto_offset}" none
    probe_with_ca "${output}" quic-initial-mutate --host proxy --port 8443 \
      --server-name proxy --ca-cert /tmp/ca.pem \
      --xor-offset-from-end "${crypto_offset}"
    persist_raw_wire quic "$(jq -er '.first_mutated_initial_base64' "${output}")"
  else
    local profiles=(
      byedpi-split-sni
      byedpi-tlsrec-sni
      goodbyedpi-native-frag
      goodbyedpi-frag-by-sni
      dpibreak-segment-0-1
      dpibreak-segment-0-5
    )
    profile="${profiles[b1 % ${#profiles[@]}]}"
    record_mutation tls fragmented-client-hello "${profile}" sni-fragmentation
    probe_with_ca "${output}" dpi-tls-client --profile "${profile}" \
      --host proxy --port 8443 --server-name proxy --authority example.test \
      --path "/sni-fragment?probe=$(input_hex 2 12)" --ca-cert /tmp/ca.pem \
      --expect-status 200
  fi
}

case_http_framing() {
  local b0 b1 b2 protocol key shadow_key before after shadow_before shadow_after output request
  local payload cl_header
  b0="$(input_byte 0)"; b1="$(input_byte 1)"; b2="$(input_byte 2)"
  require_concurrency_bound 1
  protocol=$((b0 % 3)); key="$(case_key)-main"; shadow_key="$(case_key)-shadow"
  before="$(request_count "${key}")"; shadow_before="$(request_count "${shadow_key}")"
  payload="$(input_hex 3 16)"; cl_header="$(((b2 % 2) == 0))"
  [[ "${cl_header}" == 1 ]] && cl_header='Content-Length' || cl_header='content-length'
  output="${work_dir}/framing-case.json"
  local protocol_names=(h1 h2 h3) framing_transform=header-case
  ((protocol == 0 && b1 % 4 == 0)) && framing_transform='header-case+equivalent-content-length'
  local h2_profiles=(data-stream-zero headers-stream-zero settings-stream-one)
  if ((protocol == 1)); then
    record_mutation h2 raw-frame-error "${h2_profiles[b1 % ${#h2_profiles[@]}]}" none
  else
    record_mutation "${protocol_names[protocol]}" framing-boundary "variant-$((b1 % 4))" \
      "${framing_transform}"
  fi
  if ((protocol == 0)); then
    case $((b1 % 4)) in
      0) request="$(printf 'POST /case?operation_id=%s HTTP/1.1\r\nHost: example.test\r\n%s: %s\r\n%s: 0%s\r\nConnection: close\r\n\r\n%s' "${key}" "${cl_header}" "${#payload}" "${cl_header}" "${#payload}" "${payload}" | base64 -w0)" ;;
      1) request="$(printf 'POST /case?operation_id=%s HTTP/1.1\r\nHost: example.test\r\n%s: %s\r\n%s: 9\r\nConnection: close\r\n\r\n%s' "${key}" "${cl_header}" "${#payload}" "${cl_header}" "${payload}" | base64 -w0)" ;;
      2) request="$(printf 'POST /case?operation_id=%s HTTP/1.1\r\nHost: example.test\r\n%s: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n' "${key}" "${cl_header}" "${#payload}" | base64 -w0)" ;;
      *) request="$(printf 'POST /case?operation_id=%s HTTP/1.1\r\nHost: example.test\r\nContent-Length: 99\r\n\r\nGET /shadow?operation_id=%s HTTP/1.1\r\nHost: example.test\r\nX-Incomplete:' "${key}" "${shadow_key}" | base64 -w0)" ;;
    esac
    persist_raw_wire h1 "${request}"
    raw_tls_request "${request}" "${output}"
  elif ((protocol == 1)); then
    probe_with_ca "${output}" raw-h2 --host proxy --port 8443 \
      --server-name proxy --ca-cert /tmp/ca.pem \
      --profile "${h2_profiles[b1 % ${#h2_profiles[@]}]}"
    persist_raw_wire h2 "$(jq -er '.request_base64' "${output}")"
  else
    if ((b1 % 2 == 0)); then
      record_mutation h3 incomplete-request-stream body-prefix-reset stream-reset
      probe_with_ca "${output}" downstream --protocol h3 \
        --host proxy --port 8443 --server-name proxy --authority example.test \
        --path "/case?operation_id=${key}&variant=${b1}" --ca-cert /tmp/ca.pem \
        --method POST --body "${payload}" --omit-content-length \
        --header "${cl_header}: $(( ${#payload} + 7 ))" \
        --h3-reset-after-body-prefix
    else
      record_mutation h3 authority-host-mismatch host-mismatch header-value
      if ! probe_with_ca "${output}" downstream --protocol h3 \
        --host proxy --port 8443 --server-name proxy --authority example.test \
        --path "/case?operation_id=${key}&variant=${b1}" --ca-cert /tmp/ca.pem \
        --header "Host: mismatch-$(input_hex 4 8).invalid"; then
        :
      fi
    fi
    # Stream reset or semantic rejection is expected. The upstream counters
    # remain the authoritative boundary oracle.
  fi
  after="$(request_count "${key}")"
  shadow_after="$(request_count "${shadow_key}")"
  if ((protocol == 0 && b1 % 4 == 0)); then
    ((after >= before && after - before <= 1)) || {
      echo "equivalent duplicate length changed the upstream request boundary" >&2
      return 1
    }
  elif ((after != before)); then
    echo "malformed request crossed the upstream boundary" >&2
    return 1
  fi
  [[ "${shadow_after}" == "${shadow_before}" ]] || {
    echo "partial shadow request crossed the upstream boundary" >&2
    return 1
  }
}

case_waf_bypass() {
  local b0 b1 b2 b3 b4 b5 protocol key path before after output body content_type header_name
  local marker=sf-known-attack attack_location header_value body_value body_encoding=identity
  b0="$(input_byte 0)"; b1="$(input_byte 1)"; b2="$(input_byte 2)"; b3="$(input_byte 3)"; b4="$(input_byte 4)"; b5="$(input_byte 5)"
  require_concurrency_bound 1
  protocol=$((b0 % 3)); key="$(case_key)"
  attack_location=$((b1 % 3)); path='/clean'; body_value="$(input_hex 5 24)"
  header_value="case-$(input_hex 29 8)"
  if ((attack_location == 0)); then
    [[ $((b4 % 2)) == 0 ]] && path="/${marker}" || path='/%73f-known-attack'
  elif ((attack_location == 1)); then
    body_value="${marker}"
  else
    header_value="${marker}-$(input_hex 29 8)"
  fi
  path+="?operation_id=${key}"
  case $((b2 % 3)) in
    0) body="{\"attack\":\"${body_value}\"}"; content_type='application/json' ;;
    1) body="attack=${body_value}"; content_type='application/x-www-form-urlencoded' ;;
    *) body=$'--sf\r\nContent-Disposition: form-data; name="attack"\r\n\r\n'"${body_value}"$'\r\n--sf--\r\n'; content_type='multipart/form-data; boundary=sf' ;;
  esac
  [[ $((b3 % 2)) == 0 ]] && header_name='Content-Type' || header_name='content-type'
  local protocol_names=(h1 h2 h3) locations=(path body header) transform=header-case
  local encodings=(identity gzip deflate br zstd)
  if ((attack_location == 1 && protocol != 0)); then
    body_encoding="${encodings[b4 % ${#encodings[@]}]}"
    [[ "${body_encoding}" == identity ]] || transform="${transform}+content-coding"
  fi
  ((protocol != 0)) && transform="${transform}+body-fragmentation-$((b5 % 16 + 1))"
  ((attack_location == 0 && b4 % 2 == 1)) && transform='header-case+unreserved-percent-encoding'
  record_mutation "${protocol_names[protocol]}" "${content_type}+${body_encoding}" \
    "attack-in-${locations[attack_location]}" "${transform}"
  before="$(request_count "${key}")"; output="${work_dir}/waf-case.json"
  if ((protocol == 0)); then
    mock_client "${output}" https example.test 8443 "${path}" 403 POST "${body}" \
      "${header_name}: ${content_type}" "X-Fuzz-Case: ${header_value}"
  else
    local downstream_args=(
      downstream --protocol "$([[ ${protocol} == 1 ]] && echo h2 || echo h3)"
      --host proxy --port 8443 --server-name proxy --authority example.test
      --path "${path}" --ca-cert /tmp/ca.pem --expect-status 403 --method POST
      --body-chunk-size "$((b5 % 16 + 1))"
      --header "${header_name}: ${content_type}" --header "X-Fuzz-Case: ${header_value}"
    )
    if ((protocol == 1 && attack_location == 1)); then
      downstream_args+=(--h2-eager-body)
    fi
    if [[ "${body_encoding}" == identity ]]; then
      downstream_args+=(--body "${body}")
    else
      downstream_args+=(--body-base64 "$(printf '%s' "${body}" | base64 -w0)" \
        --content-encoding "${body_encoding}")
    fi
    probe_with_ca "${output}" "${downstream_args[@]}"
    if ((protocol == 1 && attack_location == 1)); then
      jq -e '
        .status == 403
        and .body == "security-fuzz-waf-body-blocked"
        and .request_body_complete == true
      ' "${output}" >/dev/null || {
        echo "H2 WAF body rejection did not prove complete request delivery" >&2
        return 1
      }
    fi
  fi
  after="$(request_count "${key}")"
  [[ "${after}" == "${before}" ]] || { echo "must-block request reached protected upstream" >&2; return 1; }
}

case_auth_bypass() {
  local b0 b1 b2 profile protocol path expected key before after output allowed variant transform
  local auth_header identity malformed
  local -a request_headers
  b0="$(input_byte 0)"; b1="$(input_byte 1)"; b2="$(input_byte 2)"
  require_concurrency_bound 1
  profile=$((b0 % 5)); protocol=$((b1 % 3)); key="$(case_key)"; allowed=0
  case "${profile}" in
    0) path="/deny?operation_id=${key}"; expected=401 ;;
    1) path="/timeout-closed?operation_id=${key}"; expected=503 ;;
    2) path="/malformed-closed?operation_id=${key}"; expected=503 ;;
    3) path="/reset-closed?operation_id=${key}"; expected=503 ;;
    *) path="/malformed-open?operation_id=${key}"; expected=200; allowed=1 ;;
  esac
  [[ $((b2 % 2)) == 0 ]] && auth_header='Authorization' || auth_header='authorization'
  identity="attacker-$(input_hex 3 16)"
  malformed="Bearer malformed-$(input_hex 19 12)"
  local protocol_names=(h1 h2 h3)
  local profiles=(explicit-deny timeout-closed malformed-response-closed reset-response-closed malformed-response-open)
  local variants=(empty-authorization malformed-authorization duplicate-authorization duplicate-cookie)
  variant=$((b2 % ${#variants[@]})); transform='header-case'
  case "${variant}" in
    0) request_headers+=("${auth_header}: ") ;;
    1) request_headers+=("${auth_header}: ${malformed}") ;;
    2)
      request_headers+=("${auth_header}: ${malformed}" "${auth_header}: Basic invalid-$(input_hex 31 8)")
      transform="${transform}+duplicate-field"
      ;;
    *)
      request_headers+=("${auth_header}: ${malformed}" \
        "Cookie: session=invalid-$(input_hex 31 8)" \
        "Cookie: other=invalid-$(input_hex 39 8)")
      transform="${transform}+duplicate-field"
      ;;
  esac
  request_headers+=("Remote-User: ${identity}" "X-Auth-User: ${identity}" \
    "X-Forwarded-User: ${identity}")
  record_mutation "${protocol_names[protocol]}" "${profiles[profile]}" \
    "spoofed-identity-and-${variants[variant]}" "${transform}"
  before="$(request_count "${key}")"; output="${work_dir}/auth-case.json"
  if ((protocol == 0)); then
    mock_client "${output}" https example.test 8443 "${path}" "${expected}" GET '' \
      "${request_headers[@]}"
  else
    downstream_request "$([[ ${protocol} == 1 ]] && echo h2 || echo h3)" \
      "${path}" "${expected}" "${output}" "${request_headers[@]}"
  fi
  after="$(request_count "${key}")"
  if ((allowed == 0 && after != before)); then
    echo "invalid authentication reached protected upstream" >&2
    return 1
  fi
  if ((allowed == 1)); then
    ((after == before + 1)) || { echo "declared fail-open error was not isolated to one request" >&2; return 1; }
    if jq -e --arg identity "${identity}" \
      '.body | fromjson | .headers | to_entries[] | select((.key == "remote-user" or .key == "x-auth-user" or .key == "x-forwarded-user") and .value == $identity)' \
      "${output}" >/dev/null 2>&1; then
      echo "attacker identity header crossed external-auth boundary" >&2
      return 1
    fi
  fi
}

case_websocket_webtransport() {
  local b0 b1 b2 mode output request response_file response_hex forbidden_hex forbidden_echo_hex payload_hex
  local sessions expected_statuses extended_protocol
  b0="$(input_byte 0)"; b1="$(input_byte 1)"; b2="$(input_byte 2)"
  output="${work_dir}/session-case.json"
  if ((b0 % 2 == 0)); then
    require_concurrency_bound 1
    printf 'ws\n' >"${work_dir}/last-session-mode"
    mode=$((b1 % 4)); payload_hex="$(input_hex 3 2)"; forbidden_echo_hex=''
    local ws_variants=(unmasked-data fragmented-control oversized-control orphan-continuation)
    record_mutation ws malformed-frame "${ws_variants[mode]}" none
    case "${mode}" in
      0)
        request="$( { printf 'GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: b3hpYmVsdC1mdXp6LWtleQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'; printf '\x81\x04%s' "${payload_hex}"; } | base64 -w0)"
        forbidden_hex="8104$(printf '%s' "${payload_hex}" | od -An -v -tx1 | tr -d ' \n')"
        ;;
      1)
        request="$( { printf 'GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: b3hpYmVsdC1mdXp6LWtleQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'; printf '\x09\x84\x10\x20\x30\x40%s' "${payload_hex}"; } | base64 -w0)"
        forbidden_hex="098410203040$(printf '%s' "${payload_hex}" | od -An -v -tx1 | tr -d ' \n')"
        forbidden_echo_hex='8904'
        ;;
      2)
        request="$( { printf 'GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: b3hpYmVsdC1mdXp6LWtleQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'; printf '\x89\xfe\x00\x7e\x10\x20\x30\x40'; } | base64 -w0)"
        forbidden_hex='89fe007e10203040'
        ;;
      *)
        request="$( { printf 'GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: b3hpYmVsdC1mdXp6LWtleQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'; printf '\x80\x80\x10\x20\x30\x40'; } | base64 -w0)"
        forbidden_hex='808010203040'
        forbidden_echo_hex='8000'
        ;;
    esac
    persist_raw_wire ws "${request}"
    raw_tls_request "${request}" "${output}"
    response_file="${work_dir}/session-response.bin"
    jq -r '.response_base64' "${output}" | base64 -d >"${response_file}"
    head -n 1 "${response_file}" | grep -Eq '^HTTP/1[.]1 101 ' || {
      echo "valid WebSocket upgrade did not establish before frame mutation" >&2
      return 1
    }
    response_hex="$(od -An -v -tx1 "${response_file}" | tr -d ' \n')"
    [[ "${response_hex}" != *8a* ]] || {
      echo "malformed WebSocket control frame elicited a pong" >&2
      return 1
    }
    [[ "${response_hex}" != *"${forbidden_hex}"* ]] || {
      echo "malformed WebSocket frame was echoed as valid application data" >&2
      return 1
    }
    if [[ -n "${forbidden_echo_hex}" && "${response_hex}" == *"${forbidden_echo_hex}"* ]]; then
      echo "malformed WebSocket frame was transformed into an application echo" >&2
      return 1
    fi
    printf 'rejected-or-closed\n' >"${work_dir}/last-session-result"
    [[ "$(wc -c <"${response_file}")" -le 16384 ]] || {
      echo "malformed WebSocket response exceeded the bounded outcome envelope" >&2
      return 1
    }
  else
    printf 'wt\n' >"${work_dir}/last-session-mode"
    case $((b1 % 3)) in
      0)
        sessions=1; require_concurrency_bound "${sessions}"
        record_mutation webtransport stream-and-datagram-echo "sessions-${sessions}" none
        expected_statuses=200
        probe_with_ca "${output}" webtransport-multiplex --host proxy --port 8443 \
          --server-name proxy --authority example.test \
          --path "/wt?case=$(input_hex 3 8)" --ca-cert /tmp/ca.pem \
          --sessions "${sessions}" --expect-statuses "${expected_statuses}" \
          --extended-protocol webtransport
        ;;
      *)
        require_concurrency_bound 1
        [[ $((b1 % 3)) == 1 ]] && extended_protocol=connect-udp || extended_protocol=none
        record_mutation webtransport rejected-extended-connect "${extended_protocol}" none
        probe_with_ca "${output}" webtransport-multiplex --host proxy --port 8443 \
          --server-name proxy --authority example.test \
          --path "/wt?case=$(input_hex 3 8)" --ca-cert /tmp/ca.pem \
          --sessions 1 --expect-rejected --extended-protocol "${extended_protocol}"
        ;;
    esac
  fi
}

turn_probe() {
  local transport="$1" auth="$2" expect="$3" output="$4" mutation="${5:-none}" username="${6:-}" port="${7:-}"
  [[ -n "${username}" ]] || username="$(read_credential "${turn_username_file}")"
  local turn_password
  turn_password="$(read_credential "${turn_password_file}")"
  local args=(turn-client --transport "${transport}" --host proxy)
  if [[ -n "${port}" ]]; then
    args+=(--port "${port}")
  else
    case "${transport}" in
      udp) args+=(--port 3478) ;;
      tcp) args+=(--port 3479) ;;
      tls) args+=(--port 5349 --server-name proxy --ca-cert /tmp/ca.pem) ;;
    esac
  fi
  args+=(--username "${username}" --realm turn.example.test --password "${turn_password}" \
    --auth "${auth}" --expect "${expect}" --mutation "${mutation}")
  if [[ "${transport}" == "tls" ]]; then
    probe_with_ca "${output}" "${args[@]}"
  else
    probe_without_files "${args[@]}" >"${output}"
  fi
}

start_turn_allocation_probe() {
  local client username turn_password
  client="$(container_name turn-allocation)"
  username="$(read_credential "${turn_username_file}")"
  turn_password="$(read_credential "${turn_password_file}")"
  [[ ! -e "${turn_allocation_client_file}" && ! -L "${turn_allocation_client_file}" ]] || {
    echo "TURN allocation probe state already exists" >&2
    return 1
  }
  if docker container inspect "${client}" >/dev/null 2>&1; then
    echo "TURN allocation probe container already exists" >&2
    return 1
  fi
  printf '%s\n' "${client}" >"${turn_allocation_client_file}"
  if ! docker create \
    --name "${client}" --label "${label}" --network "${network}" \
    "${probe_image}" turn-client --transport udp --host proxy --port 3480 \
    --username "${username}" --realm turn.example.test --password "${turn_password}" \
    --auth valid --expect allocate-success --mutation none \
    --allocation-hold-ms 4000 >/dev/null; then
    rm -f "${turn_allocation_client_file}"
    return 1
  fi
  docker start "${client}" >/dev/null
  printf '%s\n' "${client}"
}

wait_for_turn_allocation_visibility() {
  local client="$1" connections
  for _attempt in $(seq 1 20); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "${client}" 2>/dev/null || echo false)" != "true" ]]; then
      break
    fi
    connections="$(runtime_connections)"
    if jq -e '.turn.allocations_active == 1 and .turn.udp_clients_active >= 1' \
      <<<"${connections}" >/dev/null \
      && [[ "$(docker inspect -f '{{.State.Running}}' "${client}" 2>/dev/null || echo false)" == "true" ]]; then
      return 0
    fi
    sleep 0.1
  done
  docker logs "${client}" >&2 2>&1 || true
  echo "TURN edge allocation did not become visible while its probe was active" >&2
  return 1
}

finish_turn_allocation_probe() {
  local client expected_client wait_output wait_status=0 output
  [[ -e "${turn_allocation_client_file}" || -L "${turn_allocation_client_file}" ]] || return 0
  [[ -f "${turn_allocation_client_file}" && ! -L "${turn_allocation_client_file}" ]] || {
    echo "TURN allocation probe state is not a regular file" >&2
    return 1
  }
  IFS= read -r client <"${turn_allocation_client_file}"
  expected_client="$(container_name turn-allocation)"
  [[ "${client}" == "${expected_client}" ]] || {
    echo "TURN allocation probe state named an unexpected container" >&2
    return 1
  }
  docker container inspect "${client}" >/dev/null 2>&1 || {
    echo "TURN allocation probe container is missing" >&2
    return 1
  }
  wait_output="$(timeout --foreground 10s docker wait "${client}" 2>&1)" || wait_status=$?
  if ((wait_status != 0)); then
    docker logs "${client}" >&2 2>&1 || true
    echo "TURN allocation probe did not finish within its bounded hold" >&2
    return 1
  fi
  output="${work_dir}/turn-edge-allocation.json"
  (set +o pipefail; docker logs "${client}" 2>&1 | head -c 262144) >"${output}"
  if [[ "${wait_output}" != "0" ]] \
    || ! jq -e '.transport == "udp" and .expect == "allocate-success"' "${output}" >/dev/null; then
    echo "TURN allocation probe did not complete successfully" >&2
    return 1
  fi
  docker rm "${client}" >/dev/null
  rm -f "${turn_allocation_client_file}"
}

read_last_turn_transport() {
  local marker="${work_dir}/last-turn-transport" transport marker_size
  [[ -f "${marker}" && ! -L "${marker}" ]] || {
    echo "TURN recovery transport marker is not a regular file" >&2
    return 1
  }
  if ! IFS= read -r transport <"${marker}"; then
    echo "TURN recovery transport marker must contain one newline-terminated transport" >&2
    return 1
  fi
  case "${transport}" in
    udp|tcp|tls) ;;
    *)
      echo "TURN recovery transport marker contains an unsupported transport" >&2
      return 1
      ;;
  esac
  marker_size="$(wc -c <"${marker}")"
  [[ "${marker_size}" -eq $(( ${#transport} + 1 )) ]] || {
    echo "TURN recovery transport marker must contain exactly one transport" >&2
    return 1
  }
  printf '%s\n' "${transport}"
}

case_turn_runtime() {
  local b0 b1 b2 transport auth expectation output mutation username edge_mutation
  b0="$(input_byte 0)"; b1="$(input_byte 1)"; b2="$(input_byte 2)"
  require_concurrency_bound 1
  case $((b0 % 3)) in 0) transport=udp;; 1) transport=tcp;; *) transport=tls;; esac
  if ((b1 % 2 == 0)); then
    auth=invalid
    expectation=rejected
    case $((b2 % 4)) in
      0) mutation='none' ;;
      1) mutation='truncated-attribute' ;;
      2) mutation='length-mismatch' ;;
      *)
        # ChannelData carries no MESSAGE-INTEGRITY and is authoritative at the
        # selected upstream in proxy-pool mode. Echo proves one bounded handoff;
        # the post-case introspection baseline proves no local allocation.
        mutation='channel-data'
        expectation='echo'
        ;;
    esac
  else
    # `validate` deliberately leaves nonce challenges authoritative at the
    # upstream when credentials are absent. The controlled echo proves that
    # handoff without claiming that OxiBelt granted an allocation.
    auth=missing
    expectation="echo"
    mutation=none
  fi
  username="turn-$(input_hex 3 8)"
  record_mutation "${transport}+udp" proxy-pool-and-edge-relay \
    "${auth}-${mutation}" none
  printf '%s\n' "${transport}" >"${work_dir}/last-turn-transport"
  output="${work_dir}/turn-case.json"
  turn_probe "${transport}" "${auth}" "${expectation}" "${output}" "${mutation}" "${username}"
  case $((b2 % 3)) in
    0) edge_mutation='truncated-attribute' ;;
    1) edge_mutation='length-mismatch' ;;
    *) edge_mutation='channel-length-mismatch' ;;
  esac
  turn_probe udp invalid rejected "${work_dir}/turn-edge-malformed.json" \
    "${edge_mutation}" "$(read_credential "${turn_username_file}")" 3480
}

case_admin_authz() {
  local b0 b1 b2 mode before after output request body token auth_name payload mutation_header mutation_lines principal envelope_variant envelope_shape response_status admission_context precondition expected_previous_revision target
  b0="$(input_byte 0)"; b1="$(input_byte 1)"; b2="$(input_byte 2)"
  require_concurrency_bound 1
  mode=$((b0 % 4)); before="$(admin_state_digest)"; payload="$(input_hex 3 24)"
  output="${work_dir}/admin-case.json"
  case $((b2 % 3)) in
    0) body="{\"format\":\"toml\",\"config\":\"invalid-${payload}\"}" ;;
    1) body="{\"unknown_${payload}\":true}" ;;
    *) body="[\"${payload}\"]" ;;
  esac
  [[ $((b1 % 2)) == 0 ]] && auth_name='Authorization' || auth_name='authorization'
  local admin_profiles=(missing-auth malformed-auth denied-auth authorized-malformed-body)
  principal="admin"
  [[ "${mode}" == 2 ]] && principal="denied"
  case $((b2 % 4)) in
    0) envelope_variant="signature-invalid" ;;
    1) envelope_variant="digest-mismatch" ;;
    2) envelope_variant="principal-mismatch" ;;
    *) envelope_variant="unknown-signer" ;;
  esac
  envelope_shape=$((b1 % 4))
  case "${mode}" in
    0) token='' ;;
    1) token="${auth_name}: Bearer malformed-${payload}" ;;
    2) token="${auth_name}: Bearer $(read_credential "${denied_token_file}")" ;;
    *) token="${auth_name}: Bearer $(read_credential "${admin_token_file}")"; body="{\"format\":" ;;
  esac
  admission_context="$(admin_admission_context)"
  precondition="$(jq -er '.precondition' <<<"${admission_context}")"
  expected_previous_revision="$(jq -er '.expected_previous_revision' <<<"${admission_context}")"
  target="$(jq -cer '.target' <<<"${admission_context}")"
  mutation_header="$(mutation_envelope_header "${body}" "${principal}" "${envelope_variant}" \
    POST /admin/v1/config/load "${precondition}" "${expected_previous_revision}" "${target}")"
  case "${envelope_shape}" in
    0) mutation_lines='' ;;
    1) mutation_lines=$'X-OxiBelt-Mutation: malformed+base64\r\n' ;;
    2) mutation_lines="X-OxiBelt-Mutation: ${mutation_header}"$'\r\n' ;;
    *) mutation_lines="X-OxiBelt-Mutation: ${mutation_header}"$'\r\nX-OxiBelt-Mutation: duplicate\r\n' ;;
  esac
  record_mutation h1 admin-config-load "${admin_profiles[mode]}-${envelope_variant}-envelope-${envelope_shape}" header-case
  request="$(
    {
      printf 'POST /admin/v1/config/load HTTP/1.1\r\nHost: proxy\r\nContent-Type: application/json\r\nContent-Length: %s\r\nIf-Match: "%s"\r\n' "${#body}" "${precondition}"
      [[ -z "${token}" ]] || printf '%s\r\n' "${token}"
      printf '%s' "${mutation_lines}"
      printf 'Connection: close\r\n\r\n%s' "${body}"
    } | base64 -w0
  )"
  persist_raw_wire admin "${request}" redact-bearer
  probe_without_files raw-http --host proxy --port 9092 --request-base64 "${request}" >"${output}"
  response_status="$(jq -er '.response_base64 | @base64d' "${output}" | head -n 1 | awk '{print $2}')"
  [[ "${response_status}" =~ ^(400|401|403|409|412)$ ]] || {
    echo "Admin mutation envelope request did not fail closed: ${response_status}" >&2
    return 1
  }
  after="$(admin_state_digest)"
  [[ "${before}" == "${after}" ]] || { echo "Admin canonical state changed after rejected request" >&2; return 1; }
}

case_target() {
  case "${target}" in
    path_security) case_path_security ;;
    tls_quic_sni) case_tls_quic_sni ;;
    http_framing) case_http_framing ;;
    waf_bypass) case_waf_bypass ;;
    auth_bypass) case_auth_bypass ;;
    websocket_webtransport) case_websocket_webtransport ;;
    turn_runtime) case_turn_runtime ;;
    admin_authz) case_admin_authz ;;
  esac
}

wait_for_zero_tunnel_counts() {
  local connections
  for _attempt in $(seq 1 20); do
    connections="$(runtime_connections)"
    if jq -e '.tunnels.websocket_active == 0 and .tunnels.webtransport_sessions_active == 0' \
      <<<"${connections}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "session runtime counts did not recover" >&2
  return 1
}

wait_for_zero_turn_counts() {
  local connections
  for _attempt in $(seq 1 100); do
    connections="$(runtime_connections)"
    if jq -e '.turn.tcp_connections_active == 0 and .turn.tls_connections_active == 0 and .turn.udp_clients_active == 0 and .turn.allocations_active == 0' \
      <<<"${connections}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "TURN runtime counts did not recover" >&2
  return 1
}

admin_valid_mutation() {
  local output="${work_dir}/admin-recovery.json" admin_header admission_context precondition expected_previous_revision target mutation_header
  admin_header="Authorization: Bearer $(read_credential "${admin_token_file}")"
  admission_context="$(admin_admission_context)"
  precondition="$(jq -er '.precondition' <<<"${admission_context}")"
  expected_previous_revision="$(jq -er '.expected_previous_revision' <<<"${admission_context}")"
  target="$(jq -cer '.target' <<<"${admission_context}")"
  mutation_header="$(mutation_envelope_header '' admin valid POST \
    /admin/v1/tls/downstream/reload "${precondition}" "${expected_previous_revision}" "${target}")"
  admin_request "${output}" /admin/v1/tls/downstream/reload 200 POST '' \
    "${admin_header}" "If-Match: \"${precondition}\"" \
    "X-OxiBelt-Mutation: ${mutation_header}"
  jq -e '.body | fromjson | .ok == true' "${output}" >/dev/null
}

recovery_target() {
  local mode="${1:-post-case}" output="${work_dir}/recovery.json" client transport
  case "${mode}" in
    startup|post-case) ;;
    *)
      echo "unsupported security-fuzz recovery mode" >&2
      return 1
      ;;
  esac
  docker inspect -f '{{.State.Running}}' "${proxy}" | grep -qx true
  case "${target}" in
    path_security)
      downstream_any_status h2 static.example.test /static/public.txt "${output}"
      jq -e '.status == 200' "${output}" >/dev/null
      ;;
    tls_quic_sni|http_framing)
      downstream_request h3 '/recovery?operation_id=recovery' 200 "${output}"
      ;;
    waf_bypass)
      downstream_request h2 /sf-known-attack 403 "${output}"
      downstream_request h2 /clean 200 "${work_dir}/recovery-clean.json"
      ;;
    auth_bypass)
      downstream_request h2 /deny 401 "${output}" 'Authorization: Bearer malformed'
      downstream_request h2 /valid 200 "${work_dir}/recovery-valid.json" \
        'Authorization: Bearer synthetic-valid'
      ;;
    websocket_webtransport)
      if [[ "$(cat "${work_dir}/last-session-mode" 2>/dev/null || echo ws)" == "wt" ]]; then
        probe_with_ca "${output}" webtransport-multiplex --host proxy --port 8443 \
          --server-name proxy --authority example.test --path /wt --ca-cert /tmp/ca.pem \
          --sessions 1 --expect-statuses 200
      else
        probe_with_ca "${output}" websocket-client --host proxy --port 8443 \
          --server-name proxy --authority example.test --path /ws --ca-cert /tmp/ca.pem \
          --payload recovery --expect-status 101
      fi
      wait_for_zero_tunnel_counts
      ;;
    turn_runtime)
      if [[ "${mode}" == "startup" ]]; then
        turn_probe udp valid echo "${output}" \
          && wait_for_zero_turn_counts
      else
        transport="$(read_last_turn_transport)" \
          && client="$(start_turn_allocation_probe)" \
          && wait_for_turn_allocation_visibility "${client}" \
          && finish_turn_allocation_probe \
          && turn_probe "${transport}" valid echo "${output}" \
          && wait_for_zero_turn_counts
      fi
      ;;
    admin_authz)
      admin_valid_mutation
      ;;
  esac
}

show_topology_diagnostics() {
  docker ps -a --filter "label=${label}" --format '{{.Names}} {{.Status}}' >&2 || true
  docker volume inspect "${fixture_volume}" >&2 || true
  docker network inspect "${network}" >&2 || true
}

assert_topology_absent() {
  local containers
  if ! containers="$(docker ps -aq --filter "label=${label}")"; then
    echo "failed to enumerate scoped security-fuzz containers" >&2
    return 1
  fi
  if [[ -z "${containers}" ]] \
    && ! docker volume inspect "${fixture_volume}" >/dev/null 2>&1 \
    && ! docker network inspect "${network}" >/dev/null 2>&1; then
    return 0
  fi
  echo "security-fuzz topology already contains scoped resources" >&2
  show_topology_diagnostics
  return 1
}

start_topology() {
  require_image "${proxy_image}"
  require_image "${mock_image}"
  require_image "${probe_image}"
  if [[ "${target}" == "admin_authz" ]]; then
    require_image "${postgres_image}"
  fi
  assert_topology_absent
  generate_certificates
  generate_credentials
  generate_mutation_signer
  prepare_config
  docker network create --label "${label}" "${network}" >/dev/null
  start_target_helpers
  seed_proxy_fixture_volume
  start_proxy
  for _attempt in $(seq 1 40); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "${proxy}" 2>/dev/null || echo false)" != "true" ]]; then
      break
    fi
    if recovery_target startup >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  docker logs "${proxy}" 2>&1 | tail -n 80 >&2 || true
  echo "security-fuzz proxy did not become ready" >&2
  return 1
}

stop_topology() {
  local cleanup_status=0 containers container
  if ! containers="$(docker ps -aq --filter "label=${label}")"; then
    echo "failed to enumerate scoped security-fuzz containers" >&2
    return 1
  fi
  while read -r container; do
    [[ -n "${container}" ]] || continue
    if ! docker rm -f "${container}" >/dev/null; then
      docker inspect "${container}" >/dev/null 2>&1 && cleanup_status=1
    fi
  done <<<"${containers}"
  if docker volume inspect "${fixture_volume}" >/dev/null 2>&1 \
    && ! docker volume rm "${fixture_volume}" >/dev/null; then
    docker volume inspect "${fixture_volume}" >/dev/null 2>&1 && cleanup_status=1
  fi
  if docker network inspect "${network}" >/dev/null 2>&1 \
    && ! docker network rm "${network}" >/dev/null; then
    docker network inspect "${network}" >/dev/null 2>&1 && cleanup_status=1
  fi

  if ! containers="$(docker ps -aq --filter "label=${label}")"; then
    cleanup_status=1
  elif [[ -n "${containers}" ]]; then
    cleanup_status=1
  fi
  docker volume inspect "${fixture_volume}" >/dev/null 2>&1 && cleanup_status=1
  docker network inspect "${network}" >/dev/null 2>&1 && cleanup_status=1
  if ((cleanup_status != 0)); then
    echo "security-fuzz topology cleanup left scoped resources" >&2
    show_topology_diagnostics
    return 1
  fi
}

case "${command}" in
  start) start_topology ;;
  case)
    [[ -f "${OXIBELT_SECURITY_FUZZ_INPUT_FILE:-}" ]] || { echo "security-fuzz input is missing" >&2; exit 2; }
    [[ "${OXIBELT_SECURITY_FUZZ_CASE:-}" =~ ^[0-9]+$ ]] || { echo "invalid security-fuzz case" >&2; exit 2; }
    case_target
    ;;
  recovery) recovery_target ;;
  stop) stop_topology ;;
  *) echo "usage: executor.sh <start|case|recovery|stop>" >&2; exit 2 ;;
esac
