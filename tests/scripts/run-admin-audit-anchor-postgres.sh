#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

postgres_image="${OXIBELT_POSTGRES_IMAGE:-postgres:18-alpine}"
if [[ ! "${postgres_image}" =~ ^[[:alnum:]][[:alnum:]_.:/@-]*$ ]]; then
  echo "OXIBELT_POSTGRES_IMAGE must be one non-option Docker image reference" >&2
  exit 2
fi

random_hex() {
  local bytes="$1"
  local value
  value="$(od -An -N "${bytes}" -tx1 /dev/urandom)"
  value="${value//[[:space:]]/}"
  if [[ ! "${value}" =~ ^[[:xdigit:]]+$ ]]; then
    echo "Failed to generate ephemeral PostgreSQL test material" >&2
    exit 1
  fi
  printf '%s' "${value}"
}

run_suffix="$(random_hex 8)"
run_token="$(printf '%s-%s' "$$" "${run_suffix}" | tr -c '[:alnum:]_.-' '-')"
local_container="oxibelt-audit-local-${run_token}"
authority_container="oxibelt-audit-authority-${run_token}"
test_label="dev.oxibelt.test=admin-audit-anchor-${run_token}"

local_owner="local_owner_${run_suffix}"
local_database="local_audit_${run_suffix}"
local_password="$(random_hex 32)"
authority_owner="anchor_owner_${run_suffix}"
authority_database="anchor_db_${run_suffix}"
authority_owner_password="$(random_hex 32)"
runtime_role="anchor_runtime_${run_suffix}"
runtime_password="$(random_hex 32)"
verifier_role="anchor_verifier_${run_suffix}"
verifier_password="$(random_hex 32)"
authority_id="anchor-authority-${run_suffix}"

for identifier in \
  "${local_owner}" "${local_database}" "${authority_owner}" \
  "${authority_database}" "${runtime_role}" "${verifier_role}"; do
  if [[ ! "${identifier}" =~ ^[a-z][a-z0-9_]{1,62}$ ]]; then
    echo "Generated PostgreSQL identifier is invalid" >&2
    exit 1
  fi
done
for secret in \
  "${local_password}" "${authority_owner_password}" \
  "${runtime_password}" "${verifier_password}"; do
  if [[ ! "${secret}" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "Generated PostgreSQL password is invalid" >&2
    exit 1
  fi
done

docker_publish_args=(--publish 127.0.0.1::5432)
if [[ "${REMOTE_CONTAINERS:-}" == "true" ]]; then
  docker_publish_args=()
fi

cleanup() {
  docker rm --force --volumes "${local_container}" >/dev/null 2>&1 || true
  docker rm --force --volumes "${authority_container}" >/dev/null 2>&1 || true
}

postgres_logs() {
  docker logs "${local_container}" >&2 || true
  docker logs "${authority_container}" >&2 || true
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker run --detach \
  --name "${local_container}" \
  --label "${test_label}" \
  "${docker_publish_args[@]}" \
  --env "POSTGRES_USER=${local_owner}" \
  --env "POSTGRES_PASSWORD=${local_password}" \
  --env "POSTGRES_DB=${local_database}" \
  "${postgres_image}" >/dev/null

docker run --detach \
  --name "${authority_container}" \
  --label "${test_label}" \
  "${docker_publish_args[@]}" \
  --env "POSTGRES_USER=${authority_owner}" \
  --env "POSTGRES_PASSWORD=${authority_owner_password}" \
  --env "POSTGRES_DB=${authority_database}" \
  "${postgres_image}" >/dev/null

ready=0
for _attempt in $(seq 1 60); do
  if docker exec "${local_container}" pg_isready \
    --host 127.0.0.1 --username "${local_owner}" --dbname "${local_database}" >/dev/null 2>&1 \
    && docker exec "${authority_container}" pg_isready \
      --host 127.0.0.1 --username "${authority_owner}" --dbname "${authority_database}" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" != "1" ]]; then
  echo "Both PostgreSQL instances did not become ready within 60 seconds" >&2
  postgres_logs
  exit 1
fi

docker cp \
  "${repo_root}/deploy/postgres/admin-audit-anchor-v1.sql" \
  "${authority_container}:/tmp/admin-audit-anchor-v1.sql"
docker exec \
  --env "PGPASSWORD=${authority_owner_password}" \
  --env "PGOPTIONS=-c oxibelt.anchor_authority_id=${authority_id}" \
  "${authority_container}" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --host 127.0.0.1 --username "${authority_owner}" --dbname "${authority_database}" \
    --file /tmp/admin-audit-anchor-v1.sql >/dev/null

docker exec --env "PGPASSWORD=${authority_owner_password}" "${authority_container}" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --host 127.0.0.1 --username "${authority_owner}" --dbname "${authority_database}" \
    --command "CREATE ROLE \"${runtime_role}\" LOGIN PASSWORD '${runtime_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; CREATE ROLE \"${verifier_role}\" LOGIN PASSWORD '${verifier_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;" >/dev/null
docker exec --env "PGPASSWORD=${authority_owner_password}" "${authority_container}" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --host 127.0.0.1 --username "${authority_owner}" --dbname "${authority_database}" \
    --command "GRANT USAGE ON SCHEMA oxibelt_audit_anchor_v1 TO \"${runtime_role}\", \"${verifier_role}\"; GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.authority_info() TO \"${runtime_role}\", \"${verifier_role}\"; GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.append_checkpoint(jsonb), oxibelt_audit_anchor_v1.lookup_checkpoint(text,text,bigint) TO \"${runtime_role}\"; GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.checkpoints(text,text), oxibelt_audit_anchor_v1.head(text,text) TO \"${verifier_role}\";" >/dev/null

local_host_override="${OXIBELT_ADMIN_AUDIT_LOCAL_POSTGRES_CONNECT_HOST:-${OXIBELT_POSTGRES_CONNECT_HOST:-}}"
authority_host_override="${OXIBELT_ADMIN_AUDIT_ANCHOR_POSTGRES_CONNECT_HOST:-${OXIBELT_POSTGRES_CONNECT_HOST:-}}"
for override in "${local_host_override}" "${authority_host_override}"; do
  if [[ -n "${override}" && ! "${override}" =~ ^[[:alnum:]][[:alnum:].-]*$ ]]; then
    echo "PostgreSQL connect-host overrides must be one IPv4 address or DNS name" >&2
    postgres_logs
    exit 2
  fi
done

if [[ "${REMOTE_CONTAINERS:-}" == "true" ]]; then
  local_host="${local_host_override:-$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${local_container}")}"
  authority_host="${authority_host_override:-$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${authority_container}")}"
  local_port=5432
  authority_port=5432
else
  local_host="${local_host_override:-127.0.0.1}"
  authority_host="${authority_host_override:-127.0.0.1}"
  local_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "${local_container}")"
  authority_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "${authority_container}")"
fi
for host in "${local_host}" "${authority_host}"; do
  if [[ ! "${host}" =~ ^[[:alnum:]][[:alnum:].-]*$ ]]; then
    echo "Docker returned an invalid PostgreSQL address" >&2
    postgres_logs
    exit 1
  fi
done
for port in "${local_port}" "${authority_port}"; do
  if [[ ! "${port}" =~ ^[0-9]+$ ]]; then
    echo "Docker returned an invalid PostgreSQL port" >&2
    postgres_logs
    exit 1
  fi
done

export OXIBELT_REQUIRE_ADMIN_AUDIT_ANCHOR_POSTGRES_TESTS=1
export OXIBELT_TEST_ADMIN_AUDIT_LOCAL_POSTGRES_URL="postgres://${local_owner}:${local_password}@${local_host}:${local_port}/${local_database}"
export OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_RUNTIME_POSTGRES_URL="postgres://${runtime_role}:${runtime_password}@${authority_host}:${authority_port}/${authority_database}"
export OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_VERIFIER_POSTGRES_URL="postgres://${verifier_role}:${verifier_password}@${authority_host}:${authority_port}/${authority_database}"
export OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_AUTHORITY_ID="${authority_id}"

cd -- "${repo_root}"
if ! timeout --signal=TERM 35m \
  cargo test --all-features --locked -p oxibelt --lib \
  'admin_audit::anchor::postgres_tests::' -- --test-threads=1; then
  postgres_logs
  exit 1
fi
