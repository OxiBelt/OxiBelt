#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

postgres_image="${OXIBELT_POSTGRES_IMAGE:-postgres:18-alpine}"
if [[ ! "${postgres_image}" =~ ^[[:alnum:]][[:alnum:]_.:/@-]*$ ]]; then
  echo "OXIBELT_POSTGRES_IMAGE must be one non-option Docker image reference" >&2
  exit 2
fi
run_token="$(printf '%s-%s' "${GITHUB_RUN_ID:-local}" "$$" | tr -c '[:alnum:]_.-' '-')"
container_name="oxibelt-admin-operation-postgres-${run_token}"
test_label="dev.oxibelt.test=admin-operation-postgres-${run_token}"
postgres_password="$(od -An -N 32 -tx1 /dev/urandom)"
postgres_password="${postgres_password//[[:space:]]/}"
if [[ ! "${postgres_password}" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "Failed to generate an ephemeral PostgreSQL test password" >&2
  exit 1
fi
docker_publish_args=(--publish 127.0.0.1::5432)
if [[ "${REMOTE_CONTAINERS:-}" == "true" ]]; then
  # The devcontainer can reach sibling rootless containers directly, so no
  # host listener is needed merely to cross container namespaces.
  docker_publish_args=()
fi

cleanup() {
  docker rm --force --volumes "${container_name}" >/dev/null 2>&1 || true
}

postgres_logs() {
  docker logs "${container_name}" >&2 || true
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker run --detach \
  --name "${container_name}" \
  --label "${test_label}" \
  "${docker_publish_args[@]}" \
  --env POSTGRES_USER=oxibelt \
  --env "POSTGRES_PASSWORD=${postgres_password}" \
  --env POSTGRES_DB=oxibelt \
  "${postgres_image}" >/dev/null

ready=0
for _attempt in $(seq 1 60); do
  if docker exec "${container_name}" pg_isready \
    --host 127.0.0.1 \
    --username oxibelt \
    --dbname oxibelt >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "${ready}" != "1" ]]; then
  echo "PostgreSQL did not become ready within 60 seconds" >&2
  postgres_logs
  exit 1
fi

postgres_connect_host="${OXIBELT_POSTGRES_CONNECT_HOST:-}"
if [[ "${REMOTE_CONTAINERS:-}" == "true" ]]; then
  postgres_connect_host="${postgres_connect_host:-$(docker inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "${container_name}")}"
  host_port="5432"
else
  postgres_connect_host="${postgres_connect_host:-127.0.0.1}"
  host_port="$(docker inspect \
    --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' \
    "${container_name}")"
fi
if [[ ! "${postgres_connect_host}" =~ ^[[:alnum:]][[:alnum:].-]*$ ]]; then
  echo "OXIBELT_POSTGRES_CONNECT_HOST must be one IPv4 address or DNS name" >&2
  postgres_logs
  exit 2
fi
if [[ ! "${host_port}" =~ ^[0-9]+$ ]]; then
  echo "Docker returned an invalid PostgreSQL host port" >&2
  postgres_logs
  exit 1
fi

export OXIBELT_REQUIRE_ADMIN_OPERATION_POSTGRES_TESTS=1
export OXIBELT_TEST_ADMIN_OPERATION_POSTGRES_URL="postgres://oxibelt:${postgres_password}@${postgres_connect_host}:${host_port}/oxibelt"

cd -- "${repo_root}"
if ! timeout --signal=TERM 35m \
  cargo test --all-features --locked -p oxibelt --lib \
  'admin_operations::store::postgres_tests::' -- --test-threads=1; then
  postgres_logs
  exit 1
fi
