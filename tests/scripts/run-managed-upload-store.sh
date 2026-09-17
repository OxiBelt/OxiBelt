#!/usr/bin/env bash
# Qualify managed uploads against isolated PostgreSQL and TLS-only MinIO.
set -euo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
test_binary=""
postgres_image="${OXIBELT_POSTGRES_IMAGE:-postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2}"
minio_release="RELEASE.2025-10-15T17-29-55Z"
minio_version="2025-10-15T17:29:55Z"
minio_commit="9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a"
minio_sha256="45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841"
runtime_image="alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
mc_image="quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"

die(){ echo "managed upload store check: $*" >&2; exit 1; }
while (($#)); do case "$1" in
  --test-binary) (($#>=2))||die "--test-binary requires a path"; test_binary="$2"; shift 2;;
  *) die "unknown argument: $1";;
esac; done
for command in cargo cp cut date docker grep hostname id jq mkdir mktemp openssl rm sed sha256sum sleep timeout; do command -v "$command" >/dev/null||die "missing command: $command"; done
[[ -z "$test_binary" || -x "$test_binary" ]]||die "test binary is not executable: $test_binary"
docker version --format '{{.Server.Version}}' >/dev/null
if ! docker info --format '{{json .SecurityOptions}}'|grep -Fq 'name=rootless'; then
  [[ "${OXIBELT_MANAGED_UPLOAD_ALLOW_HOSTED_DOCKER:-}" == 1 && "${GITHUB_ACTIONS:-}" == true ]]||die "rootless Docker is required"
fi

work_dir=""; network=""; pg=""; minio=""; mc=""; seed=""; image=""; client=""; cert_volume=""; data_volume=""; connected=false
cleanup(){ status=$?; set +e
  [[ -n "$mc" ]]&&docker rm -f "$mc" >/dev/null 2>&1
  [[ -n "$seed" ]]&&docker rm -f "$seed" >/dev/null 2>&1
  [[ -n "$pg" ]]&&docker rm -fv "$pg" >/dev/null 2>&1
  [[ -n "$minio" ]]&&docker rm -fv "$minio" >/dev/null 2>&1
  $connected&&docker network disconnect -f "$network" "$client" >/dev/null 2>&1
  [[ -n "$network" ]]&&docker network rm "$network" >/dev/null 2>&1
  [[ -n "$cert_volume" ]]&&docker volume rm "$cert_volume" >/dev/null 2>&1
  [[ -n "$data_volume" ]]&&docker volume rm "$data_volume" >/dev/null 2>&1
  [[ -n "$image" ]]&&docker image rm -f "$image" >/dev/null 2>&1
  [[ -n "$work_dir" ]]&&rm -rf -- "$work_dir"
  exit "$status"
}; trap cleanup EXIT

mkdir -p "$repo_root/target"
work_dir="$(mktemp -d "$repo_root/target/managed-upload-store.XXXXXX")"
run_id="$(printf '%s' "$$:${RANDOM}:$(date +%s%N)"|sha256sum|cut -c1-16)"
network="oxibelt-upload-${run_id}"; pg="oxibelt-upload-pg-${run_id}"; minio="oxibelt-upload-s3-${run_id}"
image="oxibelt/managed-upload-minio:${run_id}"; label="oxibelt.test.run=managed-upload-${run_id}"
cert_volume="oxibelt-upload-certs-${run_id}"; data_volume="oxibelt-upload-data-${run_id}"
docker_root="$repo_root"
if mounts="$(docker inspect "$(hostname)" --format '{{json .Mounts}}' 2>/dev/null)"; then
  client="$(hostname)"
  docker_root="$(jq -r --arg repo "$repo_root" '[.[] as $mount|select($repo==$mount.Destination or ($repo|startswith($mount.Destination+"/")))|{n:($mount.Destination|length),p:($mount.Source+($repo|ltrimstr($mount.Destination)))}]|sort_by(.n)|last.p//empty' <<<"$mounts")"
  [[ "$docker_root" == /* ]]||die "cannot map repository into Docker host"
fi
docker_work="$docker_root${work_dir#"$repo_root"}"
mkdir -p "$work_dir/certs" "$work_dir/data" "$work_dir/mc-ca"
ca="$work_dir/ca.crt"; cakey="$work_dir/ca.key"; key="$work_dir/certs/private.key"; csr="$work_dir/server.csr"; cert="$work_dir/certs/public.crt"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 -subj '/CN=OxiBelt upload test CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$cakey" -out "$ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=minio' -addext 'subjectAltName=DNS:minio,DNS:localhost,IP:127.0.0.1' -keyout "$key" -out "$csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 -CA "$ca" -CAkey "$cakey" -CAcreateserial -in "$csr" -out "$cert" -extfile <(printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:minio,DNS:localhost,IP:127.0.0.1') >/dev/null 2>&1
chmod 0600 "$cakey" "$key"; cp "$ca" "$work_dir/mc-ca/upload-ca.crt"

docker build --pull=false --label "$label" --build-arg MINIO_SOURCE_RELEASE="$minio_release" --build-arg MINIO_SOURCE_VERSION="$minio_version" --build-arg MINIO_SOURCE_COMMIT="$minio_commit" --build-arg MINIO_SOURCE_SHA256="$minio_sha256" -t "$image" "$repo_root/tests/docker/ct_object_store_minio"
docker network create --label "$label" "$network" >/dev/null
docker volume create --label "$label" "$cert_volume" >/dev/null
docker volume create --label "$label" "$data_volume" >/dev/null
minio_uid="$(docker run --rm --entrypoint id "$image" -u)"; minio_gid="$(docker run --rm --entrypoint id "$image" -g)"
[[ "$minio_uid" =~ ^[0-9]+$ && "$minio_gid" =~ ^[0-9]+$ ]]||die "could not resolve MinIO image identity"
seed="oxibelt-upload-seed-${run_id}"
docker create --name "$seed" --label "$label" --mount "type=volume,src=$cert_volume,dst=/certs" --mount "type=volume,src=$data_volume,dst=/data" "$runtime_image" sh -c "chown -R $minio_uid:$minio_gid /certs /data && chmod 0700 /certs /data && chmod 0600 /certs/private.key && chmod 0644 /certs/public.crt" >/dev/null
docker cp "$work_dir/certs/." "$seed:/certs"
docker start --attach "$seed" >/dev/null
docker rm "$seed" >/dev/null; seed=""
if [[ -n "$client" ]]; then docker network connect "$network" "$client"; connected=true; fi
pgpass="$(printf '%s' "pg:${run_id}"|sha256sum|cut -c1-32)"; access="upload${run_id}"; secret="$(printf '%s' "s3:${run_id}"|sha256sum|cut -c1-40)"
docker run -d --name "$pg" --label "$label" --network "$network" --network-alias postgres -p 127.0.0.1::5432 -e POSTGRES_USER=oxibelt -e POSTGRES_DB=oxibelt -e POSTGRES_PASSWORD="$pgpass" "$postgres_image" >/dev/null
docker run -d --name "$minio" --label "$label" --network "$network" --network-alias minio -p 127.0.0.1::9000 -e MINIO_ROOT_USER="$access" -e MINIO_ROOT_PASSWORD="$secret" --mount "type=volume,src=$cert_volume,dst=/certs,readonly" --mount "type=volume,src=$data_volume,dst=/data" "$image" server --certs-dir /certs /data >/dev/null
for _ in {1..30}; do docker exec "$pg" pg_isready -U oxibelt -d oxibelt >/dev/null 2>&1&&break; sleep 1; done
docker exec "$pg" pg_isready -U oxibelt -d oxibelt >/dev/null||die "PostgreSQL not ready"
mc_run(){ mc="oxibelt-upload-mc-${run_id}"; status=0; timeout 30s docker run --name "$mc" --rm --network "$network" --mount "type=bind,src=$docker_work/mc-ca,dst=/root/.mc/certs/CAs,readonly" -e "MC_HOST_local=https://${access}:${secret}@minio:9000" "$mc_image" "$@"||status=$?; if ((status!=0)); then docker rm -f "$mc" >/dev/null 2>&1||true; fi; mc=""; return "$status"; }
for _ in {1..30}; do mc_run ready local >/dev/null 2>&1&&break; sleep 1; done
mc_run ready local >/dev/null||die "MinIO not ready"
bucket="upload-${run_id}"; bucket2="upload-second-${run_id}"; mc_run mb "local/$bucket" >/dev/null; mc_run mb "local/$bucket2" >/dev/null

pg_host=127.0.0.1; pg_port="$(docker port "$pg" 5432/tcp|sed -n 's/^127\.0\.0\.1:\([0-9]*\)$/\1/p')"; s3_host=127.0.0.1; s3_port="$(docker port "$minio" 9000/tcp|sed -n 's/^127\.0\.0\.1:\([0-9]*\)$/\1/p')"
verify_option=-verify_ip
if [[ -n "$client" ]]; then pg_host=postgres; pg_port=5432; s3_host=minio; s3_port=9000; verify_option=-verify_hostname; fi
openssl s_client -connect "$s3_host:$s3_port" -verify_return_error "$verify_option" "$s3_host" -CAfile "$ca" </dev/null >/dev/null 2>&1||die "MinIO TLS verification failed"
export TEST_UPLOAD_POSTGRES_URL="postgres://oxibelt:${pgpass}@${pg_host}:${pg_port}/oxibelt"
export TEST_UPLOAD_S3_ENDPOINT="https://${s3_host}:${s3_port}" TEST_UPLOAD_S3_BUCKET="$bucket" TEST_UPLOAD_S3_BUCKET_2="$bucket2" TEST_UPLOAD_S3_REGION=us-east-1
export TEST_UPLOAD_S3_ACCESS_KEY="$access" TEST_UPLOAD_S3_SECRET_KEY="$secret" TEST_UPLOAD_S3_ROOT_CERTIFICATE="$ca" OXIBELT_REQUIRE_UPLOAD_POSTGRES_S3_TESTS=1
test_name='uploads::postgres_s3::tests::postgres_s3_lifecycle_fences_discovery_and_enforces_session_quota'
if [[ -n "$test_binary" ]]; then "$test_binary" --exact "$test_name" --nocapture; else cargo test --locked -p oxibelt --lib "$test_name" -- --exact --nocapture; fi
echo "managed upload store check: PASS"
