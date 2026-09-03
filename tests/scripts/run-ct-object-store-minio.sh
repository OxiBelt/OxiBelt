#!/usr/bin/env bash
# Exercise the CT S3 object-store adapter against a TLS-only, versioned MinIO
# server. All Docker resources are uniquely labelled and removed on exit.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
temp_root="${OXIBELT_CT_OBJECT_STORE_TEMP_ROOT:-${repo_root}/target}"
receipt_output=""
work_dir=""
network_name=""
minio_container=""
mc_container=""
image_name=""
client_container=""
client_network_connected="false"

minio_source_release="RELEASE.2025-10-15T17-29-55Z"
minio_source_version="2025-10-15T17:29:55Z"
minio_source_commit="9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a"
minio_source_sha256="45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841"
minio_builder_image="golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56"
minio_runtime_image="alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
mc_image="quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"

die() {
  echo "CT object-store MinIO check: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "${mc_container}" ]]; then
    docker rm --force "${mc_container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${minio_container}" ]]; then
    docker rm --force "${minio_container}" >/dev/null 2>&1 || true
  fi
  if [[ "${client_network_connected}" == "true" ]]; then
    docker network disconnect --force "${network_name}" "${client_container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${network_name}" ]]; then
    docker network rm "${network_name}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${image_name}" ]]; then
    docker image rm --force "${image_name}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${work_dir}" ]]; then
    rm -rf -- "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT

while (($#)); do
  case "$1" in
    --receipt-output)
      (($# >= 2)) || die "--receipt-output requires a path"
      receipt_output="$2"
      shift 2
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "${receipt_output}" ]] || die "--receipt-output is required"

for command in cargo chmod cp cut date dirname docker git grep head hostname id jq mkdir mktemp mv openssl rm sed sha256sum sleep timeout; do
  require_command "${command}"
done

docker version --format '{{.Server.Version}}' >/dev/null
if ! docker info --format '{{json .SecurityOptions}}' | grep -Fq 'name=rootless'; then
  [[ "${OXIBELT_CT_OBJECT_STORE_ALLOW_HOSTED_DOCKER:-}" == "1" \
    && "${GITHUB_ACTIONS:-}" == "true" \
    && "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] \
    || die "CT object-store MinIO check requires rootless Docker outside GitHub-hosted CI"
fi

source_revision="$(git -C "${repo_root}" rev-parse HEAD)"
source_tree="$(git -C "${repo_root}" rev-parse 'HEAD^{tree}')"
[[ "${source_revision}" =~ ^[0-9a-f]{40}$ && "${source_tree}" =~ ^[0-9a-f]{40}$ ]] \
  || die "current Git revision and source tree must be full lowercase hashes"
source_worktree_state="clean"
if ! git -C "${repo_root}" diff --quiet \
  || ! git -C "${repo_root}" diff --cached --quiet \
  || [[ -n "$(git -C "${repo_root}" ls-files --others --exclude-standard)" ]]; then
  source_worktree_state="modified"
fi
if [[ "${GITHUB_ACTIONS:-}" == "true" && "${source_worktree_state}" != "clean" ]]; then
  die "hosted CT object-store evidence requires a clean exact-revision checkout"
fi

docker_repo_root="${repo_root}"
if container_mounts="$(docker inspect "$(hostname)" --format '{{json .Mounts}}' 2>/dev/null)"; then
  client_container="$(hostname)"
  mapped_repo_root="$(
    jq -r --arg repo "${repo_root}" '
      [
        .[] as $mount
        | select(
            $repo == $mount.Destination
            or ($repo | startswith($mount.Destination + "/"))
          )
        | {
            length: ($mount.Destination | length),
            path: ($mount.Source + ($repo | ltrimstr($mount.Destination)))
          }
      ]
      | sort_by(.length)
      | last.path // empty
    ' <<<"${container_mounts}"
  )"
  [[ -n "${mapped_repo_root}" && "${mapped_repo_root}" == /* ]] \
    || die "could not derive the host-visible repository path from Docker mount metadata"
  docker_repo_root="${mapped_repo_root}"
fi

mkdir -p -- "${temp_root}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-ct-object-store-minio.XXXXXX")"
[[ "${work_dir}" == "${repo_root}"/* ]] \
  || die "ephemeral CT object-store directory escaped the repository root"
docker_work_dir="${docker_repo_root}${work_dir#"${repo_root}"}"
run_id="$(printf '%s' "${source_revision}:${BASHPID}:${RANDOM}:$(date +%s%N)" | sha256sum | cut -c1-16)"
[[ "${run_id}" =~ ^[0-9a-f]{16}$ ]] || die "could not derive a bounded run ID"
network_name="oxibelt-ct-object-store-${run_id}"
minio_container="oxibelt-ct-minio-${run_id}"
image_name="oxibelt/ct-object-store-minio:${run_id}"
test_label="oxibelt.test.run=ct-object-store-minio-${run_id}"
cert_dir="${work_dir}/certs"
data_dir="${work_dir}/data"
mc_ca_dir="${work_dir}/mc-ca"
mkdir -p "${cert_dir}" "${data_dir}" "${mc_ca_dir}"

ca_key="${work_dir}/ca.key"
ca_cert="${work_dir}/ca.crt"
server_key="${cert_dir}/private.key"
server_csr="${work_dir}/server.csr"
server_cert="${cert_dir}/public.crt"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=OxiBelt CT object-store test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -keyout "${ca_key}" -out "${ca_cert}" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=127.0.0.1' \
  -addext 'subjectAltName=DNS:minio,DNS:localhost,IP:127.0.0.1' \
  -keyout "${server_key}" -out "${server_csr}" >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial \
  -in "${server_csr}" -out "${server_cert}" \
  -extfile <(
    printf '%s\n' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth' \
      'subjectAltName=DNS:minio,DNS:localhost,IP:127.0.0.1' \
      'authorityKeyIdentifier=keyid,issuer'
  ) >/dev/null 2>&1
chmod 0600 "${ca_key}" "${server_key}"
cp -- "${ca_cert}" "${mc_ca_dir}/ct-object-store-test-ca.crt"

docker build --pull=false --label "${test_label}" \
  --build-arg "MINIO_SOURCE_RELEASE=${minio_source_release}" \
  --build-arg "MINIO_SOURCE_VERSION=${minio_source_version}" \
  --build-arg "MINIO_SOURCE_COMMIT=${minio_source_commit}" \
  --build-arg "MINIO_SOURCE_SHA256=${minio_source_sha256}" \
  --tag "${image_name}" "${repo_root}/tests/docker/ct_object_store_minio"
docker network create --label "${test_label}" "${network_name}" >/dev/null
if [[ -n "${client_container}" ]]; then
  docker network connect "${network_name}" "${client_container}"
  client_network_connected="true"
fi

access_key_id="minio${run_id:0:12}"
secret_access_key="$(printf '%s' "${run_id}:${source_tree}" | sha256sum | cut -c1-40)"
docker run --detach --name "${minio_container}" --label "${test_label}" \
  --network "${network_name}" --network-alias minio --publish 127.0.0.1::9000 \
  --user "$(id --user):$(id --group)" \
  --env "MINIO_ROOT_USER=${access_key_id}" \
  --env "MINIO_ROOT_PASSWORD=${secret_access_key}" \
  --mount "type=bind,src=${docker_work_dir}/certs,dst=/certs,readonly" \
  --mount "type=bind,src=${docker_work_dir}/data,dst=/data" \
  "${image_name}" server --certs-dir /certs /data >/dev/null

mc_run_as() {
  local alias="$1"
  local username="$2"
  local password="$3"
  shift 3
  local status=0
  local -a policy_mount=()
  if [[ -n "${docker_workload_policy_file:-}" ]]; then
    policy_mount=(
      --mount "type=bind,src=${docker_workload_policy_file},dst=/workload-policy.json,readonly"
    )
  fi
  mc_sequence=$((mc_sequence + 1))
  mc_container="oxibelt-ct-mc-${run_id}-${mc_sequence}"
  timeout --signal=TERM --kill-after=2s 5s docker run \
    --name "${mc_container}" --label "${test_label}" --rm \
    --network "${network_name}" \
    --mount "type=bind,src=${docker_work_dir}/mc-ca,dst=/root/.mc/certs/CAs,readonly" \
    "${policy_mount[@]}" \
    --env "MC_HOST_${alias}=https://${username}:${password}@minio:9000" \
    "${mc_image}" "$@" || status=$?
  if ((status != 0)); then
    docker rm --force "${mc_container}" >/dev/null 2>&1 || true
  fi
  mc_container=""
  return "${status}"
}

mc_run() {
  mc_run_as local "${access_key_id}" "${secret_access_key}" "$@"
}

mc_workload_run() {
  mc_run_as workload "${workload_access_key_id}" "${workload_secret_access_key}" "$@"
}

mc_sequence=0
for _attempt in {1..18}; do
  if mc_run ready local >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
mc_run ready local >/dev/null || {
  docker logs "${minio_container}" >&2 || true
  die "MinIO did not become ready"
}

bucket="ct-object-store-${run_id}"
mc_run mb --with-lock "local/${bucket}" >/dev/null
mc_run retention set --default compliance 1d "local/${bucket}/" >/dev/null
retention_info="$(mc_run stat --json "local/${bucket}")"
if ! jq -e '
      .status == "success"
      and .Versioning.status == "Enabled"
      and .ObjectLock.enabled == "Enabled"
      and (.ObjectLock.mode | ascii_upcase) == "COMPLIANCE"
      and .ObjectLock.validity == "1DAYS"
    ' <<<"${retention_info}" >/dev/null; then
  jq '{status, Versioning, ObjectLock}' <<<"${retention_info}" >&2 || true
  die "MinIO bucket did not report exact versioning and retention policy"
fi

delete_denial_bucket="ct-delete-denial-${run_id}"
mc_run mb "local/${delete_denial_bucket}" >/dev/null
mc_run version enable "local/${delete_denial_bucket}" >/dev/null

workload_access_key_id="ctworkload${run_id:0:10}"
workload_secret_access_key="$(printf '%s' "workload:${run_id}:${source_tree}" | sha256sum | cut -c1-40)"
workload_policy_name="ct-workload-${run_id}"
workload_policy_file="${work_dir}/workload-policy.json"
docker_workload_policy_file="${docker_work_dir}/workload-policy.json"
jq --null-input \
  --arg bucket "${bucket}" \
  --arg delete_denial_bucket "${delete_denial_bucket}" '
  {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketVersions"],
        Resource: [
          "arn:aws:s3:::" + $bucket,
          "arn:aws:s3:::" + $delete_denial_bucket
        ]
      },
      {
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
        Resource: [
          "arn:aws:s3:::" + $bucket + "/*",
          "arn:aws:s3:::" + $delete_denial_bucket + "/*"
        ]
      },
      {
        Effect: "Deny",
        Action: ["s3:DeleteObject", "s3:DeleteObjectVersion"],
        Resource: [
          "arn:aws:s3:::" + $bucket + "/*",
          "arn:aws:s3:::" + $delete_denial_bucket + "/*"
        ]
      }
    ]
  }
' >"${workload_policy_file}"
chmod 0600 "${workload_policy_file}"
mc_run admin user add local "${workload_access_key_id}" "${workload_secret_access_key}" >/dev/null
mc_run admin policy create local "${workload_policy_name}" /workload-policy.json >/dev/null
mc_run admin policy attach local "${workload_policy_name}" \
  --user "${workload_access_key_id}" >/dev/null

host_port="$(docker port "${minio_container}" 9000/tcp | sed -n 's#^127\.0\.0\.1:\([0-9][0-9]*\)$#\1#p' | head -n 1)"
[[ "${host_port}" =~ ^[0-9]+$ ]] || die "could not determine the MinIO loopback port"
endpoint_host="127.0.0.1"
endpoint_port="${host_port}"
openssl_verify_option="-verify_ip"
if [[ -n "${client_container}" ]]; then
  endpoint_host="minio"
  endpoint_port="9000"
  openssl_verify_option="-verify_hostname"
fi
timeout --signal=TERM --kill-after=2s 5s openssl s_client \
  -connect "${endpoint_host}:${endpoint_port}" \
  -verify_return_error "${openssl_verify_option}" "${endpoint_host}" -CAfile "${ca_cert}" \
  </dev/null >/dev/null 2>&1 \
  || die "MinIO TLS endpoint failed CA and endpoint identity verification"

OXIBELT_TEST_CT_MINIO_ENDPOINT="https://${endpoint_host}:${endpoint_port}" \
OXIBELT_TEST_CT_MINIO_BUCKET="${bucket}" \
OXIBELT_TEST_CT_MINIO_ACCESS_KEY_ID="${workload_access_key_id}" \
OXIBELT_TEST_CT_MINIO_SECRET_ACCESS_KEY="${workload_secret_access_key}" \
OXIBELT_TEST_CT_MINIO_CA_PEM="${ca_cert}" \
  cargo test --locked -p oxibelt minio_tls_publishes_with_test_root_certificate

delete_probe_object="workload/${delete_denial_bucket}/delete-probe"
mc_workload_run cp /workload-policy.json "${delete_probe_object}" >/dev/null
delete_probe_listing="$(
  mc_run ls --versions --recursive --json "local/${delete_denial_bucket}/"
)" || die "MinIO could not list delete-denial probe versions"
if ! delete_probe_version="$(
  jq -ers '
    [
      .[]
      | select(
          .status == "success"
          and .key == "delete-probe"
          and .isDeleteMarker != true
          and (.versionId | type) == "string"
          and (.versionId | length) > 0
        )
      | .versionId
    ]
    | if length == 1 then .[0] else false end
  ' <<<"${delete_probe_listing}"
)"; then
  jq -s '[.[] | {status, key, versionId, isDeleteMarker}]' \
    <<<"${delete_probe_listing}" >&2 || true
  die "MinIO delete-denial probe did not report an exact version ID"
fi

require_workload_access_denied() {
  local label="$1"
  shift
  local output
  local status
  if output="$(mc_workload_run "$@" 2>&1)"; then
    die "CT workload identity unexpectedly completed ${label}"
  else
    status=$?
  fi
  ((status == 1)) || die "CT workload ${label} returned an unexpected client status"
  jq -es '
    length == 1
    and .[0].status == "error"
    and .[0].error.type == "error"
    and .[0].error.cause.message == "Access Denied."
  ' <<<"${output}" >/dev/null \
    || {
      jq -s '[.[] | {status, error: {type: .error.type, cause: .error.cause}}]' \
        <<<"${output}" >&2 || true
      die "CT workload ${label} did not return structured AccessDenied"
    }
}

require_workload_access_denied "object deletion" rm --json "${delete_probe_object}"
require_workload_access_denied \
  "object-version deletion" \
  rm --json --version-id "${delete_probe_version}" "${delete_probe_object}"
mc_run ready local >/dev/null || die "MinIO became unavailable during delete-denial probes"
current_probe_stat="$(mc_workload_run stat --json "${delete_probe_object}")" \
  || die "CT workload could not read back the delete-denial probe"
jq -e '.status == "success" and .size > 0' <<<"${current_probe_stat}" >/dev/null \
  || die "CT workload delete-denial probe readback was malformed"
version_probe_stat="$(
  mc_workload_run stat --json --version-id "${delete_probe_version}" "${delete_probe_object}"
)" || die "CT workload could not read back the exact delete-denial probe version"
jq -e --arg version "${delete_probe_version}" \
  '.status == "success" and .size > 0 and .versionID == $version' \
  <<<"${version_probe_stat}" >/dev/null \
  || die "CT workload exact-version delete-denial readback was malformed"

receipt_parent="$(dirname -- "${receipt_output}")"
[[ -d "${receipt_parent}" ]] || mkdir -p -- "${receipt_parent}"
receipt_temporary="$(mktemp "${receipt_output}.XXXXXX")"
jq --null-input \
  --arg revision "${source_revision}" \
  --arg tree "${source_tree}" \
  --arg worktree_state "${source_worktree_state}" \
  --arg minio_release "${minio_source_release}" \
  --arg minio_commit "${minio_source_commit}" \
  --arg minio_source_sha256 "${minio_source_sha256}" \
  --arg minio_builder_image "${minio_builder_image}" \
  --arg minio_runtime_image "${minio_runtime_image}" \
  --arg mc_image "${mc_image}" \
  '{schemaVersion: 1, kind: "ct-object-store-minio", source: {revision: $revision, tree: $tree, worktreeState: $worktree_state}, minio: {release: $minio_release, commit: $minio_commit, sourceSha256: $minio_source_sha256, builderImage: $minio_builder_image, runtimeImage: $minio_runtime_image}, mcImage: $mc_image, transport: "tls", clientTrust: "test-only ClientOptions::with_root_certificate", retention: {mode: "COMPLIANCE", validity: "1DAYS"}, deleteDenial: {object: true, objectVersion: true}}' \
  >"${receipt_temporary}"
chmod 0600 "${receipt_temporary}"
mv -- "${receipt_temporary}" "${receipt_output}"
