#!/usr/bin/env bash
# Read-only OCI Helm chart verification. Registry credentials, if needed, are
# supplied by the caller; this script never logs in, pushes, tags, or deletes.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: verify-release-helm-chart.sh --mode <rebuild|consume> \
  --repository <ghcr.io/oxibelt/charts/...> --digest <sha256:...> \
  --version <strict-semver> --chart-name <name> --expected-archive <path> \
  --work-directory <empty-directory> [--workspace-path <path> --release-ref <ref> --revision <sha>]

`rebuild` requires Helm v4.2.3, an approved `helm_chart_release.ts` helper,
and exact source inputs. `consume` permits Helm v3.21.3 or v4.2.3 and never
claims cross-version package-byte production equality. Set HELM_BIN, ORAS_BIN,
NODE_BIN, and HELM_CHART_RELEASE_HELPER to inject test fixtures.
USAGE
}

mode="" repository="" digest="" version="" chart_name="" expected_archive="" work_directory=""
workspace_path="" release_ref="" revision=""
declare -A seen=()
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --mode|--repository|--digest|--version|--chart-name|--expected-archive|--work-directory|--workspace-path|--release-ref|--revision)
      [[ -z "${seen[$1]:-}" && $# -ge 2 && -n "${2:-}" && "${2:-}" != --* ]] || { usage; exit 2; }
      seen[$1]=1
      case "$1" in
        --mode) mode="$2" ;;
        --repository) repository="$2" ;;
        --digest) digest="$2" ;;
        --version) version="$2" ;;
        --chart-name) chart_name="$2" ;;
        --expected-archive) expected_archive="$2" ;;
        --work-directory) work_directory="$2" ;;
        --workspace-path) workspace_path="$2" ;;
        --release-ref) release_ref="$2" ;;
        --revision) revision="$2" ;;
      esac
      shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

case "${repository}:${chart_name}" in
  ghcr.io/oxibelt/charts/oxibelt:oxibelt|ghcr.io/oxibelt/charts/oxibelt-gateway-controller:oxibelt-gateway-controller) ;;
  *) usage; exit 2 ;;
esac
[[ "${mode}" == rebuild || "${mode}" == consume ]] || { usage; exit 2; }
[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || { usage; exit 2; }
[[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-beta\.(0|[1-9][0-9]*)|-build\.[0-9a-f]{8})?$ ]] || { usage; exit 2; }
maximum_archive_bytes=$((16 * 1024 * 1024))
maximum_json_bytes=$((128 * 1024))

helm_bin="${HELM_BIN:-helm}" oras_bin="${ORAS_BIN:-oras}" node_bin="${NODE_BIN:-node}"
for command in "${helm_bin}" "${node_bin}" "${oras_bin}" awk cmp find sha256sum sort stat; do command -v "${command}" >/dev/null 2>&1 || { echo "required command is unavailable: ${command}" >&2; exit 2; }; done

assert_no_symlink_path() {
  local input_path="$1" label="$2" absolute_path current_path segment
  local -a path_segments
  [[ -n "${input_path}" && "${input_path}" != ".." && "${input_path}" != ../* && "${input_path}" != */.. && "${input_path}" != */../* ]] || { echo "${label} path is invalid" >&2; return 1; }
  if [[ "${input_path}" == /* ]]; then absolute_path="${input_path}"; else absolute_path="$(pwd -P)/${input_path}"; fi
  current_path="/"
  IFS=/ read -r -a path_segments <<< "${absolute_path#/}"
  for segment in "${path_segments[@]}"; do
    [[ -n "${segment}" && "${segment}" != "." ]] || continue
    current_path="${current_path%/}/${segment}"
    [[ ! -L "${current_path}" ]] || { echo "${label} path must not contain symlinks" >&2; return 1; }
    [[ -e "${current_path}" ]] || { echo "${label} path component is missing" >&2; return 1; }
  done
  printf '%s\n' "${absolute_path}"
}

expected_archive="$(assert_no_symlink_path "${expected_archive}" "expected archive")" || exit 2
work_directory="$(assert_no_symlink_path "${work_directory}" "work directory")" || exit 2
[[ -f "${expected_archive}" && ! -L "${expected_archive}" ]] || { echo "expected archive must be a regular non-symlink file" >&2; exit 2; }
[[ -d "${work_directory}" && ! -L "${work_directory}" && "${work_directory}" != / ]] || { echo "work directory must be a non-symlink directory" >&2; exit 2; }
[[ -z "$(find "${work_directory}" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { echo "work directory must be empty" >&2; exit 2; }

helm_version="$("${helm_bin}" version --short)"
oras_version="$("${oras_bin}" version)"
[[ "${oras_version}" =~ (^|[[:space:]])1\.3\.3($|[[:space:]]) ]] || { echo "ORAS must be the approved 1.3.3 acquisition client" >&2; exit 1; }
if [[ "${mode}" == rebuild ]]; then
  [[ "${helm_version}" =~ ^v4\.2\.3(\+[0-9A-Za-z.-]+)?$ ]] || { echo "byte rebuild requires Helm v4.2.3, found ${helm_version}" >&2; exit 1; }
  [[ "${release_ref}" == "refs/tags/${version}" && "${revision}" =~ ^[0-9a-f]{40}$ && -n "${workspace_path}" ]] || { usage; exit 2; }
else
  [[ "${helm_version}" =~ ^v(3\.21\.3|4\.2\.3)(\+[0-9A-Za-z.-]+)?$ ]] || { echo "consumption verification requires Helm 3.21.3 or 4.2.3, found ${helm_version}" >&2; exit 1; }
fi

trap 'rm -rf -- "${work_directory}/.verify-release-helm-chart"' EXIT
scratch="${work_directory}/.verify-release-helm-chart"
mkdir -m 0700 "${scratch}"
expected_snapshot="${scratch}/expected.tgz"
"${node_bin}" --input-type=module --eval '
import * as Fs from "node:fs";
const [source, target, maximumText] = process.argv.slice(1);
const maximum = Number(maximumText);
const noFollow = Fs.constants.O_NOFOLLOW;
if (!Number.isSafeInteger(maximum) || maximum <= 0 || noFollow === undefined) throw new Error("unsafe snapshot contract");
let sourceDescriptor; let targetDescriptor;
try {
  sourceDescriptor = Fs.openSync(source, Fs.constants.O_RDONLY | noFollow);
  const before = Fs.fstatSync(sourceDescriptor);
  if (!before.isFile() || before.size <= 0 || before.size > maximum) throw new Error("source archive is outside the bounded contract");
  targetDescriptor = Fs.openSync(target, Fs.constants.O_WRONLY | Fs.constants.O_CREAT | Fs.constants.O_EXCL | noFollow, 0o600);
  const chunk = Buffer.allocUnsafe(Math.min(65536, before.size)); let remaining = before.size;
  while (remaining > 0) { const read = Fs.readSync(sourceDescriptor, chunk, 0, Math.min(chunk.length, remaining), null); if (read === 0) throw new Error("source archive changed while it was read"); let offset = 0; while (offset < read) offset += Fs.writeSync(targetDescriptor, chunk, offset, read - offset); remaining -= read; }
  if (Fs.readSync(sourceDescriptor, Buffer.allocUnsafe(1), 0, 1, null) !== 0) throw new Error("source archive grew while it was read");
  const after = Fs.fstatSync(sourceDescriptor); const snapshot = Fs.fstatSync(targetDescriptor);
  if (!after.isFile() || after.size !== before.size || after.dev !== before.dev || after.ino !== before.ino || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || !snapshot.isFile() || snapshot.size !== before.size) throw new Error("source archive changed while it was read");
  Fs.fsyncSync(targetDescriptor);
} finally { if (targetDescriptor !== undefined) Fs.closeSync(targetDescriptor); if (sourceDescriptor !== undefined) Fs.closeSync(sourceDescriptor); }
' "${expected_archive}" "${expected_snapshot}" "${maximum_archive_bytes}"
[[ -f "${expected_snapshot}" && ! -L "${expected_snapshot}" && "$(stat -c%s -- "${expected_snapshot}")" -gt 0 && "$(stat -c%s -- "${expected_snapshot}")" -le "${maximum_archive_bytes}" ]] || { echo "expected archive snapshot is outside the bounded size contract" >&2; exit 2; }

tag_descriptor="${scratch}/tag-descriptor.json" descriptor="${scratch}/descriptor.json" manifest="${scratch}/manifest.json" config_blob="${scratch}/config.json" verified_archive="${scratch}/${chart_name}-${version}.tgz"

capture_bounded() {
  local output_path="$1" maximum_bytes="$2"
  shift 2
  # POSIX/Bash `ulimit -f` counts 1024-byte blocks.  Round up, so a registry
  # process cannot write more than the declared byte contract before a later
  # size and digest check runs.
  (
    ulimit -f "$(((maximum_bytes + 1023) / 1024))"
    "$@" >"${output_path}"
  ) || { echo "registry command failed within its bounded output contract" >&2; exit 1; }
  [[ -f "${output_path}" && ! -L "${output_path}" && -s "${output_path}" && "$(stat -c%s -- "${output_path}")" -le "${maximum_bytes}" ]] || { echo "registry JSON is outside the bounded file contract" >&2; exit 1; }
}

fetch_bounded_output() {
  local output_path="$1" maximum_bytes="$2"
  shift 2
  # The ORAS process creates --output itself, so apply the same limit in its
  # process before it can create an unbounded local registry artifact.
  (
    ulimit -f "$(((maximum_bytes + 1023) / 1024))"
    "$@" >/dev/null
  ) || { echo "registry command failed within its bounded output contract" >&2; exit 1; }
  [[ -f "${output_path}" && ! -L "${output_path}" && -s "${output_path}" && "$(stat -c%s -- "${output_path}")" -le "${maximum_bytes}" ]] || { echo "registry output is outside the bounded file contract" >&2; exit 1; }
}
capture_bounded "${tag_descriptor}" "${maximum_json_bytes}" "${oras_bin}" manifest fetch --descriptor "${repository}:${version}"
capture_bounded "${descriptor}" "${maximum_json_bytes}" "${oras_bin}" manifest fetch --descriptor "${repository}@${digest}"
fetch_bounded_output "${manifest}" "${maximum_json_bytes}" "${oras_bin}" manifest fetch --output "${manifest}" "${repository}@${digest}"
for bounded_json in "${tag_descriptor}" "${descriptor}" "${manifest}"; do
  [[ -f "${bounded_json}" && ! -L "${bounded_json}" && -s "${bounded_json}" && "$(stat -c%s -- "${bounded_json}")" -le "${maximum_json_bytes}" ]] || { echo "registry JSON is outside the bounded file contract" >&2; exit 1; }
done
expected_sha="$(sha256sum "${expected_snapshot}" | awk '{print $1}')"
[[ "${expected_sha}" =~ ^[0-9a-f]{64}$ ]] || { echo "expected archive SHA-256 is invalid" >&2; exit 1; }

# shellcheck disable=SC2016
# JavaScript template literal intentionally expands in Node.
read -r config_digest config_size layer_digest layer_size < <("${node_bin}" --input-type=module --eval '
import * as Crypto from "node:crypto";
import * as Fs from "node:fs";
const [tagDescriptorPath, descriptorPath, manifestPath, expectedDigest, archiveSha, archiveSize] = process.argv.slice(1);
const assertNoDuplicateKeys = text => {
  let offset = 0; let nodes = 0;
  const skip = () => { while (/[\t\n\r ]/.test(text[offset] ?? "")) offset += 1; };
  const expect = character => { if (text[offset] !== character) throw new Error("invalid JSON structure"); offset += 1; };
  const string = () => { const start = offset; expect("\""); while (offset < text.length) { const character = text[offset++]; if (character === "\"") return JSON.parse(text.slice(start, offset)); if (character === "\\") { if (offset >= text.length) throw new Error("invalid JSON escape"); offset += 1; } else if (character < " ") throw new Error("invalid JSON string"); } throw new Error("unterminated JSON string"); };
  const value = depth => { if (depth > 64 || ++nodes > 8192) throw new Error("JSON nesting or item limit exceeded"); skip(); if (text[offset] === "{") { offset += 1; skip(); const keys = new Set(); if (text[offset] === "}") { offset += 1; return; } while (true) { skip(); const key = string(); if (keys.has(key)) throw new Error("duplicate JSON key"); keys.add(key); skip(); expect(":"); value(depth + 1); skip(); if (text[offset] === "}") { offset += 1; return; } expect(","); } } if (text[offset] === "[") { offset += 1; skip(); if (text[offset] === "]") { offset += 1; return; } while (true) { value(depth + 1); skip(); if (text[offset] === "]") { offset += 1; return; } expect(","); } } if (text[offset] === "\"") { string(); return; } const match = /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y; match.lastIndex = offset; const token = match.exec(text); if (token === null) throw new Error("invalid JSON scalar"); offset += token[0].length; };
  value(0); skip(); if (offset !== text.length) throw new Error("trailing JSON content");
};
const parseStrict = path => { const bytes = Fs.readFileSync(path); const text = bytes.toString("utf8"); if (!Buffer.from(text, "utf8").equals(bytes)) throw new Error("not UTF-8"); assertNoDuplicateKeys(text); return { bytes, value: JSON.parse(text) }; };
const exactKeys = (value, keys) => { if (value === null || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) throw new Error("unexpected JSON keys"); };
const descriptorValue = (value, maximum) => { exactKeys(value, ["mediaType", "digest", "size"]); if (typeof value.mediaType !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.digest ?? "") || !Number.isSafeInteger(value.size) || value.size <= 0 || value.size > maximum) throw new Error("invalid descriptor"); return value; };
const tagDescriptor = descriptorValue(parseStrict(tagDescriptorPath).value, 131072);
const descriptor = descriptorValue(parseStrict(descriptorPath).value, 131072);
const rawManifest = parseStrict(manifestPath);
const manifest = rawManifest.value;
const manifestKeys = Object.keys(manifest).sort().join(",");
if (manifestKeys !== "config,layers,schemaVersion" && manifestKeys !== "config,layers,mediaType,schemaVersion") throw new Error("unexpected manifest JSON keys");
if (tagDescriptor.mediaType !== descriptor.mediaType || tagDescriptor.digest !== descriptor.digest || tagDescriptor.size !== descriptor.size || descriptor.mediaType !== "application/vnd.oci.image.manifest.v1+json" || descriptor.digest !== expectedDigest || descriptor.size !== rawManifest.bytes.length || `sha256:${Crypto.createHash("sha256").update(rawManifest.bytes).digest("hex")}` !== expectedDigest || manifest.schemaVersion !== 2 || ("mediaType" in manifest && manifest.mediaType !== descriptor.mediaType)) throw new Error("tag and immutable manifest descriptors do not bind the same exact raw manifest bytes");
const config = descriptorValue(manifest.config, 131072);
if (config.mediaType !== "application/vnd.cncf.helm.config.v1+json") throw new Error("invalid Helm config descriptor");
if (!Array.isArray(manifest.layers) || manifest.layers.length !== 1) throw new Error("manifest must have one chart layer");
const layer = descriptorValue(manifest.layers[0], 16777216);
if (layer.mediaType !== "application/vnd.cncf.helm.chart.content.v1.tar+gzip" || layer.digest !== `sha256:${archiveSha}` || layer.size !== Number(archiveSize)) throw new Error("chart layer does not bind exact archive");
console.log(`${config.digest} ${config.size} ${layer.digest} ${layer.size}`);
' "${tag_descriptor}" "${descriptor}" "${manifest}" "${digest}" "${expected_sha}" "$(stat -c%s -- "${expected_snapshot}")")
[[ "${config_digest}" =~ ^sha256:[0-9a-f]{64}$ && "${config_size}" =~ ^[1-9][0-9]*$ && "${config_size}" -le "${maximum_json_bytes}" && "${layer_digest}" =~ ^sha256:[0-9a-f]{64}$ && "${layer_size}" =~ ^[1-9][0-9]*$ && "${layer_size}" -le "${maximum_archive_bytes}" ]] || { echo "manifest config or layer binding is invalid" >&2; exit 1; }
fetch_bounded_output "${config_blob}" "${maximum_json_bytes}" "${oras_bin}" blob fetch --output "${config_blob}" "${repository}@${config_digest}"
[[ -f "${config_blob}" && ! -L "${config_blob}" && "$(stat -c%s -- "${config_blob}")" -eq "${config_size}" ]] || { echo "registry config blob does not match its descriptor size" >&2; exit 1; }
[[ "sha256:$(sha256sum "${config_blob}" | awk '{print $1}')" == "${config_digest}" ]] || { echo "registry config blob does not match its descriptor digest" >&2; exit 1; }
fetch_bounded_output "${verified_archive}" "${maximum_archive_bytes}" "${oras_bin}" blob fetch --output "${verified_archive}" "${repository}@${layer_digest}"
[[ -f "${verified_archive}" && ! -L "${verified_archive}" && "$(stat -c%s -- "${verified_archive}")" -eq "${layer_size}" && "$(stat -c%s -- "${verified_archive}")" -le "${maximum_archive_bytes}" ]] || { echo "registry chart layer is outside the bounded size contract" >&2; exit 1; }
[[ "sha256:$(sha256sum "${verified_archive}" | awk '{print $1}')" == "${layer_digest}" ]] || { echo "registry chart layer does not match its descriptor digest" >&2; exit 1; }
cmp -- "${expected_snapshot}" "${verified_archive}"

chart_yaml="${scratch}/chart.yaml"
"${helm_bin}" show chart "${verified_archive}" >"${chart_yaml}"
[[ -f "${chart_yaml}" && ! -L "${chart_yaml}" && -s "${chart_yaml}" && "$(stat -c%s -- "${chart_yaml}")" -le "${maximum_json_bytes}" ]] || { echo "local chart metadata is outside the bounded file contract" >&2; exit 1; }
# helm show emits a YAML mapping.  Parse the bounded mapping semantically so
# quoted and plain YAML scalars have the same value without accepting a
# different chart identity or annotation set.
"${node_bin}" --input-type=module --eval '
import * as Fs from "node:fs";
const [path, expectedName, expectedVersion] = process.argv.slice(1);
const bytes = Fs.readFileSync(path); const text = bytes.toString("utf8");
if (!Buffer.from(text, "utf8").equals(bytes) || bytes.length === 0 || bytes.length > 131072) throw new Error("invalid bounded chart metadata");
const scalar = value => { const trimmed = value.trim(); const singleQuote = String.fromCharCode(39); if (trimmed.startsWith("\"") && trimmed.endsWith("\"")) return JSON.parse(trimmed); if (trimmed.startsWith(singleQuote) && trimmed.endsWith(singleQuote)) return trimmed.slice(1, -1).split(singleQuote + singleQuote).join(singleQuote); if (trimmed === "" || /[\r\n]/.test(trimmed)) throw new Error("invalid YAML scalar"); return trimmed; };
const chart = new Map(); const annotations = new Map(); let inAnnotations = false;
for (const line of text.split(/\n/)) { if (line === "" || /^\s*#/.test(line)) continue; const nested = /^  ([^:#][^:]*):[ \t]*(.*)$/.exec(line); if (inAnnotations && nested !== null) { const key = nested[1].trim(); if (annotations.has(key)) throw new Error("duplicate chart annotation"); annotations.set(key, scalar(nested[2])); continue; } inAnnotations = false; const top = /^([^ \t:#][^:]*):[ \t]*(.*)$/.exec(line); if (top === null) continue; const key = top[1].trim(); if (chart.has(key)) throw new Error("duplicate chart metadata key"); const value = key === "annotations" && top[2].trim() === "" ? "" : scalar(top[2]); chart.set(key, value); inAnnotations = key === "annotations" && value === ""; }
if (chart.get("name") !== expectedName || chart.get("version") !== expectedVersion || chart.get("appVersion") !== expectedVersion) throw new Error("local chart metadata identity is invalid");
const expectedAnnotations = new Map([["oxibelt.dev/feature-status", "experimental"], ["oxibelt.dev/kubernetes-support-policy", "1"]]);
if (annotations.size !== expectedAnnotations.size) throw new Error("local chart annotation set is invalid");
for (const [key, value] of expectedAnnotations) if (annotations.get(key) !== value) throw new Error("local chart annotation value is invalid");
' "${chart_yaml}" "${chart_name}" "${version}"
"${helm_bin}" lint --strict "${verified_archive}" --kube-version 1.34.8
"${helm_bin}" template "${chart_name}" "${verified_archive}" --kube-version 1.34.8 >"${scratch}/rendered.yaml"
"${helm_bin}" install "${chart_name}" "${verified_archive}" --namespace verify --dry-run=client --debug >"${scratch}/install.yaml"

if [[ "${mode}" == rebuild ]]; then
  helper="${HELM_CHART_RELEASE_HELPER:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)/devops/sources/helm_chart_release.ts}"
  workspace_path="$(assert_no_symlink_path "${workspace_path}" "workspace")" || exit 2
  helper="$(assert_no_symlink_path "${helper}" "Helm chart release helper")" || exit 2
  [[ -d "${workspace_path}" && -f "${helper}" && ! -L "${helper}" ]] || { echo "Helm chart release helper and workspace must be regular non-symlink paths" >&2; exit 2; }
  rebuilt="${scratch}/rebuilt"; mkdir -m 0700 "${rebuilt}"
  "${node_bin}" --import tsx "${helper}" prepare --workspace-path "${workspace_path}" --ref "${release_ref}" --revision "${revision}" --output-directory "${rebuilt}"
  cmp -- "${expected_snapshot}" "${rebuilt}/${chart_name}-${version}.tgz"
fi

echo "${mode} Helm OCI verification passed for ${repository}@${digest} (${helm_version})"
