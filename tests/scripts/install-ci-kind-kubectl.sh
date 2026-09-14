#!/usr/bin/env bash
# Install the exact CI Kind and kubectl clients without using a mutable tool cache.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/scripts/lib/verified-download.sh
source "${script_dir}/lib/verified-download.sh"

die() {
  echo "${1}" >&2
  exit 1
}

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <kubectl-version> <install-dir>" >&2
  exit 2
fi

kubectl_version="$1"
install_dir="$2"
kind_version="v0.33.0"
kind_sha256="aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"

[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] \
  || die "the CI Kind installer supports only Linux x86_64"
[[ "${install_dir}" = /* ]] || die "the CI tool install directory must be absolute"
[[ ! -e "${install_dir}" && ! -L "${install_dir}" ]] \
  || die "refusing to replace an existing CI tool install directory"

case "${kubectl_version}" in
  v1.34.11)
    kubectl_sha256="8efbb9435132a190920eb65a47a8c1ecf755ad85ab57a600c9bedbab460bb7a8"
    ;;
  v1.35.8)
    kubectl_sha256="874d5e72dbb819f43cff16bcd1e4f8bac5b7f2361fe1e55049b0a6c676fb0cbf"
    ;;
  v1.36.4)
    kubectl_sha256="8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a"
    ;;
  v1.37.0)
    kubectl_sha256="6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f"
    ;;
  *)
    die "unsupported pinned kubectl version: ${kubectl_version}"
    ;;
esac

install_parent="$(dirname -- "${install_dir}")"
mkdir -p -- "${install_parent}" || die "could not create the CI tool install parent"
[[ -d "${install_parent}" && ! -L "${install_parent}" ]] \
  || die "the CI tool install parent must be a real directory"

if ! staging_dir="$(mktemp -d "${install_parent}/.oxibelt-ci-tools.XXXXXX")"; then
  die "could not create a private CI tool staging directory"
fi
trap 'rm -rf -- "${staging_dir}" || true' EXIT
trap 'exit 1' HUP INT TERM

download_verified_sha256 \
  "https://github.com/kubernetes-sigs/kind/releases/download/${kind_version}/kind-linux-amd64" \
  "${kind_sha256}" \
  "${staging_dir}/kind"
download_verified_sha256 \
  "https://dl.k8s.io/release/${kubectl_version}/bin/linux/amd64/kubectl" \
  "${kubectl_sha256}" \
  "${staging_dir}/kubectl"

chmod 0755 "${staging_dir}/kind" "${staging_dir}/kubectl"
kind_report="$("${staging_dir}/kind" version)"
[[ "${kind_report}" == "kind ${kind_version} "* ]] \
  || die "downloaded Kind does not report ${kind_version}"
kubectl_report="$("${staging_dir}/kubectl" version --client=true --output=json)"
actual_kubectl_version="$(sed -n 's/.*"gitVersion":[[:space:]]*"\([^"]*\)".*/\1/p' <<<"${kubectl_report}")"
[[ "${actual_kubectl_version}" == "${kubectl_version}" ]] \
  || die "downloaded kubectl does not report ${kubectl_version}"

if ! mv -T --no-clobber -- "${staging_dir}" "${install_dir}" \
  || [[ -e "${staging_dir}" || -L "${staging_dir}" ]]; then
  die "refusing to publish over an existing CI tool install directory"
fi
staging_dir=""
trap - EXIT HUP INT TERM

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "${install_dir}" >>"${GITHUB_PATH}"
fi

echo "Installed Kind ${kind_version} and kubectl ${kubectl_version}"
