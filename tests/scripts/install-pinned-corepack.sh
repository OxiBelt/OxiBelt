#!/bin/sh
set -eu

# Node 25 and newer no longer bundle Corepack. Bootstrap its reviewed npm
# release by exact version and tarball digest, without running package scripts.
readonly expected_node_version="v26.12.1"
readonly corepack_version="0.36.0"
readonly corepack_sha512_hex="4a2889b01859a9d0623c74c497a393dec012ad1aca21c61340cb15197c7a104fe033c5853306237885fc4edf11894e08bf627a2db4fc2a919f08eb01a51581ff"

die() {
  printf 'pinned Corepack bootstrap: %s\n' "$1" >&2
  exit 1
}

[ "$(node --version)" = "${expected_node_version}" ] \
  || die "expected Node.js ${expected_node_version}, found $(node --version)"

temporary_dir="$(mktemp -d)"
trap 'rm -rf -- "${temporary_dir}"' EXIT

npm pack --ignore-scripts --pack-destination "${temporary_dir}" \
  "corepack@${corepack_version}" >/dev/null
corepack_archive="${temporary_dir}/corepack-${corepack_version}.tgz"
[ -f "${corepack_archive}" ] || die 'npm did not produce the pinned Corepack archive'

actual_sha512="$(node --input-type=module - "${corepack_archive}" <<'NODE'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

process.stdout.write(createHash('sha512').update(readFileSync(process.argv[2])).digest('hex'))
NODE
)"
[ "${actual_sha512}" = "${corepack_sha512_hex}" ] \
  || die "Corepack archive SHA-512 mismatch: ${actual_sha512}"

npm install --global --ignore-scripts --no-audit --no-fund "${corepack_archive}" \
  >/dev/null
[ "$(corepack --version)" = "${corepack_version}" ] \
  || die "installed Corepack does not report ${corepack_version}"

corepack enable pnpm
corepack install
[ "$(pnpm --version)" = "12.15.0" ] \
  || die 'the project packageManager pin did not select pnpm 12.15.0'
