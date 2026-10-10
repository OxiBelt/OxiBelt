#!/usr/bin/env bash
# Each component's upstream version variables intentionally live in its subshell.
# shellcheck disable=SC2030,SC2031
# Runs only as the subordinate-ID-enabled sandbox user; builds no rootful daemon.
set -euo pipefail
umask 077
[[ $(id -u) == 1001 && $(uname -m) == riscv64 && -f /.dockerenv && $(cat /proc/1/comm) == systemd ]]
root=/opt/oxibelt-preflight
home=/home/runner
evidence=${home}/evidence
tools=${home}/native-tools
lock=${root}/riscv-native-tools.lock.json
mkdir -p "${tools}/bin" "${tools}/src" "${tools}/downloads" "${tools}/build-tmp" "${home}/.config/systemd/user" "${home}/.config/docker"
export GOTMPDIR="${tools}/build-tmp" TMPDIR="${tools}/build-tmp"
trap 'printf "native tools build failed\n" >"/home/runner/preflight-failed"' ERR

field() {
  python3 - "${lock}" "$1" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
for part in sys.argv[2].split('.'):
    value = value[part]
print(value)
PY
}
download() {
  local name=$1 url=$2 digest=$3
  [[ ${digest} =~ ^[a-f0-9]{64}$ && ${url} == https://* ]]
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 30 --max-time 300 --retry 2 "${url}" -o "${tools}/downloads/${name}.tar.gz"
  printf '%s  %s\n' "${digest}" "${tools}/downloads/${name}.tar.gz" | sha256sum --check --status
}
build_logged() {
  local name=$1
  shift
  "$@" 2>&1 | tail -c 4194304 >"${evidence}/build-${name}.log"
}
download go "$(field go.url)" "$(field go.sha256)"
tar --extract --gzip --no-same-owner --file "${tools}/downloads/go.tar.gz" --directory "${tools}"
export PATH="${tools}/go/bin:${tools}/bin:/usr/sbin:/usr/bin:/sbin:/bin"
for command in ip iptables ip6tables newuidmap newgidmap slirp4netns mount mountpoint nsenter systemctl; do
  command -v "${command}" >/dev/null
done
export GOTOOLCHAIN=local GOFLAGS='-mod=vendor -trimpath -buildvcs=false -p=2' GOMAXPROCS=2 GOPROXY=off GOSUMDB=off
[[ $(go version) == 'go version go1.26.8 linux/riscv64' ]]
[[ $(go env GOHOSTARCH) == riscv64 && $(go env GOARCH) == riscv64 ]]
for name in engine cli containerd runc; do
  download "${name}" "$(field "sources.${name}.url")" "$(field "sources.${name}.sha256")"
  mkdir -p "${tools}/src/${name}"
  tar --extract --gzip --no-same-owner --strip-components=1 --file "${tools}/downloads/${name}.tar.gz" --directory "${tools}/src/${name}"
  [[ -d ${tools}/src/${name}/vendor ]]
done
(
  cd "${tools}/src/engine"
  VERSION=$(field sources.engine.version)
  DOCKER_GITCOMMIT=$(field sources.engine.commit)
  export VERSION DOCKER_GITCOMMIT
  export DOCKER_BUILDTAGS=seccomp SOURCE_DATE_EPOCH=1791158400
  build_logged engine bash hack/make.sh binary
  install -m 755 bundles/binary-daemon/dockerd bundles/binary-daemon/docker-proxy "${tools}/bin/"
  install -m 755 contrib/dockerd-rootless.sh contrib/dockerd-rootless-setuptool.sh "${tools}/bin/"
)
(
  cd "${tools}/src/cli"
  VERSION=$(field sources.cli.version)
  GITCOMMIT=$(field sources.cli.commit)
  export VERSION GITCOMMIT SOURCE_DATE_EPOCH=1791158400
  build_logged cli bash scripts/with-go-mod.sh sh scripts/build/binary
  install -m 755 build/docker-linux-riscv64 "${tools}/bin/docker"
)
(
  cd "${tools}/src/containerd"
  # Match the pinned Makefile's binary recipes directly. Its parse-time API
  # test inventory evaluates an unvendored nested module even for binaries.
  containerd_ldflags="-X github.com/containerd/containerd/v2/version.Version=v$(field sources.containerd.version) -X github.com/containerd/containerd/v2/version.Revision=$(field sources.containerd.commit) -X github.com/containerd/containerd/v2/version.Package=github.com/containerd/containerd/v2 -s -w"
  # Invoked through the bounded build_logged wrapper below.
  # shellcheck disable=SC2329
  compile_containerd() {
    go build -buildmode=pie -tags urfave_cli_no_docs -ldflags "${containerd_ldflags}" -o bin/containerd ./cmd/containerd
    CGO_ENABLED=0 go build -tags 'urfave_cli_no_docs no_grpc' -ldflags "${containerd_ldflags} -extldflags -static" -o bin/containerd-shim-runc-v2 ./cmd/containerd-shim-runc-v2
    go build -buildmode=pie -tags urfave_cli_no_docs -ldflags "${containerd_ldflags}" -o bin/ctr ./cmd/ctr
  }
  build_logged containerd compile_containerd
  install -m 755 bin/containerd bin/containerd-shim-runc-v2 bin/ctr "${tools}/bin/"
)
(
  cd "${tools}/src/runc"
  # Upstream supports Go path resolution in place of optional Rust libpathrs.
  build_logged runc make RUNC_BUILDTAGS="$(field build.runcBuildTags)" COMMIT="$(field sources.runc.commit)" GIT_BRANCH=locked-source runc
  install -m 755 runc "${tools}/bin/"
)
download rootlesskit "$(field rootlesskit.url)" "$(field rootlesskit.sha256)"
tar --extract --gzip --no-same-owner --file "${tools}/downloads/rootlesskit.tar.gz" --directory "${tools}/bin" rootlesskit
printf '%s  %s\n' "$(field probeSourceSha256)" "${root}/riscv-rootless-limit-probe.c" | sha256sum --check --status
gcc -O2 -static -Wall -Wextra -Werror -o "${home}/limit-probe" "${root}/riscv-rootless-limit-probe.c"

python3 - "${lock}" "${tools}/bin" "${evidence}/native-tools.json" "${home}/limit-probe" <<'PY'
import hashlib, json, pathlib, struct, subprocess, sys
lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
directory = pathlib.Path(sys.argv[2])
commands = {
    'docker': ('--version', lock['sources']['cli']['version']),
    'dockerd': ('--version', lock['sources']['engine']['version']),
    'docker-proxy': ('-version', lock['sources']['engine']['version']),
    'containerd': ('--version', lock['sources']['containerd']['version']),
    'containerd-shim-runc-v2': ('-v', lock['sources']['containerd']['version']),
    'ctr': ('--version', lock['sources']['containerd']['version']),
    'runc': ('--version', lock['sources']['runc']['version']),
    'rootlesskit': ('--version', lock['rootlesskit']['version']),
}
manifest = {'schemaVersion': 1, 'architecture': 'riscv64', 'lockSha256': hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest(), 'binaries': {}, 'scripts': {}}
for name, (argument, expected) in commands.items():
    data = (directory / name).read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01', name
    assert struct.unpack_from('<H', data, 18)[0] == 243, name
    version = subprocess.check_output([str(directory / name), argument], text=True, stderr=subprocess.STDOUT, timeout=15).strip()
    # Require a complete numeric version token, never a substring match.
    import re
    assert re.search(r'(?<![\d.])' + re.escape(expected) + r'(?![\d.])', version), (name, version)
    if name == 'runc':
        assert 'libseccomp:' in version, version
    manifest['binaries'][name] = {'sha256': hashlib.sha256(data).hexdigest(), 'elfMachine': 243, 'version': version}
for name in ('dockerd-rootless.sh', 'dockerd-rootless-setuptool.sh'):
    manifest['scripts'][name] = {'sha256': hashlib.sha256((directory / name).read_bytes()).hexdigest()}
probe = pathlib.Path(sys.argv[4]).read_bytes()
assert probe[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', probe, 18)[0] == 243
manifest['binaries']['limit-probe'] = {'sha256': hashlib.sha256(probe).hexdigest(), 'elfMachine': 243, 'version': 'native-cgroup-enforcement-v1'}
with open(sys.argv[3], 'w') as output:
    json.dump(manifest, output, indent=2, sort_keys=True)
    output.write('\n')
PY
cat >"${home}/.config/docker/daemon.json" <<'EOF'
{"exec-opts":["native.cgroupdriver=systemd"],"data-root":"/home/runner/.local/share/docker","log-driver":"local","log-opts":{"max-size":"10m","max-file":"2"}}
EOF
cat >"${home}/.config/systemd/user/docker.service" <<'EOF'
[Unit]
Description=Isolated native rootless Docker
[Service]
Type=simple
Environment=PATH=/home/runner/native-tools/bin:/usr/sbin:/usr/bin:/sbin:/bin DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns
ExecStart=/home/runner/native-tools/bin/dockerd-rootless.sh --host=unix:///run/user/1001/docker.sock --config-file=/home/runner/.config/docker/daemon.json
Delegate=yes
KillMode=mixed
TimeoutStopSec=30
EOF
systemctl --user daemon-reload
systemctl --user start docker.service
export DOCKER_HOST=unix:///run/user/1001/docker.sock
ready=false
for ((attempt=0; attempt<60; attempt++)); do
  if timeout 5 docker info --format '{{json .}}' >"${evidence}/docker-info.json" 2>"${evidence}/docker-start.log"; then
    ready=true
    break
  fi
  sleep 2
done
[[ ${ready} == true ]]
python3 - "${evidence}/docker-info.json" <<'PY'
import json, sys
info = json.load(open(sys.argv[1]))
assert info['Architecture'] == 'riscv64'
assert info['ServerVersion'] == '29.8.0'
assert info['CgroupVersion'] == '2' and info['CgroupDriver'] == 'systemd'
assert {'name=rootless', 'name=cgroupns', 'name=seccomp,profile=builtin'}.issubset(info['SecurityOptions'])
PY
printf 'native rootless tools ready\n' >"${home}/preflight-ready"
