#!/usr/bin/env bash
# PID 1 bootstrap for the disposable native container, never a host installer.
set -euo pipefail
umask 077
root=/opt/oxibelt-preflight
home=/home/runner
evidence=${home}/evidence
bootstrap_stage=guard
bootstrap_receipt_enabled=0
bootstrap_failure() {
  local exit_code=$1 failure_line=$2
  # Diagnostic failures must neither recurse nor replace the bootstrap status.
  trap - ERR
  set +e
  printf 'sandbox bootstrap failed: stage=%s line=%s exit_code=%s\n' \
    "${bootstrap_stage}" "${failure_line}" "${exit_code}" >&3
  if [[ ${bootstrap_receipt_enabled} == 1 ]]; then
    mkdir -p "${evidence}" 2>/dev/null
    # noclobber retains the first receipt; omit commands and environment data.
    (
      umask 077
      set -o noclobber
      [[ ! -e ${evidence}/bootstrap-failure.json && ! -L ${evidence}/bootstrap-failure.json ]] || exit 0
      printf '{"schema_version":1,"stage":"%s","line":%s,"exit_code":%s}\n' \
        "${bootstrap_stage}" "${failure_line}" "${exit_code}" >"${evidence}/bootstrap-failure.json"
    ) 2>/dev/null
    printf 'sandbox bootstrap failed\n' >"${home}/preflight-failed" 2>/dev/null
  fi
  exit "${exit_code}"
}
if [[ ${1:-} != --prepare-user && ${1:-} != --record-failure ]]; then
  # Keep the original stderr even when a failing command redirects its output.
  exec 3>&2
  trap 'bootstrap_failure "$?" "$LINENO"' ERR
fi
[[ $(id -u) == 0 && $(uname -m) == riscv64 && -f /.dockerenv ]]

if [[ ${1:-} == --prepare-user ]]; then
  [[ $(cat /proc/1/comm) == systemd ]]
  # systemd may add its fusectl API mount after the PID 1 bootstrap guard.
  # Protect its existing VFS mount before the runner can create user namespaces.
  python3 "${root}/check-riscv-network-sysctl.py" --protect-systemd-mounts \
    >>"${evidence}/network-mount.log" 2>&1
  loginctl enable-linger runner
  systemctl start user@1001.service
  exit 0
fi
if [[ ${1:-} == --record-failure ]]; then
  [[ $(cat /proc/1/comm) == systemd ]]
  if [[ ${SERVICE_RESULT:-unknown} != success ]]; then
    # Copy only named unit diagnostics, without environment or unrestricted
    # journal output. User Docker messages identify uid 1001 and its unit.
    mkdir -p "${evidence}"
    journalctl --no-pager --lines=500 --output=short-iso \
      --unit=oxibelt-native-prepare.service --unit=oxibelt-native-build.service \
      2>&1 | tail -c 1048576 >"${evidence}/systemd-build-failure.log" || true
    journalctl --no-pager --lines=500 --output=short-iso \
      _UID=1001 _SYSTEMD_USER_UNIT=docker.service \
      2>&1 | tail -c 1048576 >"${evidence}/systemd-docker-failure.log" || true
    chown runner:runner "${evidence}/systemd-build-failure.log" "${evidence}/systemd-docker-failure.log"
    printf '%s\n' "native tool preparation failed: ${SERVICE_RESULT:-unknown}" >"${home}/preflight-failed"
    chown runner:runner "${home}/preflight-failed"
  fi
  exit 0
fi
[[ $$ == 1 && $(id -u) == 0 && $(uname -m) == riscv64 ]]
bootstrap_receipt_enabled=1
[[ -f ${root}/riscv-native-tools.lock.json && -f /usr/share/keyrings/debian-archive-keyring.gpg ]]
mkdir -p "${evidence}"
# docker cp preserves the provider user's ownership. Admit only flat regular
# staging files before normalizing ownership for the root-only proc helper.
bootstrap_stage=staging-ownership
[[ ! -L ${root%/*} && -d ${root%/*} && ! -L ${root} && -d ${root} ]]
shopt -s dotglob nullglob
staged_files=("${root}"/*)
shopt -u dotglob nullglob
for staged_file in "${staged_files[@]}"; do
  [[ ! -L ${staged_file} && -f ${staged_file} ]]
  case ${staged_file##*/} in
    riscv-native-sandbox-bootstrap.sh|riscv-native-sandbox-build-tools.sh|riscv-native-tools.lock.json|\
    check-riscv-native-runner.py|check-riscv-rootless-enforcement.py|riscv-rootless-limit-probe.c|\
    check-riscv-network-sysctl.py|check-riscv-proc-mount.py|workflow-identity.json) ;;
    *) false ;;
  esac
done
chown --no-dereference 0:0 -- "${root}" "${staged_files[@]}"
chmod 755 -- "${root}"
chmod 644 -- "${staged_files[@]}"
# Detach propagation before adding any sandbox-local mount exception.
bootstrap_stage=propagation
mount --make-rprivate /

# Freeze all dependency resolution while retaining Debian archive authentication.
bootstrap_stage=apt-sources
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
cat >/etc/apt/sources.list.d/oxibelt.sources <<'EOF'
Types: deb
URIs: http://snapshot.debian.org/archive/debian/20261005T000000Z/
Suites: trixie
Components: main
Architectures: riscv64
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
EOF
export DEBIAN_FRONTEND=noninteractive
bootstrap_stage=apt-update
timeout 600 apt-get update 2>&1 | tail -c 4194304 >"${evidence}/apt-update.log"
# Python is the sole bootstrap parser, at its exact locked version.
bootstrap_stage=python-install
python_version=$(sed -n 's/^      "python3": "\([^"]*\)",\?$/\1/p' "${root}/riscv-native-tools.lock.json")
[[ ${python_version} == 3.13.5-1 ]]
timeout 1200 apt-get install -y --no-install-recommends --allow-downgrades "python3=${python_version}" 2>&1 | tail -c 4194304 >"${evidence}/apt-bootstrap.log"
bootstrap_stage=package-install
mapfile -t packages < <(python3 - "${root}/riscv-native-tools.lock.json" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
assert lock['architecture'] == 'riscv64'
assert lock['debian']['snapshot'] == '20261005T000000Z'
for name, version in lock['debian']['packages'].items():
    print(f'{name}={version}')
PY
)
[[ ${#packages[@]} == 19 ]]
timeout 1200 apt-get install -y --no-install-recommends --allow-downgrades "${packages[@]}" 2>&1 | tail -c 4194304 >"${evidence}/apt-install.log"
bootstrap_stage=package-verify
python3 - "${root}/riscv-native-tools.lock.json" "${evidence}/packages.json" <<'PY'
import json, subprocess, sys
lock = json.load(open(sys.argv[1]))
installed = {}
for name, version in lock['debian']['packages'].items():
    actual = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', name], text=True)
    assert actual == version, (name, actual, version)
    installed[name] = actual
with open(sys.argv[2], 'w') as out:
    json.dump({'locked': installed, 'inventory': subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n'], text=True).splitlines()}, out, sort_keys=True)
PY
# RootlessKit inherits these mounts when it creates its user namespace. Only
# network sysctls may be writable; their lookups use the caller's network
# namespace. Keep the enclosing /proc/sys and all Docker masks intact.
bootstrap_stage=network-mount
[[ ! -L /proc/sys/net && -d /proc/sys/net ]]
mount --bind /proc/sys/net /proc/sys/net
mount -o remount,bind,rw,nosuid,nodev,noexec /proc/sys/net
python3 "${root}/check-riscv-network-sysctl.py" --check-mounts \
  >"${evidence}/network-mount.log" 2>&1
# A root-only full procfs grant lets nested runc mount its own PID namespace.
# Keep the original /proc masks and readonly sysctls; no provider mount changes.
bootstrap_stage=proc-helper
python3 "${root}/check-riscv-network-sysctl.py" --prepare-proc-mount \
  >>"${evidence}/network-mount.log" 2>&1
bootstrap_stage=runner-user
useradd --uid 1001 --create-home --shell /bin/bash runner
# RootlessKit prepares its private TAP via ip tuntap before slirp4netns opens
# this node. Create it only in this sandbox's private /dev, with the matching
# outer device-cgroup rule; no provider device is mounted into the sandbox.
bootstrap_stage=tun
[[ ! -L /dev/net ]]
mkdir -p /dev/net
chmod 755 /dev/net
if [[ ! -e /dev/net/tun && ! -L /dev/net/tun ]]; then
  mknod -m 600 /dev/net/tun c 10 200
fi
[[ ! -L /dev/net/tun && -c /dev/net/tun && $(stat -c '%t:%T' /dev/net/tun) == a:c8 ]]
chown runner:runner /dev/net/tun
chmod 600 /dev/net/tun
bootstrap_stage=runner-user
printf 'runner:100000:65536\n' >/etc/subuid
printf 'runner:100000:65536\n' >/etc/subgid
chown -R runner:runner "${home}"
chmod 700 "${home}" "${evidence}"
bootstrap_stage=systemd-setup
mkdir -p /etc/systemd/system/user@.service.d /etc/systemd/journald.conf.d
cat >/etc/systemd/system/user@.service.d/delegate.conf <<'EOF'
[Service]
Delegate=cpu memory pids
EOF
cat >/etc/systemd/journald.conf.d/oxibelt.conf <<'EOF'
[Journal]
Storage=volatile
RuntimeMaxUse=64M
EOF
cat >/etc/systemd/system/oxibelt-native-prepare.service <<'EOF'
[Unit]
After=systemd-logind.service
Requires=systemd-logind.service
[Service]
Type=oneshot
ExecStart=/bin/bash /opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh --prepare-user
ExecStopPost=/bin/bash /opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh --record-failure
RemainAfterExit=yes
TimeoutStartSec=120
EOF
cat >/etc/systemd/system/oxibelt-native-build.service <<'EOF'
[Unit]
Requires=oxibelt-native-prepare.service
After=oxibelt-native-prepare.service
[Service]
Type=oneshot
User=runner
Group=runner
Environment=HOME=/home/runner XDG_RUNTIME_DIR=/run/user/1001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus
ExecStart=/bin/bash /opt/oxibelt-preflight/riscv-native-sandbox-build-tools.sh
ExecStopPost=+/bin/bash /opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh --record-failure
TimeoutStartSec=5400
RemainAfterExit=yes
UMask=0077
StandardOutput=journal
StandardError=journal
EOF
cat >/etc/systemd/system/oxibelt-native.target <<'EOF'
[Unit]
Requires=oxibelt-native-build.service
After=oxibelt-native-build.service
EOF
systemctl mask systemd-firstboot.service systemd-udevd.service
# Propagation changes are confined to this container's private mount namespace.
bootstrap_stage=propagation
mount --make-rshared /
# Keep the full procfs grant private while systemd's root remains shared.
bootstrap_stage=proc-helper
mount --make-private "${root}/private-proc/proc"
bootstrap_stage=network-mount
python3 "${root}/check-riscv-network-sysctl.py" --check-mounts \
  2>&1 | tail -c 4194304 >>"${evidence}/network-mount.log"
bootstrap_stage=systemd-exec
# Bash otherwise exits on a failed exec without running its ERR trap.
shopt -s execfail
set +e
exec /lib/systemd/systemd --show-status=false --unit=oxibelt-native.target 3>&- \
  || bootstrap_failure "$?" "$LINENO"
