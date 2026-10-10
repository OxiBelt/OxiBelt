#!/usr/bin/env bash
# PID 1 bootstrap for the disposable native container, never a host installer.
set -euo pipefail
umask 077
root=/opt/oxibelt-preflight
home=/home/runner
evidence=${home}/evidence
[[ $(id -u) == 0 && $(uname -m) == riscv64 && -f /.dockerenv ]]

if [[ ${1:-} == --prepare-user ]]; then
  [[ $(cat /proc/1/comm) == systemd ]]
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
[[ -f ${root}/riscv-native-tools.lock.json && -f /usr/share/keyrings/debian-archive-keyring.gpg ]]
mkdir -p "${evidence}"
trap 'printf "sandbox bootstrap failed\n" >"${home}/preflight-failed"' ERR

# Freeze all dependency resolution while retaining Debian archive authentication.
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
timeout 600 apt-get update 2>&1 | tail -c 4194304 >"${evidence}/apt-update.log"
# Python is the sole bootstrap parser, at its exact locked version.
python_version=$(sed -n 's/^      "python3": "\([^"]*\)",\?$/\1/p' "${root}/riscv-native-tools.lock.json")
[[ ${python_version} == 3.13.5-1 ]]
timeout 1200 apt-get install -y --no-install-recommends --allow-downgrades "python3=${python_version}" 2>&1 | tail -c 4194304 >"${evidence}/apt-bootstrap.log"
mapfile -t packages < <(python3 - "${root}/riscv-native-tools.lock.json" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
assert lock['architecture'] == 'riscv64'
assert lock['debian']['snapshot'] == '20261005T000000Z'
for name, version in lock['debian']['packages'].items():
    print(f'{name}={version}')
PY
)
[[ ${#packages[@]} == 18 ]]
timeout 1200 apt-get install -y --no-install-recommends --allow-downgrades "${packages[@]}" 2>&1 | tail -c 4194304 >"${evidence}/apt-install.log"
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
useradd --uid 1001 --create-home --shell /bin/bash runner
# RootlessKit prepares its private TAP via ip tuntap before slirp4netns opens
# this node. Create it only in this sandbox's private /dev, with the matching
# outer device-cgroup rule; no provider device is mounted into the sandbox.
[[ ! -L /dev/net ]]
mkdir -p /dev/net
chmod 755 /dev/net
if [[ ! -e /dev/net/tun && ! -L /dev/net/tun ]]; then
  mknod -m 600 /dev/net/tun c 10 200
fi
[[ ! -L /dev/net/tun && -c /dev/net/tun && $(stat -c '%t:%T' /dev/net/tun) == a:c8 ]]
chown runner:runner /dev/net/tun
chmod 600 /dev/net/tun
printf 'runner:100000:65536\n' >/etc/subuid
printf 'runner:100000:65536\n' >/etc/subgid
chown -R runner:runner "${home}"
chmod 700 "${home}" "${evidence}"
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
mount --make-rshared /
exec /lib/systemd/systemd --show-status=false --unit=oxibelt-native.target
