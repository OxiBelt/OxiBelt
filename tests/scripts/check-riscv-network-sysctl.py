#!/usr/bin/env python3
"""Bounded forwarding probe inside pinned RootlessKit's detached network namespace."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOTLESSKIT = "/home/runner/native-tools/bin/rootlesskit"
LOCK = Path("/opt/oxibelt-preflight/riscv-native-tools.lock.json")
RUNTIME = Path("/run/user/1001")
PROC_PARENT = Path("/opt/oxibelt-preflight/private-proc")
PROC_HELPER = PROC_PARENT / "proc"
IPV4 = Path("/proc/sys/net/ipv4/ip_forward")
IPV6 = Path("/proc/sys/net/ipv6/conf/all/forwarding")
MAX_OUTPUT = 65536
TIMEOUT = 60
FLAGS = ["--net=slirp4netns", "--mtu=65520", "--slirp4netns-sandbox=auto",
         "--slirp4netns-seccomp=auto", "--disable-host-loopback", "--port-driver=builtin",
         "--copy-up=/etc", "--copy-up=/run", "--propagation=rslave", "--detach-netns"]


class ProbeError(ValueError):
    pass


def read_file(path: Path, maximum: int = 262144) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ProbeError("input-not-regular")
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ProbeError("input-too-large")
        return raw
    except OSError as error:
        raise ProbeError("input-unavailable") from error


def mount_metadata(text: str) -> list[dict]:
    """Parse bounded mount metadata without recording devices or mount sources."""
    if len(text.encode()) > 262144:
        raise ProbeError("mountinfo-too-large")
    mounts = []
    for line in text.splitlines():
        try:
            left, right = line.split(" - ", 1)
            fields, details = left.split(), right.split()
            point = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
            root = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[3])
            options = set(fields[5].split(","))
            if (not point.startswith("/") or ".." in Path(point).parts
                or not root.startswith("/") or ".." in Path(root).parts
                or len({"rw", "ro"}.intersection(options)) != 1 or len(details) < 3):
                raise ValueError
            mounts.append({"point": point, "root": root, "options": options,
                           "filesystem": details[0], "super_options": set(details[2].split(",")),
                           "propagation": fields[6:]})
        except (ValueError, IndexError) as error:
            raise ProbeError("invalid-mountinfo") from error

    return mounts


def mount_rows(text: str) -> list:
    return [(row["point"], row["options"], row["filesystem"]) for row in mount_metadata(text)]


def validate_proc_helper(text: str, *, required: bool = False) -> dict | None:
    """Allow exactly one full procfs visibility grant outside the protected /proc."""
    mounts = mount_metadata(text)
    matches = [row for row in mounts if row["point"] == str(PROC_HELPER)]
    for row in mounts:
        point = row["point"]
        if (point == str(PROC_PARENT) or point.startswith(str(PROC_PARENT) + "/")) and point != str(PROC_HELPER):
            raise ProbeError("unexpected-proc-helper-submount")
        if (row["filesystem"] == "proc" and point != "/proc"
            and (row["root"] == "/" or not point.startswith("/proc/")) and point != str(PROC_HELPER)):
            raise ProbeError("unexpected-procfs-alias")
    if not matches and not required:
        return None
    if len(matches) != 1:
        raise ProbeError("proc-helper-missing-or-duplicate")
    row = matches[0]
    if (row["root"] != "/" or row["filesystem"] != "proc"
        or not {"rw", "nosuid", "nodev", "noexec"} <= row["options"]
        or "rw" not in row["super_options"]
        or any(option.startswith(("subset=", "hidepid=")) for option in row["super_options"])
        or any(option.startswith("shared:") for option in row["propagation"])):
        raise ProbeError("proc-helper-mount-mismatch")
    return {"mountpoint": str(PROC_HELPER), "root": "/", "filesystem": "proc",
            "options": sorted(row["options"])}


def validate_proc_directories() -> None:
    for path in (PROC_PARENT.parent, PROC_PARENT.parent.parent, PROC_PARENT, PROC_HELPER):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022 or path.resolve(strict=True) != path):
            raise ProbeError("unsafe-proc-helper-directory")
        if path == PROC_PARENT and stat.S_IMODE(info.st_mode) != 0o700:
            raise ProbeError("unsafe-proc-helper-permissions")


def prepare_proc_mount() -> None:
    """The PID 1 Bash bootstrap creates a sandbox-local visibility grant."""
    if (os.getuid() != 0 or os.geteuid() != 0 or os.getppid() != 1
        or platform.machine() != "riscv64" or not Path("/.dockerenv").is_file()
        or read_file(Path("/proc/1/cmdline"), 256) != b"/bin/bash\0/opt/oxibelt-preflight/riscv-native-sandbox-bootstrap.sh\0"
        or Path("/proc/self/ns/mnt").stat().st_ino != Path("/proc/1/ns/mnt").stat().st_ino):
        raise ProbeError("requires-sandbox-pid-one-bootstrap-mount-namespace")
    before = read_file(Path("/proc/self/mountinfo")).decode()
    validate_mounts(before)
    if validate_proc_helper(before) is not None:
        raise ProbeError("proc-helper-already-mounted")
    root_rows = [row for row in mount_metadata(before) if row["point"] == "/"]
    if len(root_rows) != 1 or root_rows[0]["propagation"]:
        raise ProbeError("requires-private-sandbox-mount-propagation")
    for parent in (PROC_PARENT.parent.parent, PROC_PARENT.parent):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022 or parent.resolve(strict=True) != parent):
            raise ProbeError("unsafe-proc-helper-directory")
    PROC_PARENT.mkdir(mode=0o700)
    PROC_HELPER.mkdir(mode=0o700)
    validate_proc_directories()
    subprocess.run(["/usr/bin/mount", "-t", "proc", "-o", "rw,nosuid,nodev,noexec", "proc", str(PROC_HELPER)],
                   check=True, timeout=10, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    after = read_file(Path("/proc/self/mountinfo")).decode()
    validate_mounts(after, require_helper=True)
    validate_proc_directories()
    print(json.dumps(validate_proc_helper(after, required=True), sort_keys=True))


def protect_systemd_mounts() -> None:
    """Restore the known systemd fusectl mount's VFS flags before user startup."""
    if (os.getuid() != 0 or os.geteuid() != 0 or platform.machine() != "riscv64"
        or not Path("/.dockerenv").is_file()
        or read_file(Path("/proc/1/comm"), 32).strip() != b"systemd"
        or Path("/proc/self/ns/mnt").stat().st_ino != Path("/proc/1/ns/mnt").stat().st_ino):
        raise ProbeError("requires-sandbox-systemd-mount-namespace")
    text = read_file(Path("/proc/self/mountinfo")).decode()
    rows = mount_rows(text)
    targets = []
    for point, options, filesystem in rows:
        if point.startswith("/sys/") and "rw" in options and not (
            point == "/sys/fs/cgroup" or point.startswith("/sys/fs/cgroup/")):
            print(json.dumps({"mountpoint": point, "options": sorted(options), "filesystem": filesystem}))
            if (point != "/sys/fs/fuse/connections" or filesystem != "fusectl"
                or sum(row[0] == point for row in rows) != 1
                or Path(point).resolve(strict=True) != Path(point)):
                raise ProbeError("unexpected-writable-systemd-mount")
            targets.append(point)
    # Validate every other boundary before any mount mutation. Only this exact
    # systemd-created fusectl entry can be repaired; unknown mounts fail closed.
    sanitized = []
    for line in text.splitlines():
        fields = line.split()
        if fields[4] in targets:
            fields[5] = ",".join("ro" if option == "rw" else option for option in fields[5].split(","))
            line = " ".join(fields)
        sanitized.append(line)
    validate_mounts("\n".join(sanitized))
    for point in targets:
        subprocess.run(["/usr/bin/mount", "-o", "remount,bind,ro,nosuid,nodev,noexec", point],
                       check=True, timeout=10, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    validate_mounts(read_file(Path("/proc/self/mountinfo")).decode())


def validate_mounts(text: str, require_network: bool = True, *, require_helper: bool = False) -> dict:
    """Check effective mount options, including hidden writable sysctl submounts."""
    mounts = mount_rows(text)
    validate_proc_helper(text, required=require_helper)

    def effective(path):
        candidates = [(len(point), index, row) for index, row in enumerate(mounts)
                      for point in [row[0]] if path == point or path.startswith(point.rstrip("/") + "/")]
        if not candidates:
            raise ProbeError("required-mount-missing")
        return max(candidates, key=lambda row: row[:2])[2]

    for point, options, _filesystem in mounts:
        if (point.startswith("/sys/") and "rw" in options
            and not (point == "/sys/fs/cgroup" or point.startswith("/sys/fs/cgroup/"))):
            raise ProbeError("writable-noncgroup-sys-mount")
        if point.startswith("/sys/fs/cgroup/") and "rw" in options and _filesystem != "cgroup2":
            raise ProbeError("cgroup-submount-mismatch")
        if (point == "/proc/sys" or point.startswith("/proc/sys/")) and "rw" in options:
            if not (point == "/proc/sys/net" or point.startswith("/proc/sys/net/")):
                raise ProbeError("writable-nonnetwork-sysctl-mount")
            if _filesystem != "proc" or not {"nosuid", "nodev", "noexec"} <= options:
                raise ProbeError("network-sysctl-submount-mismatch")
    for path in ("/sys", "/proc/sys", "/proc/sys/kernel", "/proc/sys/user"):
        _point, options, filesystem = effective(path)
        if "ro" not in options or (path.startswith("/proc/") and filesystem != "proc"):
            raise ProbeError("required-readonly-mount-mismatch")
    point, options, filesystem = effective("/sys/fs/cgroup")
    if point != "/sys/fs/cgroup" or "rw" not in options or filesystem != "cgroup2":
        raise ProbeError("cgroup-mount-mismatch")
    if require_network:
        point, options, filesystem = effective("/proc/sys/net")
        if (point != "/proc/sys/net" or filesystem != "proc"
            or not {"rw", "nosuid", "nodev", "noexec"} <= options):
            raise ProbeError("network-sysctl-mount-mismatch")
        for point, options, filesystem in mounts:
            if point.startswith("/proc/sys/net/") and "rw" in options:
                if filesystem != "proc" or not {"nosuid", "nodev", "noexec"} <= options:
                    raise ProbeError("network-sysctl-submount-mismatch")
    return {"sys_readonly": True, "nonnetwork_sysctl_readonly": True,
            "cgroup_writable": True, "network_sysctl_writable": require_network}


def native_elf(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(20)
    except OSError as error:
        raise ProbeError("native-elf-unavailable") from error
    if len(raw) != 20 or raw[:6] != b"\x7fELF\x02\x01" or int.from_bytes(raw[18:20], "little") != 243:
        raise ProbeError("requires-native-riscv64-elf")


def prerequisites() -> dict:
    if platform.system() != "Linux" or platform.machine() != "riscv64" or os.getuid() != 1001 or os.geteuid() != 1001:
        raise ProbeError("requires-native-nonroot-runner-1001")
    native_elf(Path("/proc/self/exe"))
    native_elf(Path(ROOTLESSKIT))
    try:
        lock = json.loads(read_file(LOCK))
        if (lock["schemaVersion"] != 1 or lock["architecture"] != "riscv64"
            or lock["rootlesskit"]["version"] != "3.2.0"
            or lock["sources"]["engine"]["version"] != "29.8.0"):
            raise ProbeError("unexpected-source-lock")
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError("invalid-source-lock") from error
    validate_mounts(read_file(Path("/proc/self/mountinfo")).decode())
    return {"architecture": "riscv64", "executing_elf_machine": 243, "uid": 1001,
            "rootlesskit_version": "3.2.0", "engine_source_version": "29.8.0"}


def namespace_id(path: Path = Path("/proc/self/ns/net")) -> int:
    try:
        return path.stat().st_ino
    except OSError as error:
        raise ProbeError("network-namespace-unavailable") from error


def forwarding(path: Path) -> int:
    value = read_file(path, 32).strip()
    if value not in (b"0", b"1"):
        raise ProbeError("invalid-forwarding-value")
    return int(value)


def write_forwarding(path: Path, value: int) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "wb", buffering=0) as stream:
            # Some IPv6 forwarding handlers return 1 after applying a value.
            # A single numeric byte avoids treating that as a short write;
            # toggle still requires readback and verified restoration.
            if stream.write(str(value).encode()) != 1:
                raise ProbeError("short-sysctl-write")
    except OSError as error:
        raise ProbeError("sysctl-write-failed") from error


def toggle(path: Path, evidence: dict, *, optional: bool = False) -> None:
    try:
        before = forwarding(path)
    except ProbeError:
        if optional:
            evidence["status"] = "unavailable"
            return
        raise
    evidence.update(before=before, readback=None, restored=False)
    wrote = False
    try:
        # Restore even if a write or its readback fails after changing the value.
        write_forwarding(path, 1 - before)
        wrote = True
        evidence["readback"] = forwarding(path)
        if evidence["readback"] != 1 - before:
            raise ProbeError("forwarding-readback-mismatch")
    except ProbeError as error:
        evidence["status"] = "write-or-readback-failed"
        if optional:
            log_sysctl_error("optional-write", error)
        if not optional:
            raise
    else:
        evidence["status"] = "passed"
    finally:
        unchanged = False
        if optional and not wrote:
            try:
                unchanged = forwarding(path) == before
            except ProbeError as error:
                log_sysctl_error("optional-unchanged-read", error)
        if unchanged:
            evidence["status"] = "unavailable"
            evidence["restored"] = True
            # The optional IPv6 sysctl was never successfully written.
        else:
            try:
                write_forwarding(path, before)
                evidence["restored"] = forwarding(path) == before
            except ProbeError as error:
                log_sysctl_error("restore", error)
                evidence["restored"] = False
            if not evidence["restored"]:
                raise ProbeError("forwarding-restore-failed")


def log_sysctl_error(stage: str, error: ProbeError) -> None:
    # Fixed diagnostic labels and errno only; never emit input data or paths.
    cause = error.__cause__
    print(json.dumps({"sysctl_stage": stage, "diagnostic": str(error),
                      "errno": cause.errno if isinstance(cause, OSError) else None}), file=sys.stderr)


def guarded_state(state: Path, *, child: bool = False, identity: tuple[int, int] | None = None) -> None:
    if state.parent != RUNTIME or not re.fullmatch(r"oxibelt-network-[a-z0-9_]+", state.name):
        raise ProbeError("invalid-exclusive-state-path")
    try:
        info = state.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != (0 if child else 1001):
            raise ProbeError("invalid-exclusive-state-directory")
        if child and (identity is None or (info.st_dev, info.st_ino) != identity):
            raise ProbeError("state-directory-identity-mismatch")
        # RootlessKit's /run copy-up uses symlinks to the original contents.
        if not child and state.resolve(strict=True) != state:
            raise ProbeError("state-path-contains-symlink")
    except OSError as error:
        raise ProbeError("state-directory-unavailable") from error


def child_probe(state: Path, parent_netns: int, receipt: dict, state_identity: tuple[int, int]) -> None:
    guarded_state(state, child=True, identity=state_identity)
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ProbeError("requires-rootless-child-root")
    try:
        mappings = [tuple(map(int, row.split())) for row in read_file(Path("/proc/self/uid_map")).decode().splitlines()]
    except (ValueError, UnicodeDecodeError) as error:
        raise ProbeError("invalid-child-uid-map") from error
    if not mappings or mappings[0] != (0, 1001, 1):
        raise ProbeError("child-is-not-mapped-runner-root")
    current, detached = namespace_id(), namespace_id(state / "netns")
    receipt.update(sandbox_netns=parent_netns, detached_netns=current)
    if current == parent_netns or current != detached:
        raise ProbeError("child-did-not-enter-detached-network-namespace")
    toggle(IPV4, receipt["ipv4"])
    toggle(IPV6, receipt["ipv6"], optional=True)
    receipt["supported"] = True
    receipt["diagnostic"] = "passed"


def group_members(group: int) -> list[int]:
    # killpg uses the caller's PID namespace. A /proc scan may describe an
    # ancestor PID namespace in a nested test harness and collide with its IDs.
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return []
    except PermissionError:
        pass
    return [group]


def stop_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise ProbeError("process-group-cleanup-failed") from error
    while True:
        # A concurrent fork can finish after the first group-wide signal.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            while os.waitpid(-process.pid, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        if not group_members(process.pid):
            return
        if time.monotonic() >= deadline:
            raise ProbeError("process-group-cleanup-failed")
        time.sleep(0.01)


class Commands:
    def __init__(self):
        self.deadline = time.monotonic() + TIMEOUT
        self.log = bytearray()
        self.cleanup_confirmed = True
        # Reap orphaned grandchildren after killing the entire process group.
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise ProbeError("cannot-enable-child-subreaper")

    def call(self, arguments: list[str]) -> tuple[int, str]:
        if time.monotonic() >= self.deadline:
            raise ProbeError("command-timeout")
        try:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True,
                env={"HOME": "/home/runner", "USER": "runner", "LOGNAME": "runner",
                     "PATH": "/home/runner/native-tools/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                     "XDG_RUNTIME_DIR": str(RUNTIME)})
        except OSError as error:
            raise ProbeError("command-unavailable") from error
        output = bytearray()
        self.cleanup_confirmed = False
        try:
            with selectors.DefaultSelector() as selector:
                assert process.stdout and process.stderr
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0 or not (events := selector.select(remaining)):
                        raise ProbeError("command-timeout")
                    for key, _mask in events:
                        raw = os.read(key.fd, MAX_OUTPUT + 1 - len(self.log))
                        if not raw:
                            selector.unregister(key.fileobj)
                            continue
                        capacity = MAX_OUTPUT - len(self.log)
                        self.log.extend(raw[:capacity])
                        if len(raw) > capacity:
                            raise ProbeError("command-output-too-large")
                        if key.data:
                            output.extend(raw)
            try:
                code = process.wait(timeout=max(0.001, self.deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise ProbeError("command-timeout") from error
            try:
                return code, output.decode()
            except UnicodeDecodeError as error:
                raise ProbeError("invalid-command-output") from error
        finally:
            try:
                stop_group(process)
                self.cleanup_confirmed = True
            finally:
                process.stdout.close()
                process.stderr.close()


def parent_probe(receipt: dict, commands: Commands) -> None:
    receipt["native"] = prerequisites()
    receipt["sandbox_netns"] = namespace_id()
    receipt["parent_before"] = forwarding(IPV4)
    state = None
    try:
        code, version = commands.call([ROOTLESSKIT, "--version"])
        if code or not re.fullmatch(r"rootlesskit version 3\.2\.0\s*", version):
            raise ProbeError("rootlesskit-version-mismatch")
        runtime = RUNTIME.lstat()
        if not stat.S_ISDIR(runtime.st_mode) or runtime.st_uid != 1001 or stat.S_IMODE(runtime.st_mode) != 0o700:
            raise ProbeError("invalid-runtime-directory")
        state = Path(tempfile.mkdtemp(prefix="oxibelt-network-", dir=RUNTIME))
        guarded_state(state)
        state_info = state.lstat()
        code, output = commands.call([ROOTLESSKIT, "--state-dir=" + str(state), *FLAGS,
            "nsenter", "-n" + str(state / "netns"), "python3", str(Path(__file__).resolve()),
            "--child", str(state), "--parent-netns", str(receipt["sandbox_netns"]),
            "--state-device", str(state_info.st_dev), "--state-inode", str(state_info.st_ino)])
        try:
            child = json.loads(output)
            validate_child(child, receipt["sandbox_netns"])
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise ProbeError("invalid-child-evidence") from error
        receipt.update({key: child[key] for key in ("detached_netns", "ipv4", "ipv6")})
        if code or not child["supported"]:
            raise ProbeError(child["diagnostic"])
    finally:
        try:
            receipt["cleanup_confirmed"] = commands.cleanup_confirmed
            if state is not None and commands.cleanup_confirmed:
                receipt["cleanup_confirmed"] = False
                try:
                    # RootlessKit v3.2.0 itself removes its explicit state dir.
                    # Confirm absence only after the entire group is reaped.
                    try:
                        state.lstat()
                    except FileNotFoundError:
                        receipt["cleanup_confirmed"] = True
                    else:
                        guarded_state(state)
                        shutil.rmtree(state)
                        try:
                            state.lstat()
                        except FileNotFoundError:
                            receipt["cleanup_confirmed"] = True
                except OSError as error:
                    raise ProbeError("state-cleanup-failed") from error
        finally:
            receipt["parent_after"] = forwarding(IPV4)
            if receipt["parent_after"] != receipt["parent_before"]:
                raise ProbeError("sandbox-forwarding-changed")
    if not receipt["cleanup_confirmed"]:
        raise ProbeError("cleanup-not-confirmed")
    receipt.update(supported=True, diagnostic="passed")


def validate_child(value: dict, parent: int) -> None:
    if not isinstance(value, dict) or set(value) != {"schema_version", "supported", "diagnostic", "sandbox_netns", "detached_netns", "ipv4", "ipv6"}:
        raise ProbeError("invalid-child-evidence")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1 or type(value["supported"]) is not bool
        or not isinstance(value["diagnostic"], str) or not re.fullmatch(r"[a-z0-9-]{1,96}", value["diagnostic"])
        or value["sandbox_netns"] != parent
        or (value["detached_netns"] is not None and type(value["detached_netns"]) is not int)):
        raise ProbeError("invalid-child-evidence")
    if value["supported"]:
        ipv4 = value["ipv4"]
        if (type(value["detached_netns"]) is not int or value["detached_netns"] == parent or value["detached_netns"] <= 0
            or not isinstance(ipv4, dict) or set(ipv4) != {"before", "readback", "restored", "status"}
            or type(ipv4.get("before")) is not int or ipv4.get("before") not in (0, 1)
            or type(ipv4.get("readback")) is not int or ipv4.get("readback") != 1 - ipv4["before"] or ipv4.get("restored") is not True
            or ipv4.get("status") != "passed"):
            raise ProbeError("invalid-child-success-evidence")
        ipv6 = value["ipv6"]
        if not isinstance(ipv6, dict) or ipv6.get("status") not in ("passed", "unavailable", "write-or-readback-failed"):
            raise ProbeError("invalid-child-success-evidence")
        if ipv6["status"] != "unavailable" and ipv6.get("restored") is not True:
            raise ProbeError("invalid-child-success-evidence")
        if ipv6["status"] == "unavailable" and set(ipv6) == {"status"}:
            return
        if (set(ipv6) != {"before", "readback", "restored", "status"}
            or type(ipv6["before"]) is not int or ipv6["before"] not in (0, 1)
            or (ipv6["readback"] is not None and (type(ipv6["readback"]) is not int or ipv6["readback"] not in (0, 1)))
            or type(ipv6["restored"]) is not bool
            or (ipv6["status"] == "passed" and ipv6["readback"] != 1 - ipv6["before"])):
            raise ProbeError("invalid-child-success-evidence")


def validate_receipt(value: dict) -> dict:
    """Fail closed when consuming a successful native network-sysctl receipt."""
    fields = {"schema_version", "supported", "diagnostic", "native", "sandbox_netns",
              "detached_netns", "ipv4", "ipv6", "parent_before", "parent_after", "cleanup_confirmed"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ProbeError("invalid-network-sysctl-receipt")
    if (value["supported"] is not True or value["diagnostic"] != "passed"
        or value["cleanup_confirmed"] is not True
        or type(value["sandbox_netns"]) is not int or value["sandbox_netns"] <= 0
        or type(value["parent_before"]) is not int or value["parent_before"] not in (0, 1)
        or type(value["parent_after"]) is not int or value["parent_after"] != value["parent_before"]
        or value["native"] != {"architecture": "riscv64", "executing_elf_machine": 243, "uid": 1001,
                               "rootlesskit_version": "3.2.0", "engine_source_version": "29.8.0"}):
        raise ProbeError("invalid-network-sysctl-receipt")
    validate_child({key: value[key] for key in fields - {"native", "parent_before", "parent_after", "cleanup_confirmed"}},
                   value["sandbox_netns"])
    return value


def write_new(path: Path, raw: bytes) -> None:
    absolute = path.absolute()
    if ".." in absolute.parts or absolute.parent.resolve(strict=True) != absolute.parent:
        raise ProbeError("unsafe-evidence-path")
    try:
        fd = os.open(absolute, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except OSError as error:
        raise ProbeError("cannot-create-new-evidence-file") from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/home/runner/evidence/network-sysctl.json"))
    parser.add_argument("--check-mounts", action="store_true")
    parser.add_argument("--protect-systemd-mounts", action="store_true")
    parser.add_argument("--prepare-proc-mount", action="store_true")
    parser.add_argument("--child", type=Path)
    parser.add_argument("--parent-netns", type=int)
    parser.add_argument("--state-device", type=int)
    parser.add_argument("--state-inode", type=int)
    args = parser.parse_args(argv)
    if args.check_mounts or args.protect_systemd_mounts or args.prepare_proc_mount:
        try:
            if args.prepare_proc_mount:
                prepare_proc_mount()
            elif args.protect_systemd_mounts:
                protect_systemd_mounts()
            else:
                validate_mounts(read_file(Path("/proc/self/mountinfo")).decode())
        except (ProbeError, OSError, UnicodeDecodeError, subprocess.SubprocessError) as error:
            print("Network mount guard failed: " + str(error), file=sys.stderr)
            return 1
        return 0
    receipt = {"schema_version": 1, "supported": False, "diagnostic": "probe-not-completed",
               "sandbox_netns": args.parent_netns if args.child else None,
               "detached_netns": None, "ipv4": {}, "ipv6": {}}
    commands = None
    try:
        if args.child:
            if (args.parent_netns is None or args.parent_netns <= 0 or args.state_device is None
                or args.state_device < 0 or args.state_inode is None or args.state_inode <= 0):
                raise ProbeError("missing-parent-namespace-or-state-identity")
            child_probe(args.child, args.parent_netns, receipt, (args.state_device, args.state_inode))
        else:
            receipt.update(native=None, parent_before=None, parent_after=None, cleanup_confirmed=False)
            commands = Commands()
            parent_probe(receipt, commands)
            validate_receipt(receipt)
    except (ProbeError, OSError, UnicodeDecodeError) as error:
        receipt["diagnostic"] = str(error) if isinstance(error, ProbeError) else "probe-input-unavailable"
        receipt["supported"] = False
    if args.child:
        print(json.dumps(receipt, sort_keys=True))
    else:
        try:
            raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
            if len(raw) > 16384:
                raise ProbeError("evidence-too-large")
            write_new(args.output, raw)
            write_new(args.output.parent / "network-sysctl.log", bytes(commands.log) if commands else b"")
        except (ProbeError, OSError) as error:
            print("Cannot preserve network probe evidence: " + str(error), file=sys.stderr)
            return 2
        print("Native detached network forwarding probe " + ("passed." if receipt["supported"] else "failed; inspect network-sysctl.json."))
    return 0 if receipt["supported"] else 1


if __name__ == "__main__":
    sys.exit(main())
